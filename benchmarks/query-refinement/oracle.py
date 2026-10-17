"""Static finite string tracing; fixture code objects and sink operands are never run."""
import ast
import hashlib
import json

CONTRACT = 'finite-input-to-dynamic-evaluation-v1'
INPUTS = ('11', '22')
MAX_SOURCE_BYTES = 2048
MAX_AST_NODES = 256
IDENTITY_FIELDS = ('opcode', 'sink_ast_sha256', 'operand_ast_sha256', 'function_binding', 'binding_lineage')


class OracleFailure(Exception):
    def __init__(self, reason, status='oracle_unsupported'):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _fingerprint(node):
    return _sha(ast.dump(node, annotate_fields=True, include_attributes=False).encode('utf-8'))


def _offsets(source):
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _byte_range(source, node):
    offsets = _offsets(source)
    try:
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
    except (AttributeError, IndexError, TypeError):
        raise OracleFailure('sink_range_invalid', 'incomplete') from None
    if not (type(start) is int and type(end) is int and 0 <= start < end <= len(source)):
        raise OracleFailure('sink_range_invalid', 'incomplete')
    # Reparse the exact byte slice to independently check UTF-8 offsets and subtree identity.
    try:
        reparsed = ast.parse(source[start:end].decode('utf-8'), mode='eval').body
    except (SyntaxError, UnicodeError):
        raise OracleFailure('sink_range_invalid', 'incomplete') from None
    if _fingerprint(reparsed) != _fingerprint(node):
        raise OracleFailure('sink_range_invalid', 'incomplete')
    return start, end


def _expression_lineage(node, bindings):
    if isinstance(node, ast.Constant) and type(node.value) is str:
        try:
            node.value.encode('utf-8')
        except UnicodeError:
            raise OracleFailure('operand_utf8_invalid') from None
        return []
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in bindings:
        return list(bindings[node.id])
    raise OracleFailure('unsupported_expression_or_unbound_name')


def _prepare(source):
    if type(source) is not bytes:
        raise OracleFailure('source_not_bytes')
    if not source or len(source) > MAX_SOURCE_BYTES:
        raise OracleFailure('source_byte_budget')
    try:
        text = source.decode('utf-8')
        tree = ast.parse(text, mode='exec')
    except (UnicodeError, SyntaxError, ValueError, RecursionError):
        raise OracleFailure('source_parse_invalid') from None
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_AST_NODES:
        raise OracleFailure('ast_node_budget')
    allowed = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Assign, ast.Return,
               ast.Expr, ast.Call, ast.Name, ast.Load, ast.Store, ast.Constant)
    if any(not isinstance(node, allowed) for node in nodes):
        raise OracleFailure('unsupported_ast_node')
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise OracleFailure('unsupported_module_boundary')
    function = tree.body[0]
    args = function.args
    if (function.name != 'subject' or function.decorator_list or function.returns is not None
            or function.type_comment is not None or getattr(function, 'type_params', [])
            or args.posonlyargs or args.vararg is not None or args.kwarg is not None
            or args.kwonlyargs or args.defaults or args.kw_defaults or len(args.args) != 1
            or args.args[0].arg != 'user_input' or args.args[0].annotation is not None
            or args.args[0].type_comment is not None):
        raise OracleFailure('unsupported_function_signature')
    try:
        compile(text, '<finite-oracle>', 'exec', dont_inherit=True)  # Compile only, discard object.
    except (SyntaxError, ValueError, RecursionError):
        raise OracleFailure('source_compile_invalid') from None
    bindings = {'user_input': [{'kind': 'parameter', 'name': 'user_input'}]}
    sinks = []
    for statement in function.body:
        if isinstance(statement, ast.Assign):
            if (statement.type_comment is not None or len(statement.targets) != 1
                    or not isinstance(statement.targets[0], ast.Name)
                    or not isinstance(statement.targets[0].ctx, ast.Store)):
                raise OracleFailure('unsupported_assignment')
            name = statement.targets[0].id
            if name in ('subject', 'user_input', 'eval', 'exec') or name in bindings:
                raise OracleFailure('shadowed_or_repeated_binding')
            lineage = _expression_lineage(statement.value, bindings)
            bindings[name] = lineage + [{'kind': 'assignment', 'name': name,
                                          'value_ast_sha256': _fingerprint(statement.value)}]
        elif isinstance(statement, ast.Return):
            _expression_lineage(statement.value, bindings)
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if (not isinstance(call.func, ast.Name) or call.func.id not in ('eval', 'exec')
                    or not isinstance(call.func.ctx, ast.Load) or len(call.args) != 1 or call.keywords):
                raise OracleFailure('unsupported_call')
            lineage = _expression_lineage(call.args[0], bindings)
            start, end = _byte_range(source, call)
            sinks.append({'opcode': call.func.id, 'operand_literal': isinstance(call.args[0], ast.Constant),
                          'byte_start': start, 'byte_end': end, 'source_sha256': _sha(source),
                          'sink_bytes_sha256': _sha(source[start:end]),
                          'sink_ast_sha256': _fingerprint(call),
                          'operand_ast_sha256': _fingerprint(call.args[0]),
                          'function_binding': {'name': 'subject', 'parameter': 'user_input'},
                          'binding_lineage': lineage})
        else:
            raise OracleFailure('unsupported_statement')
    if len(sinks) > 1:
        raise OracleFailure('repeated_sink', 'incomplete')
    return function, sinks


def _value(node, values):
    if isinstance(node, ast.Constant):
        return node.value
    return values[node.id]


def _trace(source, function, sinks, input_value):
    values = {'user_input': input_value}
    record = {'input': input_value, 'source_sha256': _sha(source), 'opcode': None,
              'byte_start': None, 'byte_end': None, 'operand_hex': None}
    for statement in function.body:
        if isinstance(statement, ast.Assign):
            values[statement.targets[0].id] = _value(statement.value, values)
        elif isinstance(statement, ast.Return):
            break
        else:
            sink = sinks[0]
            record.update(opcode=sink['opcode'], byte_start=sink['byte_start'], byte_end=sink['byte_end'],
                          operand_hex=_value(statement.value.args[0], values).encode('utf-8').hex())
    return record


def observe(source):
    result = {'schema_version': 1, 'contract': CONTRACT,
              'source_sha256': _sha(source) if type(source) is bytes and len(source) <= MAX_SOURCE_BYTES else None,
              'status': 'incomplete', 'complete': False, 'relation': None,
              'reason': None, 'traces': [], 'sinks': []}
    try:
        function, sinks = _prepare(source)
        traces = [_trace(source, function, sinks, value) for value in INPUTS]
        result.update(sinks=sinks, traces=traces)
        if sinks:
            sink = sinks[0]
            identity = (sink['source_sha256'], sink['opcode'], sink['byte_start'], sink['byte_end'])
            if any((t['source_sha256'], t['opcode'], t['byte_start'], t['byte_end']) != identity for t in traces):
                raise OracleFailure('sink_trace_missing_or_identity_mismatch', 'incomplete')
            relation = 'input_dependent' if traces[0]['operand_hex'] != traces[1]['operand_hex'] else 'input_independent'
        else:
            relation = 'no_sink'
        result.update(status='complete', complete=True, relation=relation)
    except OracleFailure as error:
        result.update(status=error.status, reason=error.reason)
    return result


analyze = observe


def verify_observation(source, trace):
    result = observe(source)
    if not result['complete'] or type(trace) is not dict:
        return False
    try:
        return any(_canonical(trace) == _canonical(expected) for expected in result['traces'])
    except (TypeError, ValueError, RecursionError):
        return False


def _identity(sink):
    return {key: sink[key] for key in IDENTITY_FIELDS}


def _origin(source, sink):
    return {'source_hex': source.hex(), 'source_sha256': _sha(source), **_identity(sink)}


def map_sink(parent_source, child_source, origin=None):
    result = {'status': 'minimize_mapping_unknown', 'reason': None, 'sink_lineage_id': None,
              'origin': None, 'parent_sink': None, 'child_sink': None}
    parent = observe(parent_source)
    child = observe(child_source)
    if not (parent['complete'] and child['complete'] and len(parent['sinks']) == len(child['sinks']) == 1):
        result['reason'] = 'source_or_unique_sink_incomplete'
        return result
    parent_sink, child_sink = parent['sinks'][0], child['sinks'][0]
    result.update(parent_sink=parent_sink, child_sink=child_sink)
    if (_canonical(_identity(parent_sink)) != _canonical(_identity(child_sink))
            or parent['relation'] != child['relation']):
        result['reason'] = 'sink_operand_or_binding_changed'
        return result
    if origin is None:
        verified_origin = _origin(parent_source, parent_sink)
    else:
        try:
            if type(origin) is not dict or type(origin.get('source_hex')) is not str or len(origin['source_hex']) > MAX_SOURCE_BYTES * 2:
                raise ValueError('invalid origin')
            origin_source = bytes.fromhex(origin['source_hex'])
            if origin_source.hex() != origin['source_hex']:
                raise ValueError('noncanonical origin')
            observed_origin = observe(origin_source)
            if not observed_origin['complete'] or len(observed_origin['sinks']) != 1:
                raise ValueError('incomplete origin')
            verified_origin = _origin(origin_source, observed_origin['sinks'][0])
            if (_canonical(origin) != _canonical(verified_origin)
                    or _canonical(_identity(observed_origin['sinks'][0])) != _canonical(_identity(parent_sink))
                    or observed_origin['relation'] != parent['relation']):
                raise ValueError('origin identity changed')
        except (TypeError, ValueError, RecursionError):
            result['reason'] = 'origin_unverified'
            return result
    result.update(status='mapped', reason=None, origin=verified_origin,
                  sink_lineage_id=_sha(_canonical(verified_origin).encode('utf-8')))
    return result


def deletion_candidates(source):
    observation = observe(source)
    if not observation['complete'] or len(observation['sinks']) != 1:
        return []
    function, _ = _prepare(source)
    offsets = _offsets(source)
    candidates = []
    for index, statement in enumerate(function.body):
        if isinstance(statement, ast.Expr):
            continue
        if any(other is not statement and not (other.end_lineno < statement.lineno or other.lineno > statement.end_lineno)
               for other in function.body):
            continue
        start, end = offsets[statement.lineno - 1], offsets[statement.end_lineno]
        child = source[:start] + source[end:]
        mapping = map_sink(source, child)
        if mapping['status'] == 'mapped':
            candidates.append({'source': child, 'removed_statement': index,
                               'parent_source_sha256': _sha(source), 'source_sha256': _sha(child),
                               'mapping': mapping})
    return candidates
