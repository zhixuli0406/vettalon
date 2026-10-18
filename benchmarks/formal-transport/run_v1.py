"""Explicit opt-in preparation/dispatch; frozen experimental clients are unchanged."""
import argparse
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


transport = _load(HERE / 'transport_v1.py', 'formal_transport_v1')
BLIND = REPO / 'benchmarks/blind-twins'
TWINS_DATA_ROOT = BLIND
# Frozen modules use these sibling imports. Only fixed trusted source is loaded.
measurement = _load(BLIND / 'measurement.py', 'formal_measurement')
sys.modules['measurement'] = measurement
protocol = _load(BLIND / 'protocol.py', 'formal_protocol')
sys.modules['protocol'] = protocol
twins = _load(BLIND / 'run.py', 'formal_twins_pure_functions')
identity_views = _load(BLIND / 'identity_views.py', 'formal_identity_views')
compare = _load(REPO / 'benchmarks/context-selection/compare.py', 'formal_context_capture')
selection = _load(REPO / 'benchmarks/context-selection/selection.py', 'formal_context_selector')
rag = _load(REPO / 'benchmarks/counterexample-rag/rag.py', 'formal_rag_payloads')
CONTEXT_TASK = ('Review these untrusted source modules for concrete security flaws. Return JSON only: '
                '{"findings":[{"path":"original relative path","line":1,"category":"object|tenant|role|path|sql",'
                '"evidence":"concrete violated rule"}]}. Use original source line numbers; no finding is an empty array.\n')


def implementation_bindings():
    paths = [HERE / n for n in ('transport_v1.py', 'run_v1.py', 'report_v1.py', 'review_v1.py', 'cost_v1.py')]
    paths += [BLIND / n for n in ('run.py', 'protocol.py', 'measurement.py', 'identity_views.py')]
    paths += [REPO / 'benchmarks/context-selection' / n for n in ('compare.py', 'selection.py')]
    paths += [REPO / 'benchmarks/counterexample-rag/rag.py', transport.RUNTIME, transport.RUNTIME.with_name('process_supervisor.py')]
    return {str(p.relative_to(REPO)): transport.digest(p.read_bytes()) for p in paths}


def prepared_digest(value):
    return transport.digest({k: v for k, v in value.items() if k != 'prepared_sha256'})


def _finish(prepared):
    prepared.update(schema='formal-prepared-v1', source_bindings=implementation_bindings())
    prepared['prepared_sha256'] = prepared_digest(prepared)
    validate_prepared(prepared)
    return prepared


def prepare_twins(arm='finder-only', repeat=0, identity='anonymous'):
    if arm not in ('finder-only', 'samefamily', 'crossfamily') or type(repeat) is not int or not 0 <= repeat <= 4:
        raise ValueError('Fixed arm and repeat 0..4 required')
    if identity not in ('anonymous', 'identified'): raise ValueError('Unsupported identity view')
    payloads, labels = protocol.generate()
    manifest = transport.read_json(TWINS_DATA_ROOT / 'manifest.json')
    expected = {p['id']: p['source_sha256'] for p in payloads}
    if {p['id']: p['source_sha256'] for p in manifest['cases']} != expected:
        raise ValueError('Materialized source manifest mismatch')
    for payload in payloads:
        if transport.read_json(TWINS_DATA_ROOT / 'anonymous' / (payload['id'] + '.json')) != payload:
            raise ValueError('Actual materialized source mismatch')
    frozen = json.loads(twins.read_regular((protocol.ARTIFACTS / 'denominator.json').absolute(), 2 * 1024 * 1024))
    protocol.validate_frozen_canonical(frozen, twins.read_regular((protocol.ARTIFACTS / 'canonical-oracle.json').absolute(), 2 * 1024 * 1024))
    scope = transport.read_json(TWINS_DATA_ROOT / 'fixed-five-pair-subset.json')
    payloads, selected_labels = protocol.select_scope(payloads, labels, scope)
    manifest_sha = transport.digest((TWINS_DATA_ROOT / 'manifest.json').read_bytes())
    rows = []
    for payload in payloads:
        binding = {'kind': 'self-authored-synthetic', 'collection': 'vettalon-self-authored-twins',
                   'artifact': f"benchmarks/blind-twins/anonymous/{payload['id']}.json", 'source_manifest_sha256': manifest_sha}
        view = identity_views.build_view(payload) if identity == 'anonymous' else identity_views.build_view(payload, 'identified', binding)
        rows.append({'id': payload['id'], 'source_sha256': payload['source_sha256'], 'payload': view})
    return _finish({'experiment': 'twins', 'identity_view': identity,
        'execution_status': 'prepared-not-dispatched' if identity == 'anonymous' else 'prepare-only-no-budget-for-second-identity',
        'arm': arm, 'repeat': repeat, 'task': twins.TASK, 'scope_manifest': scope,
        'scope_sha256': protocol.digest(scope), 'frozen_denominator_sha256': protocol.digest(frozen),
        'source_manifest_raw_sha256': manifest_sha, 'rows': rows, 'comparable': True,
        'human_adjudicated_corpus': False, 'external_holdout': False})


def _select_context(root, mode):
    with tempfile.TemporaryDirectory(prefix='vettalon-formal-selection-') as name:
        directory = Path(name)
        request = directory / 'selection-request.json'
        transport.write_new(request, {'root': str(root), 'mode': mode})
        runtime = transport.load_runtime()
        receipt = runtime.invoke([sys.executable, '-B', '-I', '-S', str(Path(__file__).resolve()), '--selection-worker', str(request)],
            directory, {'PATH': os.defpath, 'LANG': 'C', 'HOME': str(directory), 'TMPDIR': str(directory),
                        'PYTHONDONTWRITEBYTECODE': '1'}, 2, stdout_cap=4 * 1024 * 1024, stderr_cap=128 * 1024)
        if not runtime.successful_run(receipt): raise ValueError('Selection process controls incomplete')
        return json.loads(receipt['stdout'])


def _validate_context_range_budget(modules):
    """Check actual selected ranges independently of the selector's claimed byte total."""
    total = 0
    for module in modules:
        for segment in module['ranges']:
            low = segment.get('start_byte'); high = segment.get('end_byte')
            if type(low) is not int or type(high) is not int or not 0 <= low < high:
                raise ValueError('Invalid context byte range')
            total += high - low
            if total > 16384: raise ValueError('Context selected-byte cap exceeded')
    return total


def prepare_context(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): raise ValueError('Real source directory required')
    root = root.resolve(); initial = compare.capture(root); snapshot = initial['snapshot']
    rows = []
    with tempfile.TemporaryDirectory(prefix='vettalon-formal-snapshot-') as name:
        frozen = Path(name)
        for index, (path, source) in enumerate(snapshot.items()):
            if index < 40 and 'raw_base64' in source:
                target = frozen / path; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(base64.b64decode(source['raw_base64'], validate=True))
        frozen_before = compare.capture(frozen)
        for mode in compare.MODES:
            row = {'id': mode, 'source_sha256': transport.digest(initial), 'payload': {'modules': []},
                   'selection_status': 'selection_failure', 'selection_incomplete': True}
            rows.append(row)
            try:
                selected = _select_context(frozen, mode)
                compare.validate_selection_result(selected, mode, 40, 16384, 2, 3)
                compare.validate_selection_scope(selected, frozen_before['snapshot'], 2)
                by_path = {item['path']: item for item in selected['files']}
                if len(by_path) != len(selected['files']) or any(path not in snapshot for path in by_path):
                    raise ValueError('Selected paths differ from frozen scope')
                modules = []
                for index, (path, source) in enumerate(snapshot.items()):
                    module = by_path.get(path, {'path': path, 'status': source['status'], 'ranges': []})
                    if index >= 40: module = {'path': path, 'status': 'module_cap', 'ranges': []}
                    if source['status'] == 'captured' and index < 40 and path not in by_path:
                        raise ValueError('Captured source omitted by selector')
                    if module['status'] in ('selected', 'truncated') and not module['ranges']:
                        raise ValueError('Selected status has no source range')
                    if source['status'] == 'captured' and index < 40:
                        compare.verify_selected_ranges(module, source)
                    modules.append({'path': path, 'source_sha256': source['source_sha256'],
                                    'status': module['status'], 'ranges': module['ranges']})
                _validate_context_range_budget(modules)
                row.update(payload={'modules': modules}, selection=selected, selection_status='ready',
                           selection_incomplete=selected['incomplete'])
                if len((CONTEXT_TASK + json.dumps(row['payload'])).encode()) > 32768:
                    row.update(selection_status='prompt_budget', selection_incomplete=True)
            except (OSError, ValueError, KeyError) as error:
                row.update(error=type(error).__name__, payload={'modules': [
                    {'path': path, 'source_sha256': source['source_sha256'], 'status': source['status'], 'ranges': []}
                    for path, source in snapshot.items()]})
        unchanged = compare.capture(root) == initial and compare.capture(frozen) == frozen_before
    return _finish({'experiment': 'context', 'identity_view': 'anonymous', 'execution_status': 'prepared-not-dispatched',
        'task': CONTEXT_TASK, 'scope_sha256': transport.digest(sorted(snapshot)), 'snapshot_sha256': transport.digest(initial),
        'snapshot': snapshot, 'source_root': str(root),
        'comparable': unchanged and initial['inventory_complete'] and initial['source_capture_complete']
                      and all(row['selection_status'] == 'ready' for row in rows),
        'initial_capture': initial,
        'inventory_complete': initial['inventory_complete'], 'module_denominator': len(snapshot) if initial['inventory_complete'] else None,
        'inventoried_module_lower_bound': len(snapshot), 'rows': rows,
        'human_adjudicated_corpus': False, 'external_holdout': False})


def prepare_rag():
    result = rag.dry_run()
    return _finish({'experiment': 'rag', 'identity_view': 'anonymous', 'execution_status': 'prepared-not-dispatched',
        'task': twins.TASK, 'scope_sha256': transport.digest(result['holdout_query_ids']),
        'corpus_digest': result['corpus_digest'], 'corpus_ids': result['corpus_ids'],
        'rows': [{'id': row['query_id'] + ':' + row['arm'], 'query_id': row['query_id'], 'arm': row['arm'],
                  'source_sha256': row['query_source_sha256'], 'payload': row['payload']} for row in result['rows']],
        'comparable': True, 'human_adjudicated_corpus': False, 'external_holdout': False})


def validate_prepared(prepared):
    if (type(prepared) is not dict or prepared.get('schema') != 'formal-prepared-v1'
            or prepared.get('prepared_sha256') != prepared_digest(prepared)
            or prepared.get('experiment') not in ('twins', 'context', 'rag')
            or type(prepared.get('rows')) is not list or not prepared['rows']):
        raise ValueError('Prepared experiment binding mismatch')
    ids = [row['id'] for row in prepared['rows']]
    if len(ids) != len(set(ids)): raise ValueError('Duplicate prepared case')
    expected_twins = {}
    if prepared['experiment'] == 'twins':
        payloads, labels = protocol.generate()
        payloads, labels = protocol.select_scope(payloads, labels, prepared['scope_manifest'])
        expected_twins = {p['id']: p for p in payloads}
        if (set(ids) != set(expected_twins) or prepared['scope_sha256'] != protocol.digest(prepared['scope_manifest'])
                or type(prepared['repeat']) is not int or not 0 <= prepared['repeat'] <= 4
                or prepared['arm'] not in ('finder-only', 'samefamily', 'crossfamily') or prepared['task'] != twins.TASK):
            raise ValueError('Twins scope, repeat or task differs from frozen protocol')
    elif prepared['experiment'] == 'context':
        if (set(ids) != set(compare.MODES) or prepared['task'] != CONTEXT_TASK
                or prepared['snapshot_sha256'] != transport.digest(prepared['initial_capture'])
                or prepared['snapshot'] != prepared['initial_capture']['snapshot']
                or prepared['scope_sha256'] != transport.digest(sorted(prepared['snapshot']))):
            raise ValueError('Context snapshot, mode or task mismatch')
        if (prepared['comparable'] and
                (not prepared['initial_capture']['inventory_complete']
                 or not prepared['initial_capture']['source_capture_complete']
                 or any(row['selection_status'] != 'ready' for row in prepared['rows']))):
            raise ValueError('Incomplete context source or selection cannot be comparable')
    else:
        corpus, queries = rag.build()
        query_ids = {query['id'] for query in queries}
        expected_ids = {case + ':' + arm for case in query_ids for arm in ('baseline', 'random', 'retrieval')}
        if (set(ids) != expected_ids or prepared['task'] != twins.TASK
                or prepared['scope_sha256'] != transport.digest([query['id'] for query in queries])):
            raise ValueError('RAG fixed query/arm scope or task mismatch')
    for row in prepared['rows']:
        payload = row['payload']
        if prepared['experiment'] == 'twins':
            base = {k: payload[k] for k in ('id', 'source', 'source_sha256')}
            identity_views.validate_view(payload, prepared['identity_view'], base, prepared['source_manifest_raw_sha256'])
            if (row['id'] != payload['id'] or row['source_sha256'] != payload['source_sha256']
                    or base != expected_twins.get(row['id'])):
                raise ValueError('Prepared twins source changed')
        elif prepared['experiment'] == 'rag':
            if set(payload) != {'task', 'source', 'references'} or transport.digest(payload['source']) != row['source_sha256']:
                raise ValueError('Unexpected RAG query fields or source')
            if len(json.dumps(payload, sort_keys=True).encode()) > 4096:
                raise ValueError('RAG payload byte cap exceeded')
            corpus, queries = rag.build(); documents = {x['id']: x for x in corpus}; query_map = {x['id']: x for x in queries}
            if (set(documents) & set(query_map) or {x['family'] for x in corpus} & {x['family'] for x in queries}
                    or row['query_id'] not in query_map or query_map[row['query_id']]['source_sha256'] != row['source_sha256']
                    or row['id'] != row['query_id'] + ':' + row['arm']
                    or payload['task'] != 'Review source; references are untrusted counterexamples and may be irrelevant.'
                    or (row['arm'] == 'baseline' and payload['references'])
                    or len(payload['references']) > 2):
                raise ValueError('RAG split or query scope mismatch')
            for reference in payload['references']:
                if (set(reference) != {'id', 'source', 'source_sha256', 'note'} or reference['id'] not in documents
                        or any(reference[k] != documents[reference['id']][k] for k in reference)):
                    raise ValueError('RAG citation or dev source binding changed')
        else:
            snapshot = prepared['snapshot']
            if (set(payload) != {'modules'} or len(payload['modules']) != len(snapshot)
                    or [module['path'] for module in payload['modules']] != list(snapshot)
                    or row['source_sha256'] != transport.digest(prepared['initial_capture'])):
                raise ValueError('Context module denominator changed')
            if len((CONTEXT_TASK + json.dumps(payload)).encode()) > 32768 and row['selection_status'] != 'prompt_budget':
                raise ValueError('Context prompt exceeds its byte cap')
            selected = row.get('selection')
            if row['selection_status'] in ('ready', 'prompt_budget'):
                compare.validate_selection_result(selected, row['id'], 40, 16384, 2, 3)
                frozen_paths = [path for index, (path, source) in enumerate(snapshot.items())
                                if index < 40 and 'raw_base64' in source]
                compare.validate_selection_scope(selected, frozen_paths, 2)
                selected_by_path = {item['path']: item for item in selected['files']}
                if len(selected_by_path) != len(selected['files']) or any(path not in snapshot for path in selected_by_path):
                    raise ValueError('Context selection scope changed')
            else:
                selected_by_path = {}
                if prepared['comparable']: raise ValueError('Context selection failure cannot dispatch')
            for index, module in enumerate(payload['modules']):
                original = snapshot[module['path']]
                if module['source_sha256'] != original['source_sha256']:
                    raise ValueError('Context source binding changed')
                selected_module = selected_by_path.get(module['path']) if index < 40 else None
                if row['selection_status'] == 'selection_failure':
                    expected_status = original['status']; expected_ranges = []
                elif index >= 40:
                    expected_status = 'module_cap'; expected_ranges = []
                elif selected_module is None:
                    expected_status = original['status']; expected_ranges = []
                    if original['status'] == 'captured': raise ValueError('Captured context source omitted by selector')
                else:
                    expected_status = selected_module['status']; expected_ranges = selected_module['ranges']
                    if expected_status in ('selected', 'truncated') and not expected_ranges:
                        raise ValueError('Selected status has no source range')
                    if original['status'] == 'captured': compare.verify_selected_ranges(selected_module, original)
                if module['status'] != expected_status or module['ranges'] != expected_ranges:
                    raise ValueError('Context range binding changed')
            _validate_context_range_budget(payload['modules'])
    return True


def budget_plan(prepared, models, backend='local-ollama-http-v1', input_token_cap=None):
    validate_prepared(prepared)
    if not prepared['comparable']: raise ValueError('Snapshot or inventory incomplete; no dispatch')
    if prepared['identity_view'] != 'anonymous': raise ValueError('Second identity has no execution budget')
    experiment = prepared['experiment']
    if experiment == 'twins':
        if set(models) != {'finder', 'samefamily_verifier', 'crossfamily_verifier'}:
            raise ValueError('One fixed finder/samefamily/crossfamily roster required for all three arms')
        family = models['finder']['family']
        known = {'qwen', 'llama', 'gemma', 'phi', 'mistral'}
        if any(model['family'] not in known for model in models.values()):
            raise ValueError('Unknown declared architecture family')
        protocol.validate_arm('samefamily', family, models['samefamily_verifier']['family'])
        protocol.validate_arm('crossfamily', family, models['crossfamily_verifier']['family'])
        for left in models.values():
            for right in models.values():
                if left['name'] == right['name'] and left != right:
                    raise ValueError('One named model cannot have contradictory digest or family')
    elif set(models) != {'finder'}:
        raise ValueError('Context/RAG use one explicit finder role')
    calls = 250 if experiment == 'twins' else len(prepared['rows'])
    value = {'schema': 'formal-budget-v1', 'purpose': 'd01-anonymous-fixed-five-pair-v1' if experiment == 'twins' else experiment + '-' + prepared['scope_sha256'][:24] + '-v1',
        'experiment': experiment, 'backend': backend, 'models': copy.deepcopy(models),
        'scope_sha256': prepared['scope_sha256'], 'task_sha256': transport.digest(prepared['task']),
        'source_bindings': prepared['source_bindings'], 'max_calls': calls, 'max_output_tokens': 1024,
        'max_total_output_tokens': calls * 1024, 'per_call_seconds': 90, 'per_run_seconds': 1200,
        'input_token_cap': input_token_cap, 'inflight': 1, 'automatic_retries': 0}
    transport.validate_plan(value)
    return value


def initial_raw(prepared, plan):
    validate_prepared(prepared); transport.validate_plan(plan)
    rows = []
    for item in prepared['rows']:
        row = copy.deepcopy(item)
        row.update(status='missing', attempts=[], adjudication='U', differential_oracle=False, cache=False, retry_count=0,
                   fingerprint=transport.digest({'prepared': prepared['prepared_sha256'], 'plan': transport.digest(plan), 'id': item['id']}))
        rows.append(row)
    return {'schema': 'formal-experiment-v1', 'kind': 'opt-in-client-transport-experiment',
        'experiment': prepared['experiment'], 'prepared': copy.deepcopy(prepared), 'budget_plan': copy.deepcopy(plan),
        'rows': rows, 'status': 'initializing', 'usage_summary': transport.summarize_usage([]),
        'human_adjudicated_corpus': prepared['human_adjudicated_corpus'], 'external_holdout': prepared['external_holdout'],
        'model_identity_status': 'declared-only-serving-not-verified', 'provider_controls_verified': None,
        'raw_semantics': 'Client admission and provider-reported usage; no human verdict, billing, or upstream cancellation guarantee.'}


def parse_context_answer(text, payload):
    try:
        value = json.loads(text)
        if type(value) is not dict or set(value) != {'findings'} or type(value['findings']) is not list or len(value['findings']) > 40:
            return None
        modules = {m['path']: m for m in payload['modules']}
        for finding in value['findings']:
            if (type(finding) is not dict or set(finding) != {'path', 'line', 'category', 'evidence'}
                    or type(finding['path']) is not str or finding['path'] not in modules
                    or type(finding['line']) is not int or finding['category'] not in ('object', 'tenant', 'role', 'path', 'sql')
                    or type(finding['evidence']) is not str or not finding['evidence'].strip()
                    or not any(s['start_line'] <= finding['line'] <= s['end_line'] for s in modules[finding['path']]['ranges'])):
                return None
        return value
    except (ValueError, KeyError, TypeError):
        return None


def execute(prepared, plan, output_name):
    validate_prepared(prepared)
    expected = budget_plan(prepared, plan['models'], plan['backend'], plan['input_token_cap'])
    if plan != expected: raise ValueError('Budget does not bind this prepared source and task')
    if type(output_name) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', output_name):
        raise ValueError('Owned output name required, not an arbitrary path')
    first_prompt = prepared['task'] + json.dumps(prepared['rows'][0]['payload'])
    for role in plan['models']: transport.ensure_ready(plan, first_prompt, role)
    for path, expected_sha in plan['source_bindings'].items():
        if transport.digest((REPO / path).read_bytes()) != expected_sha:
            raise ValueError('Prepared implementation changed before dispatch')
    if prepared['experiment'] == 'context' and compare.capture(Path(prepared['source_root'])) != prepared['initial_capture']:
        raise ValueError('Source snapshot changed after preparation; no dispatch')
    output = transport.RUN_ROOT / output_name
    if output.exists(): raise FileExistsError('Preserve existing raw run')
    transport.mkdir_durable(output)
    ledger = transport.Ledger(transport.canonical_budget_path(plan), plan)
    raw = initial_raw(prepared, plan)
    transport.write_new(output / 'initial.json', raw)
    start = time.monotonic(); usages = []; calls = 0
    implementation = {'runner_sha256': protocol.digest(Path(__file__).read_text()),
        'protocol_sha256': protocol.digest((BLIND / 'protocol.py').read_text()),
        'measurement_sha256': protocol.digest((BLIND / 'measurement.py').read_text())}
    resources = measurement.RunnerResources(implementation)
    _, local_labels = protocol.generate()
    label_map = {label['id']: label for label in local_labels}
    active_row = None
    try:
        stop = False
        for index, row in enumerate(raw['rows']):
            active_row = row
            if stop: break
            if prepared['experiment'] == 'context' and row['selection_status'] != 'ready':
                row['status'] = row['selection_status']; continue
            began = time.monotonic(); current = None
            stages = [('finder', 'finder')]
            if prepared['experiment'] == 'twins' and prepared['arm'] != 'finder-only':
                stages.append(('verifier', prepared['arm'] + '_verifier'))
            for stage, role in stages:
                row['failed_stage'] = stage
                remaining = plan['per_run_seconds'] - (time.monotonic() - start)
                if remaining <= 0 or (prepared['experiment'] == 'twins' and calls >= 20):
                    row['status'] = 'budget_exhausted'; stop = True; break
                prompt = prepared['task'] + json.dumps(row['payload'])
                parent = None
                if stage == 'verifier':
                    parent = transport.digest(current)
                    prompt += '\nIndependent review of candidate; reject if no concrete flaw: ' + json.dumps(current)
                arm = prepared.get('arm', row.get('arm', row['id']))
                key = f"{arm}|{prepared.get('repeat', 0)}|{row['id']}|{stage}"
                attempt = transport.dispatch_one(ledger, key, prompt, role, output / f'{index:03d}-{stage}',
                    min(90, remaining), parent_sha256=parent)
                row['attempts'].append(attempt); calls += 1; usages.append(attempt['usage'])
                if attempt['status'] != 'complete':
                    row['status'] = attempt['status']; stop = True; break
                if prepared['experiment'] == 'context':
                    parsed = parse_context_answer(attempt['text'], row['payload'])
                else:
                    parsed = twins.parse_answer(attempt['text'], row['payload']['source'])
                attempt['parsed'] = parsed
                if parsed is None:
                    row['status'] = 'parse_failure'; ledger.halt('answer parse failure'); stop = True; break
                current = parsed
                if stage == 'finder': row['finder_candidate'] = parsed
                else: row['verifier_parent_sha256'] = parent
                row['status'] = 'complete'; row.pop('failed_stage', None)
                if prepared['experiment'] == 'context': row['surfaced'] = bool(parsed['findings'])
                else: row['surfaced'] = parsed['vulnerability']
                if prepared['experiment'] == 'twins':
                    hit = parsed['vulnerability'] and parsed['category'] == label_map[row['id']]['family']
                    if stage == 'finder': row['detected'] = bool(hit)
                    row['root_cause_correct'] = bool(hit)
                else:
                    row['detected'] = row['finder_candidate'].get('vulnerability', row['surfaced'])
            row['wall_seconds'] = time.monotonic() - began
        raw['status'] = 'complete' if all(row['status'] == 'complete' for row in raw['rows']) else 'incomplete'
    except BaseException as error:
        raw.update(status='incomplete', error=type(error).__name__)
        if (active_row is not None and active_row.get('failed_stage') in ('finder', 'verifier')
                and active_row.get('status') in ('missing', 'complete')):
            active_row.update(status='stage_incomplete', error=type(error).__name__)
        ledger.halt(type(error).__name__)
        raise
    finally:
        raw.update(calls=calls, usage_summary=transport.summarize_usage(usages), budget_totals=ledger.totals(),
                   wall_seconds=time.monotonic() - start, resource_evidence=resources.finish(), implementation=implementation)
        raw['source_postcheck'] = {}; raw['source_postcheck_errors'] = {}
        for path, expected_sha in plan['source_bindings'].items():
            try:
                raw['source_postcheck'][path] = transport.digest((REPO / path).read_bytes()) == expected_sha
            except OSError as error:
                raw['source_postcheck'][path] = False
                raw['source_postcheck_errors'][path] = type(error).__name__
        if prepared['experiment'] == 'context':
            raw['target_snapshot_postcheck'] = compare.capture(Path(prepared['source_root'])) == prepared['initial_capture']
            if not raw['target_snapshot_postcheck']: raw['status'] = 'incomplete'; ledger.halt('target snapshot changed')
        if not all(raw['source_postcheck'].values()): raw['status'] = 'incomplete'; ledger.halt('implementation changed')
        transport.write_new(output / 'raw.json', raw)
        ledger.close()
    return raw


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--selection-worker':
        request = transport.read_json(Path(sys.argv[2]))
        if set(request) != {'root', 'mode'}: raise ValueError('Fixed selection request required')
        print(json.dumps(selection.select(request['root'], request['mode'], max_modules=40, byte_budget=16384, time_budget=2, depth=3)))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare'); prepare.add_argument('experiment', choices=('twins', 'context', 'rag'))
    prepare.add_argument('--output', type=Path, required=True); prepare.add_argument('--source', type=Path)
    prepare.add_argument('--arm', default='finder-only'); prepare.add_argument('--repeat', type=int, default=0)
    prepare.add_argument('--identity', choices=('anonymous', 'identified'), default='anonymous')
    run = commands.add_parser('execute'); run.add_argument('--prepared', type=Path, required=True)
    run.add_argument('--models', type=Path, required=True); run.add_argument('--output-name', required=True)
    run.add_argument('--backend', choices=('local-ollama-http-v1', 'grok-cli'), default='local-ollama-http-v1')
    run.add_argument('--input-token-cap', type=int)
    args = parser.parse_args()
    if args.command == 'prepare':
        if args.output.exists(): raise FileExistsError('Prepared output must be new')
        if args.experiment == 'context':
            if args.source is None: raise ValueError('Context source required')
            if args.source.resolve() in args.output.resolve().parents: raise ValueError('Output overlaps source')
            result = prepare_context(args.source)
        elif args.experiment == 'twins': result = prepare_twins(args.arm, args.repeat, args.identity)
        else: result = prepare_rag()
        transport.write_new(args.output, result)
        print(json.dumps({'status': result['execution_status'], 'rows': len(result['rows']), 'model_calls': 0}))
    else:
        prepared = transport.read_json(args.prepared, 16 * 1024 * 1024)
        plan = budget_plan(prepared, transport.read_json(args.models), args.backend, args.input_token_cap)
        result = execute(prepared, plan, args.output_name)
        print(json.dumps({'status': result['status'], 'calls': result['calls']}))


if __name__ == '__main__': main()
