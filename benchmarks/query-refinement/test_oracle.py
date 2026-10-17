"""Finite AST oracle tests; no fixture module/code object is executed."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest import mock

import oracle

DEV = Path(__file__).parent / 'fixtures' / 'dev'


def source(body):
    return ('def subject(user_input):\n' + body).encode('utf-8')


class OracleTests(unittest.TestCase):
    def test_fixed_dev_traces_match_hand_calculation_and_compile_only(self):
        expected = {
            'a73c.py': ('input_dependent', ['11', '22']),
            'b84d.py': ('input_dependent', ['11', '22']),
            'c95e.py': ('input_independent', ['11', '11']),
            'd06f.py': ('input_independent', ['pass', 'pass']),
            'e17a.py': ('input_independent', ['11', '11']),
            'f28b.py': ('no_sink', [None, None]),
        }
        for filename, (relation, operands) in expected.items():
            with self.subTest(filename=filename):
                data = (DEV / filename).read_bytes()
                compile(data, filename, 'exec')  # Compile only; never execute this code object.
                result = oracle.observe(data)
                self.assertTrue(result['complete'])
                self.assertEqual(result['relation'], relation)
                self.assertEqual(result['source_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual([t['input'] for t in result['traces']], ['11', '22'])
                self.assertEqual([None if t['operand_hex'] is None else bytes.fromhex(t['operand_hex']).decode() for t in result['traces']], operands)

    def test_minimal_original_literal_form_is_supported(self):
        result = oracle.observe(source('    eval("11")\n'))
        self.assertTrue(result['complete'])
        self.assertEqual(result['relation'], 'input_independent')
        self.assertTrue(result['sinks'][0]['operand_literal'])

    def test_alias_assignment_retains_input_binding_lineage(self):
        result = oracle.observe(source('    alias = user_input\n    operand = alias\n    eval(operand)\n'))
        self.assertEqual(result['relation'], 'input_dependent')
        self.assertEqual([x['name'] for x in result['sinks'][0]['binding_lineage']], ['user_input', 'alias', 'operand'])

    def test_constants_and_controlled_return_never_execute_python(self):
        with mock.patch('builtins.eval', side_effect=AssertionError('fixture eval executed')), mock.patch('builtins.exec', side_effect=AssertionError('fixture exec executed')):
            for data in [source('    eval(user_input)\n'), source('    exec("pass")\n'), source('    return user_input\n')]:
                self.assertTrue(oracle.observe(data)['complete'])

    def test_unsupported_syntax_is_not_safe(self):
        bodies = [
            '    import os\n    eval(user_input)\n',
            '    thing.eval(user_input)\n',
            '    eval(user_input + "x")\n',
            '    eval(user_input, {})\n',
            '    eval(source=user_input)\n',
            '    result = eval(user_input)\n',
            '    return eval(user_input)\n',
            '    for value in user_input:\n        eval(value)\n',
            '    if user_input:\n        eval(user_input)\n',
            '    value = lambda: user_input\n',
            '    value = [x for x in user_input]\n',
            '    global value\n    eval(user_input)\n',
            '    value = 11\n    eval(value)\n',
            '    eval(missing)\n',
        ]
        for body in bodies:
            with self.subTest(body=body):
                result = oracle.observe(source(body))
                self.assertFalse(result['complete'])
                self.assertIsNone(result['relation'])
                self.assertEqual(result['status'], 'oracle_unsupported')

    def test_shadowing_and_repeated_bindings_are_rejected(self):
        for body in ['    eval = "11"\n    eval(user_input)\n', '    exec = "11"\n    eval(user_input)\n', '    user_input = "11"\n    eval(user_input)\n', '    item = "11"\n    item = "22"\n    eval(item)\n']:
            with self.subTest(body=body):
                result = oracle.observe(source(body))
                self.assertFalse(result['complete'])
                self.assertIsNone(result['relation'])

    def test_function_signature_and_module_boundaries_are_closed(self):
        for data in [b'def subject(eval):\n    eval("11")\n', b'def subject(user_input="11"):\n    eval(user_input)\n', b'@decorator\ndef subject(user_input):\n    eval(user_input)\n', b'def subject(user_input):\n    eval(user_input)\nother = "11"\n', b'async def subject(user_input):\n    eval(user_input)\n', b'def subject(user_input: str):\n    eval(user_input)\n']:
            with self.subTest(data=data):
                self.assertFalse(oracle.observe(data)['complete'])

    def test_repeated_or_unobserved_sink_is_incomplete(self):
        for body in ['    eval(user_input)\n    eval(user_input)\n', '    return user_input\n    exec(user_input)\n']:
            result = oracle.observe(source(body))
            self.assertEqual(result['status'], 'incomplete')
            self.assertIsNone(result['relation'])

    def test_utf8_byte_ranges_bind_the_actual_sink(self):
        data = source('    note = "é中"; eval(user_input)\n')
        result = oracle.observe(data)
        self.assertTrue(result['complete'])
        sink = result['sinks'][0]
        self.assertEqual(data[sink['byte_start']:sink['byte_end']], b'eval(user_input)')
        self.assertEqual(sink['byte_start'], data.index(b'eval('))
        self.assertEqual(sink['sink_bytes_sha256'], hashlib.sha256(b'eval(user_input)').hexdigest())

    def test_wrong_source_range_opcode_or_operand_cannot_verify(self):
        data = source('    eval(user_input)\n')
        result = oracle.observe(data)
        self.assertTrue(result['complete'])
        trace = result['traces'][0]
        self.assertTrue(oracle.verify_observation(data, trace))
        for key, value in [('source_sha256', '0' * 64), ('byte_start', trace['byte_start'] + 1), ('byte_end', trace['byte_end'] - 1), ('opcode', 'exec'), ('operand_hex', '3333'), ('input', '33'), ('byte_start', True)]:
            changed = dict(trace, **{key: value})
            self.assertFalse(oracle.verify_observation(data, changed), key)
        self.assertFalse(oracle.verify_observation(data + b'\n', trace))

    def test_budget_and_invalid_bytes_never_become_safe(self):
        for data in [b'\xff', b'x' * 2049, source('    value = "' + 'x' * 2100 + '"\n'), 'not bytes', b'def subject(:\n']:
            self.assertFalse(oracle.observe(data)['complete'])
        many = source(''.join(f'    a{i} = "x"\n' for i in range(65)) + '    eval(user_input)\n')
        self.assertLess(len(many), 2048)
        result = oracle.observe(many)
        self.assertFalse(result['complete'])
        self.assertEqual(result['reason'], 'ast_node_budget')

    def test_deletion_moves_range_and_source_identity_but_preserves_lineage(self):
        parent = (DEV / 'c95e.py').read_bytes()
        child = parent.replace(b'    note = "context"\n', b'')
        mapping = oracle.map_sink(parent, child)
        self.assertEqual(mapping['status'], 'mapped')
        self.assertNotEqual(mapping['parent_sink']['source_sha256'], mapping['child_sink']['source_sha256'])
        self.assertNotEqual(mapping['parent_sink']['byte_start'], mapping['child_sink']['byte_start'])
        next_map = oracle.map_sink(child, child + b'\n', origin=mapping['origin'])
        self.assertEqual(next_map['status'], 'mapped')
        self.assertEqual(next_map['sink_lineage_id'], mapping['sink_lineage_id'])

    def test_sink_operand_and_binding_changes_stop_mapping(self):
        pairs = [
            (source('    eval(user_input)\n'), source('    exec(user_input)\n')),
            (source('    eval("11")\n'), source('    eval("22")\n')),
            (source('    expr = "11"\n    eval(expr)\n'), source('    expr = "22"\n    eval(expr)\n')),
            (source('    eval(user_input)\n'), source('    eval(user_input)\n    eval(user_input)\n')),
            (source('    eval(user_input)\n'), source('    eval = "11"\n    eval(user_input)\n')),
        ]
        for parent, child in pairs:
            with self.subTest(parent=parent, child=child):
                self.assertEqual(oracle.map_sink(parent, child)['status'], 'minimize_mapping_unknown')

    def test_forged_origin_is_revalidated_from_exact_bytes(self):
        parent = (DEV / 'c95e.py').read_bytes()
        child = parent.replace(b'    note = "context"\n', b'')
        valid = oracle.map_sink(parent, child)
        self.assertEqual(valid['status'], 'mapped')
        for key, value in [('source_sha256', '0' * 64), ('source_hex', 'ff'), ('sink_ast_sha256', '0' * 64), ('binding_lineage', [{'kind': 'parameter', 'name': 'untrusted'}])]:
            origin = copy.deepcopy(valid['origin']); origin[key] = value
            self.assertEqual(oracle.map_sink(parent, child, origin=origin)['status'], 'minimize_mapping_unknown')

    def test_candidates_delete_only_irrelevant_whole_statements(self):
        parent = (DEV / 'c95e.py').read_bytes()
        candidates = oracle.deletion_candidates(parent)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]['source'], parent.replace(b'    note = "context"\n', b''))
        self.assertEqual(candidates[0]['mapping']['status'], 'mapped')
        needed = source('    expr = "11"\n    eval(expr)\n')
        self.assertEqual(oracle.deletion_candidates(needed), [])
        self.assertEqual(oracle.deletion_candidates(source('    eval(user_input)\n')), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
