"""Comparison contracts; fixture sources are never executed and no provider is called."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import compare


class ComparisonTests(unittest.TestCase):
    def fixture(self, root):
        (root/'entry.py').write_text('from storage import read_record\ndef route(name):\n    return read_record(name)\n')
        (root/'storage.py').write_text('from pathlib import Path\ndef read_record(name):\n    return Path(name).read_text()\n')

    def test_default_dry_run_freezes_same_scope_and_restorable_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            report=compare.compare(root,Path(directory).resolve()/'result.json')
        self.assertEqual(report['adapter'],'dry-run')
        self.assertEqual(report['dispatched_calls'],0)
        self.assertEqual(len(report['modes']),3)
        self.assertEqual(report['module_denominator'],2)
        for mode in report['modes']:
            self.assertEqual(mode['scope_sha256'],report['scope_sha256'])
            self.assertEqual(mode['snapshot_sha256'],report['snapshot_sha256'])
            self.assertEqual(mode['prompt_sha256'],hashlib.sha256(mode['prompt'].encode()).hexdigest())
            self.assertEqual(len(mode['modules']),2)
            for module in mode['modules']:
                source=report['snapshot'][module['path']]['source']
                for segment in module['ranges']:
                    restored=''.join(source.splitlines(keepends=True)[segment['start_line']-1:segment['end_line']])
                    self.assertTrue(restored.startswith(segment['text']))
            self.assertNotIn('recall',mode)

    def test_explicit_mock_captures_received_prompts_with_hard_caps(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(result['dispatched_calls'],3)
        self.assertEqual(result['real_model_calls'],0)
        for mode in result['modes']:
            self.assertEqual(mode['delivery']['received_prompt'],mode['prompt'])
            self.assertLessEqual(len(mode['delivery']['response'].encode()),256)
            self.assertLessEqual(len(mode['prompt'].encode()),32768)

    def test_unsupported_provider_and_overwrite_refused_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory).resolve()/'existing.json';output.write_text('original')
            with patch.object(compare,'capture',side_effect=AssertionError('must not read')):
                with self.assertRaises(FileExistsError): compare.compare(Path('/missing'),output)
                with self.assertRaises(ValueError): compare.compare(Path('/missing'),Path(directory).resolve()/'new',adapter='cloud')
            self.assertEqual(output.read_text(),'original')

    def test_omitted_parser_failure_and_unknown_calls_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir()
            for number in range(42):
                (root/f'x{number:02d}.py').write_text('def broken(\n' if number==0 else 'def process(x):\n    return plugin(x)\n')
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(result['module_denominator'],42)
        for mode in result['modes']:
            self.assertEqual(len(mode['modules']),42)
            self.assertEqual(sum(module['status']=='module_cap' for module in mode['modules']),2)
            self.assertEqual(mode['modules'][0]['status'],'parser_fallback')
            self.assertTrue(mode['selection']['unknown_calls'])
            self.assertTrue(mode['incomplete'])

    def test_prompt_and_selection_byte_failures_not_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock',byte_budget=16,prompt_byte_cap=40)
        self.assertEqual(result['dispatched_calls'],0)
        for mode in result['modes']:
            self.assertEqual(mode['status'],'prompt_budget')
            self.assertLessEqual(mode['selection']['selected_bytes'],16)
            self.assertEqual(len(mode['modules']),2)

    def test_changed_source_is_not_comparable_and_remains_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            original=compare.select
            def changing(*args,**kwargs):
                (root/'entry.py').write_text('changed source\n')
                return original(*args,**kwargs)
            with patch.object(compare,'select',side_effect=changing):
                result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
            self.assertFalse(result['comparable'])
            self.assertEqual(result['status'],'snapshot_changed')
            self.assertEqual(result['dispatched_calls'],0)
            self.assertEqual(len(result['modes']),3)

    def test_selection_failure_and_timeout_keep_all_modes_and_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            with patch.object(compare,'select',side_effect=TimeoutError('controlled')):
                result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(len(result['modes']),3)
        self.assertEqual(result['dispatched_calls'],0)
        self.assertTrue(all(len(mode['modules'])==2 and mode['status']=='selection_failure' for mode in result['modes']))

    def test_shared_caps_are_strict_and_not_boolean(self):
        for option,value in [('max_modules',41),('byte_budget',16385),('time_budget',2.1),('prompt_byte_cap',32769),('output_byte_cap',257),('max_calls',4),('max_calls',True)]:
            with tempfile.TemporaryDirectory() as directory, self.subTest(option=option), self.assertRaises(ValueError):
                compare.compare(Path('/missing'),Path(directory).resolve()/'out.json',**{option:value})

    def test_crlf_and_multibyte_bytes_are_restorable(self):
        raw='def process(x):\r\n    return "中文" + x\r\n'.encode()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();(root/'entry.py').write_bytes(raw)
            result=compare.compare(root,Path(directory).resolve()/'result.json',byte_budget=33)
        source=result['snapshot']['entry.py']
        self.assertEqual(source['raw_bytes_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(source['source'].encode(),raw)
        for mode in result['modes']:
            self.assertLessEqual(mode['selection']['selected_bytes'],33)
            for segment in mode['modules'][0]['ranges']:
                self.assertEqual(segment['sha256'],hashlib.sha256(segment['text'].encode()).hexdigest())
                self.assertIn(segment['text'],source['source'])

    def test_output_overlap_refused_and_inventory_unknown_not_complete_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            with self.assertRaises(ValueError): compare.compare(root,root/'result.json')
            before=compare.capture
            def incomplete(*args,**kwargs):
                result=before(*args,**kwargs);result['inventory_complete']=False
                result['inventory_issues']=['controlled inventory failure'];return result
            with patch.object(compare,'capture',side_effect=incomplete):
                result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertIsNone(result['module_denominator'])
        self.assertFalse(result['comparable'])
        self.assertEqual(result['dispatched_calls'],0)
        self.assertEqual(result['status'],'scope_incomplete')
        self.assertEqual(result['inventoried_module_lower_bound'],2)

    def test_hard_selection_subprocess_timeout_retains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock',time_budget=.000001)
        self.assertTrue(all(mode['status']=='selection_failure' for mode in result['modes']))
        self.assertEqual(result['dispatched_calls'],0)

    @unittest.skipUnless(hasattr(__import__('os'),'mkfifo'),'Platform has no FIFO fixture API')
    def test_nonregular_source_never_blocks_capture(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();os.mkfifo(root/'pipe.py')
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(result['module_denominator'],1)
        self.assertTrue(all(mode['modules'][0]['status']=='unsupported_file' for mode in result['modes']))

    def test_output_and_call_budgets_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            response=compare.compare(root,Path(directory).resolve()/'response.json',adapter='mock',output_byte_cap=1)
            calls=compare.compare(root,Path(directory).resolve()/'calls.json',adapter='mock',max_calls=1)
        self.assertTrue(all(mode['status']=='output_budget' for mode in response['modes']))
        self.assertEqual(response['dispatched_calls'],0)
        self.assertEqual(calls['dispatched_calls'],1)
        self.assertEqual(sum(mode['status']=='call_budget' for mode in calls['modes']),2)

    def test_cross_scope_comparison_rejected(self):
        report={'schema':'context-comparison-v1','scope_sha256':'a','snapshot_sha256':'b','implementation':{'selector_sha256':'c'},'modes':[]}
        mismatch=copy.deepcopy(report);mismatch['scope_sha256']='different'
        with self.assertRaises(ValueError): compare.validate_comparison([report,mismatch])


if __name__=='__main__': unittest.main()
