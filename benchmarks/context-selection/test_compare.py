"""Comparison contracts; fixture sources are never executed and no provider is called."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import compare


class ComparisonTests(unittest.TestCase):
    def fixture(self, root):
        (root/'entry.py').write_text('from storage import read_record\ndef route(name):\n    return read_record(name)\n')
        (root/'storage.py').write_text('from pathlib import Path\ndef read_record(name):\n    return Path(name).read_text()\n')

    def test_selection_worker_imports_sibling_under_isolated_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            result=subprocess.run(
                [sys.executable,'-I','-S',str(Path(compare.__file__).resolve()),'--selection-worker'],
                input=json.dumps({'root':str(root),'mode':'baseline'}),
                text=True,capture_output=True,timeout=10,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['mode'],'baseline')

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
                snapshot=report['snapshot'][module['path']]
                raw=base64.b64decode(snapshot['raw_base64']) if 'raw_base64' in snapshot else b''
                for segment in module['ranges']:
                    self.assertEqual(raw[segment['start_byte']:segment['end_byte']],segment['text'].encode())
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
        self.assertFalse(result['source_capture_complete'])
        self.assertFalse(result['comparable'])
        self.assertEqual(result['dispatched_calls'],0)

    def test_mixed_python_typescript_scope_is_not_dispatched(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
            (root/'index.ts').write_text('export const result = check();\n')
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertFalse(result['inventory_complete'])
        self.assertIn('unsupported-language',result['inventory_issues'])
        self.assertEqual(result['snapshot']['index.ts']['status'],'unsupported_language')
        self.assertIsNone(result['module_denominator'])
        self.assertEqual(result['inventoried_module_lower_bound'],3)
        self.assertEqual(result['status'],'scope_incomplete')
        self.assertEqual(result['dispatched_calls'],0)
        self.assertTrue(all(mode['delivery']['status']=='snapshot-or-scope-incomplete-not-dispatched'
                            for mode in result['modes']))

    def test_go_and_unknown_suffixes_block_dispatch_with_source_receipts(self):
        for name,expected_status,expected_issue in (
            ('danger.go','unsupported_language','unsupported-language'),
            ('future.zig','unknown_source_type','unknown-source-type'),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()/'source';root.mkdir()
                (root/'safe.py').write_text('def route():\n    return 1\n')
                (root/name).write_text('untrusted source\n')
                (root/'README.md').write_text('Documentation only\n')
                result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
                self.assertEqual(result['snapshot'][name]['status'],expected_status)
                self.assertEqual(result['excluded_data_files'],['README.md'])
                self.assertEqual(result['snapshot']['safe.py']['raw_bytes_sha256'],
                                 hashlib.sha256(b'def route():\n    return 1\n').hexdigest())
                self.assertIn(expected_issue,result['inventory_issues'])
                self.assertFalse(result['inventory_complete'])
                self.assertFalse(result['comparable'])
                self.assertEqual(result['status'],'scope_incomplete')
                self.assertEqual(result['dispatched_calls'],0)

    def test_symlinked_python_source_blocks_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir()
            outside=Path(directory).resolve()/'outside.py';outside.write_text('def hidden():\n    return 1\n')
            (root/'safe.py').write_text('def route():\n    return 1\n')
            (root/'link.py').symlink_to(outside)
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertIn('symlink-source-not-read',result['inventory_issues'])
        self.assertEqual(result['snapshot']['link.py']['status'],'symlink_skipped')
        self.assertEqual(result['status'],'scope_incomplete')
        self.assertEqual(result['dispatched_calls'],0)

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
        raw='def process(x):\r\n    return "中文\u2028sample" + x\r\n'.encode()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();(root/'entry.py').write_bytes(raw)
            result=compare.compare(root,Path(directory).resolve()/'result.json',byte_budget=33)
            complete=compare.compare(root,Path(directory).resolve()/'complete.json',byte_budget=256)
        source=result['snapshot']['entry.py']
        self.assertEqual(source['raw_bytes_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(source['source'].encode(),raw)
        for mode in result['modes']:
            self.assertLessEqual(mode['selection']['selected_bytes'],33)
            for segment in mode['modules'][0]['ranges']:
                self.assertEqual(segment['sha256'],hashlib.sha256(segment['text'].encode()).hexdigest())
                self.assertEqual(raw[segment['start_byte']:segment['end_byte']],segment['text'].encode())
        self.assertEqual(complete['modes'][0]['status'],'ready')
        self.assertEqual(complete['modes'][0]['modules'][0]['ranges'][0]['text'].encode(),raw)

    def test_range_verification_rejects_offset_line_hash_and_truncation_tampering(self):
        raw='def route():\r\n    return "中\u2028文"\r\n'.encode()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir();(root/'entry.py').write_bytes(raw)
            report=compare.compare(root,Path(directory).resolve()/'result.json')
            clipped=compare.compare(root,Path(directory).resolve()/'clipped.json',byte_budget=18)
        original=report['snapshot']['entry.py']
        baseline=report['modes'][0]['modules'][0]
        self.assertEqual(baseline['ranges'][0]['text'].encode(),raw)
        cases=[]
        def tampered(**changes):
            module=copy.deepcopy(baseline);module['ranges'][0].update(changes)
            return module
        cases.append(tampered(start_byte=1))
        cases.append(tampered(end_byte=2))
        cases.append(tampered(end_byte=raw.index('中'.encode())+1,truncated=True))
        cases.append(tampered(start_line=2))
        cases.append(tampered(end_line=3))
        cases.append(tampered(sha256='0'*64))
        cases.append(tampered(truncated=True))
        cases.append(tampered(start_byte=True))
        duplicated=copy.deepcopy(baseline);duplicated['ranges'].append(copy.deepcopy(duplicated['ranges'][0]))
        duplicated['selected_bytes']*=2;cases.append(duplicated)
        wrong_total=copy.deepcopy(baseline);wrong_total['selected_bytes']-=1;cases.append(wrong_total)
        for module in cases:
            with self.subTest(segment=module['ranges'][0]), self.assertRaises(ValueError):
                compare.verify_selected_ranges(module,original)
        for field in ('raw_bytes_sha256','source_sha256'):
            module=copy.deepcopy(baseline);module[field]='0'*64
            with self.subTest(field=field),self.assertRaises(ValueError):
                compare.verify_selected_ranges(module,original)
        forged_snapshot=copy.deepcopy(original);forged_snapshot['raw_base64']='Zm9yZ2Vk'
        with self.assertRaises(ValueError): compare.verify_selected_ranges(baseline,forged_snapshot)
        clipped_module=clipped['modes'][0]['modules'][0]
        self.assertTrue(clipped_module['ranges'][0]['truncated'])
        compare.verify_selected_ranges(clipped_module,original)
        clipped_module['ranges'][0]['truncated']=False
        with self.assertRaises(ValueError): compare.verify_selected_ranges(clipped_module,original)

    def test_prior_splitlines_prefix_false_positive_cannot_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir()
            (root/'entry.py').write_text('def route():\n    return "left"\n')
            trusted_select=compare.select
            def forged_select(*args,**kwargs):
                selected=trusted_select(*args,**kwargs)
                if selected['mode']=='baseline':
                    segment=selected['files'][0]['ranges'][0]
                    # The old splitlines/prefix check accepted this unchanged text
                    # despite a forged byte interval that omitted almost all of it.
                    segment['end_byte']=segment['start_byte']+2
                return selected
            with patch.object(compare,'select',side_effect=forged_select):
                report=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(report['modes'][0]['status'],'selection_failure')
        self.assertEqual(report['dispatched_calls'],0)
        self.assertTrue(all(mode['delivery']['status']=='selection-failure-not-dispatched'
                            for mode in report['modes']))

    def test_worker_response_request_mismatch_blocks_all_mock_calls(self):
        mutations=(('mode',lambda selected: selected.update(mode='functions')),
                   ('schema',lambda selected: selected.update(schema='unknown')),
                   ('module_cap',lambda selected: selected.update(module_cap=1)),
                   ('byte_budget',lambda selected: selected.update(byte_budget=1)),
                   ('time_budget_seconds',lambda selected: selected.update(time_budget_seconds=1)),
                   ('depth_cap',lambda selected: selected.update(depth_cap=2)),
                   ('files',lambda selected: selected.pop('files')),
                   ('incomplete',lambda selected: selected.pop('incomplete')))
        for label,mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
                trusted_select=compare.select
                def forged_select(*args,**kwargs):
                    selected=trusted_select(*args,**kwargs)
                    if args[1]=='baseline': mutate(selected)
                    return selected
                with patch.object(compare,'select',side_effect=forged_select):
                    report=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
                self.assertEqual(report['modes'][0]['status'],'selection_failure')
                self.assertFalse(report['comparable'])
                self.assertEqual(report['dispatched_calls'],0)
                self.assertTrue(all(mode['delivery']['status']=='selection-failure-not-dispatched'
                                    for mode in report['modes']))

    def test_worker_scope_and_incomplete_contradictions_block_comparison(self):
        mutations=(('inventory',lambda selected: selected.update(inventory_complete=False,incomplete=False)),
                   ('unsupported',lambda selected: selected['unsupported_sources'].append('hidden.rs')),
                   ('omitted',lambda selected: selected['omitted_modules'].append('entry.py')),
                   ('missing-file',lambda selected: selected['files'].pop()),
                   ('false-incomplete',lambda selected: selected.update(incomplete=False,
                                                                      unknown_calls=['forged.unknown'])),
                   ('unknown-status',lambda selected: (selected['files'][0].update(status='model_verified'),
                                                       selected.update(incomplete=True))),
                   ('status',lambda selected: (selected['files'][0].update(status='byte_budget'),
                                                selected.update(incomplete=False))))
        for label,mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()/'source';root.mkdir();self.fixture(root)
                trusted_select=compare.select
                def forged_select(*args,**kwargs):
                    selected=trusted_select(*args,**kwargs)
                    if args[1]=='baseline': mutate(selected)
                    return selected
                with patch.object(compare,'select',side_effect=forged_select):
                    report=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
                self.assertFalse(report['comparable'])
                self.assertEqual(report['modes'][0]['status'],'selection_failure')
                self.assertEqual(report['dispatched_calls'],0)

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
            root=Path(directory).resolve()/'source';root.mkdir()
            (root/'safe.py').write_text('def route():\n    return 1\n')
            os.mkfifo(root/'pipe.py')
            result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(result['module_denominator'],2)
        self.assertTrue(all(any(module['path']=='pipe.py' and module['status']=='unsupported_file'
                                for module in mode['modules']) for mode in result['modes']))
        self.assertFalse(result['source_capture_complete'])
        self.assertFalse(result['comparable'])
        self.assertEqual(result['status'],'scope_incomplete')
        self.assertEqual(result['dispatched_calls'],0)

    def test_unreadable_source_blocks_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir()
            (root/'safe.py').write_text('def route():\n    return 1\n')
            (root/'sealed.py').write_text('def hidden():\n    return 1\n')
            original_open=Path.open
            def refuse_sealed(path,*args,**kwargs):
                if path.name=='sealed.py' and args and args[0]=='rb':
                    raise PermissionError('controlled unreadable source')
                return original_open(path,*args,**kwargs)
            with patch.object(Path,'open',refuse_sealed):
                result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(result['snapshot']['sealed.py']['status'],'read_failure')
        self.assertFalse(result['source_capture_complete'])
        self.assertFalse(result['comparable'])
        self.assertEqual(result['dispatched_calls'],0)

    @unittest.skipUnless(hasattr(__import__('socket'),'AF_UNIX'),'Platform has no Unix socket files')
    def test_socket_source_blocks_dispatch(self):
        import socket
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'source';root.mkdir()
            (root/'safe.py').write_text('def route():\n    return 1\n')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as endpoint:
                endpoint.bind(str(root/'source.py'))
                result=compare.compare(root,Path(directory).resolve()/'result.json',adapter='mock')
        self.assertEqual(result['snapshot']['source.py']['status'],'unsupported_file')
        self.assertFalse(result['source_capture_complete'])
        self.assertFalse(result['comparable'])
        self.assertEqual(result['dispatched_calls'],0)

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
