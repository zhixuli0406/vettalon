"""Self-authored process fixtures only; no Docker, scanners, models, or target code."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('LINK_TEST_SOURCE', str(Path(__file__).with_name('link.py'))))
spec = importlib.util.spec_from_file_location('process_link_under_test', SOURCE)
link = importlib.util.module_from_spec(spec)
spec.loader.exec_module(link)


class ProcessCommandTests(unittest.TestCase):
    def test_invalid_utf8_is_incomplete_and_preserves_actual_bytes(self):
        with self.assertRaises(link.CommandFailure) as error:
            link.command([sys.executable, '-B', '-I', '-S', '-c', 'import os;os.write(1,b"\\xff")'], 2)
        run = error.exception.receipt['process']
        self.assertEqual(run['error'], 'invalid-utf8')
        self.assertEqual(run['captures']['stdout']['raw_base64'], '/w==')
        self.assertTrue(run['captures']['stdout']['decode_error'])

    def test_normal_success_and_nonzero_keep_actual_receipt(self):
        argv = [sys.executable, '-B', '-I', '-S', '-c', 'print("ok")']
        receipt = link.command(argv, 2)
        self.assertEqual(receipt['stdout'], 'ok\n')
        self.assertTrue(receipt['process']['control_complete'])
        link.validate_receipt(receipt, argv)
        argv = [sys.executable, '-B', '-I', '-S', '-c', 'import sys;print("negative");sys.exit(3)']
        receipt = link.command(argv, 2)
        self.assertEqual(receipt['returncode'], 3)
        self.assertEqual(receipt['process']['returncode'], 3)
        self.assertEqual(receipt['process']['error'], 'nonzero-exit')
        with self.assertRaises(ValueError):
            link.validate_receipt(receipt, argv)

    def test_both_stream_caps_and_aggregate_acceptance_gate(self):
        for source in ('import sys;sys.stdout.write("x"*8192)',
                       'import sys;sys.stderr.write("x"*8192)',
                       'import sys;sys.stdout.write("x"*80);sys.stderr.write("y"*80)'):
            with self.subTest(source=source), self.assertRaises(link.CommandFailure) as error:
                link.command([sys.executable, '-B', '-I', '-S', '-c', source], 2, byte_cap=100)
            receipt = error.exception.receipt
            self.assertTrue(receipt['output_limited'])
            self.assertEqual(receipt['combined_acceptance_cap'], 100)
            self.assertEqual(receipt['per_stream_capture_cap'], 100)
            self.assertLessEqual(sum(c['retained_bytes'] for c in receipt['process']['captures'].values()), 200)

    def test_short_timeout_retains_control_observation_without_retry(self):
        with self.assertRaises(link.CommandFailure) as error:
            link.command([sys.executable, '-B', '-I', '-S', '-c', 'import time;time.sleep(3)'], .1)
        receipt = error.exception.receipt
        self.assertTrue(receipt['timed_out'])
        self.assertEqual(receipt['process']['error'], 'timeout')
        self.assertLess(receipt['wall_seconds'], 2)

    def test_normal_leader_exit_cleans_inherited_pipe_child(self):
        source = ('import subprocess,sys;subprocess.Popen([sys.executable,"-B","-I","-S",'
                  '"-c","import time;time.sleep(10)"]);print("leader-complete")')
        receipt = link.command([sys.executable, '-B', '-I', '-S', '-c', source], 2)
        self.assertEqual(receipt['returncode'], 0)
        self.assertIn('leader-complete', receipt['stdout'])
        self.assertIsNone(receipt['process']['cleanup_error'])
        self.assertTrue(receipt['process']['control_complete'])
        self.assertLess(receipt['wall_seconds'], 3)

    def test_invalid_limits_fail_before_loading_or_spawning(self):
        with patch.object(link, 'load_runtime', side_effect=AssertionError('no runtime load')):
            for timeout in (True, float('nan'), float('inf'), 0, 301):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    link.command(['never-run'], timeout)
            for cap in (True, 0, -1, 1.5, link.COMMAND_BYTES + 1):
                with self.subTest(cap=cap), self.assertRaises(ValueError):
                    link.command(['never-run'], 1, byte_cap=cap)

    def test_missing_or_changed_helper_fails_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory, patch('subprocess.Popen') as spawn:
            with patch.object(link, 'RUNTIME_DIRECTORY', Path(directory)):
                with self.assertRaises(ValueError):
                    link.command([sys.executable, '-c', 'print("never")'], 1)
                for name in link.RUNTIME_PINS:
                    (Path(directory) / name).write_text('# changed\n')
                with self.assertRaises(ValueError):
                    link.command([sys.executable, '-c', 'print("never")'], 1)
            spawn.assert_not_called()

    def test_provider_and_docker_environment_are_not_forwarded(self):
        with patch.dict(os.environ, {'XAI_API_KEY': 'synthetic-test-only', 'DOCKER_HOST': 'synthetic-test-only'}):
            source = 'import os;print("XAI_API_KEY" in os.environ);print("DOCKER_HOST" in os.environ)'
            receipt = link.command([sys.executable, '-B', '-I', '-S', '-c', source], 2)
        self.assertEqual(receipt['stdout'], 'False\nFalse\n')

    def test_nested_control_capture_caps_and_projection_tampering_are_rejected(self):
        argv = [sys.executable, '-B', '-I', '-S', '-c', 'print("ok")']
        original = link.command(argv, 2)
        for mutation in ('missing', 'control', 'cleanup', 'utf8', 'truncated', 'hash', 'streamcap',
                         'declaredcap', 'boolcap', 'argv', 'stdout', 'seconds', 'boolcode'):
            bad = copy.deepcopy(original)
            if mutation == 'missing': bad.pop('process')
            elif mutation == 'control': bad['process']['control_complete'] = False
            elif mutation == 'cleanup': bad['process']['cleanup_error'] = 'unknown'
            elif mutation == 'utf8': bad['process']['captures']['stdout']['decode_error'] = True
            elif mutation == 'truncated': bad['process']['captures']['stdout']['truncated'] = True
            elif mutation == 'hash': bad['process']['captures']['stdout']['sha256'] = '0'*64
            elif mutation == 'streamcap': bad['process']['captures']['stdout']['cap_bytes'] += 1
            elif mutation == 'declaredcap': bad['combined_acceptance_cap'] -= 1
            elif mutation == 'boolcap': bad['per_stream_capture_cap'] = True
            elif mutation == 'argv': bad['process']['command'] = ['different']
            elif mutation == 'stdout': bad['stdout'] = 'different'
            elif mutation == 'seconds': bad['wall_seconds'] = 0
            else: bad['returncode'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                link.validate_receipt(bad, argv)


if __name__ == '__main__':
    unittest.main()
