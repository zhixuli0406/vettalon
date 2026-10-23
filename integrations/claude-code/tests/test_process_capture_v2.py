"""Versioned capture tests: self-authored children only, no provider/scanner calls."""
import ast
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
CANONICAL = ROOT / 'scripts/runtime/process_capture_v2.py'
LEGACY = ROOT / 'benchmarks/reachability/adapter.py'


def module(path=CANONICAL):
    path = Path(os.environ.get('VETTALON_TEST_CAPTURE_PATH', str(path)))
    spec = importlib.util.spec_from_file_location('capture_v2_test', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class CaptureV2Tests(unittest.TestCase):
    def test_frozen_source_and_only_reviewed_timeout_delta(self):
        old = LEGACY.read_text(); new = CANONICAL.read_text()
        # Pins the reviewed reference file. Re-pinned for 7dc3687a6 (adapter
        # 0.3.0, O16): it changed only classify, scan, the new
        # blind_spot_signals and their constants; the four functions compared
        # below are byte-identical to the fdb772853 version this test froze.
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(), '321f759a13bc8de1f40750baac451b9027ef4ef1a1dee9a1e6838375b5991b26')
        def functions(source):
            return {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
        prior, current = functions(old), functions(new)
        self.assertEqual(set(current), {'digest', 'decode_status', 'invoke', 'successful_run'})
        for name in ('digest', 'decode_status', 'successful_run'):
            self.assertEqual(current[name], prior[name])
        changes = [
            ('stderr_cap=STDERR_CAP, timeout_ceiling_seconds=120):', 'stderr_cap=STDERR_CAP):'),
            ('or timeout > 600\n                or type(timeout_ceiling_seconds) is not int or not 0 < timeout_ceiling_seconds <= 600\n                or any', 'or any'),
            ('deadline = started + min(timeout, timeout_ceiling_seconds)', 'deadline = started + min(timeout, 120)'),
        ]
        restored = current['invoke']
        for revised, original in changes:
            self.assertEqual(restored.count(revised), 1)
            restored = restored.replace(revised, original, 1)
        self.assertEqual(restored, prior['invoke'])
        supervisor = (ROOT / 'scripts/runtime/process_supervisor.py').read_bytes()
        self.assertEqual(hashlib.sha256(supervisor).hexdigest(), '0d58c2d5315e8ac48e8d8cf66d4796cf8fc1c83e073276e225879777761d9c36')

    def test_limits_reject_before_spawn_and_accept_explicit_180_600(self):
        runtime = module()
        with patch.object(runtime.subprocess, 'Popen', side_effect=OSError('self-authored no spawn')) as spawn:
            for timeout, ceiling in [(True, 120), (float('nan'),120), (float('inf'),120), (0,120), (601,600), (1,True), (1,0), (1,601), (1,float('nan'))]:
                with self.subTest(timeout=timeout, ceiling=ceiling):
                    result = runtime.invoke(['self-authored-never-run'], '.', {}, timeout, timeout_ceiling_seconds=ceiling)
                    self.assertEqual(result['error'], 'invalid-limits')
            spawn.assert_not_called()
            for timeout in (180,600):
                result = runtime.invoke(['self-authored-never-run'], '.', {}, timeout, timeout_ceiling_seconds=600)
                self.assertEqual(result['error'], 'process-error')
            self.assertEqual(spawn.call_count, 2)

    @unittest.skipUnless(os.name == 'posix', 'POSIX group ownership')
    def test_bounded_streams_invalid_utf8_and_timeout_are_not_success(self):
        runtime = module()
        for source, timeout, expected in [
            ("import sys;sys.stdout.write('x'*8192)", 2, 'output-limit'),
            ("import sys;sys.stderr.write('x'*8192)", 2, 'output-limit'),
            ("import os;os.write(1,b'\\xff')", 2, 'invalid-utf8'),
            ("import time;time.sleep(3)", .15, 'timeout'),
        ]:
            with self.subTest(expected=expected, source=source):
                run = runtime.invoke([sys.executable,'-I','-S','-c',source], '.', {'PATH':os.defpath}, timeout, stdout_cap=128, stderr_cap=128)
                self.assertEqual(run['error'], expected)
                self.assertFalse(runtime.successful_run(run))
                self.assertLessEqual(run['captures']['stdout']['retained_bytes'],128)
                self.assertLessEqual(run['captures']['stderr']['retained_bytes'],128)
                if expected == 'invalid-utf8': self.assertEqual(run['captures']['stdout']['raw_base64'], '/w==')

    @unittest.skipUnless(os.name == 'posix', 'POSIX group ownership')
    def test_normal_leader_exit_cleans_inherited_pipe_child(self):
        runtime = module()
        source = "import subprocess,sys;subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(10)']);print('leader-complete')"
        run = runtime.invoke([sys.executable,'-I','-S','-c',source], '.', {'PATH':os.defpath}, 2)
        self.assertTrue(runtime.successful_run(run), run)
        self.assertIn('leader-complete', run['stdout'])
        self.assertLess(run['seconds'], 3)


if __name__ == '__main__': unittest.main()
