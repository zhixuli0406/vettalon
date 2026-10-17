"""Standalone installed-layout and strict process-result tests, no real CLI providers."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / 'integrations/claude-code/plugins/vettalon'
SCRIPT = Path(os.environ.get('VETTALON_TEST_PLUGIN_SCRIPT', str(PLUGIN / 'scripts/vettalon_plugin.py')))


def load_script(path=SCRIPT):
    spec = importlib.util.spec_from_file_location('installed_plugin_test', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class RuntimeBundleTests(unittest.TestCase):
    def test_bundle_exact_source_and_supervisor_bytes(self):
        for name in ('process_capture_v2.py','process_supervisor.py'):
            self.assertEqual((ROOT/'scripts/runtime'/name).read_bytes(), (PLUGIN/'scripts/runtime'/name).read_bytes())

    def test_findings_exit_preserves_receipt_and_rejects_partial_failure(self):
        plugin = load_script(); runtime = plugin.load_runtime()
        run = {'command':['self-authored'], 'returncode':1, 'error':'nonzero-exit', 'seconds':.1,
               'stdout':'','stderr':'','control_schema':1,'control_complete':True,'timed_out':False,
               'cleanup_error':None,'captures':{name:{'cap_bytes':128,'observed_bytes':0,'retained_bytes':0,
                'sha256':hashlib.sha256(b'').hexdigest(),'truncated':False,'decode_error':False} for name in ('stdout','stderr')}}
        original = copy.deepcopy(run)
        self.assertTrue(plugin.process_accepted(run, runtime, findings_exit=True))
        self.assertEqual(run, original)
        self.assertFalse(plugin.process_accepted(run, runtime, findings_exit=False))
        for key,value in [('returncode',True),('control_complete',False),('timed_out',True),('cleanup_error','cleanup-deadline'),('error','timeout')]:
            bad=copy.deepcopy(run);bad[key]=value
            self.assertFalse(plugin.process_accepted(bad,runtime,findings_exit=True))
        for key,value in [('truncated',True),('decode_error',True),('sha256','0'*64)]:
            bad=copy.deepcopy(run);bad['captures']['stdout'][key]=value
            self.assertFalse(plugin.process_accepted(bad,runtime,findings_exit=True))

    def test_metadata_uses_bounded_bridge_and_never_echoes_raw_failure(self):
        plugin=load_script()
        with patch.object(plugin,'run_command',return_value={'returncode':2,'stderr':'SECRET_DO_NOT_PRINT'}) as bridge:
            with self.assertRaisesRegex(plugin.SetupError,'metadata/configuration check failed') as error:
                plugin.metadata(['/trusted/vettalon','scan','--help'])
            self.assertNotIn('SECRET_DO_NOT_PRINT',str(error.exception))
            self.assertEqual(bridge.call_args.kwargs, {'stdout_cap':1048576,'stderr_cap':262144})
            self.assertEqual(bridge.call_args.args[1],15)

    @unittest.skipUnless(os.name == 'posix','POSIX metadata capture')
    def test_actual_metadata_overflow_fails_with_fixed_error(self):
        plugin=load_script()
        with tempfile.TemporaryDirectory(prefix='metadata cap ') as directory:
            fake=Path(directory)/'trusted-metadata'
            fake.write_text('#!'+sys.executable+'\nimport sys\nsys.stdout.write("x"*(2*1024*1024))\n')
            fake.chmod(0o755)
            with self.assertRaisesRegex(plugin.SetupError,'metadata/configuration check failed'):
                plugin.metadata([str(fake),'--help'])

    def test_report_only_does_not_load_posix_runtime(self):
        plugin=load_script()
        with tempfile.TemporaryDirectory() as directory:
            report=Path(directory)/'report.json';report.write_text('{"findings":[]}')
            with patch.object(plugin,'load_runtime',side_effect=AssertionError('report must not load runtime')):
                self.assertEqual(plugin.main(['report','--path',str(report)]),0)

    @unittest.skipUnless(os.name == 'posix','POSIX installed runtime')
    def test_installed_copy_outside_repo_without_pythonpath_and_tamper_refused(self):
        with tempfile.TemporaryDirectory(prefix='vettalon installed ') as directory:
            root=Path(directory);installed=root/'plugin';shutil.copytree(PLUGIN,installed)
            script=installed/'scripts/vettalon_plugin.py';scope=root/'audited';scope.mkdir()
            fake=root/'trusted-cli';fake.write_text('#!'+sys.executable+'\nimport sys,json\nfrom pathlib import Path\nif "--help" in sys.argv: print("--profile --report --sarif --max-modules --time-budget --rank --no-prior");sys.exit(0)\nfor flag,data in [("--report",{"findings":[],"run_status":"incomplete","incomplete_reason":"units_failed"}),("--sarif",{"version":"2.1.0","runs":[]})]: Path(sys.argv[sys.argv.index(flag)+1]).write_text(json.dumps(data))\nsys.exit(1)\n');fake.chmod(0o755)
            env=dict(os.environ,VETTALON_BIN=str(fake));env.pop('PYTHONPATH',None)
            def call(*args): return subprocess.run([sys.executable,'-B','-I','-S',str(script),*args],cwd=root,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(call('doctor','--scope',str(scope)).returncode,0)
            output=root/'output';result=call('scan','--scope',str(scope),'--output-dir',str(output))
            self.assertEqual(result.returncode,1,result.stderr)
            receipt=json.loads((output/'process-receipt.json').read_text())
            self.assertEqual(receipt['classification'],'finding-exit');self.assertEqual(receipt['run']['returncode'],1)
            self.assertEqual(receipt['run']['error'],'nonzero-exit')
            self.assertEqual(receipt['effective_timeout_seconds'],180)
            self.assertEqual(call('report','--path',str(output/'report.json')).returncode,0)
            runtime=installed/'scripts/runtime/process_capture_v2.py';runtime.write_text(runtime.read_text()+'\n# tamper\n')
            result=call('doctor','--scope',str(scope));self.assertEqual(result.returncode,2)
            self.assertIn('runtime',result.stderr)


if __name__ == '__main__': unittest.main()
