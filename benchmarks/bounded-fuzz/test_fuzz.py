import unittest
from fuzz import bounded_search, minimize, replay

class FuzzTests(unittest.TestCase):
    def test_bounded_search_and_safe_counterpart(self):
        result=bounded_search(max_cases=128)
        self.assertLessEqual(result['attempts'],128)
        self.assertIsNotNone(result['counterexample'])
        self.assertTrue(replay(result['counterexample'],False))
        self.assertFalse(replay(result['counterexample'],True))
    def test_minimization_preserves_real_effect_and_replays(self):
        token='0001'
        result=minimize(token,max_replays=64)
        self.assertLessEqual(result['replays'],64)
        self.assertLessEqual(len(result['minimal']),len(token))
        self.assertTrue(replay(result['minimal'],False))
        self.assertFalse(replay(result['minimal'],True))
    def test_cap_rejected_and_no_finding_is_not_clean(self):
        with self.assertRaises(ValueError): bounded_search(max_cases=1001)
        r=bounded_search(max_cases=1)
        self.assertEqual(r['status'],'no-counterexample-within-budget')
        self.assertFalse(r['proved_safe'])

class NativeRunnerTests(unittest.TestCase):
    def test_existing_raw_is_not_overwritten(self):
        import tempfile
        from pathlib import Path
        from fuzz import native_sandbox
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'raw.json';out.write_text('preserve')
            with self.assertRaises(FileExistsError): native_sandbox(out)
            self.assertEqual(out.read_text(),'preserve')

    def test_exit_zero_without_control_is_incomplete_and_container_removed(self):
        import tempfile,json,types
        from pathlib import Path
        from unittest.mock import patch
        import fuzz
        def check(args,**kwargs):
            if args[1:3]==['image','inspect']: return json.dumps([{'Id':'sha256:mock','RepoDigests':[]}])
            if args[1]=='create': return 'mock-cid'
            return json.dumps([{'State':{'ExitCode':0},'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'Memory':134217728,'NanoCpus':500000000,'PidsLimit':32,'SecurityOpt':['no-new-privileges']},'Mounts':[],'Config':{'User':'65534:65534'}}])
        observed={'vulnerable_security_effect':True,'patched_security_effect':False,'normal_control':False,'search_attempts':2,'minimize_replays':4}
        result=types.SimpleNamespace(stdout=json.dumps(observed),stderr='',returncode=0)
        with tempfile.TemporaryDirectory() as d, patch.object(fuzz.subprocess,'check_output',side_effect=check),patch.object(fuzz.subprocess,'run',return_value=result) as call:
            raw=fuzz.native_sandbox(Path(d)/'raw.json')
            self.assertEqual(raw['status'],'incomplete')
            self.assertEqual(call.call_args_list[-1].args[0][:3],['docker','rm','-f'])

class NativeFailureRetentionTests(unittest.TestCase):
    def test_missing_image_create_empty_stdout_and_timeout_retained(self):
        import tempfile,json,subprocess,types
        from pathlib import Path
        from unittest.mock import patch
        import fuzz
        for scenario in ['missing-image','create-failure','empty-stdout','timeout','bool-counter']:
            def check(args,**kwargs):
                if args[1:3]==['image','inspect']:
                    if scenario=='missing-image': raise subprocess.CalledProcessError(1,args,output='image missing')
                    return json.dumps([{'Id':'sha256:mock','RepoDigests':[]}])
                if args[1]=='create':
                    if scenario=='create-failure': raise OSError('daemon unavailable')
                    return 'mock-cid'
                return json.dumps([{'State':{'ExitCode':0},'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'Memory':134217728,'NanoCpus':500000000,'PidsLimit':32,'SecurityOpt':['no-new-privileges']},'Mounts':[],'Config':{'User':'65534:65534'}}])
            def call(args,**kwargs):
                if args[1]=='start' and scenario=='timeout': raise subprocess.TimeoutExpired(args,30,output='partial output')
                observed={'vulnerable_security_effect':True,'patched_security_effect':False,'normal_control':True,'search_attempts':True,'minimize_replays':4}
                return types.SimpleNamespace(stdout='' if scenario=='empty-stdout' else json.dumps(observed),stderr='',returncode=0)
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as d, patch.object(fuzz.subprocess,'check_output',side_effect=check),patch.object(fuzz.subprocess,'run',side_effect=call):
                out=Path(d)/'raw.json'
                result=fuzz.native_sandbox(out)
                self.assertEqual(result['status'],'incomplete')
                self.assertEqual(json.loads(out.read_text())['status'],'incomplete')
                if scenario=='timeout': self.assertEqual(result['stdout'],'partial output')
