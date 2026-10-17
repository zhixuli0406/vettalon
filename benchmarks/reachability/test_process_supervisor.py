"""Self-authored process fixtures only; no Go/tool downloads or model calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import adapter


CHILD = r'''
import json,os,pathlib,sys,time
p=pathlib.Path(sys.argv[1]); token=sys.argv[2]; start=time.monotonic()
(p/'ready').write_text(token)
try:
 while time.monotonic()-start<2 and not (p/'release').exists():
  if (p/'challenge').exists():(p/'ack').write_text((p/'challenge').read_text())
  time.sleep(.005)
finally:(p/'exited').write_text(token)
'''
LEADER = r'''
import os,pathlib,subprocess,sys,time
p=pathlib.Path(sys.argv[1]); mode=sys.argv[2]
opts=dict(stdin=subprocess.DEVNULL)
if mode=='normal':opts.update(stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
else:opts['start_new_session']=True
subprocess.Popen([sys.executable,'-I','-S',str(p/'child.py'),str(p),'owned-token'],**opts)
end=time.monotonic()+.8
while not (p/'ready').exists() and time.monotonic()<end:time.sleep(.005)
print('PARTIAL',flush=True)
if mode!='normal':time.sleep(3)
'''


def observed_run(command=None, stdout='ok', stderr=''):
    """Explicit fixture satisfying the new bounded observation contract."""
    streams = {}
    for name, text, cap in [('stdout', stdout, 4 * 1024 * 1024), ('stderr', stderr, 1024 * 1024)]:
        raw = text.encode()
        streams[name] = dict(cap_bytes=cap, observed_bytes=len(raw), retained_bytes=len(raw),
                             sha256=hashlib.sha256(raw).hexdigest(), truncated=False, decode_error=False)
    return dict(command=command or ['fixture'], returncode=0, stdout=stdout, stderr=stderr,
                seconds=.01, error=None, control_schema=1, control_complete=True,
                timed_out=False, cleanup_error=None, captures=streams)


class ProcessSupervisorTests(unittest.TestCase):
    def env(self, root):
        return {'PATH': os.defpath, 'HOME': str(root), 'TMPDIR': str(root), 'LANG': 'C'}

    def test_normal_leader_exit_cleans_live_owned_child(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'child.py').write_text(CHILD)
            (root/'leader.py').write_text(LEADER)
            try:
                run = adapter.invoke([sys.executable, '-I', '-S', str(root/'leader.py'), str(root), 'normal'], root, self.env(root), 1)
                self.assertEqual((root/'ready').read_text(), 'owned-token')
                (root/'challenge').write_text('after-return-unique-challenge')
                end = time.monotonic()+.12
                while not (root/'ack').exists() and time.monotonic()<end:
                    time.sleep(.005)
                self.assertFalse((root/'ack').exists(), 'same owned child executed after successful invoke returned')
                self.assertEqual(run['returncode'], 0)
                self.assertTrue(adapter.successful_run(run))
            finally:
                (root/'release').write_text('release')
                time.sleep(.02)

    def test_stdout_and_stderr_caps_preserve_bounded_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            command = [sys.executable, '-I', '-S', '-c', "import os;os.write(1,b'O'*131072);os.write(2,b'E'*131072)"]
            for stream in ['stdout', 'stderr']:
                code = f"import os;os.write({1 if stream=='stdout' else 2},b'X'*131072)"
                run = adapter.invoke(command[:-1]+[code], root, self.env(root), 1, stdout_cap=1024, stderr_cap=1024)
                self.assertLessEqual(len(run[stream].encode()), 1024)
                self.assertTrue(run['captures'][stream]['truncated'])
                self.assertEqual(run['error'], 'output-limit')
                self.assertFalse(adapter.successful_run(run))

    def test_inherited_pipe_cleanup_has_deadline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'child.py').write_text(CHILD)
            (root/'leader.py').write_text(LEADER)
            try:
                started = time.monotonic()
                run = adapter.invoke([sys.executable, '-I', '-S', str(root/'leader.py'), str(root), 'pipe'], root, self.env(root), .25)
                self.assertLess(time.monotonic()-started, 1.6)
                self.assertEqual(run['error'], 'timeout')
                self.assertIsNotNone(run['cleanup_error'])
                self.assertIn('PARTIAL', run['stdout'])
            finally:
                (root/'release').write_text('release')
                end = time.monotonic()+.3
                while not (root/'exited').exists() and time.monotonic()<end:
                    time.sleep(.005)

    def test_nonzero_and_invalid_utf8_are_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for code in ["import sys;print('partial');sys.exit(7)", "import os;os.write(1,b'\\xff')"]:
                run = adapter.invoke([sys.executable, '-I', '-S', '-c', code], root, self.env(root), 1)
                self.assertFalse(adapter.successful_run(run))
                self.assertIsNotNone(run['error'])
            self.assertTrue(run['captures']['stdout']['decode_error'])
            self.assertEqual(run['captures']['stdout']['sha256'], hashlib.sha256(b'\xff').hexdigest())

    def test_target_does_not_inherit_private_control_fds(self):
        code = "import os,json;openfds=[]\nfor fd in range(3,64):\n try:os.fstat(fd);openfds.append(fd)\n except OSError:pass\nprint(json.dumps(openfds))"
        with tempfile.TemporaryDirectory() as temp:
            run = adapter.invoke([sys.executable, '-I', '-S', '-c', code], Path(temp), self.env(temp), 1)
            self.assertTrue(adapter.successful_run(run))
            self.assertEqual(json.loads(run['stdout']), [])

    def test_status_frame_rejects_missing_duplicate_truncated_unknown_and_bool(self):
        good = b'{"schema":1,"exit_code":0,"error":null}\n'
        self.assertEqual(adapter.decode_status(good)['exit_code'], 0)
        for raw in [b'', good+good, good[:-1], good.replace(b'0', b'true'), good.replace(b'"schema":1', b'"schema":9'), b'x'*2048, b'\xff\n']:
            with self.subTest(raw=raw[:32]):
                with self.assertRaises(ValueError):adapter.decode_status(raw)

    def test_config_limit_and_invalid_timeouts_fail_before_spawn(self):
        with patch('adapter.subprocess.Popen') as spawn:
            for timeout in [0, -1, float('nan'), float('inf')]:
                run = adapter.invoke(['fixture'], Path.cwd(), {}, timeout)
                self.assertEqual(run['error'], 'invalid-limits')
            run = adapter.invoke(['x'*70000], Path.cwd(), {}, 1)
            self.assertEqual(run['error'], 'config-limit')
            spawn.assert_not_called()

    def test_ignored_sigchld_is_explicitly_unsupported(self):
        with patch('adapter.signal.getsignal', return_value=signal.SIG_IGN), patch('adapter.subprocess.Popen') as spawn:
            run = adapter.invoke(['fixture'], Path.cwd(), {}, 1)
            self.assertEqual(run['error'], 'unsupported-sigchld')
            spawn.assert_not_called()


class ObservationContractTests(unittest.TestCase):
    def test_cache_rejects_legacy_missing_or_inconsistent_control(self):
        good = observed_run()
        self.assertTrue(adapter.valid_cached_run(good))
        mutations = [lambda r:r.pop('control_complete'), lambda r:r.update(control_complete=False),
                     lambda r:r.update(cleanup_error='failed'), lambda r:r.update(timed_out=True),
                     lambda r:r['captures']['stdout'].update(truncated=True),
                     lambda r:r['captures']['stdout'].update(retained_bytes=True),
                     lambda r:r['captures']['stdout'].update(observed_bytes=999),
                     lambda r:r['captures']['stderr'].update(sha256='bad'),
                     lambda r:r['captures']['stdout'].update(cap_bytes=0),
                     lambda r:r['captures']['stdout'].update(decode_error=True)]
        for mutate in mutations:
            item = copy.deepcopy(good);mutate(item)
            self.assertFalse(adapter.valid_cached_run(item))

    def test_zero_exit_metadata_errors_are_unknown(self):
        from test_adapter import ScanIntegrationTests
        for stage in ['version', 'env', 'list']:
            fixture = ScanIntegrationTests();fixture.setUp()
            try:
                def fake(command, cwd, env, timeout):
                    old = fixture.fake_run(command, cwd, env, timeout)
                    run = observed_run(command, old['stdout'])
                    if stage in command:run['error']='timeout'
                    return run
                with patch('adapter.invoke', side_effect=fake):
                    result = fixture.run_scan()
                self.assertEqual(result['status'], 'unknown')
                self.assertFalse(fixture.cache.exists())
            finally:fixture.tearDown()

    def test_helper_source_hash_participates_in_fingerprint(self):
        with patch('adapter.supervisor_source_hash', return_value='changed'):
            self.assertIn('changed', adapter.implementation_fingerprint())


class ProtocolAndCleanupTests(unittest.TestCase):
    def env(self, root):
        return {'PATH': os.defpath, 'HOME': str(root), 'LANG': 'C'}

    def test_real_bad_status_frames_fail_closed(self):
        frames = [b'', b'{"schema":1,"exit_code":0,"error":null}',
                  b'{"schema":1,"exit_code":0,"error":null}\n'*2,
                  b'{"schema":1,"exit_code":0,"error":null,"extra":true}\n',
                  b'{"schema":1,"exit_code":0,"exit_code":7,"error":null}\n', b'X'*1100]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index, frame in enumerate(frames):
                helper = root/f'helper-{index}.py'
                helper.write_text(f"import os,sys,time\na,b=map(int,sys.argv[1:])\nwhile os.read(a,4096):pass\nos.close(a)\nos.write(b,{frame!r})\nos.close(b)\ntime.sleep(2)\n")
                with patch('adapter.SUPERVISOR', helper):
                    run = adapter.invoke(['unused'], root, self.env(root), .5)
                self.assertEqual(run['error'], 'invalid-status')
                self.assertFalse(adapter.successful_run(run))

    def test_blocked_config_transfer_is_in_execution_deadline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);helper = root/'not-reading.py'
            helper.write_text('import time;time.sleep(2)\n')
            started = time.monotonic()
            with patch('adapter.SUPERVISOR', helper):
                run = adapter.invoke(['unused', 'x'*50000], root, self.env(root), .08)
            self.assertEqual(run['error'], 'timeout')
            self.assertLess(time.monotonic()-started, .6)
            self.assertFalse(run['control_complete'])

    def test_group_is_signalled_before_any_parent_wait_and_only_once(self):
        real_kill, real_wait = os.killpg, os.waitpid
        signalled = []
        def kill(pid, sig):
            signalled.append(pid);return real_kill(pid, sig)
        def wait(pid, options):
            self.assertIn(pid, signalled)
            return real_wait(pid, options)
        with tempfile.TemporaryDirectory() as temp, patch('adapter.os.killpg', side_effect=kill), patch('adapter.os.waitpid', side_effect=wait):
            run = adapter.invoke([sys.executable, '-I', '-S', '-c', "print('ok')"], Path(temp), self.env(temp), 1)
        self.assertTrue(adapter.successful_run(run))
        self.assertEqual(len(signalled), 1)

    def test_signal_and_lost_wait_errors_cannot_be_success(self):
        real_kill, real_wait = os.killpg, os.waitpid
        for fault in ['signal', 'wait']:
            count = []
            def kill(pid, sig):
                count.append(pid);real_kill(pid, sig)
                if fault=='signal':raise PermissionError('synthetic failure after real cleanup')
            def wait(pid, options):
                result = real_wait(pid, options)
                if fault=='wait' and result[0]==pid:raise ChildProcessError('synthetic loss after actual reap')
                return result
            with tempfile.TemporaryDirectory() as temp, patch('adapter.os.killpg', side_effect=kill), patch('adapter.os.waitpid', side_effect=wait):
                run = adapter.invoke([sys.executable, '-I', '-S', '-c', "print('partial')"], Path(temp), self.env(temp), 1)
            self.assertFalse(adapter.successful_run(run))
            self.assertIsNotNone(run['cleanup_error'])
            self.assertIn('partial', run['stdout'])
            self.assertEqual(len(count), 1)

    def test_selector_failure_and_cancellation_close_owned_descriptors(self):
        import selectors
        real_factory = selectors.DefaultSelector
        for fault in [OSError('controlled selector failure'), KeyboardInterrupt()]:
            before = len(list(Path('/dev/fd').iterdir())) if Path('/dev/fd').exists() else None
            class OnceFail:
                def __init__(self):self.inner=real_factory();self.failed=False
                def register(self,*a):return self.inner.register(*a)
                def unregister(self,*a):return self.inner.unregister(*a)
                def close(self):return self.inner.close()
                def select(self,*a):
                    if not self.failed:self.failed=True;raise fault
                    return self.inner.select(*a)
            with tempfile.TemporaryDirectory() as temp, patch('adapter.selectors.DefaultSelector', OnceFail):
                run = adapter.invoke([sys.executable, '-I', '-S', '-c', 'import time;time.sleep(2)'], Path(temp), self.env(temp), 1)
            self.assertIn(run['error'], ['process-error', 'cancelled'])
            self.assertFalse(adapter.successful_run(run))
            if before is not None:self.assertEqual(len(list(Path('/dev/fd').iterdir())), before)

    def test_target_spawn_error_and_invalid_configuration_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = adapter.invoke(['/missing/controlled-target'], root, self.env(root), 1)
            self.assertEqual(run['error'], 'process-error')
            self.assertTrue(run['control_complete'])
            for command, env in [([], {}), (['a'], {'key': 1}), ([None], {}), (['a\0'], {})]:
                self.assertEqual(adapter.invoke(command, root, env, 1)['error'], 'invalid-config')
            self.assertEqual(adapter.invoke(['a'], root, {}, 1, stdout_cap=0)['error'], 'invalid-limits')
            self.assertEqual(adapter.invoke(['a'], root, {}, 1, stderr_cap=adapter.STDERR_CAP+1)['error'], 'invalid-limits')


class RunnerObservationTests(unittest.TestCase):
    def test_runner_rejects_zero_exit_errors_at_each_setup_stage(self):
        import run_experiment
        for stage in ['initial', 'buildinfo', 'host-setup', 'invalid-download']:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp);db=root/'db';db.mkdir();(db/'GO-2021-0113.json').write_text('{}')
                def fake(command, cwd, env, timeout):
                    run = observed_run(command, json.dumps({'Dir': temp}))
                    if ((stage=='initial' and '-json' in command)
                        or (stage=='buildinfo' and '-m' in command)
                        or (stage=='host-setup' and 'download' in command and '-json' not in command)):
                        run['cleanup_error']='controlled-cleanup-error'
                    if stage=='invalid-download' and '-json' in command:run=observed_run(command,'not-json')
                    return run
                with patch('sys.argv',['runner','--tool','/owned/tool','--db',str(db),'--output',str(root/'output')]), patch('run_experiment.DB_SHA256', adapter.digest(b'{}')), patch('adapter.invoke',side_effect=fake), patch('adapter.scan') as scan:
                    self.assertEqual(run_experiment.main(), 2)
                    scan.assert_not_called()


class HelperUnitTests(unittest.TestCase):
    def run_helper(self, packet, spawn_error=False):
        import process_supervisor
        config_read, config_write = os.pipe()
        status_read, status_write = os.pipe()
        os.write(config_write, packet)
        os.close(config_write)
        class HeldLeader(BaseException):pass
        try:
            with patch('sys.argv', ['supervisor', str(config_read), str(status_write)]), patch('process_supervisor.subprocess.Popen') as spawn, patch('process_supervisor.signal.pause', side_effect=HeldLeader):
                spawn.return_value.wait.return_value=0
                if spawn_error:spawn.side_effect=OSError('controlled spawn error')
                with self.assertRaises(HeldLeader):process_supervisor.main()
                frame=os.read(status_read,2048)
                if spawn.called:
                    self.assertTrue(spawn.call_args.kwargs['close_fds'])
                    self.assertNotIn('pass_fds',spawn.call_args.kwargs)
                return adapter.decode_status(frame),spawn.called
        finally:
            os.close(status_read)
            for fd in [config_read,status_write]:
                try:os.close(fd)
                except OSError:pass

    def test_helper_retains_leader_after_success_and_spawn_error(self):
        packet=json.dumps({'argv':['fixed'], 'cwd':'/private', 'env':{}}).encode()
        frame,called=self.run_helper(packet)
        self.assertTrue(called);self.assertEqual(frame['exit_code'],0)
        frame,called=self.run_helper(packet,spawn_error=True)
        self.assertTrue(called);self.assertEqual(frame['error'],'process-error')

    def test_helper_invalid_configuration_never_spawns_target(self):
        for config in [{}, {'argv':[], 'cwd':'/private', 'env':{}},
                       {'argv':['fixed'], 'cwd':None, 'env':{}},
                       {'argv':['fixed'], 'cwd':'/private', 'env':{'k':1}}]:
            frame,called=self.run_helper(json.dumps(config).encode())
            self.assertFalse(called);self.assertEqual(frame['error'],'supervisor-error')
        frame,called=self.run_helper(b'not-json')
        self.assertFalse(called);self.assertEqual(frame['error'],'supervisor-error')
