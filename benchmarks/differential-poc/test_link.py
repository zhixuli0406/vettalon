"""Contract tests for fresh synthetic runner-to-finding linkage."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('proof_link', Path(__file__).with_name('link.py'))
link = importlib.util.module_from_spec(spec)
spec.loader.exec_module(link)


def unit_process_receipt(receipt):
    """Explicit unit transport stub, never evidence of a real supervised child."""
    run = {'command': receipt['argv'], 'returncode': receipt['returncode'],
           'stdout': receipt['stdout'], 'stderr': receipt['stderr'],
           'seconds': receipt['wall_seconds'], 'error': None if receipt['returncode'] == 0 else 'nonzero-exit',
           'control_schema': 1, 'control_complete': True, 'timed_out': receipt['timed_out'],
           'cleanup_error': None, 'captures': {}}
    for name in ('stdout', 'stderr'):
        raw = run[name].encode()
        run['captures'][name] = {'cap_bytes': link.COMMAND_BYTES, 'observed_bytes': len(raw),
                                 'retained_bytes': len(raw), 'sha256': link.sha(raw),
                                 'truncated': False, 'decode_error': False}
    receipt.update(process_contract=link.PROCESS_CONTRACT, process=run,
                   combined_acceptance_cap=link.COMMAND_BYTES, per_stream_capture_cap=link.COMMAND_BYTES)
    return receipt


def simulated_row(payload, label, identity, image, cid):
    """Only a unit-test transport stub; never written as real execution evidence."""
    script = link.harness(payload, label, identity)
    observed = {'security_effect': label['vulnerable'], 'normal_control': True,
                'principal': 'alice-or-viewer', 'object': 'dummy-record', 'operation': 'read-or-write',
                'state': 'synthetic-only', 'uid': 65534, 'run_identity': identity,
                'case_id': payload['id'], 'source_sha256': payload['source_sha256']}
    info = {'Id': cid, 'Image': image, 'Name': '/' + link.container_name(payload, identity), 'Config': {'Cmd': ['python', '-I', '-B', '-c', script],
            'Labels': {'vettalon.link-run': identity, 'vettalon.link-case': payload['id']},
            'Entrypoint': None, 'User': '65534:65534'},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'Privileged': False,
            'Binds': None, 'Devices': None, 'Memory': 134217728, 'NanoCpus': 500000000, 'PidsLimit': 32,
            'SecurityOpt': ['no-new-privileges'], 'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=8m,mode=1777'}},
            'Mounts': [], 'State': {'Status': 'exited', 'Running': False, 'ExitCode': 0, 'OOMKilled': False, 'Error': ''}}
    created = copy.deepcopy(info); created['State']['Status'] = 'created'
    commands = {}
    for phase, argv, stdout in [
            ('create', link.create_argv(payload, label, identity, image), cid + '\n'),
            ('created_inspect', ['docker','inspect',cid], json.dumps([created])),
            ('start', ['docker','start','-a',cid], json.dumps(observed)),
            ('inspect', ['docker','inspect',cid], json.dumps([info])),
            ('cleanup', ['docker','rm','-f',cid], cid + '\n')]:
        commands[phase] = unit_process_receipt({'argv': argv, 'stdout': stdout, 'stderr': '', 'returncode': 0,
                           'timed_out': False, 'output_limited': False, 'wall_seconds': 0.01})
    return {'case_id': payload['id'], 'source_sha256': payload['source_sha256'], 'harness_sha256': link.digest(script),
            'run_identity': identity, 'container_id': cid, 'commands': commands, 'observed': observed,
            'created_inspect': created, 'inspect': info}


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.payloads, self.labels = link.generate()
        self.label = next(x for x in self.labels if x['variant'] == 0 and x['vulnerable'])
        self.payload = next(x for x in self.payloads if x['id'] == self.label['id'])
        self.finding = {'id': 'synthetic-test', 'status': 'candidate', 'file': 'synthetic/' + self.label['id'] + '.py', 'file_hash': self.payload['source_sha256']}
        self.report = {'schema_version': 2, 'findings': [self.finding]}
        self.bindings = {'schema': 'vettalon-synthetic-link-v1', 'items': [{'finding_id': self.finding['id'], 'pair_id': self.label['pair_id'], 'case_id': self.label['id']}]}
        self.identity = 'a' * 64
        self.image = 'sha256:' + 'b' * 64

    def test_exact_binding_and_hash_required(self):
        self.assertEqual(len(link.bind_pairs(self.report, self.bindings)), 1)
        for change in [{'file_hash': None}, {'file_hash': '0' * 64}, {'file': 'other.py'}, {'status': 'confirmed'}, {'id': 'wrong'}]:
            report = copy.deepcopy(self.report)
            report['findings'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                link.bind_pairs(report, self.bindings)
        for key, value in [('pair_id', 'wrong'), ('case_id', self.labels[1]['id'])]:
            bindings = copy.deepcopy(self.bindings)
            bindings['items'][0][key] = value
            with self.assertRaises(ValueError): link.bind_pairs(self.report, bindings)

    def test_schema_duplicate_and_budget_refused(self):
        for report in [{**self.report, 'schema_version': 1}, {**self.report, 'schema_version': True}, {**self.report, 'findings': [self.finding, self.finding]}]:
            with self.assertRaises(ValueError): link.bind_pairs(report, self.bindings)
        bad = copy.deepcopy(self.bindings)
        bad['items'] *= 2
        with self.assertRaises(ValueError): link.bind_pairs(self.report, bad)

    def row(self):
        return simulated_row(self.payload, self.label, self.identity, self.image, 'c' * 64)

    def test_stdout_nonce_control_and_raw_receipts_reconciled(self):
        row = self.row()
        link.validate_execution(row, self.payload, self.label, self.identity, self.image, set())
        for mutation in ['nonce', 'stdout', 'observed', 'control', 'source', 'harness', 'cleanup', 'timeout', 'exit', 'created', 'label', 'command', 'raw']:
            row = self.row()
            if mutation == 'nonce': row['run_identity'] = 'd' * 64
            elif mutation == 'stdout': row['commands']['start']['stdout'] = '{}'
            elif mutation == 'observed': row['observed']['security_effect'] = False
            elif mutation == 'control': row['observed'].pop('normal_control')
            elif mutation == 'source': row['source_sha256'] = '0' * 64
            elif mutation == 'harness': row['harness_sha256'] = '0' * 64
            elif mutation == 'cleanup': row['commands']['cleanup']['returncode'] = 1
            elif mutation == 'timeout': row['commands']['start']['timed_out'] = True
            elif mutation == 'exit': row['commands']['start']['returncode'] = True
            elif mutation == 'created': row['created_inspect']['State']['Status'] = 'exited'
            elif mutation == 'label': row['inspect']['Config']['Labels']['vettalon.link-run'] = 'e' * 64
            elif mutation == 'command': row['inspect']['Config']['Cmd'][-1] = 'print(1)'
            elif mutation == 'raw': row['commands']['inspect']['stdout'] = '[]'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                link.validate_execution(row, self.payload, self.label, self.identity, self.image, set())

    def test_consistently_tampered_raw_still_fails_semantic_contract(self):
        for mutation in ['control', 'effect', 'uid', 'nonce', 'created', 'exited', 'image', 'name', 'command', 'network', 'mounts', 'tmpfs', 'privileged']:
            row = self.row()
            if mutation in ['control', 'effect', 'uid', 'nonce']:
                key, value = {'control': ('normal_control', False), 'effect': ('security_effect', False),
                              'uid': ('uid', True), 'nonce': ('run_identity', 'd' * 64)}[mutation]
                row['observed'][key] = value
                row['commands']['start']['stdout'] = json.dumps(row['observed'])
            else:
                phase = 'created_inspect' if mutation == 'created' else 'inspect'
                info = row[phase]
                if mutation in ['created', 'exited']: info['State']['Status'] = 'running'
                elif mutation == 'image': info['Image'] = 'sha256:' + 'e' * 64
                elif mutation == 'name': info['Name'] = '/reused-name'
                elif mutation == 'command': info['Config']['Cmd'][-1] = 'print(1)'
                elif mutation == 'network': info['HostConfig']['NetworkMode'] = 'bridge'
                elif mutation == 'mounts': info['Mounts'] = [{'Type': 'bind'}]
                elif mutation == 'tmpfs': info['HostConfig']['Tmpfs'] = {}
                elif mutation == 'privileged': info['HostConfig']['Privileged'] = True
                row['commands'][phase]['stdout'] = json.dumps([info])
            for receipt in row['commands'].values():
                unit_process_receipt(receipt)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                link.validate_execution(row, self.payload, self.label, self.identity, self.image, set())

    def test_malformed_nested_inspect_shapes_refused(self):
        for phase in ['created_inspect', 'inspect']:
            for field in ['Config', 'HostConfig', 'State', 'Labels']:
                for malformed in [None, [], 'wrong']:
                    row = self.row()
                    if field == 'Labels': row[phase]['Config'][field] = malformed
                    else: row[phase][field] = malformed
                    row['commands'][phase]['stdout'] = json.dumps([row[phase]])
                    unit_process_receipt(row['commands'][phase])
                    with self.subTest(phase=phase, field=field, malformed=malformed), self.assertRaises(ValueError):
                        link.validate_execution(row, self.payload, self.label, self.identity, self.image, set())

    def test_reused_container_refused(self):
        with self.assertRaises(ValueError):
            link.validate_execution(self.row(), self.payload, self.label, self.identity, self.image, {'c' * 64})

    def test_instrumentation_is_opt_in_and_does_not_exec_source_on_host(self):
        plain = link.harness(self.payload, self.label)
        instrumented = link.harness(self.payload, self.label, self.identity)
        self.assertNotIn('run_identity', plain)
        self.assertIn(self.identity, instrumented)
        self.assertNotEqual(link.digest(plain), link.digest(instrumented))

    def test_inputs_regular_bounded_and_no_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root / 'input.json'; source.write_text('{}')
            self.assertEqual(link.read_file(source, 4), b'{}')
            with self.assertRaises(ValueError): link.read_file(source, 1)
            alias = root / 'alias'; alias.symlink_to(source)
            with self.assertRaises(ValueError): link.read_file(alias, 4)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): link.read_file(fifo, 4)

    def test_local_unix_socket_is_required(self):
        import socket
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            regular = root / 'regular'; regular.write_text('not a socket')
            with self.assertRaises(ValueError): link.local_docker(regular)
            path = root / 'sock'
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(path))
                argv, identity = link.local_docker(path)
                self.assertEqual(argv, ['docker', '--host', 'unix://' + str(path)])
                self.assertEqual(identity['canonical'], str(path))
                alias = root / 'alias-sock'; alias.symlink_to(path)
                self.assertEqual(link.local_docker(alias)[1]['canonical'], str(path))
            finally:
                sock.close()

    def test_command_caps_timeout_and_raw_bytes(self):
        import sys
        with self.assertRaises(link.CommandFailure):
            link.command([sys.executable, '-c', 'print("x"*10000)'], 2, byte_cap=100)
        with self.assertRaises(link.CommandFailure):
            link.command([sys.executable, '-c', 'import time;time.sleep(1)'], 0.03)
        receipt = link.command([sys.executable, '-c', 'print("ok")'], 2)
        self.assertEqual(receipt['stdout'], 'ok\n')
        self.assertEqual(receipt['returncode'], 0)

    def test_bundle_roles_file_hash_and_no_verdict_promotion(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp).resolve() / 'new'
            out.mkdir()
            labels = [x for x in self.labels if x['pair_id'] == self.label['pair_id']]
            rows = [simulated_row(next(p for p in self.payloads if p['id'] == label['id']), label, self.identity, self.image, f'{i+10:064x}') for i, label in enumerate(labels)]
            pair = link.bind_pairs(self.report, self.bindings)[0]
            manifest = link.write_bundle(out, pair, rows, self.identity, 'f' * 64)
            self.assertEqual({a['role'] for a in manifest['artifacts']}, {'vulnerable_source','patched_source','vulnerable_execution','patched_execution','normal_control'})
            self.assertIsNone(manifest['human_decision'])
            self.assertEqual(self.finding['status'], 'candidate')
            for artifact in manifest['artifacts']:
                data = (out / pair['binding']['case_id'] / artifact['path']).read_bytes()
                self.assertEqual(link.sha(data), artifact['sha256'])
                self.assertEqual(len(data), artifact['bytes'])
            with self.assertRaises(FileExistsError): link.write_bundle(out, pair, rows, self.identity, 'f' * 64)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        LinkTests.setUp(self)
        local = patch.object(link, 'local_docker', return_value=(['docker'], {'kind': 'unit_test_stub_only'}))
        local.start()
        self.addCleanup(local.stop)
    def stub(self, fail_phase=None):
        rows, phases = {}, {}
        def command(argv, timeout, byte_cap=link.COMMAND_BYTES):
            receipt = {'argv': argv, 'timed_out': False, 'output_limited': False,
                       'returncode': 0, 'stdout': '', 'stderr': '', 'wall_seconds': 0.001}
            if len(argv) > 1 and argv[1] == 'validate':
                if fail_phase == 'validator':
                    receipt['timed_out'] = True
                    raise link.CommandFailure(receipt)
            elif argv[1:3] == ['image', 'inspect']:
                receipt['stdout'] = json.dumps([{'Id': self.image}])
                if fail_phase == 'image':
                    receipt['output_limited'] = True
                    raise link.CommandFailure(receipt)
            elif argv[1] == 'create':
                identity = next(a.split('=', 1)[1] for a in argv if a.startswith('vettalon.link-run='))
                case_id = next(a.split('=', 1)[1] for a in argv if a.startswith('vettalon.link-case='))
                label = next(l for l in self.labels if l['id'] == case_id)
                payload = next(p for p in self.payloads if p['id'] == case_id)
                cid = f'{len(rows)+1:064x}'
                rows[cid] = simulated_row(payload, label, identity, self.image, cid)
                phases[cid] = 0
                receipt = rows[cid]['commands']['create']
                if fail_phase == 'create':
                    receipt = copy.deepcopy(receipt)
                    receipt.update(stdout='', timed_out=True)
                    raise link.CommandFailure(receipt)
            elif argv[1] == 'inspect':
                phase = 'created_inspect' if phases[argv[-1]] == 0 else 'inspect'
                receipt = rows[argv[-1]]['commands'][phase]
                phases[argv[-1]] += 1
            elif argv[1] == 'start':
                receipt = rows[argv[-1]]['commands']['start']
            elif argv[1] == 'rm':
                receipt['stdout'] = argv[-1] + '\n'
                if fail_phase == 'cleanup': receipt['returncode'] = 1
                if fail_phase == 'helper_cleanup': raise ValueError('Process runtime is missing or changed')
            else:
                raise AssertionError('Unexpected subprocess: ' + repr(argv))
            return unit_process_receipt(receipt)
        return command

    def prepare(self, root):
        self.report['repo'] = str(root)
        (root / 'synthetic').mkdir()
        (root / self.finding['file']).write_text(self.payload['source'])
        report = root / 'report.json'; report.write_text(json.dumps(self.report))
        bindings = root / 'bindings.json'; bindings.write_text(json.dumps(self.bindings))
        validator = root / 'vettalon'; validator.write_text('declared test stub'); validator.chmod(0o700)
        return report, bindings, validator

    def test_fresh_launch_produces_bound_manifest(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            report, bindings, validator = self.prepare(root)
            with patch.object(link, 'command', side_effect=self.stub()):
                result = link.launch(report, bindings, root / 'new', validator, Path('/unit-test-socket'))
            self.assertEqual(result['status'], 'synthetic_contract_matched', result)
            self.assertEqual(result['containers'], 2)
            self.assertEqual(result['origin'], 'operator_supplied')
            self.assertFalse(result['finding_status_changed'])
            self.assertEqual(len(result['manifests']), 1)
            self.assertNotEqual(result['run_identity'], self.identity)
            with patch.object(link, 'command', side_effect=AssertionError('must refuse output reuse')):
                with self.assertRaises(FileExistsError): link.launch(report, bindings, root / 'new', validator, Path('/unit-test-socket'))

    def test_all_five_families_stub_pipeline(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            report = link.make_fixture(root / 'fixture')
            _, _, validator = self.prepare(root)
            # The separate fixture report remains the input; prepare only supplies a stub executable.
            with patch.object(link, 'command', side_effect=self.stub()):
                result = link.launch(root / 'fixture/report.json', root / 'fixture/bindings.json', root / 'new', validator, Path('/unit-test-socket'))
            self.assertEqual(result['status'], 'synthetic_contract_matched', result)
            self.assertEqual(result['containers'], 10)
            self.assertEqual(len(result['manifests']), 5)
            batch = json.loads((root / 'new/batch.json').read_text())
            self.assertEqual(len({r['container_id'] for r in batch['rows']}), 10)
            self.assertEqual({r['run_identity'] for r in batch['rows']}, {result['run_identity']})
            self.assertTrue(all(f['status'] == 'candidate' for f in report['findings']))

    def test_failures_preserve_raw_and_never_emit_verified_manifests(self):
        from unittest.mock import patch
        for phase in ['validator', 'image', 'create', 'cleanup', 'helper_cleanup']:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                report, bindings, validator = self.prepare(root)
                with patch.object(link, 'command', side_effect=self.stub(phase)) as calls:
                    result = link.launch(report, bindings, root / 'new', validator, Path('/unit-test-socket'))
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['manifests'], [])
                self.assertEqual(list((root / 'new').glob('*/manifest.json')), [])
                if phase in ['validator', 'image']:
                    failure = 'report-validation-failure.json' if phase == 'validator' else 'image-inspect-failure.json'
                    self.assertTrue((root / 'new' / failure).is_file())
                if phase == 'create':
                    cleanup = [call.args[0] for call in calls.call_args_list if call.args[0][1] == 'rm']
                    self.assertEqual(len(cleanup), 1)
                    self.assertTrue(cleanup[0][-1].startswith('vettalon-link-'))
                    raw = json.loads(next((root / 'new').glob('raw-*.json')).read_text())
                    self.assertTrue(raw['commands']['create']['timed_out'])
                if phase == 'helper_cleanup':
                    raw_files = list((root / 'new').glob('raw-*.json'))
                    self.assertEqual(len(raw_files), 1)
                    raw = json.loads(raw_files[0].read_text())
                    self.assertIn('cleanup_error', raw)
                    self.assertIn('Process runtime is missing or changed', raw['cleanup_error'])

    def test_actual_source_mismatch_refused_before_docker(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            report, bindings, validator = self.prepare(root)
            (root / self.finding['file']).write_text('wrong source')
            with patch.object(link, 'command', side_effect=AssertionError('no subprocess permitted')):
                with self.assertRaises(ValueError): link.launch(report, bindings, root / 'new', validator, Path('/unit-test-socket'))

    def test_input_and_persisted_raw_mutation_refused(self):
        from unittest.mock import patch
        for mutation in ['report', 'source', 'raw']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                report, bindings, validator = self.prepare(root)
                stub = self.stub()
                cleanup_count = 0
                def mutate(argv, timeout, byte_cap=link.COMMAND_BYTES):
                    nonlocal cleanup_count
                    receipt = stub(argv, timeout, byte_cap)
                    if argv[1] == 'rm':
                        cleanup_count += 1
                        if cleanup_count == 2:
                            if mutation == 'report': report.write_text('{}')
                            elif mutation == 'source': (root / self.finding['file']).write_text('tampered')
                            else: next((root / 'new').glob('raw-*.json')).write_text('{}')
                    return receipt
                with patch.object(link, 'command', side_effect=mutate):
                    result = link.launch(report, bindings, root / 'new', validator, Path('/unit-test-socket'))
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['manifests'], [])

    def test_malformed_image_receipt_preserves_incomplete_summary(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            report, bindings, validator = self.prepare(root)
            stub = self.stub()
            def malformed(argv, timeout, byte_cap=link.COMMAND_BYTES):
                receipt = stub(argv, timeout, byte_cap)
                if argv[1:3] == ['image', 'inspect']: receipt['stdout'] = '["not-an-object"]'
                return receipt
            with patch.object(link, 'command', side_effect=malformed):
                result = link.launch(report, bindings, root / 'new', validator, Path('/unit-test-socket'))
            self.assertEqual(result['status'], 'incomplete')
            self.assertTrue((root / 'new/image-inspect.json').is_file())
            self.assertTrue((root / 'new/checks.json').is_file())
            self.assertEqual(result['manifests'], [])

    def test_duplicate_json_and_nonfinite_values_refused(self):
        for text in ['{"x":1,"x":2}', '{"x":NaN}']:
            with self.assertRaises(ValueError): link.json_data(text)

    def test_fixture_is_explicit_synthetic_and_hashes_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve() / 'fixture'
            report = link.make_fixture(root)
            bindings = json.loads((root / 'bindings.json').read_text())
            self.assertEqual(len(link.bind_pairs(report, bindings)), 5)
            self.assertEqual(report['run_status'], 'incomplete')
            for finding in report['findings']:
                self.assertEqual(link.sha((root / finding['file']).read_bytes()), finding['file_hash'])
                expected = link.sha(('\0'.join([finding['source_engine'], finding['rule_id'], finding['file'], '1', finding['snippet']])).encode())[:16]
                self.assertEqual(finding['id'], 'synthetic_fixture-' + expected)
            with self.assertRaises(FileExistsError): link.make_fixture(root)


if __name__ == '__main__': unittest.main()
