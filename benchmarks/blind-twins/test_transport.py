"""Offline formal bridge tests; no provider, model server, or Docker invocation."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import aggregate
import ledger
import protocol
import run
import transport


class FormalTransportBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.materialized = self.root / 'sources'
        (self.materialized / 'anonymous').mkdir(parents=True)
        payloads, labels = protocol.generate()
        manifest = {'schema': protocol.SCHEMA, 'synthetic': True, 'count': len(payloads),
                    'cases': [{'id': p['id'], 'source_sha256': p['source_sha256']} for p in payloads]}
        (self.materialized / 'manifest.json').write_text(json.dumps(manifest))
        (self.materialized / 'fixed-five-pair-subset.json').write_text(json.dumps(protocol.fixed_subset()))
        for payload in payloads:
            (self.materialized / 'anonymous' / f"{payload['id']}.json").write_text(json.dumps(payload))
        self.artifacts = self.root / 'artifacts'
        self.artifacts.mkdir()
        canonical = json.dumps({'schema': protocol.SCHEMA, 'kind': 'unit-only',
                                'no-oracle-executed': True, 'rows': []}) + '\n'
        (self.artifacts / 'canonical-oracle.json').write_text(canonical)
        self.denominator = self.artifacts / 'denominator.json'
        self.denominator.write_text(json.dumps({
            'schema': protocol.SCHEMA, 'canonical_sha256': protocol.digest(canonical),
            'manifest_sha256': protocol.digest(labels), 'positive_denominator': len(labels)//2,
            'canonical_rebuildable_denominator': 0, 'eligible_pairs': [],
            'excluded_from_canonical_denominator': sorted({x['pair_id'] for x in labels})}))
        self.formal = transport._load('run_v1.py')
        for module, name, value in ((self.formal, 'TWINS_DATA_ROOT', self.materialized),
                                    (self.formal.protocol, 'ARTIFACTS', self.artifacts)):
            guard = patch.object(module, name, value)
            guard.start(); self.addCleanup(guard.stop)
        self.models = {
            'finder': {'name': 'unit-finder', 'digest': 'a' * 64, 'family': 'qwen'},
            'samefamily_verifier': {'name': 'unit-same', 'digest': 'b' * 64, 'family': 'qwen'},
            'crossfamily_verifier': {'name': 'unit-cross', 'digest': 'c' * 64, 'family': 'gemma'}}

    def test_batch_preflight_blocks_unknown_controls_before_network_or_ledger(self):
        before = {str(path.relative_to(self.root)) for path in self.root.rglob('*')}
        with patch('http.client.HTTPConnection', side_effect=AssertionError('network')), patch(
                'urllib.request.urlopen', side_effect=AssertionError('network')), patch.object(
                self.formal.transport, 'Ledger', side_effect=AssertionError('ledger')) as opened_ledger, patch.object(
                self.formal.transport, 'write_new', side_effect=AssertionError('artifact write')) as wrote, patch.object(
                self.formal.transport, 'dispatch_one', side_effect=AssertionError('dispatch')) as dispatched, patch.object(
                self.formal.transport, 'request_ollama_once', side_effect=AssertionError('provider request')) as requested:
            result = run.preflight_formal_batch(self.models, self.formal)
        opened_ledger.assert_not_called()
        wrote.assert_not_called()
        dispatched.assert_not_called()
        requested.assert_not_called()
        self.assertEqual({str(path.relative_to(self.root)) for path in self.root.rglob('*')}, before)
        self.assertEqual(result['requested_calls'], 250)
        self.assertEqual(result['reserved_output_tokens_ceiling'], 256000)
        self.assertEqual(result['calls_by_arm'], {'finder-only': 50, 'samefamily': 100, 'crossfamily': 100})
        self.assertFalse(result['dispatch_enabled'])
        self.assertEqual(set(result['capabilities']['blockers']), set(self.models))
        self.assertIsNone(result['capabilities']['observed']['provider_attempts'])
        self.assertEqual(result['formal_provider_calls'], 0)
        self.assertEqual(result['formal_ledger_debits'], 0)

    def test_forged_positive_canonical_rejected_by_formal_prepare_and_reader(self):
        payloads,labels=protocol.generate()
        canonical=json.dumps({'schema':protocol.SCHEMA,'kind':'canonical-oracle',
            'planned_cases':len(payloads),'rows':[
                {'id':payload['id'],'source_sha256':payload['source_sha256'],
                 'harness_sha256':protocol.digest(protocol.harness(payload,label)),
                 'status':'complete','oracle_pass':True,'oracle_executed':False}
                for payload,label in zip(payloads,labels)]})+'\n'
        (self.artifacts/'canonical-oracle.json').write_text(canonical)
        frozen=json.loads(self.denominator.read_text())
        frozen.update(canonical_sha256=protocol.digest(canonical),
                      canonical_rebuildable_denominator=10,
                      eligible_pairs=sorted({label['pair_id'] for label in labels}),
                      excluded_from_canonical_denominator=[])
        self.denominator.write_text(json.dumps(frozen))
        with patch('http.client.HTTPConnection',side_effect=AssertionError('network')),patch(
                'urllib.request.urlopen',side_effect=AssertionError('network')):
            with self.assertRaises(ValueError):
                self.formal.prepare_twins()
            legacy=self.root/'forged-legacy-raw.json'
            legacy.write_text(json.dumps({'schema':protocol.SCHEMA,'rows':[],
                'frozen_denominator_sha256':protocol.digest(frozen)}))
            report=transport._load('report_v1.py')
            with self.assertRaises(ValueError):
                report.read_report(legacy,self.denominator)
            selected,_=protocol.select_scope(payloads,labels,protocol.fixed_subset())
            prepared={'frozen_denominator_sha256':protocol.digest(frozen),
                      'scope_manifest':protocol.fixed_subset(),
                      'rows':[{'id':item['id'],'source_sha256':item['source_sha256']}
                              for item in selected]}
            with self.assertRaises(ValueError):
                report._twins_metrics({'rows':[]},prepared,self.denominator)

    def test_foreign_model_control_or_second_identity_fails_closed(self):
        prepared = self.formal.prepare_twins()
        plan = self.formal.budget_plan(prepared, self.models)
        wrong = {'effective_output_tokens': 1024, 'client_visible_requests_per_worker': 1,
                 'automatic_retries': 0, 'model_name': 'wrong-name',
                 'model_digest': 'a' * 64, 'evidence': 'unit-only'}
        with patch.object(self.formal.transport, '_validated_controls', return_value=wrong):
            result = transport.preflight_capabilities(prepared, plan, self.formal)
        self.assertFalse(result['ready'])
        self.assertEqual(set(result['blockers']), set(self.models))
        with self.assertRaises(ValueError):
            ledger.schedule(identity_view='identified')

    def test_default_ledger_path_matches_formal_writer_and_rejects_copy(self):
        plan = self.formal.budget_plan(self.formal.prepare_twins(), self.models)
        canonical = self.formal.transport.canonical_budget_path(plan)
        self.assertEqual(ledger._canonical_budget_path(plan), canonical)
        with self.assertRaisesRegex(ValueError, 'canonical budget path'):
            ledger.reconcile_debits(plan, ledger.schedule(), self.root / 'copied-budget', [])

    def test_aggregate_routes_formal_raw_to_existing_reader(self):
        prepared = self.formal.prepare_twins()
        plan = self.formal.budget_plan(prepared, self.models)
        raw = self.formal.initial_raw(prepared, plan)
        raw.update(status='incomplete', calls=0, budget_totals={'debits': 0, 'reserved_output_tokens': 0})
        path = self.root / 'formal-raw.json'
        path.write_text(json.dumps(raw))
        result = aggregate.aggregate(path, self.denominator)
        self.assertEqual(result['kind'], 'formal-v1-readonly-recomputed')
        self.assertEqual(result['requested']['batch_calls_ceiling'], 250)
        self.assertEqual(result['enforced']['durable_debits_recorded'], 0)
        self.assertIsNone(result['observed']['provider_attempts'])
        self.assertEqual(result['context_evidence_gap']['status'], 'not-measured')

    def test_aggregate_rejects_symlink_and_oversized_raw_before_formal_reader(self):
        source = self.root / 'source.json'
        source.write_text(json.dumps({'schema': 'formal-experiment-v1'}))
        linked = self.root / 'linked.json'
        linked.symlink_to(source)
        oversized = self.root / 'oversized.json'
        with oversized.open('wb') as handle:
            handle.truncate(16 * 1024 * 1024 + 1)
        with patch.object(transport, 'project_formal_report',
                          side_effect=AssertionError('formal reader must not run')) as reader:
            with self.assertRaisesRegex(ValueError, 'Cannot read ordinary file'):
                aggregate.aggregate(linked, self.denominator)
            with self.assertRaisesRegex(ValueError, 'Bounded regular file required'):
                aggregate.aggregate(oversized, self.denominator)
        reader.assert_not_called()

    def test_projection_keeps_unknown_usage_and_provider_attempts_unknown(self):
        raw = {'experiment': 'twins', 'status': 'incomplete', 'budget_plan': {'max_calls': 250,
               'max_output_tokens': 1024, 'max_total_output_tokens': 256000,
               'automatic_retries': 0, 'inflight': 1}, 'calls': 1,
               'rows': [{'cache':False,'retry_count':0,'attempts': [{'attempt_key': 'unit', 'debit': 1,
                          'reserved_output_tokens': 1024, 'worker_invocations': 1,
                          'client_request_entries': None,
                          'provider_requests_received': None,
                          'usage':{'input_tokens':None,'output_tokens':None}}]}]}
        path = self.root / 'projection.json'; path.write_text(json.dumps(raw))
        summary = {'input_tokens': None, 'output_tokens': None, 'known_input_tokens': 0,
                   'known_output_tokens': 0, 'unknown_input_attempts': 1,
                   'unknown_output_attempts': 1, 'usd': None, 'human_minutes': None,
                   'billing_verified': False}
        fake = SimpleNamespace(read_report=lambda *_: {'kind': 'formal-v1-readonly-recomputed',
            'raw_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'metrics': {},
            'usage_summary': summary, 'run_debits_recorded': 1,
            'run_reserved_output_tokens': 1024, 'batch_ledger_verified': False})
        projected = transport.project_formal_report(path, formal_report=fake)
        self.assertIsNone(projected['observed']['input_tokens'])
        self.assertIsNone(projected['observed']['provider_attempts'])
        self.assertEqual(projected['observed']['known_output_tokens'], 0)
        self.assertEqual(projected['observed']['client_request_entries_unknown'], 1)
        self.assertIsNone(projected['retry']['client_recorded_repeat_dispatches'])
        self.assertIsNone(projected['observed']['provider_requests_received'])

        raw['rows'][0]['attempts'][0]['client_request_entries'] = 1
        path.write_text(json.dumps(raw))
        known = transport.project_formal_report(path, formal_report=SimpleNamespace(
            read_report=lambda *_: dict(fake.read_report(), raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
        self.assertEqual(known['retry']['client_recorded_repeat_dispatches'], 0)

    def test_projection_rejects_forged_provider_receipt_and_symlink_raw(self):
        raw = {'experiment': 'twins', 'status': 'incomplete', 'budget_plan': {'max_calls': 250,
               'max_output_tokens': 1024, 'max_total_output_tokens': 256000,
               'automatic_retries': 0, 'inflight': 1}, 'calls': 1,
               'rows': [{'cache': False, 'retry_count': 0, 'attempts': [{
                   'attempt_key': 'unit', 'debit': 1, 'reserved_output_tokens': 1024,
                   'worker_invocations': 1, 'client_request_entries': 1,
                   'provider_requests_received': None,
                   'usage': {'input_tokens': None, 'output_tokens': None}}]}]}
        path = self.root / 'receipt.json'
        summary = {'input_tokens': None, 'output_tokens': None, 'known_input_tokens': 0,
                   'known_output_tokens': 0, 'unknown_input_attempts': 1,
                   'unknown_output_attempts': 1, 'usd': None, 'human_minutes': None,
                   'billing_verified': False}
        fake = SimpleNamespace(read_report=lambda *_: {'kind': 'formal-v1-readonly-recomputed',
            'raw_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'metrics': {},
            'usage_summary': summary, 'run_debits_recorded': 1,
            'run_reserved_output_tokens': 1024, 'batch_ledger_verified': False})
        for value in (0, 1):
            raw['rows'][0]['attempts'][0]['provider_requests_received'] = value
            path.write_text(json.dumps(raw))
            with self.subTest(value=value), self.assertRaises(ValueError):
                transport.project_formal_report(path, formal_report=fake)
        path.unlink()
        target = self.root / 'target.json'; target.write_text(json.dumps(raw))
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            transport.project_formal_report(path, formal_report=fake)

    def test_writer_rejects_path_swap_without_touching_symlink_target(self):
        path = self.root / 'checkpoint.json'
        victim = self.root / 'victim.json'; victim.write_text('original')
        writer = run.RawArtifactWriter(path)
        try:
            writer.write({'status': 'initializing'})
            path.unlink(); path.symlink_to(victim)
            with self.assertRaises(ValueError):
                writer.write({'status': 'complete'})
            self.assertEqual(victim.read_text(), 'original')
        finally:
            writer.close()

    def test_writer_rejects_symlinked_parent(self):
        actual = self.root / 'actual-parent'; actual.mkdir()
        alias = self.root / 'parent-alias'; alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError):
            run.RawArtifactWriter(alias / 'raw.json')
        self.assertFalse((actual / 'raw.json').exists())

    def test_batch_status_requires_every_raw_status_complete(self):
        planned = ledger.schedule()
        paths = []
        for arm in ('finder-only', 'samefamily', 'crossfamily'):
            for repeat in range(5):
                attempts = [{'attempt_key': slot['attempt_key']} for slot in planned['slots']
                            if slot['arm'] == arm and slot['repeat'] == repeat]
                raw = {'status': 'incomplete' if (arm, repeat) == ('finder-only', 0) else 'complete',
                       'prepared': {'arm': arm, 'repeat': repeat}, 'budget_plan': self.formal.budget_plan(
                           self.formal.prepare_twins('finder-only', 0), self.models),
                       'rows': [{'attempts': attempts}]}
                path = self.root / f'{arm}-{repeat}-status.json'
                path.write_text(json.dumps(raw)); paths.append(path)
        report = {'metrics': {'incomplete': 0}, 'observed': {'unknown_input_attempts': 0,
                  'unknown_output_attempts': 0, 'known_input_tokens': 0, 'known_output_tokens': 0}}
        def project(path, *_):
            raw = json.loads(Path(path).read_bytes())
            return dict(report, raw_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                        raw_status=raw['status'])
        audited = {'reconciled': True, 'recorded_debits': 250,
                   'recorded_dispatch_entries': 250, 'raw_attempts_bound': 250}
        with patch.object(transport, 'project_formal_report', side_effect=project), patch.object(
                ledger, 'reconcile_debits', return_value=audited):
            result = aggregate.aggregate_formal_batch(paths, self.denominator, self.root / 'unused-ledger')
        self.assertEqual(result['status'], 'incomplete')

        for path in paths:
            raw = json.loads(path.read_text())
            raw['status'] = 'complete'
            for attempt in raw['rows'][0]['attempts']:
                attempt.update(worker_invocations=1, client_request_entries=None)
            path.write_text(json.dumps(raw))
        with patch.object(transport, 'project_formal_report', side_effect=project), patch.object(
                ledger, 'reconcile_debits', return_value=audited):
            unknown = aggregate.aggregate_formal_batch(paths, self.denominator, self.root / 'unused-ledger')
        self.assertEqual(unknown['status'], 'incomplete')
        self.assertFalse(unknown['enforced']['all_client_entries_recorded'])

        for path in paths:
            raw = json.loads(path.read_text())
            for attempt in raw['rows'][0]['attempts']:
                attempt['client_request_entries'] = 1
            path.write_text(json.dumps(raw))
        audited['recorded_dispatch_entries'] = 249
        with patch.object(transport, 'project_formal_report', side_effect=project), patch.object(
                ledger, 'reconcile_debits', return_value=audited):
            missing_dispatch = aggregate.aggregate_formal_batch(paths, self.denominator, self.root / 'unused-ledger')
        self.assertEqual(missing_dispatch['status'], 'incomplete')
        self.assertFalse(missing_dispatch['enforced']['all_dispatch_entries_bound'])
        audited['recorded_dispatch_entries'] = 250
        with patch.object(transport, 'project_formal_report', side_effect=project), patch.object(
                ledger, 'reconcile_debits', return_value=audited):
            complete = aggregate.aggregate_formal_batch(paths, self.denominator, self.root / 'unused-ledger')
        self.assertEqual(complete['status'], 'complete')

    def test_projection_rejects_extra_worker_and_entry(self):
        raw = {'experiment': 'twins', 'budget_plan': {'max_calls': 250,
               'max_output_tokens': 1024, 'max_total_output_tokens': 256000,
               'automatic_retries': 0, 'inflight': 1}, 'calls': 1,
               'rows': [{'cache':False,'retry_count':0,'attempts': [{'attempt_key': 'unit', 'debit': 1,
                          'reserved_output_tokens': 1024, 'worker_invocations': 2,
                          'client_request_entries': 1,
                          'provider_requests_received': None,
                          'usage':{'input_tokens':None,'output_tokens':None}}]}]}
        path = self.root / 'bad-projection.json'
        summary = {'input_tokens': None, 'output_tokens': None, 'known_input_tokens': 0,
                   'known_output_tokens': 0, 'unknown_input_attempts': 1,
                   'unknown_output_attempts': 1, 'usd': None, 'human_minutes': None,
                   'billing_verified': False}
        for invocation, entry in ((2, 1), (1, 2), (1, True)):
            raw['rows'][0]['attempts'][0].update(worker_invocations=invocation,
                                                  client_request_entries=entry)
            path.write_text(json.dumps(raw))
            fake = SimpleNamespace(read_report=lambda *_: {'kind': 'formal-v1-readonly-recomputed',
                'raw_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'metrics': {},
                'usage_summary': summary, 'run_debits_recorded': 1,
                'run_reserved_output_tokens': 1024, 'batch_ledger_verified': False})
            with self.subTest(invocation=invocation, entry=entry), self.assertRaises(ValueError):
                transport.project_formal_report(path, formal_report=fake)

    def test_projection_rejects_over_cap_usage_and_forged_retry(self):
        raw = {'experiment': 'twins', 'budget_plan': {'max_calls': 250,
               'max_output_tokens': 1024, 'max_total_output_tokens': 256000,
               'automatic_retries': 0, 'inflight': 1}, 'calls': 1,
               'rows': [{'cache': False, 'retry_count': 0, 'attempts': [{
                   'attempt_key': 'unit', 'debit': 1, 'reserved_output_tokens': 1024,
                   'worker_invocations': 1, 'client_request_entries': 1,
                   'provider_requests_received': None,
                   'usage': {'input_tokens': 2, 'output_tokens': 4}}]}]}
        path = self.root / 'usage.json'
        for mutation in ('over-cap', 'boolean', 'retry'):
            bad = copy.deepcopy(raw)
            if mutation == 'over-cap': bad['rows'][0]['attempts'][0]['usage']['output_tokens'] = 1025
            elif mutation == 'boolean': bad['rows'][0]['attempts'][0]['usage']['output_tokens'] = True
            else: bad['rows'][0]['retry_count'] = 1
            path.write_text(json.dumps(bad))
            summary = {'input_tokens': 2, 'output_tokens': 4, 'known_input_tokens': 2,
                       'known_output_tokens': 4, 'unknown_input_attempts': 0,
                       'unknown_output_attempts': 0, 'usd': None, 'human_minutes': None,
                       'billing_verified': False}
            fake = SimpleNamespace(read_report=lambda *_: {'kind': 'formal-v1-readonly-recomputed',
                'raw_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'metrics': {},
                'usage_summary': summary, 'run_debits_recorded': 1,
                'run_reserved_output_tokens': 1024, 'batch_ledger_verified': False})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                transport.project_formal_report(path, formal_report=fake)

    def test_batch_reader_reconciles_one_empty_shared_ledger_without_claiming_effect(self):
        paths=[]; plan=None
        for arm in ('finder-only', 'samefamily', 'crossfamily'):
            for repeat in range(5):
                prepared=self.formal.prepare_twins(arm,repeat)
                current=self.formal.budget_plan(prepared,self.models)
                if plan is None: plan=current
                self.assertEqual(current,plan)
                raw=self.formal.initial_raw(prepared,plan)
                raw.update(status='incomplete', calls=0,
                           budget_totals={'debits':0,'reserved_output_tokens':0})
                path=self.root/f'{arm}-{repeat}.json'
                path.write_text(json.dumps(raw)); paths.append(path)
        ledger_path=self.root/'ledger'
        (ledger_path/'debits').mkdir(parents=True)
        (ledger_path/'batch.json').write_text(json.dumps(plan))
        with patch.object(ledger, '_canonical_budget_path', return_value=ledger_path):
            result=aggregate.aggregate_formal_batch(paths,self.denominator,ledger_path)
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(result['requested']['calls'],250)
        self.assertEqual(result['enforced']['ledger']['recorded_debits'],0)
        self.assertIsNone(result['observed']['provider_attempts'])
        self.assertIsNone(result['observed']['output_tokens'])
        with patch.object(ledger, '_canonical_budget_path', return_value=ledger_path), self.assertRaises(ValueError):
            aggregate.aggregate_formal_batch(paths[:-1]+[paths[0]],self.denominator,ledger_path)


if __name__ == '__main__': unittest.main()
