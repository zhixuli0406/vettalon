"""Only self-authored payloads and the actual HTTP path with fake connections."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_transport_v1 import load, plan, Connection, Response, controls, fake_worker, synthetic_baseline, roster, fixture_controls

r = load('run_v1')
t = r.transport


class RunTests(unittest.TestCase):
    def test_fixed_roster_three_arms_share_fifty_fake_requests_and_one_budget(self):
        class RosterConnection(Connection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.selected_model = json.loads(body)['model']
            def getresponse(self):
                value = json.loads(Response.body); value['model'] = self.selected_model
                return type('BoundResponse', (Response,), {'body': json.dumps(value).encode()})()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); plans = []; outputs = []
            with patch.object(t, 'BUDGET_ROOT', root / 'budgets'), patch.object(t, 'RUN_ROOT', root / 'runs'), \
                 patch.object(t, '_validated_controls', side_effect=fixture_controls), \
                 patch.object(t, '_invoke_worker', side_effect=lambda *args: fake_worker(*args, module=t)), \
                 patch.object(t.http.client, 'HTTPConnection', RosterConnection):
                for arm in ('finder-only', 'samefamily', 'crossfamily'):
                    prepared = r.prepare_twins(arm=arm); p = r.budget_plan(prepared, roster()); plans.append(p)
                    outputs.append(r.execute(prepared, p, arm))
            self.assertEqual(plans[0], plans[1]); self.assertEqual(plans[1], plans[2])
            batch = root / 'budgets' / 'd01-anonymous-fixed-five-pair-v1'
            self.assertEqual(len(list((batch / 'debits').glob('*.started.json'))), 50)
            self.assertEqual(outputs[-1]['budget_totals'], {'debits': 50, 'reserved_output_tokens': 51200})
            self.assertEqual(len([call for call in Connection.calls if call[0] == 'request']), 50)

    def test_source_postcheck_read_error_halts_but_retains_partial_raw(self):
        prepared = r.prepare_twins(); p = plan()
        p.update(source_bindings=prepared['source_bindings'], scope_sha256=prepared['scope_sha256'],
                 task_sha256=t.digest(prepared['task']))
        original_read = Path.read_bytes; fail = [False]
        target = r.HERE / 'run_v1.py'
        def read(path):
            if fail[0] and path == target: raise OSError('controlled missing source')
            return original_read(path)
        def dispatch(*args):
            value = fake_worker(*args, module=t); fail[0] = True; return value
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(t, 'BUDGET_ROOT', root / 'budgets'), patch.object(t, 'RUN_ROOT', root / 'runs'), \
                 patch.object(t, '_validated_controls', side_effect=fixture_controls), patch.object(t, '_invoke_worker', dispatch), \
                 patch.object(t.http.client, 'HTTPConnection', Connection), patch.object(Path, 'read_bytes', read), \
                 patch.object(r, 'budget_plan', return_value=p):
                raw = r.execute(prepared, p, 'postcheck')
            self.assertEqual(raw['status'], 'incomplete')
            self.assertFalse(raw['source_postcheck']['benchmarks/formal-transport/run_v1.py'])
            self.assertEqual(raw['source_postcheck_errors']['benchmarks/formal-transport/run_v1.py'], 'OSError')
            self.assertTrue((root / 'runs/postcheck/raw.json').is_file())
            self.assertTrue((root / 'budgets/d01-anonymous-fixed-five-pair-v1/halted.json').is_file())

    def execute_fake(self, prepared, directory):
        models = roster() if prepared['experiment'] == 'twins' else {'finder': roster()['finder']}
        p = r.budget_plan(prepared, models,
                          input_token_cap=None if prepared['experiment'] == 'twins' else 4096)
        with patch.object(t, 'BUDGET_ROOT', directory / 'budgets'), patch.object(t, 'RUN_ROOT', directory / 'runs'), \
             patch.object(t, '_validated_controls', side_effect=fixture_controls), patch.object(t, '_count_input_tokens', return_value=10), \
             patch.object(t, '_invoke_worker', side_effect=lambda *args: fake_worker(*args, module=t)), patch.object(t.http.client, 'HTTPConnection', Connection):
            return r.execute(prepared, p, 'offline')

    def setUp(self):
        Connection.calls = []; Connection.error = None; Connection.response = Response
        baseline = synthetic_baseline(r); self.baseline = baseline.__enter__()
        self.addCleanup(baseline.__exit__, None, None, None)
        for target in ('http.client.HTTPConnection', 'urllib.request.urlopen', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('No real provider, metadata or subprocess in unit tests'))
            guard.start(); self.addCleanup(guard.stop)

    def test_prepare_and_default_never_dispatch(self):
        with patch.object(t, '_invoke_worker', side_effect=AssertionError('no worker')), patch.object(t.http.client, 'HTTPConnection', side_effect=AssertionError('no network')):
            prepared = r.prepare_twins()
            self.assertEqual(len(prepared['rows']), 10)
            self.assertEqual(prepared['identity_view'], 'anonymous')
            p = r.budget_plan(prepared, roster())
            with self.assertRaises(t.CapabilityError): t.ensure_ready(p, 'x', 'finder')

    def test_twins_all_rows_frozen_and_finder_failure_keeps_denominator(self):
        prepared = r.prepare_twins(arm='samefamily')
        p = r.budget_plan(prepared, roster())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(t, 'BUDGET_ROOT', root / 'budgets'), patch.object(t, 'RUN_ROOT', root / 'runs'), \
                 patch.object(t, '_validated_controls', side_effect=fixture_controls), patch.object(t, '_invoke_worker', side_effect=TimeoutError('controlled')) as worker:
                raw = r.execute(prepared, p, 'failure')
            self.assertEqual(worker.call_count, 1); self.assertEqual(len(raw['rows']), 10)
            self.assertEqual(raw['rows'][0]['failed_stage'], 'finder')
            report = load('report_v1').read_report(root / 'runs' / 'failure' / 'raw.json',
                                                   (self.baseline['artifacts'] / 'denominator.json').resolve())
            self.assertEqual(report['metrics']['positive_denominator'], 5)
            self.assertEqual(report['metrics']['safe_denominator'], 5)
            self.assertEqual(report['metrics']['incomplete'], 10)

    def test_twins_arm_family_and_source_fingerprints_fail_closed(self):
        prepared = r.prepare_twins(arm='crossfamily')
        models = roster(); models['crossfamily_verifier']['family'] = 'qwen'
        with self.assertRaises(ValueError): r.budget_plan(prepared, models)
        bad = copy.deepcopy(prepared); bad['rows'][0]['source_sha256'] = '0' * 64
        with self.assertRaises(ValueError): r.validate_prepared(bad)
        models['crossfamily_verifier']['family'] = 'unknown'
        with self.assertRaises(ValueError): r.budget_plan(prepared, models)

    def test_verifier_parent_and_failed_stage_survive_rejection(self):
        prepared = r.prepare_twins(arm='samefamily')
        p = r.budget_plan(prepared, roster())
        seen = []
        def dispatch(ledger, key, prompt, role, out, timeout, parent_sha256=None):
            seen.append((key, prompt, parent_sha256))
            answer = {'vulnerability': True, 'category': 'object', 'line': 1, 'evidence': 'offline candidate'}
            return {'status': 'complete' if len(seen) == 1 else 'response-parse-failure', 'text': json.dumps(answer), 'usage': {'input_tokens': 1, 'output_tokens': 1}}
        with tempfile.TemporaryDirectory() as directory, patch.object(t, 'BUDGET_ROOT', Path(directory) / 'budgets'), patch.object(t, 'RUN_ROOT', Path(directory) / 'runs'), \
             patch.object(t, '_validated_controls', side_effect=fixture_controls), patch.object(t, 'dispatch_one', dispatch):
            raw = r.execute(prepared, p, 'lineage')
        self.assertEqual(len(seen), 2); self.assertIsNotNone(seen[1][2])
        self.assertIn('finder_candidate', raw['rows'][0]); self.assertEqual(raw['rows'][0]['failed_stage'], 'verifier')

    def test_finder_success_then_verifier_exception_retains_observation_not_final_metric(self):
        prepared = r.prepare_twins(arm='samefamily'); p = r.budget_plan(prepared, roster())
        label = next(x for x in r.protocol.generate()[1] if x['id'] == prepared['rows'][0]['id'])
        answer = {'vulnerability': True, 'category': label['family'], 'line': 1, 'evidence': 'unit candidate'}
        snapshots = {}
        def dispatch(ledger, key, prompt, role, directory, timeout, parent_sha256=None):
            if role != 'finder': raise OSError('self-authored verifier launch failure')
            value = {'attempt_key': key, 'status': 'complete', 'debit': 1, 'reserved_output_tokens': 1024,
                     'prompt': prompt, 'prompt_sha256': t.digest(prompt), 'parent_sha256': parent_sha256,
                     'model': p['models'][role]['name'], 'usage': {'input_tokens': 1, 'output_tokens': 1},
                     'text': json.dumps(answer)}
            directory.mkdir(parents=True, exist_ok=False)
            path = directory / 'attempt.json'; data = json.dumps(value).encode(); path.write_bytes(data)
            snapshots[str(path)] = data
            value['attempt_artifact'] = {'path': str(path), 'sha256': t.digest(data)}
            return value
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.object(t, 'BUDGET_ROOT', root / 'budgets'), patch.object(t, 'RUN_ROOT', root / 'runs'), \
                 patch.object(t, '_validated_controls', side_effect=fixture_controls), patch.object(t, 'dispatch_one', side_effect=dispatch):
                with self.assertRaises(OSError): r.execute(prepared, p, 'verifier-exception')
            raw_path = root / 'runs/verifier-exception/raw.json'; data = raw_path.read_bytes(); raw = json.loads(data)
            row = raw['rows'][0]
            self.assertEqual(row['status'], 'stage_incomplete')
            self.assertEqual(row['failed_stage'], 'verifier'); self.assertEqual(row['error'], 'OSError')
            self.assertTrue(row['surfaced']); self.assertEqual(raw['calls'], 1)
            review = load('review_v1'); review.validate_derived(data, snapshots, runner_context=r)
            labels = r.protocol.select_scope(*r.protocol.generate(), prepared['scope_manifest'])[1]
            self.assertEqual(r.protocol.metrics(labels, raw['rows'], [])['incomplete'], 10)

    def test_new_output_or_identity_never_resets_original_budget(self):
        prepared = r.prepare_twins(); models = roster()
        p = r.budget_plan(prepared, models)
        with tempfile.TemporaryDirectory() as directory, patch.object(t, 'BUDGET_ROOT', Path(directory)):
            self.assertEqual(t.canonical_budget_path(p), t.canonical_budget_path(copy.deepcopy(p)))
        identified = r.prepare_twins(identity='identified')
        self.assertEqual(identified['execution_status'], 'prepare-only-no-budget-for-second-identity')
        with self.assertRaises(ValueError): r.budget_plan(identified, models)

    def test_context_three_actual_payloads_reach_shared_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir()
            (source / 'entry.py').write_text('def process(x):\n    return open(x)\n')
            with patch.object(r, '_select_context', side_effect=lambda path, mode: r.selection.select(path, mode)):
                prepared = r.prepare_context(source)
            class ContextResponse(Response):
                body = json.dumps({'model': 'fixture-model', 'done': True, 'message': {'content': '{"findings":[]}'}, 'prompt_eval_count': 10, 'eval_count': 7}).encode()
            Connection.response = ContextResponse
            raw = self.execute_fake(prepared, root)
        self.assertEqual(len([x for x in Connection.calls if x[0] == 'request']), 3)
        self.assertEqual({x['id'] for x in raw['rows']}, {'baseline', 'functions', 'callchain'})
        self.assertTrue(all(x['status'] == 'complete' for x in raw['rows']))

    def test_context_mutation_unknown_inventory_and_path_failures_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'entry.py').write_text('def process(x):\n    return plugin(x)\n')
            def changing(path, mode):
                (root / 'entry.py').write_text('changed\n')
                return r.selection.select(path, mode)
            with patch.object(r, '_select_context', side_effect=changing): prepared = r.prepare_context(root)
            self.assertFalse(prepared['comparable'])
            with self.assertRaises(ValueError): r.budget_plan(prepared, {'finder': {'name': 'one', 'digest': 'a' * 64, 'family': 'qwen'}})
        self.assertIsNone(r.parse_context_answer('{"findings":[{"path":"../bad","line":1,"category":"path","evidence":"x"}]}', {'modules': []}))

    def test_rag_payloads_keep_split_and_citations_without_labels(self):
        prepared = r.prepare_rag()
        with tempfile.TemporaryDirectory() as directory:
            raw = self.execute_fake(prepared, Path(directory))
        self.assertEqual(len([x for x in Connection.calls if x[0] == 'request']), 24)
        self.assertFalse(raw['human_adjudicated_corpus']); self.assertFalse(raw['external_holdout'])
        for call in [x for x in Connection.calls if x[0] == 'request']:
            prompt = json.loads(call[3])['messages'][0]['content']
            self.assertNotIn('"family":', prompt); self.assertNotIn('"split":', prompt)

    def test_rag_query_or_reference_leak_and_tamper_refuse(self):
        prepared = r.prepare_rag()
        for mutation in ('label', 'reference'):
            bad = copy.deepcopy(prepared)
            if mutation == 'label': bad['rows'][0]['payload']['label'] = 'safe'
            else: bad['rows'][1]['payload']['references'][0]['source_sha256'] = '0' * 64
            bad['prepared_sha256'] = r.prepared_digest(bad)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): r.validate_prepared(bad)


if __name__ == '__main__': unittest.main()
