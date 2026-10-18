"""Offline contracts. Fake connections traverse the actual request builder."""
import base64
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


t = load('transport_v1')


def plan(experiment='twins', max_calls=250):
    return {'schema': 'formal-budget-v1', 'purpose': 'd01-anonymous-fixed-five-pair-v1' if experiment == 'twins' else experiment + '-unit-v1',
            'experiment': experiment, 'backend': 'local-ollama-http-v1',
            'models': {'finder': {'name': 'fixture-model', 'digest': 'a' * 64, 'family': 'qwen'}},
            'scope_sha256': 'b' * 64, 'task_sha256': 'c' * 64, 'source_bindings': {'fixture.py': 'd' * 64},
            'max_calls': max_calls, 'max_output_tokens': 1024, 'max_total_output_tokens': max_calls * 1024,
            'per_call_seconds': 90, 'per_run_seconds': 1200, 'input_token_cap': None if experiment == 'twins' else 4096,
            'inflight': 1, 'automatic_retries': 0}


class Response:
    status = 200
    body = json.dumps({'model': 'fixture-model', 'message': {'content': json.dumps(
        {'vulnerability': False, 'category': 'none', 'line': 0, 'evidence': 'offline response'})},
        'done': True, 'prompt_eval_count': 10, 'eval_count': 7}).encode()

    def read(self, limit):
        return self.body[:limit]


class Connection:
    calls = []
    response = Response
    error = None

    def __init__(self, host, port, timeout):
        self.calls.append(('connect', host, port, timeout))

    def request(self, method, path, body, headers):
        self.calls.append(('request', method, path, body, headers))
        if self.error:
            raise self.error

    def getresponse(self):
        self.calls.append(('getresponse',))
        return self.response()

    def close(self):
        self.calls.append(('close',))


def receipt(value):
    stdout = json.dumps(value)
    result = {'command': ['offline-contract-worker'], 'returncode': 0, 'seconds': 0.01,
              'error': None, 'control_schema': 1, 'control_complete': True,
              'timed_out': False, 'cleanup_error': None, 'stdout': stdout, 'stderr': '', 'captures': {}}
    for name, maximum in [('stdout', 4 * 1024 * 1024), ('stderr', 128 * 1024)]:
        raw = result[name].encode()
        result['captures'][name] = {'cap_bytes': maximum, 'observed_bytes': len(raw),
            'retained_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'truncated': False, 'decode_error': False}
    return result


def fake_worker(spec_path, directory, timeout, module=None):
    module = t if module is None else module
    packet = json.loads(spec_path.read_text())
    with patch.object(module, 'RUN_ROOT', directory.parent), patch.object(module, 'canonical_budget_path', return_value=Path(packet['ledger_path'])):
        return receipt(module.http_worker(spec_path))


def controls():
    return {'effective_output_tokens': 1024, 'client_visible_requests_per_worker': 1,
            'automatic_retries': 0, 'evidence': 'unit-fixture-only-not-production-readiness',
            'model_name': 'fixture-model', 'model_digest': 'a' * 64}


def roster():
    finder = {'name': 'fixture-model', 'digest': 'a' * 64, 'family': 'qwen'}
    return {'finder': dict(finder), 'samefamily_verifier': dict(finder),
            'crossfamily_verifier': {'name': 'fixture-cross', 'digest': 'b' * 64, 'family': 'llama'}}


def fixture_controls(backend, model_name='fixture-model'):
    known = {'fixture-model': 'a' * 64, 'fixture-cross': 'b' * 64}
    if model_name not in known: return None
    return dict(controls(), model_name=model_name, model_digest=known[model_name])


@contextmanager
def synthetic_baseline(runner):
    """Temporary unit bookkeeping only: zero containers, models or canonical proof."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); data = root / 'data'; artifacts = root / 'artifacts'
        (data / 'anonymous').mkdir(parents=True); artifacts.mkdir()
        payloads, labels = runner.protocol.generate()
        for payload in payloads:
            (data / 'anonymous' / (payload['id'] + '.json')).write_text(json.dumps(payload))
        (data / 'manifest.json').write_text(json.dumps({'schema': runner.protocol.SCHEMA,
            'cases': [{'id': p['id'], 'source_sha256': p['source_sha256']} for p in payloads], 'synthetic': True}))
        (data / 'fixed-five-pair-subset.json').write_text(json.dumps(runner.protocol.fixed_subset()))
        canonical_text = json.dumps({'kind': 'unit-bookkeeping-only', 'container_execution': False, 'canonical_success_claimed': False})
        (artifacts / 'canonical-oracle.json').write_text(canonical_text)
        frozen = {'schema': runner.protocol.SCHEMA, 'kind': 'unit-denominator-no-container-validation',
                  'manifest_sha256': runner.protocol.digest(labels), 'canonical_sha256': runner.protocol.digest(canonical_text),
                  'positive_denominator': len(labels)//2,
                  'canonical_rebuildable_denominator': 0, 'eligible_pairs': [],
                  'excluded_from_canonical_denominator': sorted({x['pair_id'] for x in labels})}
        (artifacts / 'denominator.json').write_text(json.dumps(frozen))
        legacy = {'schema': runner.protocol.SCHEMA, 'kind': 'self-authored-unit-legacy-schema-no-inference',
                  'frozen_denominator_sha256': runner.protocol.digest(frozen),
                  'rows': [{'id': p['id'], 'source_sha256': p['source_sha256'], 'status': 'missing', 'attempts': [],
                            'adjudication': 'U'} for p in payloads]}
        legacy_path = artifacts / 'legacy-unit.json'; legacy_path.write_text(json.dumps(legacy))
        with patch.object(runner, 'TWINS_DATA_ROOT', data), patch.object(runner.protocol, 'ARTIFACTS', artifacts):
            yield {'root': root, 'data': data, 'artifacts': artifacts, 'legacy': legacy_path}


class TransportTests(unittest.TestCase):
    def setUp(self):
        Connection.calls = []; Connection.error = None; Connection.response = Response
        for target in ('http.client.HTTPConnection', 'urllib.request.urlopen', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('No real provider, metadata or subprocess in unit tests'))
            guard.start(); self.addCleanup(guard.stop)

    def test_unknown_grok_controls_reject_before_debit_or_spawn(self):
        p = plan(); p['backend'] = 'grok-cli'
        with tempfile.TemporaryDirectory() as directory, patch.object(t, '_invoke_worker') as worker:
            with self.assertRaises(t.CapabilityError): t.ensure_ready(p, 'prompt', 'finder')
            self.assertEqual(list(Path(directory).iterdir()), []); worker.assert_not_called()

    def test_capability_boolean_or_http_ok_cannot_bless_formal(self):
        for extra in ({'enforced': True}, {'http_status': 200}, {'eval_count': 7}):
            p = plan(); p.update(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError): t.validate_plan(p)
        with self.assertRaises(t.CapabilityError): t.ensure_ready(plan(), 'prompt', 'finder')

    def test_model_readiness_evidence_rejects_wrong_name_and_digest_before_debit(self):
        for field, wrong in [('name', 'unverified-other-model'), ('digest', 'f' * 64)]:
            p = plan(); p['models'] = {'finder': dict(p['models']['finder'])}; p['models']['finder'][field] = wrong
            with self.subTest(field=field), patch.object(t, '_validated_controls', return_value=controls()), patch.object(t, '_invoke_worker', side_effect=AssertionError('Wrong model reached worker')) as worker:
                with tempfile.TemporaryDirectory() as directory:
                    ledger = t.Ledger(Path(directory) / 'ledger', p)
                    with self.assertRaises(t.CapabilityError):
                        t.dispatch_one(ledger, 'key', 'x', 'finder', Path(directory) / 'attempt', 1)
                    self.assertEqual(ledger.totals()['debits'], 0); worker.assert_not_called()

    def test_registered_real_request_builder_sends_exact_one_body(self):
        with patch.object(t.http.client, 'HTTPConnection', Connection):
            result = t.request_ollama_once({'model': 'fixture-model', 'prompt': 'data only',
                                          'timeout_seconds': 90, 'max_output_tokens': 1024})
        self.assertEqual(result['status'], 'complete')
        requests = [x for x in Connection.calls if x[0] == 'request']
        self.assertEqual(len(requests), 1); self.assertEqual(requests[0][1:3], ('POST', '/api/chat'))
        body = json.loads(requests[0][3]); self.assertFalse(body['stream'])
        self.assertEqual(body['options']['num_predict'], 1024)
        self.assertEqual(body['messages'], [{'role': 'user', 'content': 'data only'}])
        self.assertEqual(Connection.calls[0][1:3], ('127.0.0.1', 11434))
        self.assertEqual(result['client_request_entries'], 1)

    def test_http_errors_redirect_and_transport_exception_never_retry(self):
        for code in (301, 307, 429, 500):
            Connection.calls = []; Connection.response = type('Bad', (Response,), {'status': code})
            with self.subTest(code=code), patch.object(t.http.client, 'HTTPConnection', Connection):
                result = t.request_ollama_once({'model': 'fixture-model', 'prompt': 'x', 'timeout_seconds': 1, 'max_output_tokens': 1024})
                self.assertEqual(result['status'], 'http-error')
                self.assertEqual(len([x for x in Connection.calls if x[0] == 'request']), 1)
        for error in (ConnectionResetError(), TimeoutError()):
            Connection.calls = []; Connection.error = error
            with self.subTest(error=type(error).__name__), patch.object(t.http.client, 'HTTPConnection', Connection):
                result = t.request_ollama_once({'model': 'fixture-model', 'prompt': 'x', 'timeout_seconds': 1, 'max_output_tokens': 1024})
                self.assertEqual(result['status'], 'transport-error')
                self.assertEqual(len([x for x in Connection.calls if x[0] == 'request']), 1)

    def test_predebit_is_durable_before_worker_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ledger = t.Ledger(root / 'ledger', plan())
            def checking_worker(*args):
                records = list((root / 'ledger' / 'debits').glob('*.started.json'))
                self.assertEqual(len(records), 1)
                self.assertEqual(json.loads(records[0].read_text())['reserved_output_tokens'], 1024)
                return fake_worker(*args)
            with patch.object(t, '_validated_controls', return_value=controls()), patch.object(t, '_invoke_worker', checking_worker), patch.object(t.http.client, 'HTTPConnection', Connection):
                value = t.dispatch_one(ledger, 'finder-only|0|c-unit|finder', 'prompt', 'finder', root / 'attempt', 90)
            self.assertEqual(value['status'], 'complete'); self.assertEqual(ledger.totals()['reserved_output_tokens'], 1024)
            ledger.close()

    def test_fsync_or_exclusive_write_failure_prevents_dispatch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(t, '_invoke_worker') as worker:
            root = Path(directory)
            with patch.object(t, '_fsync_directory', side_effect=OSError('directory fsync failed')):
                with self.assertRaises(OSError): t.Ledger(root / 'ledger', plan())
            worker.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            ledger = t.Ledger(Path(directory) / 'ledger', plan())
            with patch.object(t.os, 'fsync', side_effect=OSError('file fsync failed')), patch.object(t, '_invoke_worker') as worker:
                with self.assertRaises(OSError): ledger.reserve('key', {'prompt_sha256': 'a' * 64})
                worker.assert_not_called()
            self.assertEqual(len(list((ledger.path / 'debits').glob('*.started.json'))), 1)
        with tempfile.TemporaryDirectory() as directory:
            ledger = t.Ledger(Path(directory) / 'ledger', plan())
            with patch.object(t, '_fsync_directory', side_effect=OSError('debit directory fsync failed')), patch.object(t, '_invoke_worker') as worker:
                with self.assertRaises(OSError): ledger.reserve('key', {})
                worker.assert_not_called()
            self.assertEqual(ledger.totals()['debits'], 1)

    def test_fixed_attempt_key_and_owner_reject_second_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger'; ledger = t.Ledger(path, plan())
            with self.assertRaises(FileExistsError): t.Ledger(path, plan())
            ledger.reserve('same-key', {'prompt_sha256': 'a' * 64})
            with self.assertRaises(ValueError): ledger.reserve('same-key', {'prompt_sha256': 'a' * 64})
            self.assertEqual(ledger.totals()['debits'], 1)

    def test_calls_and_token_reservations_enforce_global_existing_debits(self):
        with tempfile.TemporaryDirectory() as directory:
            p = plan(max_calls=2); ledger = t.Ledger(Path(directory) / 'ledger', p)
            ledger.reserve('one', {}); ledger.reserve('two', {})
            with self.assertRaises(t.BudgetError): ledger.reserve('three', {})
            self.assertEqual(ledger.totals(), {'debits': 2, 'reserved_output_tokens': 2048})
        with tempfile.TemporaryDirectory() as directory:
            p = plan(); p['max_total_output_tokens'] = 1023
            ledger = t.Ledger(Path(directory) / 'ledger', p)
            with self.assertRaises(t.BudgetError): ledger.reserve('none', {})

    def test_crash_timeout_cancel_parse_and_capture_failures_never_refund(self):
        for change in ('raise', 'control', 'cleanup', 'truncated', 'decode'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); ledger = t.Ledger(root / 'ledger', plan())
                value = receipt({'status': 'complete'})
                if change == 'control': value['control_complete'] = False
                if change == 'cleanup': value['cleanup_error'] = 'failure'
                if change == 'truncated': value['captures']['stdout']['truncated'] = True
                if change == 'decode': value['captures']['stdout']['decode_error'] = True
                def bad(*args):
                    if change == 'raise': raise TimeoutError('controlled')
                    return value
                with patch.object(t, '_validated_controls', return_value=controls()), patch.object(t, '_invoke_worker', bad):
                    result = t.dispatch_one(ledger, 'key', 'prompt', 'finder', root / 'attempt', 1)
                self.assertNotEqual(result['status'], 'complete')
                self.assertEqual(ledger.totals()['reserved_output_tokens'], 1024)
                with self.assertRaises(t.BudgetError): ledger.reserve('replacement', {})

    def test_limits_and_usage_reject_bool_nonfinite_and_negative(self):
        for field, value in [('max_calls', True), ('per_call_seconds', float('nan')), ('per_run_seconds', float('inf')), ('max_output_tokens', 1025), ('max_total_output_tokens', -1)]:
            p = plan(); p[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): t.validate_plan(p)
        for value in (True, -1, '7', float('nan')):
            with self.subTest(value=value), self.assertRaises(ValueError): t.normalize_usage({'eval_count': value})

    def test_observed_usage_missing_partial_and_overcap_are_distinct(self):
        summary = t.summarize_usage([{'output_tokens': 7, 'input_tokens': 10}, {'output_tokens': None, 'input_tokens': None}])
        self.assertEqual(summary['known_output_tokens'], 7); self.assertIsNone(summary['output_tokens'])
        self.assertEqual(summary['unknown_output_attempts'], 1)
        self.assertEqual(t.normalize_usage({'eval_count': 0})['output_tokens'], 0)
        with self.assertRaises(ValueError): t.normalize_usage({'eval_count': 1025})

    def test_worker_start_and_wire_observation_are_distinct_denominators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ledger = t.Ledger(root / 'ledger', plan())
            with patch.object(t, '_validated_controls', return_value=controls()), patch.object(t, '_invoke_worker', side_effect=OSError('start failed')):
                result = t.dispatch_one(ledger, 'key', 'x', 'finder', root / 'attempt', 1)
            self.assertEqual(result['debit'], 1); self.assertIsNone(result['client_request_entries'])
            self.assertIsNone(result['provider_requests_received']); self.assertIsNone(result['usage']['output_tokens'])

    def test_input_token_unknown_refuses_equal_token_formal_comparison(self):
        with patch.object(t, '_validated_controls', return_value=controls()):
            with self.assertRaises(t.CapabilityError): t.ensure_ready(plan('context', 3), 'same bytes', 'finder')
            with patch.object(t, '_count_input_tokens', return_value=5000):
                with self.assertRaises(t.BudgetError): t.ensure_ready(plan('context', 3), 'x', 'finder')

    def test_capture_worker_is_fixed_and_helper_pins_match(self):
        with self.assertRaises(ValueError): t.request_ollama_once({'model': 'fixture-model', 'prompt': 'x', 'timeout_seconds': 1, 'max_output_tokens': 1024, 'url': 'https://elsewhere'})
        with patch.object(t, 'RUNTIME_SHA256', '0' * 64), self.assertRaises(ValueError): t.load_runtime()

    def test_direct_worker_replay_and_request_binding_reject_before_http(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ledger = t.Ledger(root / 'ledger', plan())
            with patch.object(t, '_validated_controls', return_value=controls()), patch.object(t, '_invoke_worker', fake_worker), patch.object(t.http.client, 'HTTPConnection', Connection):
                result = t.dispatch_one(ledger, 'key', 'prompt', 'finder', root / 'attempt', 1)
                self.assertEqual(result['status'], 'complete')
                packet = root / 'attempt' / 'worker-dispatch.json'
                before = len([x for x in Connection.calls if x[0] == 'request'])
                with patch.object(t, 'RUN_ROOT', root), patch.object(t, 'canonical_budget_path', return_value=ledger.path):
                    with self.assertRaises(FileExistsError): t.http_worker(packet)
                    request = root / 'attempt' / 'request.json'
                    changed = json.loads(request.read_text()); changed['prompt'] = 'changed'
                    request.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError): t.http_worker(packet)
                self.assertEqual(len([x for x in Connection.calls if x[0] == 'request']), before)


if __name__ == '__main__': unittest.main()
