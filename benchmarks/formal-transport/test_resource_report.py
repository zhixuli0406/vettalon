"""Self-authored read-only resource snapshots; no process or provider dispatch."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_transport_v1 import load, roster, synthetic_baseline

report = load('report_v1')
r = report.runner
KINDS = ('twins', 'context', 'rag')
IMPLEMENTATION = {'runner_sha256': 'a' * 64, 'protocol_sha256': 'b' * 64,
                  'measurement_sha256': 'c' * 64}


def resource_fixture():
    """Declared fixture values, never observations of the test process."""
    return {'schema': 'runner-resource-v1', 'implementation': dict(IMPLEMENTATION),
            'scope': 'runner-process-only', 'pid': 123, 'platform': 'linux',
            'api': 'resource.getrusage(RUSAGE_SELF)',
            'cpu': {'status': 'measured', 'user_seconds': 0.5,
                    'system_seconds': 0.25, 'total_seconds': 0.75, 'reason': None},
            'rss_lifetime_observation': {'status': 'observed', 'start_bytes': 4096,
                    'end_bytes': 8192, 'native_unit': 'KiB', 'reason': None},
            'rss_scope': 'runner-process-lifetime-high-water-mark',
            'excluded': ['model-server-process', 'child-processes', 'gpu',
                         'electricity', 'usd', 'human-review']}


class ResourceReportTests(unittest.TestCase):
    def setUp(self):
        for target in ('http.client.HTTPConnection', 'urllib.request.urlopen', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('Resource reports must never dispatch'))
            guard.start(); self.addCleanup(guard.stop)
        baseline = synthetic_baseline(r)
        self.baseline = baseline.__enter__()
        self.addCleanup(baseline.__exit__, None, None, None)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.path = self.root / 'raw.json'
        self.prepared = {'twins': r.prepare_twins(), 'rag': r.prepare_rag()}
        source = self.root / 'source'; source.mkdir()
        (source / 'entry.py').write_text('def identity(value):\n    return value\n')
        with patch.object(r, '_select_context', side_effect=lambda path, mode: r.selection.select(path, mode)):
            self.prepared['context'] = r.prepare_context(source)

    def raw(self, kind):
        prepared = self.prepared[kind]
        models = roster() if kind == 'twins' else {'finder': roster()['finder']}
        plan = r.budget_plan(prepared, models, input_token_cap=None if kind == 'twins' else 4096)
        return r.initial_raw(prepared, plan)

    def read(self, raw):
        self.path.write_text(json.dumps(raw, sort_keys=True))
        before = self.path.read_bytes()
        value = report.read_report(self.path)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(value['raw_sha256'], r.transport.digest(before))
        return value

    def test_each_reader_exposes_recorded_resources_and_wall_without_expanding_scope(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                raw = self.raw(kind)
                raw.update(resource_evidence=resource_fixture(), implementation=dict(IMPLEMENTATION), wall_seconds=2.5)
                result = self.read(raw)
                resources = result['resource_summary']
                self.assertEqual(resources['cpu_seconds'], 0.75)
                self.assertEqual(resources['wall_seconds'], 2.5)
                self.assertIsNone(resources['peak_memory_bytes'])
                observation = resources['resource_measurement']
                self.assertEqual(observation['scope'], 'runner-process-only')
                self.assertEqual(observation['rss_scope'], 'runner-process-lifetime-high-water-mark')
                self.assertEqual(observation['rss_lifetime_observation']['end_bytes'], 8192)
                self.assertEqual(observation['excluded'], resource_fixture()['excluded'])
                self.assertIsNone(result['provider_controls_verified'])
                self.assertIsNone(result['usage_summary']['usd'])
                self.assertIsNone(result['usage_summary']['human_minutes'])
                if kind in ('context', 'rag'):
                    self.assertIsNone(result['metrics'])
                    self.assertEqual(result['effectiveness'], 'unknown pending accepted ground truth/adjudication')

    def test_missing_and_explicit_null_observations_stay_unknown_for_every_reader(self):
        for kind in KINDS:
            for explicit_null in (False, True):
                with self.subTest(kind=kind, explicit_null=explicit_null):
                    raw = self.raw(kind)
                    if explicit_null:
                        raw.update(resource_evidence=None, implementation=None, wall_seconds=None)
                    resources = self.read(raw)['resource_summary']
                    self.assertIsNone(resources['cpu_seconds'])
                    self.assertIsNone(resources['peak_memory_bytes'])
                    self.assertIsNone(resources['wall_seconds'])
                    self.assertEqual(resources['resource_measurement']['status'], 'not-measured')

    def test_unavailable_cpu_and_rss_remain_unavailable_without_current_sampling(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                evidence = resource_fixture()
                evidence['cpu'] = {'status': 'unavailable', 'user_seconds': None,
                    'system_seconds': None, 'total_seconds': None, 'reason': 'fixture platform unavailable'}
                evidence['rss_lifetime_observation'] = {'status': 'unavailable', 'start_bytes': None,
                    'end_bytes': None, 'native_unit': None, 'reason': 'fixture unavailable'}
                raw = self.raw(kind)
                raw.update(resource_evidence=evidence, implementation=dict(IMPLEMENTATION), wall_seconds=0)
                with patch.object(r.measurement, '_usage', side_effect=AssertionError('No fresh sampling')):
                    resources = self.read(raw)['resource_summary']
                self.assertIsNone(resources['cpu_seconds'])
                self.assertIsNone(resources['peak_memory_bytes'])
                self.assertEqual(resources['wall_seconds'], 0)
                self.assertEqual(resources['resource_measurement']['status'], 'unavailable')

    def test_malformed_or_wrongly_bound_resource_observations_are_rejected_for_all_readers(self):
        for kind in KINDS:
            for mutation in ('schema', 'scope', 'implementation', 'cpu-total', 'rss-order', 'cpu-shape'):
                with self.subTest(kind=kind, mutation=mutation):
                    evidence = resource_fixture()
                    if mutation == 'schema': evidence['schema'] = 'untrusted-schema'
                    elif mutation == 'scope': evidence['scope'] = 'model-server-process'
                    elif mutation == 'implementation': evidence['implementation']['runner_sha256'] = 'd' * 64
                    elif mutation == 'cpu-total': evidence['cpu']['total_seconds'] = 99
                    elif mutation == 'rss-order': evidence['rss_lifetime_observation']['end_bytes'] = 1
                    else: evidence['cpu'] = []
                    raw = self.raw(kind)
                    raw.update(resource_evidence=evidence, implementation=dict(IMPLEMENTATION))
                    with self.assertRaises(ValueError): self.read(raw)

    def test_invalid_wall_observations_are_rejected_including_bool_and_nonfinite(self):
        for kind in KINDS:
            for wall in (True, False, -1, -0.5, '2.5', [], {}, float('nan'), float('inf'), -float('inf')):
                with self.subTest(kind=kind, wall=wall):
                    raw = self.raw(kind); raw['wall_seconds'] = wall
                    with self.assertRaises(ValueError): self.read(raw)

    def test_resource_reporting_preserves_existing_effectiveness_metrics_cost_and_accounting(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                raw = self.raw(kind)
                original = copy.deepcopy(raw)
                baseline = self.read(raw)
                raw.update(resource_evidence=resource_fixture(), implementation=dict(IMPLEMENTATION), wall_seconds=3)
                observed = self.read(raw)
                self.assertEqual(raw['rows'], original['rows'])
                self.assertEqual(observed['usage_summary'], baseline['usage_summary'])
                for key in ('run_debits_recorded', 'run_reserved_output_tokens', 'batch_totals_recorded',
                            'batch_ledger_verified', 'provider_controls_verified', 'effectiveness'):
                    if key in baseline: self.assertEqual(observed[key], baseline[key])
                for result in (baseline, observed):
                    self.assertEqual(result['cost_summary']['raw_sha256'], result['raw_sha256'])
                self.assertEqual({key: value for key, value in observed['cost_summary'].items() if key != 'raw_sha256'},
                                 {key: value for key, value in baseline['cost_summary'].items() if key != 'raw_sha256'})
                if kind == 'twins':
                    unaffected = {key: value for key, value in observed['metrics'].items()
                                  if key not in ('cpu_seconds', 'peak_memory_bytes', 'resource_measurement')}
                    expected = {key: value for key, value in baseline['metrics'].items()
                                if key not in ('cpu_seconds', 'peak_memory_bytes', 'resource_measurement')}
                    self.assertEqual(unaffected, expected)

    def test_legacy_reader_keeps_its_existing_output_contract(self):
        raw = json.loads(self.baseline['legacy'].read_text())
        result = self.read(raw)
        self.assertNotIn('resource_summary', result)
        self.assertEqual(result['kind'], 'legacy-synthetic-twins-readonly')
        self.assertIsNone(result['metrics']['cpu_seconds'])
        self.assertIsNone(result['metrics']['peak_memory_bytes'])
        # Every metrics rate is also reported with an interval and its n.
        rates = result['uncertainty']['rates']
        self.assertFalse(result['uncertainty']['normal_approximation_used'])
        self.assertEqual(rates['detection_recall']['n'], result['metrics']['positive_denominator'])
        self.assertEqual(rates['detection_recall']['point_bounds'], result['metrics']['detection_recall_bounds'])


if __name__ == '__main__': unittest.main()
