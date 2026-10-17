"""Historical twins only; no recall/OWASP/ranking reader ownership."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_transport_v1 import load, synthetic_baseline, roster, plan

r = load('run_v1')
report = load('report_v1')


class ReportTests(unittest.TestCase):
    def test_raw_usage_or_debit_tamper_rejected_against_immutable_attempt_projection(self):
        import test_report_integrity as integrity
        with tempfile.TemporaryDirectory() as directory:
            fixture = integrity.ReportDerivedIntegrityTests()
            fixture.root = Path(directory).resolve()
            with patch.object(integrity, 'r', report.runner):
                raw = fixture.fixture()
            path = fixture.root / 'raw.json'; path.write_text(json.dumps(raw))
            report.read_report(path)
            for key, value in [('usage', {'input_tokens': 5, 'output_tokens': 99}), ('debit', 99),
                               ('debit', True), ('usage', {'input_tokens': 5, 'output_tokens': 7.0})]:
                bad = copy.deepcopy(raw); bad['rows'][0]['attempts'][0][key] = value
                path.write_text(json.dumps(bad))
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'projection'):
                    report.read_report(path)

    def setUp(self):
        for module in (r, report.runner):
            baseline = synthetic_baseline(module); value = baseline.__enter__()
            self.addCleanup(baseline.__exit__, None, None, None)
            canonical = patch.object(module.protocol, 'ARTIFACTS', value['artifacts'].resolve())
            canonical.start(); self.addCleanup(canonical.stop)
            if module is report.runner: self.baseline = value
        for target in ('http.client.HTTPConnection', 'urllib.request.urlopen', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('Read-only report tests must not dispatch'))
            guard.start(); self.addCleanup(guard.stop)

    def test_legacy_recompute_preserves_old_bytes_and_unknown_controls(self):
        legacy = self.baseline['legacy'].resolve()
        before = legacy.read_bytes()
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('Raw reader must use bounded reads')):
            result = report.read_report(legacy)
        self.assertEqual(result['kind'], 'legacy-synthetic-twins-readonly')
        self.assertEqual(legacy.read_bytes(), before)
        self.assertIsNone(result['provider_controls_verified'])
        self.assertIsNone(result['metrics']['usd'])

    def test_formal_rows_raw_binding_and_metrics_are_recomputed(self):
        prepared = r.prepare_twins()
        raw = r.initial_raw(prepared, r.budget_plan(prepared, roster()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'raw.json'; path.write_text(json.dumps(raw))
            value = report.read_report(path)
            self.assertEqual(value['metrics']['incomplete'], 10)
            self.assertIsNone(value['metrics']['wall_p50_seconds'])
            bad = copy.deepcopy(raw); bad['rows'].append(copy.deepcopy(bad['rows'][0])); path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): report.read_report(path)

    def test_usage_reservation_usd_and_resource_scopes_never_conflate(self):
        usage = report.transport.summarize_usage([{'input_tokens': 5, 'output_tokens': 7}, {'input_tokens': None, 'output_tokens': None}])
        self.assertEqual(usage['known_output_tokens'], 7); self.assertIsNone(usage['output_tokens'])
        self.assertIsNone(usage['usd']); self.assertIsNone(usage['human_minutes'])
        self.assertEqual(usage['unknown_output_attempts'], 1)


    def test_new_attachments_on_legacy_are_explicitly_rejected(self):
        legacy = self.baseline['legacy'].resolve()
        for options in ({'include_worksheet': True}, {'review_overlay_path': legacy}, {'cost_attachment_path': legacy}):
            with self.subTest(options=options), self.assertRaises(ValueError): report.read_report(legacy, **options)


if __name__ == '__main__': unittest.main()
