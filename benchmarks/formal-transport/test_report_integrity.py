"""Artifact-derived report regressions with self-authored local snapshots only."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_transport_v1 import load, roster, synthetic_baseline

report = load('report_v1')
r = report.runner


class ReportDerivedIntegrityTests(unittest.TestCase):
    def setUp(self):
        baseline = synthetic_baseline(r)
        value = baseline.__enter__()
        self.addCleanup(baseline.__exit__, None, None, None)
        canonical = patch.object(r.protocol, 'ARTIFACTS', value['artifacts'].resolve())
        canonical.start(); self.addCleanup(canonical.stop)
        for target in ('http.client.HTTPConnection', 'urllib.request.urlopen', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('Report integrity must not dispatch'))
            guard.start()
            self.addCleanup(guard.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.path = self.root / 'raw.json'

    def fixture(self, arm='finder-only'):
        prepared = r.prepare_twins(arm=arm)
        plan = r.budget_plan(prepared, roster())
        raw = r.initial_raw(prepared, plan)
        raw['status'] = 'incomplete'
        row = raw['rows'][0]
        label = next(x for x in r.protocol.generate()[1] if x['id'] == row['id'])
        parsed = {'vulnerability': True, 'category': label['family'], 'line': 1,
                  'evidence': 'self-authored positive claim, not human adjudication'}
        prompt = prepared['task'] + json.dumps(row['payload'])
        attempt = {'attempt_key': f"{arm}|0|{row['id']}|finder", 'status': 'complete',
                   'debit': 1, 'reserved_output_tokens': 1024,
                   'prompt': prompt, 'prompt_sha256': r.transport.digest(prompt),
                   'parent_sha256': None, 'model': plan['models']['finder']['name'],
                   'usage': {'input_tokens': 2, 'output_tokens': 3}, 'text': json.dumps(parsed)}
        artifact = self.root / 'finder/attempt.json'
        artifact.parent.mkdir()
        artifact.write_text(json.dumps(attempt))
        attempt['attempt_artifact'] = {'path': str(artifact), 'sha256': r.transport.digest(artifact.read_bytes())}
        attempt['parsed'] = copy.deepcopy(parsed)
        row.update(status='complete', finder_candidate=copy.deepcopy(parsed), surfaced=True,
                   detected=True, root_cause_correct=True, attempts=[attempt])
        return raw

    def write_raw(self, raw):
        self.path.write_text(json.dumps(raw, sort_keys=True))

    def test_valid_sorted_json_artifact_snapshot_remains_readable(self):
        raw = self.fixture()
        self.write_raw(raw)
        before = self.path.read_bytes()
        result = report.read_report(self.path)
        self.assertEqual(result['kind'], 'formal-v1-readonly-recomputed')
        self.assertEqual(result['metrics']['incomplete'], 9)
        self.assertEqual(self.path.read_bytes(), before)

    def test_default_report_rejects_mutable_parsed_evidence(self):
        raw = self.fixture()
        raw['rows'][0]['attempts'][0]['parsed']['evidence'] = 'tampered mutable evidence'
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)

    def test_default_report_rejects_mutable_finder_candidate(self):
        raw = self.fixture()
        raw['rows'][0]['finder_candidate']['evidence'] = 'tampered finder statement'
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)

    def test_default_report_rejects_mutable_surface(self):
        raw = self.fixture()
        raw['rows'][0]['surfaced'] = False
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)

    def test_default_report_rejects_mutable_detection(self):
        raw = self.fixture()
        raw['rows'][0]['detected'] = False
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)

    def test_default_report_rejects_mutable_root_cause(self):
        raw = self.fixture()
        raw['rows'][0]['root_cause_correct'] = False
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)


    def test_formal_raw_cannot_promote_human_or_differential_outcomes(self):
        for key, value in (('adjudication', 'TP'), ('adjudication', 'FP'),
                           ('detection_adjudication', 'TP'), ('differential_oracle', True),
                           ('differential_oracle', 0), ('differential_status', 'complete'),
                           ('differential_status', 'incomplete')):
            raw = self.fixture()
            raw['rows'][0][key] = value
            self.write_raw(raw)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): report.read_report(self.path)
            # Each fixture owns the same local name; remove only its self-authored artifact.
            (self.root / 'finder/attempt.json').unlink()
            (self.root / 'finder').rmdir()

    def test_missing_required_verifier_is_not_a_complete_final_row(self):
        raw = self.fixture(arm='samefamily')
        row = raw['rows'][0]
        row['failed_stage'] = 'verifier'
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)
        row.update(status='stage_incomplete', error='OSError')
        self.write_raw(raw)
        value = report.read_report(self.path)
        self.assertEqual(value['metrics']['incomplete'], 10)
        self.assertEqual(row['surfaced'], True)

    def test_fresh_worksheet_overlay_records_review_without_changing_metrics_or_raw(self):
        raw = self.fixture()
        self.write_raw(raw)
        before = self.path.read_bytes()
        baseline = report.read_report(self.path)
        result = report.read_report(self.path, include_worksheet=True)
        worksheet = result['review_worksheet']
        row = worksheet['rows'][0]; stage = row['stages'][0]
        overlay = {'schema': 'formal-stage-review-overlay-v1', 'raw_sha256': worksheet['raw_sha256'],
                   'worksheet_sha256': worksheet['worksheet_sha256'], 'reviewer': 'unit-reviewer',
                   'decisions': [{'id': row['id'], 'fingerprint': row['fingerprint'], 'stage': 'finder',
                    'attempt_sha256': stage['attempt_sha256'], 'parent_parsed_sha256': None,
                    'adjudication': 'TP', 'classification': 'candidate-survives', 'reason': 'unit statement only'}]}
        path = self.root / 'overlay.json'; path.write_text(json.dumps(overlay))
        reviewed = report.read_report(self.path, review_overlay_path=path)
        self.assertEqual(reviewed['review_worksheet']['rows'][0]['stages'][0]['adjudication'], 'TP')
        self.assertEqual(reviewed['review_overlay_sha256'], r.transport.digest(path.read_bytes()))
        self.assertEqual(reviewed['metrics'], baseline['metrics'])
        self.assertEqual(self.path.read_bytes(), before)

    def test_cost_attachment_uses_validated_roster_and_observed_usage_only(self):
        raw = self.fixture(); self.write_raw(raw)
        baseline = report.read_report(self.path)
        attempt = raw['rows'][0]['attempts'][0]; model = raw['budget_plan']['models']['finder']
        attachment = {'schema': 'cost-attachment-v1', 'raw_sha256': r.transport.digest(self.path.read_bytes()),
          'prices': [{'price_id': 'unit-price', 'model': model, 'price_version': 'unit-v1',
                     'source_ref': 'unit:declared-only', 'provided_by': 'unit-operator',
                     'input_usd_per_million': '1', 'output_usd_per_million': '2'}],
          'entries': [{'attempt_key': attempt['attempt_key'], 'model': model,
                      'attempt_artifact_sha256': attempt['attempt_artifact']['sha256'],
                      'price_id': 'unit-price', 'price_version': 'unit-v1', 'human_minutes': '3',
                      'human_source_ref': 'unit:time', 'human_version': 'unit-v1', 'human_provided_by': 'unit-operator'}]}
        path = self.root / 'cost.json'; path.write_text(json.dumps(attachment))
        result = report.read_report(self.path, cost_attachment_path=path)
        self.assertEqual(result['cost_summary']['usd'], '0.000008')
        self.assertEqual(result['cost_summary']['human_minutes'], '3')
        self.assertFalse(result['cost_summary']['billing_verified'])
        self.assertEqual(result['metrics'], baseline['metrics'])
        attachment['entries'][0]['model'] = dict(model, digest='0' * 64)
        path.write_text(json.dumps(attachment))
        with self.assertRaises(ValueError): report.read_report(self.path, cost_attachment_path=path)

    def test_artifact_symlink_fifo_and_symlink_ancestor_rejected_before_opening_content(self):
        import os
        raw = self.fixture(); attempt = raw['rows'][0]['attempts'][0]
        artifact = self.root / 'finder/attempt.json'; data = artifact.read_bytes()
        saved = self.root / 'saved.json'; saved.write_bytes(data)
        artifact.unlink(); artifact.symlink_to(saved)
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)
        artifact.unlink(); os.mkfifo(artifact)
        with self.assertRaises(ValueError): report.read_report(self.path)
        artifact.unlink(); artifact.write_bytes(data)
        alias = self.root / 'alias'; alias.symlink_to(self.root / 'finder', target_is_directory=True)
        attempt['attempt_artifact']['path'] = str(alias / 'attempt.json'); self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)

    def test_attachment_strict_json_caps_and_source_refs_are_not_opened(self):
        raw = self.fixture(); self.write_raw(raw)
        path = self.root / 'cost.json'
        for data in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'\xff', b' ' * (2 * 1024 * 1024 + 1)):
            path.write_bytes(data)
            with self.subTest(prefix=data[:20]), self.assertRaises(ValueError):
                report.read_report(self.path, cost_attachment_path=path)

    def test_attachment_and_artifact_postcheck_rejects_changed_snapshot(self):
        raw = self.fixture(); self.write_raw(raw)
        original = report._read_regular
        seen = {}
        def changing(path, cap):
            data = original(path, cap)
            key = str(path); seen[key] = seen.get(key, 0) + 1
            if str(path).endswith('attempt.json') and seen[key] > 1: return data + b' '
            return data
        with patch.object(report, '_read_regular', side_effect=changing):
            with self.assertRaises(ValueError): report.read_report(self.path)

    def test_artifact_total_cap_and_outside_run_are_rejected(self):
        raw = self.fixture(); self.write_raw(raw)
        with patch.object(report, 'ARTIFACT_TOTAL_CAP', 1):
            with self.assertRaises(ValueError): report.read_report(self.path)
        raw['rows'][0]['attempts'][0]['attempt_artifact']['path'] = str(self.root.parent / 'outside/attempt.json')
        self.write_raw(raw)
        with self.assertRaises(ValueError): report.read_report(self.path)


if __name__ == '__main__':
    unittest.main()
