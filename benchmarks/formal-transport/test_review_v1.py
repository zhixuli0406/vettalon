"""Self-authored stage snapshots only; no provider, process or target execution."""
import copy
import json
import unittest
from unittest.mock import patch

from test_transport_v1 import load, roster, synthetic_baseline

review = load('review_v1')
r = review.runner


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')


class StageReviewTests(unittest.TestCase):
    def setUp(self):
        baseline = synthetic_baseline(r)
        baseline.__enter__()
        self.addCleanup(baseline.__exit__, None, None, None)
        for target in ('http.client.HTTPConnection', 'urllib.request.urlopen', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('Stage review must never dispatch'))
            guard.start()
            self.addCleanup(guard.stop)

    def snapshot(self, arm='samefamily', verifier=True):
        prepared = r.prepare_twins(arm=arm)
        plan = r.budget_plan(prepared, roster())
        raw = r.initial_raw(prepared, plan)
        raw['status'] = 'incomplete'
        row = raw['rows'][0]
        labels = {x['id']: x for x in r.protocol.generate()[1]}
        family = labels[row['id']]['family']
        finder = {'vulnerability': True, 'category': family, 'line': 1,
                  'evidence': 'self-authored candidate statement'}
        negative = {'vulnerability': False, 'category': 'none', 'line': 0,
                    'evidence': 'deployment assumptions are unknown in this fixture'}
        blobs = {}
        prompt = prepared['task'] + json.dumps(row['payload'])
        def attempt(stage, parsed, parent=None):
            role = 'finder' if stage == 'finder' else arm + '_verifier'
            item = {'attempt_key': f"{arm}|0|{row['id']}|{stage}",
                    'status': 'complete', 'debit': 1, 'reserved_output_tokens': 1024,
                    'prompt': prompt, 'prompt_sha256': r.transport.digest(prompt),
                    'parent_sha256': parent, 'model': plan['models'][role]['name'],
                    'usage': {'input_tokens': 2, 'output_tokens': 3}, 'text': json.dumps(parsed)}
            name = f"/self-authored-snapshot/{row['id']}/{stage}/attempt.json"
            data = encoded(item)
            blobs[name] = data
            item['attempt_artifact'] = {'path': name, 'sha256': r.transport.digest(data)}
            item['parsed'] = copy.deepcopy(parsed)
            row['attempts'].append(item)
        attempt('finder', finder)
        row.update(status='complete', finder_candidate=finder, detected=True,
                   root_cause_correct=True, surfaced=True)
        if verifier and arm != 'finder-only':
            parent = r.transport.digest(finder)
            prompt += '\nIndependent review of candidate; reject if no concrete flaw: ' + json.dumps(finder)
            attempt('verifier', negative, parent)
            row.update(surfaced=False, root_cause_correct=False, verifier_parent_sha256=parent)
        return raw, blobs

    def worksheet(self, raw, blobs):
        return review.build_worksheet(encoded(raw), blobs)

    def decision(self, worksheet, stage='finder'):
        row = worksheet['rows'][0]
        item = next(s for s in row['stages'] if s['stage'] == stage)
        return {'id': row['id'], 'fingerprint': row['fingerprint'], 'stage': stage,
                'attempt_sha256': item['attempt_sha256'],
                'parent_parsed_sha256': item['parent_parsed_sha256'],
                'adjudication': 'TP', 'classification': 'candidate-survives',
                'reason': 'self-authored reviewer statement; not a verified human verdict'}

    def overlay(self, worksheet, decisions):
        return {'schema': 'formal-stage-review-overlay-v1', 'raw_sha256': worksheet['raw_sha256'],
                'worksheet_sha256': worksheet['worksheet_sha256'],
                'reviewer': 'self-authored-unit-reviewer', 'decisions': decisions}

    def test_refuted_finder_candidate_remains_reviewable_without_surfacing(self):
        raw, blobs = self.snapshot()
        before = encoded(raw)
        worksheet = self.worksheet(raw, blobs)
        row = worksheet['rows'][0]
        self.assertFalse(row['derived']['surfaced'])
        self.assertTrue(row['stages'][0]['candidate']['vulnerability'])
        result = review.apply_overlay(worksheet, self.overlay(worksheet, [self.decision(worksheet)]))
        self.assertEqual(result['rows'][0]['stages'][0]['adjudication'], 'TP')
        self.assertFalse(result['rows'][0]['derived']['surfaced'])
        self.assertEqual(encoded(raw), before)
        self.assertEqual(worksheet['rows'][0]['stages'][0]['adjudication'], 'U')
        self.assertNotIn('metrics', result)
        self.assertNotIn('confirmed', result)

    def test_all_prepared_rows_and_missing_stages_keep_the_denominator(self):
        raw, blobs = self.snapshot()
        raw['rows'].pop()
        worksheet = self.worksheet(raw, blobs)
        self.assertEqual(len(worksheet['rows']), 10)
        self.assertEqual(worksheet['rows'][-1]['run_status'], 'missing')
        self.assertTrue(all(x['adjudication'] == 'U' for x in worksheet['rows'][-1]['stages']))
        self.assertTrue(all(x['attempt_sha256'] is None for x in worksheet['rows'][-1]['stages']))

    def test_raw_sha_uses_actual_bytes_including_whitespace(self):
        raw, blobs = self.snapshot()
        data = encoded(raw) + b'\n '
        self.assertEqual(review.build_worksheet(data, blobs)['raw_sha256'], r.transport.digest(data))
        self.assertNotEqual(self.worksheet(raw, blobs)['raw_sha256'], r.transport.digest(data))

    def test_mutable_parsed_cannot_replace_artifact_bound_text(self):
        raw, blobs = self.snapshot()
        raw['rows'][0]['attempts'][0]['parsed']['evidence'] = 'forged evidence'
        with self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_finder_candidate_tamper_is_rejected(self):
        raw, blobs = self.snapshot()
        raw['rows'][0]['finder_candidate']['vulnerability'] = False
        with self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_derived_surface_detection_and_root_cause_tamper_are_rejected(self):
        for key in ('surfaced', 'detected', 'root_cause_correct'):
            raw, blobs = self.snapshot()
            raw['rows'][0][key] = not raw['rows'][0][key]
            with self.subTest(key=key), self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_attempt_artifact_missing_digest_or_projection_tamper_rejected(self):
        for mutation in ('missing', 'digest', 'text', 'prompt'):
            raw, blobs = self.snapshot()
            attempt = raw['rows'][0]['attempts'][0]
            if mutation == 'missing': blobs.clear()
            elif mutation == 'digest': attempt['attempt_artifact']['sha256'] = '0' * 64
            else: attempt[mutation] = 'mutable raw changed'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_duplicate_unknown_rows_and_duplicate_artifact_rejected(self):
        for mutation in ('duplicate', 'unknown', 'artifact'):
            raw, blobs = self.snapshot()
            if mutation == 'duplicate': raw['rows'].append(copy.deepcopy(raw['rows'][0]))
            elif mutation == 'unknown': raw['rows'][0]['id'] = 'foreign-case'
            else: raw['rows'][0]['attempts'][1] = copy.deepcopy(raw['rows'][0]['attempts'][0])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_verifier_parent_and_row_fingerprint_tamper_rejected(self):
        for mutation in ('parent', 'fingerprint'):
            raw, blobs = self.snapshot()
            row = raw['rows'][0]
            if mutation == 'parent': row['verifier_parent_sha256'] = '0' * 64
            else: row['fingerprint'] = '0' * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_finder_only_has_no_invented_verifier(self):
        raw, blobs = self.snapshot(arm='finder-only')
        worksheet = self.worksheet(raw, blobs)
        self.assertEqual([s['stage'] for s in worksheet['rows'][0]['stages']], ['finder'])

    def test_wrong_raw_worksheet_fingerprint_artifact_parent_or_stage_rejected(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        for key in ('raw_sha256', 'worksheet_sha256', 'fingerprint', 'attempt_sha256', 'parent_parsed_sha256', 'stage'):
            overlay = self.overlay(worksheet, [self.decision(worksheet)])
            target = overlay if key in ('raw_sha256', 'worksheet_sha256') else overlay['decisions'][0]
            target[key] = 'verifier' if key == 'stage' else '0' * 64
            with self.subTest(key=key), self.assertRaises(ValueError): review.apply_overlay(worksheet, overlay)

    def test_duplicate_stage_decision_and_cross_run_replay_rejected(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        decision = self.decision(worksheet)
        with self.assertRaises(ValueError):
            review.apply_overlay(worksheet, self.overlay(worksheet, [decision, copy.deepcopy(decision)]))
        other = review.build_worksheet(encoded(raw) + b'\n', blobs)
        with self.assertRaises(ValueError): review.apply_overlay(other, self.overlay(worksheet, [decision]))

    def test_missing_attempt_cannot_receive_a_decision(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        decision = self.decision(worksheet)
        row = worksheet['rows'][1]
        decision.update(id=row['id'], fingerprint=row['fingerprint'], attempt_sha256=None)
        with self.assertRaises(ValueError): review.apply_overlay(worksheet, self.overlay(worksheet, [decision]))

    def test_review_taxonomy_remains_reviewer_supplied_and_not_auto_fp(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        for classification in ('U', 'code-safe', 'deployment-unknown', 'missing-path', 'unsupported'):
            decision = self.decision(worksheet)
            decision.update(classification=classification, adjudication='U')
            result = review.apply_overlay(worksheet, self.overlay(worksheet, [decision]))
            item = result['rows'][0]['stages'][0]
            self.assertEqual(item['classification'], classification)
            self.assertEqual(item['adjudication'], 'U')
            self.assertEqual(item['reviewer'], 'self-authored-unit-reviewer')

    def test_invalid_schema_blank_reason_reviewer_and_extra_fields_rejected(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        for mutation in ('schema', 'reviewer', 'reason', 'extra', 'decision'):
            overlay = self.overlay(worksheet, [self.decision(worksheet)])
            if mutation == 'schema': overlay['schema'] = 'old-overlay'
            elif mutation == 'reviewer': overlay['reviewer'] = ' '
            elif mutation == 'reason': overlay['decisions'][0]['reason'] = ''
            elif mutation == 'extra': overlay['decisions'][0]['human_verified'] = True
            else: overlay['decisions'][0]['adjudication'] = 'confirmed'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): review.apply_overlay(worksheet, overlay)

    def test_worksheet_mutation_without_digest_update_rejected(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        overlay = self.overlay(worksheet, [self.decision(worksheet)])
        worksheet['rows'][0]['stages'][0]['candidate']['evidence'] = 'changed'
        with self.assertRaises(ValueError): review.apply_overlay(worksheet, overlay)

    def test_strict_json_duplicate_key_nonfinite_invalid_utf8_and_caps_rejected(self):
        for data in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'\xff', b' ' * (16 * 1024 * 1024 + 1)):
            with self.subTest(prefix=data[:25]), self.assertRaises(ValueError): review.build_worksheet(data, {})

    def rewrite_artifact(self, attempt, blobs):
        projection = {k: v for k, v in attempt.items() if k not in ('parsed', 'attempt_artifact')}
        data = encoded(projection)
        blobs[attempt['attempt_artifact']['path']] = data
        attempt['attempt_artifact']['sha256'] = r.transport.digest(data)

    def test_prompt_json_key_order_is_semantic_not_redumped_text(self):
        raw, blobs = self.snapshot()
        row = raw['rows'][0]
        for index, attempt in enumerate(row['attempts']):
            prompt = raw['prepared']['task'] + json.dumps(row['payload'], sort_keys=True)
            if index:
                prompt += '\nIndependent review of candidate; reject if no concrete flaw: ' + json.dumps(row['finder_candidate'], sort_keys=True)
            attempt.update(prompt=prompt, prompt_sha256=r.transport.digest(prompt))
            self.rewrite_artifact(attempt, blobs)
        self.worksheet(raw, blobs)

    def test_failed_verifier_keeps_observed_finder_state_but_is_not_final_complete(self):
        for status, text in (('process-control-failure', None), ('complete', 'invalid model answer')):
            raw, blobs = self.snapshot()
            row = raw['rows'][0]
            attempt = row['attempts'][1]
            attempt.update(status=status, text=text)
            if status == 'complete': attempt['parsed'] = None
            else: attempt.pop('parsed')
            self.rewrite_artifact(attempt, blobs)
            row.update(status='parse_failure' if status == 'complete' else status,
                       failed_stage='verifier', surfaced=True, root_cause_correct=True)
            row.pop('verifier_parent_sha256')
            worksheet = self.worksheet(raw, blobs)
            observed = worksheet['rows'][0]
            self.assertTrue(observed['derived']['surfaced'])
            self.assertNotEqual(observed['run_status'], 'complete')
            result = review.apply_overlay(worksheet, self.overlay(worksheet, [self.decision(worksheet)]))
            self.assertEqual(result['rows'][0]['stages'][0]['adjudication'], 'TP')
            with self.assertRaises(ValueError):
                review.apply_overlay(worksheet, self.overlay(worksheet, [self.decision(worksheet, 'verifier')]))

    def test_negative_verifier_reply_is_not_a_positive_finding_for_tp_or_fp(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        for verdict in ('TP', 'FP'):
            decision = self.decision(worksheet, 'verifier')
            decision['adjudication'] = verdict
            with self.subTest(verdict=verdict), self.assertRaises(ValueError):
                review.apply_overlay(worksheet, self.overlay(worksheet, [decision]))
        decision.update(adjudication='U', classification='deployment-unknown')
        result = review.apply_overlay(worksheet, self.overlay(worksheet, [decision]))
        self.assertEqual(result['rows'][0]['stages'][1]['adjudication'], 'U')
        self.assertFalse(result['rows'][0]['derived']['surfaced'])

    def test_shared_derived_api_returns_validated_snapshot_and_actual_bytes_sha(self):
        raw, blobs = self.snapshot()
        data = encoded(raw)
        value = review.validate_derived(data, blobs, runner_context=r)
        self.assertEqual(value['raw_sha256'], r.transport.digest(data))
        self.assertEqual(value['raw'], raw)
        self.assertFalse(value['derived'][raw['rows'][0]['id']]['surfaced'])
        raw['rows'][0]['surfaced'] = True
        with self.assertRaises(ValueError): review.validate_derived(encoded(raw), blobs, runner_context=r)

    def test_missing_required_verifier_complete_rejected_but_stage_incomplete_preserves_finder(self):
        raw, blobs = self.snapshot(verifier=False)
        row = raw['rows'][0]
        row['failed_stage'] = 'verifier'
        # Old contradictory raw must not make a final surfaced metric from finder alone.
        with self.assertRaises(ValueError): self.worksheet(raw, blobs)
        row.update(status='stage_incomplete', error='OSError')
        worksheet = self.worksheet(raw, blobs)
        self.assertTrue(worksheet['rows'][0]['derived']['surfaced'])
        self.assertEqual(worksheet['rows'][0]['run_status'], 'stage_incomplete')
        self.assertEqual(worksheet['rows'][0]['stages'][1]['observation_status'], 'missing')
        result = review.apply_overlay(worksheet, self.overlay(worksheet, [self.decision(worksheet)]))
        self.assertEqual(result['rows'][0]['stages'][0]['adjudication'], 'TP')
        row.pop('error')
        with self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_first_stage_exception_without_artifact_remains_unknown(self):
        raw, blobs = self.snapshot()
        row = raw['rows'][1]
        row.update(status='stage_incomplete', failed_stage='finder', error='OSError')
        worksheet = self.worksheet(raw, blobs)
        item = worksheet['rows'][1]
        self.assertEqual(item['derived'], {})
        self.assertTrue(all(stage['adjudication'] == 'U' for stage in item['stages']))
        self.assertTrue(all(stage['attempt_sha256'] is None for stage in item['stages']))
        for field, value in (('failed_stage', 'verifier'), ('error', '')):
            bad = copy.deepcopy(raw)
            bad['rows'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.worksheet(bad, blobs)

    def test_overlay_malformed_unhashable_fields_are_typed_rejections(self):
        raw, blobs = self.snapshot()
        worksheet = self.worksheet(raw, blobs)
        for field in ('id', 'stage', 'classification'):
            overlay = self.overlay(worksheet, [self.decision(worksheet)])
            overlay['decisions'][0][field] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                review.apply_overlay(worksheet, overlay)

    def test_worksheet_uses_provided_runner_context_for_validation_and_fingerprint(self):
        raw, blobs = self.snapshot()
        selected = load('run_v1')
        with synthetic_baseline(selected), \
             patch.object(review.runner, 'validate_prepared', side_effect=AssertionError('Global runner must not validate')), \
             patch.object(review.runner.transport, 'digest', side_effect=AssertionError('Global runner must not fingerprint')):
            worksheet = review.build_worksheet(encoded(raw), blobs, runner_context=selected)
        self.assertEqual(worksheet['rows'][0]['fingerprint'], raw['rows'][0]['fingerprint'])
        self.assertFalse(worksheet['rows'][0]['derived']['surfaced'])

    def test_formal_producer_has_no_unbound_human_or_differential_promotion(self):
        for key, value in (('adjudication', 'TP'), ('adjudication', 'FP'),
                           ('detection_adjudication', 'TP'), ('differential_oracle', True),
                           ('differential_oracle', 0), ('differential_status', 'complete'),
                           ('differential_status', 'incomplete')):
            raw, blobs = self.snapshot(); raw['rows'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.worksheet(raw, blobs)

    def test_no_raw_artifact_path_is_opened(self):
        raw, blobs = self.snapshot()
        # All caller snapshots are in memory; no path from raw is opened.
        with patch('builtins.open', side_effect=AssertionError('No raw-controlled file opening')):
            self.worksheet(raw, blobs)


if __name__ == '__main__': unittest.main()
