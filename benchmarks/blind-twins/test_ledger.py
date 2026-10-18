"""Offline D01 schedule and durable-debit reconciliation tests."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ledger


class FormalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.planned = ledger.schedule()
        self.plan = {'schema': 'formal-budget-v1', 'purpose': 'd01-anonymous-fixed-five-pair-v1',
                     'experiment': 'twins', 'scope_sha256': self.planned['scope_sha256'],
                     'max_calls': 250, 'max_output_tokens': 1024,
                     'max_total_output_tokens': 256000, 'inflight': 1, 'automatic_retries': 0,
                     'per_call_seconds': 90,
                     'models': {'finder': {'name': 'unit-finder'},
                                'samefamily_verifier': {'name': 'unit-same'},
                                'crossfamily_verifier': {'name': 'unit-cross'}}}
        self.ledger = self.root / 'ledger'
        (self.ledger / 'debits').mkdir(parents=True)
        (self.ledger / 'batch.json').write_text(json.dumps(self.plan))
        self.run_root = self.root / 'runs'
        self.run_root.mkdir()
        canonical = patch.object(ledger, '_canonical_budget_path', return_value=self.ledger)
        canonical.start(); self.addCleanup(canonical.stop)

    def debit(self, index, key=None, reserved=1024, dispatch=False):
        slot = self.planned['slots'][index - 1]
        case_index=ledger.fixed_subset()['case_ids'].index(slot['case_id'])
        attempt_dir=self.run_root/f"unit-{slot['arm']}-{slot['repeat']}"/f"{case_index:03d}-{slot['stage']}"
        attempt_dir.mkdir(parents=True,exist_ok=True)
        prompt=f'unit-prompt-{index}'
        request={'model':self.plan['models'][slot['role']]['name'], 'prompt':prompt,
                 'max_output_tokens':1024, 'timeout_seconds':90}
        request_path=attempt_dir/'request.json';request_path.write_text(json.dumps(request))
        request_sha=hashlib.sha256(request_path.read_bytes()).hexdigest()
        data = {'schema': 'formal-debit-v1', 'slot': index,
                'attempt_key': key or slot['attempt_key'],
                'purpose': self.plan['purpose'], 'plan_sha256': hashlib.sha256(
                    json.dumps(self.plan, sort_keys=True, ensure_ascii=False,
                               separators=(',', ':'), allow_nan=False).encode()).hexdigest(),
                'reserved_output_tokens': reserved,
                'detail': {'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(), 'parent_sha256': None,
                           'role': slot['role'], 'request_sha256': request_sha,
                           'attempt_dir': str(attempt_dir), 'timeout_seconds': 90,
                           'deadline_monotonic': 1.0}}
        path = self.ledger / 'debits' / f'{index:04d}.started.json'
        path.write_text(json.dumps(data))
        started_sha=hashlib.sha256(path.read_bytes()).hexdigest()
        if dispatch:
            (self.ledger/'debits'/f'{index:04d}.dispatch-entry.json').write_text(json.dumps({
                'started_sha256':started_sha,'request_sha256':request_sha,
                'request_receipt_semantics':'single-use admission; bytes received by server unknown'}))
        artifact={'attempt_key':data['attempt_key'],'started_sha256':started_sha,
                  'prompt_sha256':data['detail']['prompt_sha256'],'parent_sha256':None,
                  'prompt':prompt,'model':request['model'],'client_request_entries':1 if dispatch else 0}
        artifact_path=attempt_dir/'attempt.json';artifact_path.write_text(json.dumps(artifact))
        return dict(artifact,attempt_artifact={'path':str(artifact_path),
                    'sha256':hashlib.sha256(artifact_path.read_bytes()).hexdigest()})

    def test_frozen_schedule_is_one_view_and_exact_ceiling(self):
        self.assertEqual(self.planned['calls_by_arm'],
                         {'finder-only': 50, 'samefamily': 100, 'crossfamily': 100})
        self.assertEqual(self.planned['runs'], 15)
        self.assertEqual(self.planned['requested_calls'], 250)
        self.assertEqual(self.planned['reserved_output_tokens_ceiling'], 256000)
        self.assertEqual(len({s['attempt_key'] for s in self.planned['slots']}), 250)
        with self.assertRaises(ValueError): ledger.schedule(identity_view='identified')
        bad_scope = copy.deepcopy(ledger.fixed_subset())
        bad_scope['case_ids'].reverse()
        with self.assertRaises(ValueError): ledger.schedule(bad_scope)

    def test_plan_fails_closed_for_extra_calls_tokens_retries_or_parallelism(self):
        for key, value in [('max_calls', 251), ('max_total_output_tokens', 256001),
                           ('max_output_tokens', 1025), ('automatic_retries', 1),
                           ('inflight', 2), ('purpose', 'new-purpose')]:
            bad = dict(self.plan, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                ledger.validate_plan(bad, self.planned)
        self.assertTrue(ledger.validate_plan(self.plan, self.planned))

    def test_reconciliation_keeps_debits_without_raw_attempt_unknown(self):
        first = self.debit(1)
        self.debit(2)
        value = ledger.reconcile_debits(self.plan, self.planned, self.ledger, [first],run_root=self.run_root)
        self.assertEqual(value['recorded_debits'], 2)
        self.assertEqual(value['recorded_reserved_output_tokens'], 2048)
        self.assertEqual(value['raw_attempts_bound'], 1)
        self.assertEqual(value['debits_without_raw_attempt'], 1)
        self.assertFalse(value['reconciled'])

    def test_duplicate_or_forged_attempt_cannot_reconcile(self):
        first = self.debit(1)
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan, self.planned, self.ledger, [first, first],run_root=self.run_root)
        forged = dict(first, started_sha256='0' * 64)
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan, self.planned, self.ledger, [forged],run_root=self.run_root)

    def test_copied_ledger_directory_cannot_be_chosen_as_canonical(self):
        copied=self.root/'copied-ledger'
        (copied/'debits').mkdir(parents=True)
        (copied/'batch.json').write_text(json.dumps(self.plan))
        with self.assertRaisesRegex(ValueError,'canonical budget path'):
            ledger.reconcile_debits(self.plan,self.planned,copied,[],run_root=self.run_root)

    def test_bad_slot_or_reservation_is_rejected(self):
        self.debit(1, reserved=True)
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan, self.planned, self.ledger, [],run_root=self.run_root)
        (self.ledger / 'debits' / '0001.started.json').unlink()
        self.debit(1, key='outside|schedule')
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan, self.planned, self.ledger, [],run_root=self.run_root)

    def test_started_role_and_raw_prompt_must_bind(self):
        first=self.debit(1)
        path=self.ledger/'debits'/'0001.started.json'
        data=json.loads(path.read_text());data['detail']['role']='crossfamily_verifier'
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[],run_root=self.run_root)
        data['detail']['role']=self.planned['slots'][0]['role'];path.write_text(json.dumps(data))
        first['started_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        first['prompt_sha256']='0'*64
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)

    def test_real_dispatch_entry_layout_is_accepted_and_unknown_file_rejected(self):
        first=self.debit(1,dispatch=True)
        value=ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)
        self.assertTrue(value['reconciled'])
        self.assertEqual(value['recorded_dispatch_entries'],1)
        (self.ledger/'debits'/'0002.dispatch-entry.json').write_text('{}')
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)
        (self.ledger/'debits'/'0002.dispatch-entry.json').unlink()
        (self.ledger/'debits'/'unexpected.json').write_text('{}')
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)

    def test_debit_directory_enumeration_is_bounded(self):
        for index in range(501):
            (self.ledger/'debits'/f'extra-{index:04d}').touch()
        with self.assertRaisesRegex(ValueError,'entry count'):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[],run_root=self.run_root)

    def test_missing_mismatched_oversized_or_symlink_request_rejected(self):
        first=self.debit(1)
        request=Path(first['attempt_artifact']['path']).with_name('request.json')
        original=request.read_bytes()
        request.unlink()
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)
        request.write_bytes(original+b' ')
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)
        request.write_bytes(b'x'*(1024*1024+1))
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)
        outside=self.root/'request-copy.json';outside.write_bytes(original)
        request.unlink();request.symlink_to(outside)
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)

    def test_attempt_directory_escape_and_moved_artifact_rejected(self):
        first=self.debit(1)
        started=self.ledger/'debits'/'0001.started.json'
        data=json.loads(started.read_text())
        data['detail']['attempt_dir']=str(self.root/'outside'/'000-finder')
        started.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[],run_root=self.run_root)
        data['detail']['attempt_dir']=str(Path(first['attempt_artifact']['path']).parent)
        started.write_text(json.dumps(data))
        first['started_sha256']=hashlib.sha256(started.read_bytes()).hexdigest()
        misplaced=self.root/'moved-attempt.json'
        misplaced.write_bytes(Path(first['attempt_artifact']['path']).read_bytes())
        first['attempt_artifact']={'path':str(misplaced),'sha256':hashlib.sha256(misplaced.read_bytes()).hexdigest()}
        with self.assertRaises(ValueError):
            ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)

    def test_request_model_and_limit_must_match_even_if_hashes_are_rewritten(self):
        first=self.debit(1)
        request_path=Path(first['attempt_artifact']['path']).with_name('request.json')
        started=self.ledger/'debits'/'0001.started.json'
        original=json.loads(request_path.read_text())
        for mutation in ({'model':'foreign-model'}, {'max_output_tokens':2048},
                         {'timeout_seconds':91}):
            request=dict(original,**mutation)
            request_path.write_text(json.dumps(request))
            data=json.loads(started.read_text())
            data['detail']['request_sha256']=hashlib.sha256(request_path.read_bytes()).hexdigest()
            if 'timeout_seconds' in mutation:data['detail']['timeout_seconds']=91
            started.write_text(json.dumps(data))
            first['started_sha256']=hashlib.sha256(started.read_bytes()).hexdigest()
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                ledger.reconcile_debits(self.plan,self.planned,self.ledger,[first],run_root=self.run_root)


if __name__ == '__main__': unittest.main()
