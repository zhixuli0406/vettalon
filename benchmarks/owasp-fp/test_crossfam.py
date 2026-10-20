"""O13 cross-family matrix: offline only. No process starts and no model is called."""
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import crossfam as xf
import crossfam_run as runner

HERE = Path(__file__).resolve().parent
REPORTS = HERE / 'reports'
ROOT = HERE.parents[1]
EXAMPLE = json.loads((HERE / 'crossfam.arms.example.json').read_text())


def arms():
    return xf.load_arms(EXAMPLE)


def arm(aid):
    return next(a for a in arms()['arms'] if a['id'] == aid)


CASE = {'id': 'BenchmarkTest00001', 'cat': 'sqli', 'real': True, 'expect_class': 'sql-injection'}


def finding(status, model='b1', cross=True, same=False, evidence=(), rule='ai/sql-injection', found_by='a1'):
    return {'source_engine': 'ai_audit', 'rule_id': rule, 'status': status, 'found_by': [found_by],
            'verification': [{'model': model, 'family': 'x', 'verdict': 'plausible',
                              'cross_family': cross, 'same_model': same}],
            'evidence': list(evidence)}


def rec(case, real, outcome, finder_pos=True, aid='X', rationale=None):
    return {'case': case, 'cat': 'sqli', 'real': real, 'arm': aid, 'finder_pos': finder_pos,
            'outcome': outcome, 'rationale': rationale, 'reason': None}


class ProductCapsTests(unittest.TestCase):
    def const(self, rel, name):
        text = (ROOT / 'crates/vettalon/src/audit' / rel).read_text()
        m = re.search(rf'pub const {name}: usize = ([0-9* ]+);', text)
        self.assertIsNotNone(m, name)
        value = 1
        for factor in m.group(1).split('*'):
            value *= int(factor)
        return value

    def test_mirrored_caps_match_the_rust_source(self):
        self.assertEqual(self.const('ai_audit.rs', 'MAX_CANDIDATES_PER_MODULE'), xf.MAX_CANDIDATES_PER_MODULE)
        self.assertEqual(self.const('ai_audit.rs', 'AI_AUDIT_PARSE_RETRIES'), xf.AI_AUDIT_PARSE_RETRIES)
        self.assertEqual(self.const('ai_audit.rs', 'MODULE_PROMPT_BUDGET_BYTES'), xf.MODULE_PROMPT_BUDGET_BYTES)
        self.assertEqual(self.const('adversarial.rs', 'MAX_REFUTER_RUNS'), xf.MAX_REFUTER_RUNS)
        self.assertEqual(self.const('adversarial.rs', 'VERIFIER_FILE_BUDGET_BYTES'), xf.VERIFIER_FILE_BUDGET_BYTES)


class ArmsTests(unittest.TestCase):
    def test_example_is_a_full_two_by_two_plus_fresh_sessions(self):
        kinds = {a['id']: a['kind'] for a in arms()['arms']}
        self.assertEqual(kinds, {'A>B': 'cross_family', 'B>A': 'cross_family', 'A>A2': 'same_family',
                                 'B>B2': 'same_family', 'A>A=': 'same_model_fresh',
                                 'B>B=': 'same_model_fresh'})

    def test_incomplete_designs_are_rejected(self):
        dup = dict(EXAMPLE, arms=EXAMPLE['arms'] + [{'id': 'A>B2', 'finder': 'a1', 'refuter': 'b2'}])
        with self.assertRaisesRegex(ValueError, 'one arm per'):
            xf.load_arms(dup)
        for drop, msg in (('A>A2', 'family-a->family-a'), ('B>A', 'family-b->family-a')):
            cfg = dict(EXAMPLE, arms=[a for a in EXAMPLE['arms'] if a['id'] != drop])
            with self.assertRaisesRegex(ValueError, msg):
                xf.load_arms(cfg)
        cfg = dict(EXAMPLE, arms=[a for a in EXAMPLE['arms'] if a['finder'] != a['refuter']])
        with self.assertRaisesRegex(ValueError, 'fresh-session'):
            xf.load_arms(cfg)

    def test_bad_ids_models_and_runs_are_rejected(self):
        bad = [dict(EXAMPLE, arms=EXAMPLE['arms'] + [EXAMPLE['arms'][0]]),
               dict(EXAMPLE, arms=EXAMPLE['arms'] + [{'id': 'Z>Z', 'finder': 'zz', 'refuter': 'a1'}]),
               dict(EXAMPLE, arms=EXAMPLE['arms'] + [{'id': '../x', 'finder': 'a1', 'refuter': 'b1'}]),
               dict(EXAMPLE, refuter_runs=6), dict(EXAMPLE, schema='other')]
        for cfg in bad:
            with self.assertRaises(ValueError):
                xf.load_arms(cfg)


class ClassifyTests(unittest.TestCase):
    def classify(self, findings, aid='A>B'):
        return xf.classify_report({'findings': findings}, CASE, arm(aid))

    def test_outcomes_from_report_status_and_evidence(self):
        self.assertEqual(self.classify([])['outcome'], 'not_flagged')
        self.assertEqual(self.classify([finding('needs_human')])['outcome'], 'survived')
        uncertain = finding('candidate', evidence=[{'kind': 'verify_uncertain', 'detail': 'verify_uncertain: 2/3 plausible'}])
        self.assertEqual(self.classify([uncertain])['outcome'], 'uncertain')
        self.assertEqual(self.classify([finding('candidate')])['outcome'], 'verify_error')
        refuted = finding('refuted', evidence=[{'kind': 'adversarial_review',
                                                'detail': 'refuted: the input is sanitized by ESAPI encoder'}])
        r = self.classify([refuted])
        self.assertEqual((r['outcome'], r['rationale']), ('refuted', 'guarded'))
        self.assertEqual(self.classify([refuted, finding('needs_human')])['outcome'], 'survived')

    def test_zero_llm_precheck_is_not_a_refuter_flip(self):
        for source, detail in (('precheck', 'precheck: line 99 is past the end of the file'),
                               ('verify', 'refuted (zero-LLM): line out of range')):
            pre = dict(finding('refuted', evidence=[{'kind': 'adversarial_review', 'source': source,
                                                     'detail': detail}]), verification=[])
            self.assertEqual(self.classify([pre])['outcome'], 'precheck_refuted')
        m = xf.arm_metrics([rec('t1', True, 'precheck_refuted'), rec('t2', True, 'refuted')])
        self.assertEqual((m['flip_rate']['k'], m['flip_rate']['n'], m['recall']['k']), (1, 1, 0))
        self.assertEqual(m['precheck_refuted'], 1)

    def test_other_engines_and_classes_do_not_count(self):
        other = [dict(finding('needs_human'), source_engine='semgrep'), finding('needs_human', rule='ai/xss')]
        self.assertEqual(self.classify(other)['outcome'], 'not_flagged')

    def test_votes_that_do_not_match_the_arm_fail_closed(self):
        self.assertEqual(self.classify([finding('needs_human', model='b2')])['outcome'], 'arm_mismatch')
        self.assertEqual(self.classify([finding('needs_human', model='a2', cross=True)], 'A>A2')['outcome'],
                         'arm_mismatch')
        self.assertEqual(self.classify([finding('needs_human', model='a1', cross=False, same=False)], 'A>A=')
                         ['outcome'], 'arm_mismatch')
        self.assertEqual(self.classify([finding('needs_human', model='a1', cross=False, same=True)], 'A>A=')
                         ['outcome'], 'survived')
        self.assertEqual(self.classify([finding('needs_human', found_by='b1')])['outcome'], 'arm_mismatch')

    def test_rationale_buckets(self):
        self.assertEqual(xf.rationale_category('endpoint auth unknown, deployment not visible'),
                         'deployment_context')
        self.assertEqual(xf.rationale_category('value is overwritten by a constant'), 'constant_or_dead_flow')
        self.assertEqual(xf.rationale_category(None), 'not_recorded')
        self.assertEqual(xf.rationale_category('weird'), 'other')


class MetricTests(unittest.TestCase):
    def test_flip_rate_correctness_and_uncertain(self):
        recs = [rec('t1', True, 'survived'), rec('t2', True, 'refuted'), rec('t3', True, 'uncertain'),
                rec('f1', False, 'refuted'), rec('f2', False, 'refuted'), rec('f3', False, 'survived'),
                rec('t4', True, 'not_flagged', finder_pos=False), rec('f4', False, 'not_run', finder_pos=False)]
        m = xf.arm_metrics(recs)
        self.assertEqual((m['recall']['k'], m['recall']['n']), (1, 4))
        self.assertEqual((m['fp_rate']['k'], m['fp_rate']['n']), (1, 4))
        self.assertEqual((m['flip_rate']['k'], m['flip_rate']['n']), (3, 6))
        self.assertEqual((m['flip_correctness']['k'], m['flip_correctness']['n']), (2, 3))
        self.assertEqual((m['wrong_kill_rate']['k'], m['wrong_kill_rate']['n']), (1, 3))
        self.assertEqual((m['uncertain_rate']['k'], m['uncertain_rate']['n']), (1, 6))
        self.assertEqual(m['not_run'], 1)
        self.assertEqual(m['flip_rationale'], {'not_recorded': {'correct': 2, 'wrong': 1}})
        self.assertIsNone(xf.arm_metrics(recs, boolean_outcomes=True)['uncertain_rate'])

    def test_overlap_skips_unrun_cases(self):
        a = [rec('t1', True, 'refuted', aid='a'), rec('t2', True, 'survived', aid='a'),
             rec('f1', False, 'survived', aid='a'), rec('t3', True, 'not_run', finder_pos=False, aid='a')]
        b = [rec('t1', True, 'refuted', aid='b'), rec('t2', True, 'refuted', aid='b'),
             rec('f1', False, 'refuted', aid='b'), rec('t3', True, 'refuted', aid='b')]
        o = xf.pair_overlap(a, b)
        self.assertEqual(o['n_compared'], 3)
        self.assertEqual(o['final_error_overlap'], {'intersection': 1, 'union': 3, 'jaccard': 1 / 3})
        self.assertEqual(o['refuter_error_overlap']['jaccard'], 1 / 3)

    def test_planned_contrasts_hold_the_finder_fixed(self):
        got = {(c['a'], c['b']) for c in xf.planned_contrasts(arms()['arms'])}
        self.assertEqual(got, {('A>A2', 'A>B'), ('A>A=', 'A>B'), ('A>A=', 'A>A2'),
                               ('B>B2', 'B>A'), ('B>B=', 'B>A'), ('B>B=', 'B>B2')})


class ReanalysisTests(unittest.TestCase):
    def setUp(self):
        self.data = xf.reanalyze(REPORTS)

    def test_the_five_killed_true_positives_and_their_unknown_rationale(self):
        cc = self.data['arms']['claude>codex']
        self.assertEqual([k['case'] for k in cc['killed_true_positives']],
                         ['BenchmarkTest00008', 'BenchmarkTest00102', 'BenchmarkTest00155',
                          'BenchmarkTest00159', 'BenchmarkTest00174'])
        self.assertEqual({k['rationale'] for k in cc['killed_true_positives']}, {'not_recorded'})
        m = cc['metrics']
        self.assertEqual((m['recall']['k'], m['finder_recall']['k'], m['fp_catch_rate']['n']), (73, 78, 0))
        paired = cc['within_arm_paired']['recall_on_true_cases']
        self.assertEqual((paired['a_better_items'], paired['b_better_items']), (5, 0))
        self.assertAlmostEqual(paired['sign_test_p'], 0.0625)

    def test_qwen_claude_flip_correctness(self):
        m = self.data['arms']['qwen>claude']['metrics']
        self.assertEqual((m['flip_correctness']['k'], m['flip_correctness']['n']), (46, 55))
        self.assertEqual((m['wrong_kill_rate']['k'], m['wrong_kill_rate']['n']), (9, 60))
        self.assertEqual((m['fp_catch_rate']['k'], m['fp_catch_rate']['n']), (46, 46))

    def test_cross_arm_overlap_and_disagreement(self):
        x = self.data['cross_arm']
        self.assertEqual(x['overlap']['final_error_overlap'], {'intersection': 3, 'union': 33, 'jaccard': 3 / 33})
        self.assertEqual(x['overlap']['refuter_error_overlap']['intersection'], 0)
        d = x['same_case_review_disagreement']
        self.assertEqual((d['tp_flagged_by_both'], d['kept_by_both'], d['killed_by_both']), (58, 47, []))
        self.assertEqual(len(d['killed_only_in_claude>codex']), 3)
        self.assertEqual(self.data['model_calls'], 0)

    def test_committed_reanalysis_is_reproducible(self):
        # Floats are compared to 12 decimals: libm results differ in the last
        # ulp across Python builds (seen: 3.12 vs 3.14 on achieved_power).
        def norm(value):
            if isinstance(value, float):
                return round(value, 12)
            if isinstance(value, dict):
                return {k: norm(v) for k, v in value.items()}
            if isinstance(value, list):
                return [norm(v) for v in value]
            return value
        committed = json.loads((REPORTS / 'crossfam-reanalysis.json').read_text())
        self.assertEqual(norm(committed), norm(json.loads(json.dumps(self.data))))


class PlanTests(unittest.TestCase):
    def test_ceilings_and_budget(self):
        plan = xf.build_plan(arms(), 160)
        self.assertEqual(plan['per_case_ceiling']['calls'], 26)
        self.assertEqual(plan['total']['calls_cap'], 6 * 160 * 26)
        self.assertEqual(plan['total']['output_tokens_cap'], 6 * 160 * 26 * 1024)
        self.assertEqual(plan['total']['calls_expected'], 3840)
        self.assertEqual(plan['proposed_budget']['calls'], 3840 + 156)
        self.assertEqual(plan['pilot_budget']['calls'], 6 * 64 + 156)
        self.assertEqual(plan['per_call'], {'output_tokens_max': 1024, 'timeout_seconds': 90,
                                            'automatic_retries': 0, 'inflight': 1})
        self.assertEqual(plan['model_calls_so_far'], 0)
        self.assertEqual(plan['plan_sha256'], xf.plan_digest(plan))

    def test_committed_plan_is_reproducible(self):
        committed = json.loads((REPORTS / 'crossfam-plan.json').read_text())
        self.assertEqual(committed, xf.build_plan(arms(), 160))
        doc = (HERE / 'CROSS-FAMILY-2026-10.md').read_text()
        self.assertEqual(doc.count(committed['plan_sha256']), 2)


class GreedyScanner:
    def scan(self, case, arm, report_path, trace_path):
        report_path.write_text('{"findings": []}')
        trace_path.write_text(''.join('{"step": "verify"}\n' for _ in range(27)))
        return 0


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cases = json.loads((REPORTS / 'sample.json').read_text())

    def tearDown(self):
        self.tmp.cleanup()

    def test_fake_full_matrix_end_to_end(self):
        cfg = arms()
        scanner = runner.FakeScanner(cfg)
        out = runner.run_matrix(cfg, self.cases, scanner, self.tmp.name, budget=10 ** 6)
        recs = out['records']
        self.assertEqual(len(recs), 6 * 160)
        self.assertEqual(scanner.scans, 6 * 160)
        self.assertEqual(out['ledger']['spent'], sum(sum(r['calls'].values()) for r in recs))
        self.assertFalse(any(r['outcome'] in ('arm_mismatch', 'not_run') for r in recs))
        self.assertTrue(any(r['outcome'] == 'uncertain' for r in recs))
        analysis = xf.analyze(cfg, recs)
        self.assertEqual(len(analysis['paired_contrasts']), 6)
        self.assertIsNotNone(analysis['paired_contrasts'][0]['result']['refuter_only_recall_on_true_cases'])
        self.assertIn('scanned', analysis['arms']['A>B']['metrics'])
        lines = (Path(self.tmp.name) / 'records.jsonl').read_text().splitlines()
        self.assertEqual(len(lines), len(recs))
        with self.assertRaisesRegex(ValueError, 'different case sets'):
            xf.analyze(cfg, [r for r in recs if not (r['arm'] == 'A>B' and r['case'] == recs[0]['case'])])
        with self.assertRaisesRegex(ValueError, 'not in the config'):
            xf.analyze(cfg, recs + [dict(recs[0], arm='Z>Z')])
        self.assertEqual(len(analysis['overlap']), 15)
        self.assertEqual(len(analysis['directionality']['cells']), 6)

    def test_budget_stop_truncates_every_arm_at_the_same_case(self):
        cfg = arms()
        out = runner.run_matrix(cfg, self.cases, runner.FakeScanner(cfg), self.tmp.name, budget=3 * 156 + 10)
        self.assertLessEqual(out['ledger']['spent'], out['ledger']['budget'])
        self.assertEqual(out['ledger']['stop_reason'], 'budget_exhausted')
        ran = {}
        for r in out['records']:
            if r['outcome'] != 'not_run':
                ran.setdefault(r['arm'], set()).add(r['case'])
        self.assertEqual(len({frozenset(v) for v in ran.values()}), 1)
        self.assertGreaterEqual(len(next(iter(ran.values()))), 3)
        self.assertEqual(len(out['records']), 6 * 160)

    def test_max_cases_caps_the_pilot(self):
        cfg = arms()
        out = runner.run_matrix(cfg, self.cases, runner.FakeScanner(cfg), self.tmp.name, budget=10 ** 6,
                                max_cases=2)
        ran = {r['case'] for r in out['records'] if r['outcome'] != 'not_run'}
        self.assertEqual((len(ran), out['ledger']['stop_reason']), (2, 'max_cases_reached'))

    def test_stratified_prefix_is_balanced(self):
        first = runner.stratified_order(self.cases)[:8]
        self.assertEqual(len({(c['cat'], c['real']) for c in first}), 8)

    def test_missing_trace_charges_the_ceiling_and_stays_in_n(self):
        class Silent:
            def scan(self, case, arm, report_path, trace_path):
                return 1
        out = runner.run_matrix(arms(), self.cases[:1], Silent(), self.tmp.name, budget=156)
        self.assertEqual(out['ledger']['spent'], 156)
        self.assertEqual({r['outcome'] for r in out['records']}, {'infra_error'})
        self.assertEqual(xf.arm_metrics([r for r in out['records'] if r['arm'] == 'A>B'])['infra_error'], 1)

    def test_a_scan_over_its_ceiling_halts(self):
        with self.assertRaises(runner.BudgetHalt):
            runner.run_matrix(arms(), self.cases[:1], GreedyScanner(), self.tmp.name, budget=10 ** 6)
        partial = json.loads((Path(self.tmp.name) / 'records.partial.json').read_text())
        self.assertEqual(partial['ledger']['spent'], 27)
        self.assertEqual(partial['ledger']['stop_reason'], 'halted_over_ceiling')
        self.assertEqual(len(partial['records']), 6)

    def test_dry_run_cli_writes_records_and_analysis(self):
        with mock.patch.object(runner.subprocess, 'run', side_effect=AssertionError('no process')):
            self.assertEqual(runner.main(['dry-run', '--out-dir', self.tmp.name, '--budget', '600']), 0)
        data = json.loads((Path(self.tmp.name) / 'records.json').read_text())
        self.assertEqual((data['model_calls'], data['fake_model']), (0, True))
        self.assertTrue((Path(self.tmp.name) / 'analysis.json').is_file())


GOOD_ROSTER = '\n'.join(
    f'[[model]]\nid = "{m}"\nbackend = "openai"\nfamily = "{f}"\nmodel = "x"\nmax_tokens = 1024\ntimeout_secs = 90\n'
    for m, f in (('a1', 'family-a'), ('a2', 'family-a'), ('b1', 'family-b'), ('b2', 'family-b')))


class GateTests(unittest.TestCase):
    def test_execute_without_approval_makes_zero_calls(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(runner, 'VettalonScanner', side_effect=AssertionError('built')), \
                mock.patch.object(runner.subprocess, 'run', side_effect=AssertionError('no process')):
            roster = Path(tmp) / 'roster.toml'
            roster.write_text(GOOD_ROSTER)
            code = runner.main(['execute', '--roster', str(roster), '--cases-dir', tmp, '--out-dir', tmp,
                                '--vettalon-bin', '/bin/false'])
        self.assertEqual(code, 2)

    def test_roster_checks(self):
        self.assertEqual(runner.roster_findings(GOOD_ROSTER, arms()), [])
        cli = GOOD_ROSTER.replace('backend = "openai"', 'backend = "cli"', 1)
        big = GOOD_ROSTER.replace('max_tokens = 1024', 'max_tokens = 8192', 1)
        slow = GOOD_ROSTER.replace('timeout_secs = 90', 'timeout_secs = 900', 1)
        for text, needle in ((cli, 'backend'), (big, 'max_tokens'), (slow, 'timeout_secs')):
            self.assertTrue(any(needle in p for p in runner.roster_findings(text, arms())), needle)

    def test_approval_binds_to_plan_and_blockers(self):
        plan = xf.build_plan(arms(), 160)
        ok = {'schema': runner.APPROVAL_SCHEMA, 'plan_sha256': plan['plan_sha256'], 'max_calls': 540,
              'max_cases': 16, 'expires_on': '2026-11-30',
              'accepted_blockers': [b['id'] for b in plan['blockers'] if b['owner_can_accept']],
              'approved_by': 'owner', 'approved_on': '2026-10-21'}
        check = lambda a: runner.approval_findings(a, plan, today='2026-10-21')
        self.assertEqual(check(ok), [])
        for bad in (dict(ok, plan_sha256='0' * 64), dict(ok, accepted_blockers=[]),
                    dict(ok, accepted_blockers='finder_reflector_call'), dict(ok, max_calls=10 ** 9),
                    dict(ok, max_cases=161), dict(ok, expires_on='2026-10-20'), dict(ok, expires_on=None)):
            self.assertTrue(check(bad), bad)

    def test_scan_command_pins_the_arm_and_never_runs_poc(self):
        cmd = runner.VettalonScanner('vettalon', 'r.toml', 'cases', 3).command(
            CASE, arm('A>B'), Path('r.json'), Path('t.jsonl'))
        joined = ' '.join(cmd)
        for part in ('--finders a1', '--verifiers b1', '--max-modules 1', '--cross-check-top 0',
                     '--refuter-runs 3', '--trace t.jsonl', '--no-prior'):
            self.assertIn(part, joined)
        self.assertNotIn('--poc', cmd)


if __name__ == '__main__':
    unittest.main()
