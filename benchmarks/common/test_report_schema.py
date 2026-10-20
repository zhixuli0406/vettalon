"""Offline checks for task records, hint levels, failure taxonomy and cost fields."""
import unittest

import report_schema as rs

UNKNOWN_COST = {'usd': None, 'tokens': None, 'wall_s': None, 'human_review_min': None}


def record(item, task='detect', hint='L0', outcome='success', cost=None, **extra):
    return {'id': item, 'task_type': task, 'hint_level': hint, 'outcome': outcome,
            'cost': dict(UNKNOWN_COST if cost is None else cost), **extra}


class RecordTests(unittest.TestCase):
    def test_schema_constants(self):
        self.assertEqual(rs.TASK_TYPES, ('detect', 'localize', 'poc', 'patch'))
        self.assertEqual(list(rs.HINT_LEVELS), ['L0', 'L1', 'L2', 'L3'])
        self.assertEqual(rs.MAIN_RESULT_HINT_LEVELS, ('L0', 'L1'))
        self.assertEqual(rs.FAILURE_TAXONOMY, ('timeout', 'infra_error', 'parse_failure', 'refusal', 'budget_exhausted'))

    def test_cost_is_null_when_unknown_and_never_zero(self):
        rs.validate_record(record('a', cost={'usd': 0.12, 'tokens': 1830, 'wall_s': 41.5, 'human_review_min': None}))
        for field in rs.COST_FIELDS:
            with self.assertRaises(ValueError):
                rs.validate_record(record('a', cost=dict(UNKNOWN_COST, **{field: 0})))
            with self.assertRaises(ValueError):
                rs.validate_record(record('a', cost=dict(UNKNOWN_COST, **{field: -1})))
        with self.assertRaises(ValueError):
            rs.validate_record(record('a', cost={'usd': None}))
        with self.assertRaises(ValueError):
            rs.validate_record(record('a', cost=dict(UNKNOWN_COST, tokens=float('nan'))))

    def test_unknown_fields_task_hint_or_outcome_rejected(self):
        for bad in [record('a', task='exploit'), record('a', hint='L4'), record('a', outcome='skipped'),
                    record('a', secret='x'), record('', task='detect')]:
            with self.assertRaises(ValueError):
                rs.validate_record(bad)


class SummaryTests(unittest.TestCase):
    def test_failures_stay_in_the_denominator_and_are_counted_by_kind(self):
        rows = [record('a'), record('b', outcome='timeout'), record('c', outcome='infra_error'),
                record('d', outcome='parse_failure'), record('e', outcome='refusal'),
                record('f', outcome='budget_exhausted'), record('g', outcome='failure')]
        cell = rs.summarize(rows)['by_task']['detect']['L0']
        self.assertEqual(cell['n'], 7)
        self.assertEqual((cell['success']['k'], cell['success']['n']), (1, 7))
        self.assertEqual({k: v['k'] for k, v in cell['operational_failures'].items()},
                         dict.fromkeys(rs.FAILURE_TAXONOMY, 1))
        self.assertEqual(cell['plain_failures'], 1)

    def test_tasks_are_never_summed_and_main_result_uses_only_l0_l1(self):
        rows = [record('a', 'detect', 'L0'), record('a', 'detect', 'L2'), record('a', 'detect', 'L3'),
                record('b', 'detect', 'L1', 'failure'), record('a', 'patch', 'L3'), record('a', 'poc', 'L1')]
        summary = rs.summarize(rows)
        self.assertFalse(summary['task_types_summed'])
        main = summary['main_result']
        self.assertEqual((main['detect']['success']['k'], main['detect']['n']), (1, 2))
        self.assertIsNone(main['patch'])
        self.assertEqual(main['poc']['n'], 1)
        self.assertNotIn('localize', main)
        self.assertEqual(sorted(summary['by_task']['detect']), ['L0', 'L1', 'L2', 'L3'])
        self.assertEqual(summary['reported_separately_hint_levels'], ['L2', 'L3'])
        lines = rs.format_summary(summary)
        self.assertIn('detect main (L0+L1) 1/2 = 50.0% [9.5%, 90.5%] Wilson 95% n=2', lines)
        self.assertIn('patch main (L0+L1): no records', lines)

    def test_cost_totals_are_null_when_any_part_is_unknown(self):
        rows = [record('a', cost={'usd': 0.5, 'tokens': 100, 'wall_s': 2.0, 'human_review_min': 5}),
                record('b', outcome='timeout', cost={'usd': 0.25, 'tokens': None, 'wall_s': 90.0, 'human_review_min': None})]
        cost = rs.summarize(rows)['by_task']['detect']['L0']['cost']
        self.assertEqual(cost['usd']['total'], 0.75)
        self.assertIsNone(cost['tokens']['total'])
        self.assertEqual((cost['tokens']['known_total'], cost['tokens']['unknown_count']), (100, 1))
        self.assertEqual(rs.summarize(rows)['by_task']['detect']['L0']['usd_per_success'], 0.75)

    def test_duplicates_rejected_but_repeats_and_arms_allowed(self):
        with self.assertRaises(ValueError):
            rs.summarize([record('a'), record('a')])
        summary = rs.summarize([record('a', repeat=0), record('a', repeat=1), record('a', arm='crossfamily')])
        self.assertEqual(summary['by_task']['detect']['L0']['n'], 3)


class AdjudicationUncertaintyTests(unittest.TestCase):
    def metrics(self, **overrides):
        base = {'metric_schema': 'adjudication-aware-v3', 'positive_denominator': 10, 'safe_denominator': 10,
                'detection_recall_bounds': [0.4, 0.6], 'surfaced_recall_bounds': [0.4, 0.6],
                'exploit_validated_recall_bounds': None, 'canonical_rebuildable_denominator': 5,
                'TP': 4, 'FP': 6, 'U': 2, 'FPR_bounds': [0.6, 0.6]}
        base.update(overrides)
        return base

    def test_pilot_shape_gets_intervals_without_changing_metrics(self):
        metrics = self.metrics()
        before = dict(metrics)
        out = rs.adjudication_uncertainty(metrics)
        self.assertEqual(metrics, before)
        rates = out['rates']
        self.assertEqual((rates['detection_recall']['k_lower'], rates['detection_recall']['k_upper']), (4, 6))
        self.assertAlmostEqual(rates['detection_recall']['interval'][0], 0.168, places=3)
        self.assertAlmostEqual(rates['detection_recall']['interval'][1], 0.832, places=3)
        self.assertEqual((rates['adjudicated_precision']['k'], rates['adjudicated_precision']['n']), (4, 10))
        self.assertEqual((rates['precision_with_unresolved']['k_lower'], rates['precision_with_unresolved']['k_upper']), (4, 6))
        self.assertEqual(rates['precision_with_unresolved']['n'], 12)
        self.assertFalse(out['normal_approximation_used'])
        self.assertTrue(all('n=' in line for line in rs.format_uncertainty(out)))

    def test_non_integer_ratios_and_foreign_schema_rejected(self):
        with self.assertRaises(ValueError):
            rs.adjudication_uncertainty(self.metrics(detection_recall_bounds=[0.45, 0.6]))
        with self.assertRaises(ValueError):
            rs.adjudication_uncertainty({'metric_schema': 'other'})


if __name__ == '__main__':
    unittest.main()
