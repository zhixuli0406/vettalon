"""Offline checks for the shared small-sample statistics (no model calls)."""
import math
import unittest

import stats


class IntervalTests(unittest.TestCase):
    def test_wilson_matches_reference_values(self):
        for (k, n), (lo, hi) in {(4, 10): (0.168, 0.687), (12, 20): (0.387, 0.781),
                                 (0, 7): (0.0, 0.354), (130, 1060): (0.104, 0.144)}.items():
            got = stats.wilson(k, n)
            self.assertAlmostEqual(got[0], lo, places=3)
            self.assertAlmostEqual(got[1], hi, places=3)

    def test_clopper_pearson_exact_reference_values(self):
        lo, hi = stats.clopper_pearson(4, 10)
        self.assertAlmostEqual(lo, 0.1216, places=4)
        self.assertAlmostEqual(hi, 0.7376, places=4)
        self.assertAlmostEqual(stats.clopper_pearson(0, 7)[1], 0.410, places=3)
        self.assertAlmostEqual(stats.clopper_pearson(0, 30)[1], 0.116, places=3)
        self.assertEqual(stats.clopper_pearson(5, 5)[1], 1.0)
        # Large n stays finite (log-space binomial, no overflow).
        lo, hi = stats.clopper_pearson(1368, 2737)
        self.assertTrue(0.47 < lo < 0.5 < hi < 0.53)

    def test_zero_successes_report_an_exact_upper_bound(self):
        r = stats.rate(0, 80)
        self.assertEqual(r['method'], 'clopper-pearson-exact')
        self.assertEqual(r['interval'][0], 0.0)
        self.assertAlmostEqual(r['one_sided_upper'], 1 - 0.05 ** (1 / 80))
        self.assertLess(r['one_sided_upper'], 3 / 80)  # rule of three is the looser approximation

    def test_rate_never_uses_normal_approximation_below_300(self):
        with self.assertRaises(ValueError):
            stats.normal_interval(30, 100)
        self.assertFalse(stats.rate(30, 299)['clt_allowed'])
        self.assertTrue(stats.rate(30, 300)['clt_allowed'])
        self.assertEqual(stats.rate(30, 299)['method'], 'wilson')
        lo, hi = stats.normal_interval(90, 300)
        self.assertLess(lo, 0.3)
        self.assertGreater(hi, 0.3)

    def test_empty_and_invalid_counts(self):
        self.assertIsNone(stats.rate(0, 0)['interval'])
        self.assertIn('n=0', stats.format_rate(0, 0))
        for bad in [(-1, 3), (4, 3), (1.0, 3), (True, 3)]:
            with self.assertRaises(ValueError):
                stats.rate(*bad)

    def test_format_rate_always_shows_interval_and_n(self):
        self.assertEqual(stats.format_rate(4, 10, 'recall'),
                         'recall 4/10 = 40.0% [16.8%, 68.7%] Wilson 95% n=10')
        self.assertEqual(stats.format_rate(0, 7), '0/7 = 0.0% [0.0%, 41.0%] exact CP 95% n=7')

    def test_bounded_rate_keeps_unresolved_items_in_n(self):
        b = stats.bounded_rate(4, 6, 10)
        self.assertEqual(b['point_bounds'], [0.4, 0.6])
        self.assertAlmostEqual(b['interval'][0], stats.wilson(4, 10)[0])
        self.assertAlmostEqual(b['interval'][1], stats.wilson(6, 10)[1])
        self.assertIn('2 unresolved kept in n', stats.format_bounded(4, 6, 10))
        with self.assertRaises(ValueError):
            stats.bounded_rate(6, 4, 10)


class PairedTests(unittest.TestCase):
    def test_exact_sign_test(self):
        self.assertEqual(stats.exact_sign_test(0, 0), 1.0)
        self.assertAlmostEqual(stats.exact_sign_test(0, 5), 0.0625)
        self.assertAlmostEqual(stats.exact_sign_test(9, 1), 2 * 11 / 1024)

    def test_paired_difference_is_item_level_and_seeded(self):
        a = {f'i{i}': i < 4 for i in range(20)}
        b = {f'i{i}': i < 10 for i in range(20)}
        r = stats.paired_difference(a, b, seed=7)
        self.assertEqual((r['n_items'], r['a_better_items'], r['b_better_items'], r['tied_items']), (20, 0, 6, 14))
        self.assertAlmostEqual(r['difference'], 0.3)
        self.assertAlmostEqual(r['sign_test_p'], 2 / 64)
        self.assertEqual(r, stats.paired_difference(a, b, seed=7))
        lo, hi = r['bootstrap_interval']
        self.assertTrue(lo <= 0.3 <= hi)

    def test_paired_arms_must_align_on_the_same_items(self):
        with self.assertRaises(ValueError):
            stats.paired_difference({'a': True, 'b': False}, {'a': True, 'c': False})
        with self.assertRaises(ValueError):
            stats.paired_difference({}, {})
        with self.assertRaises(ValueError):
            stats.paired_difference({'a': 'yes'}, {'a': True})

    def test_clustered_se_exceeds_naive_when_repeats_are_correlated(self):
        observations = {f'item{i}': [i % 2] * 5 for i in range(10)}
        r = stats.clustered_mean(observations)
        self.assertEqual((r['n_observations'], r['n_clusters']), (50, 10))
        self.assertAlmostEqual(r['mean'], 0.5)
        self.assertGreater(r['se_clustered'], 2 * r['se_naive'])
        self.assertIsNone(r['normal_interval'])
        many = {f'item{i}': [i % 2, (i + 1) % 2] for i in range(300)}
        self.assertIsNotNone(stats.clustered_mean(many)['normal_interval'])


class PowerTests(unittest.TestCase):
    def test_twenty_to_thirty_percent_needs_about_294_per_arm(self):
        n = stats.two_proportion_sample_size(0.20, 0.30)
        self.assertTrue(abs(n - 294) <= 2, n)
        self.assertAlmostEqual(stats.two_proportion_power(0.20, 0.30, n), 0.80, places=2)

    def test_small_comparisons_are_labelled_underpowered(self):
        label = stats.power_label(10, 0.20, 0.30)
        self.assertFalse(label['powered'])
        self.assertEqual(label['label'], stats.UNDERPOWERED_LABEL)
        self.assertLess(label['achieved_power'], 0.2)
        self.assertTrue(stats.power_label(300, 0.20, 0.30)['powered'])

    def test_invalid_power_inputs(self):
        for args in [(0.0, 0.3), (0.2, 0.2), (0.2, 1.0)]:
            with self.assertRaises(ValueError):
                stats.two_proportion_sample_size(*args)
        self.assertTrue(math.isfinite(stats.two_proportion_power(0.5, 0.6, 1)))


class PreRegisteredTestTests(unittest.TestCase):
    def test_fisher_exact_matches_the_textbook_example(self):
        # 1/12 vs 9/12 (the dieting example): two-sided p = 0.002759
        self.assertAlmostEqual(stats.fisher_exact(1, 12, 9, 12), 0.002759, places=5)
        self.assertEqual(stats.fisher_exact(0, 5, 0, 5), 1.0)
        self.assertAlmostEqual(stats.fisher_exact(3, 10, 3, 10), 1.0)

    def test_newcombe_matches_the_published_example(self):
        # Newcombe 1998: 56/70 vs 48/80, difference 0.2, method 10 [0.0524, 0.3339]
        r = stats.newcombe_difference(48, 80, 56, 70)
        self.assertAlmostEqual(r['difference'], 0.2)
        self.assertAlmostEqual(r['interval'][0], 0.0524, places=3)
        self.assertAlmostEqual(r['interval'][1], 0.3339, places=3)
        with self.assertRaises(ValueError):
            stats.newcombe_difference(0, 0, 1, 2)

    def test_holm_is_step_down_and_monotone(self):
        adj = stats.holm({'a': 0.01, 'b': 0.04, 'c': 0.03})
        self.assertAlmostEqual(adj['a'], 0.03)
        self.assertAlmostEqual(adj['c'], 0.06)
        self.assertAlmostEqual(adj['b'], 0.06)
        self.assertEqual(stats.holm({'x': 0.7}), {'x': 0.7})
        with self.assertRaises(ValueError):
            stats.holm({})

    def test_exact_mcnemar_power(self):
        # No net effect in the true model: power stays at or below alpha.
        self.assertLessEqual(stats.mcnemar_exact_power(100, 0.05, 0.05), 0.05)
        self.assertEqual(stats.mcnemar_exact_power(100, 0.0, 0.0), 0.0)
        self.assertLess(stats.mcnemar_exact_power(100, 0.15, 0.05), stats.mcnemar_exact_power(200, 0.15, 0.05))
        self.assertGreater(stats.mcnemar_exact_power(100, 0.10, 0.0), 0.9)
        self.assertLess(stats.mcnemar_exact_power(100, 0.10, 0.0, alpha=0.00625),
                        stats.mcnemar_exact_power(100, 0.10, 0.0))
        with self.assertRaises(ValueError):
            stats.mcnemar_exact_power(10, 0.7, 0.5)

    def test_unequal_group_power_reduces_to_the_equal_case(self):
        self.assertAlmostEqual(stats.two_proportion_power_unequal(0.2, 0.3, 294, 294),
                               stats.two_proportion_power(0.2, 0.3, 294), places=6)
        self.assertLess(stats.two_proportion_power_unequal(0.2, 0.3, 259, 294), 0.8)


if __name__ == '__main__':
    unittest.main()
