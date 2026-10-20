"""Offline summary of saved OWASP results; no scan and no model calls."""
import json
import unittest
from pathlib import Path

import run

REPORTS = Path(__file__).resolve().parent / "reports"


class SummaryTests(unittest.TestCase):
    def load(self, name):
        return json.loads((REPORTS / name).read_text())

    def test_saved_claude_codex_rates_match_published_counts_with_intervals(self):
        data = run.summary(self.load("results-claude-codex.json"))
        recall = data["rates"]["cross-family recall_on_true_cases"]
        self.assertEqual((recall["k"], recall["n"], recall["method"]), (73, 80, "wilson"))
        self.assertAlmostEqual(recall["interval"][0], 0.830, places=3)
        self.assertAlmostEqual(recall["interval"][1], 0.957, places=3)
        zero = data["rates"]["cross-family fp_rate_on_false_cases"]
        self.assertEqual((zero["k"], zero["n"], zero["method"]), (0, 80, "clopper-pearson-exact"))
        self.assertAlmostEqual(zero["one_sided_upper"], 0.0368, places=4)

    def test_paired_comparison_uses_items_and_labels_power(self):
        data = run.summary(self.load("results-qwen-claude.json"))
        fp = data["paired"]["fp_rate_on_false_cases"]
        self.assertEqual((fp["n_items"], fp["a_better_items"], fp["b_better_items"]), (80, 46, 0))
        self.assertLess(fp["sign_test_p"], 1e-10)
        power = data["power"]["recall_on_true_cases"]
        self.assertEqual(power["required_n_per_arm"], 294)
        self.assertEqual(power["label"], "underpowered: descriptive only")

    def test_every_printed_rate_has_interval_and_n(self):
        for line in run.summary_lines(self.load("results-claude-codex.json")):
            if "/80 =" in line:
                self.assertRegex(line, r"\[\d+\.\d%, \d+\.\d%\] .* n=80$")

    def test_malformed_or_duplicate_results_are_rejected(self):
        rows = self.load("results-claude-codex.json")
        with self.assertRaises(ValueError):
            run.summary(rows + rows[:1])
        broken = [dict(rows[0], crossfamily_pos=None)] + rows[1:]
        with self.assertRaises(ValueError):
            run.summary(broken)


if __name__ == "__main__":
    unittest.main()
