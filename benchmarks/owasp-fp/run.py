#!/usr/bin/env python3
"""Scan each sampled case and aggregate recall/FP for single-model vs cross-family.

  python3 run.py                         # scan every sampled case, then summarize
  python3 run.py --summarize FILE.json   # offline: re-summarize saved results, no scan

Scan mode env: VETTALON_BIN, VETTALON_CONFIG, CASES_DIR, REPORT_DIR, VETTALON_HOME.
Every rate is printed as k/n with a 95% interval (Wilson, exact for 0/n and n/n).
The single-model vs cross-family comparison is paired on the same cases.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

CONFIGS = (("single-model", "finder_pos"), ("cross-family", "crossfamily_pos"))
# Pre-registered planned effect for any two-arm claim on this sample (20% -> 30%).
PLANNED_EFFECT = (0.20, 0.30)


def _stats():
    key = "vettalon_eval_common_stats"
    if key not in sys.modules:
        path = Path(__file__).resolve().parents[1] / "common" / "stats.py"
        spec = importlib.util.spec_from_file_location(key, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return sys.modules[key]


def summary(results):
    """Rates with intervals plus a paired single-vs-cross comparison per class."""
    stats = _stats()
    if type(results) is not list or not results:
        raise ValueError("results must be a non-empty list")
    ids = [r["id"] for r in results]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id in results")
    for r in results:
        if type(r.get("real")) is not bool or any(type(r.get(k)) is not bool for _, k in CONFIGS):
            raise ValueError("each result needs boolean real, finder_pos and crossfamily_pos")
    out = {"rates": {}, "paired": {}, "power": {}}
    for cls, real in (("recall_on_true_cases", True), ("fp_rate_on_false_cases", False)):
        items = [r for r in results if r["real"] is real]
        for label, key in CONFIGS:
            out["rates"][f"{label} {cls}"] = stats.rate(sum(r[key] for r in items), len(items))
        if items:
            arms = [{r["id"]: r[key] for r in items} for _, key in CONFIGS]
            out["paired"][cls] = stats.paired_difference(arms[0], arms[1])
            out["power"][cls] = stats.power_label(len(items), *PLANNED_EFFECT)
    return out


def summary_lines(results):
    stats = _stats()
    data = summary(results)
    lines = []
    for name, r in data["rates"].items():
        lines.append(stats.format_rate(r["k"], r["n"], f"{name:<38}"))
    for cls, p in data["paired"].items():
        lo, hi = p["bootstrap_interval"]
        lines.append(f"paired cross-minus-single {cls}: {100 * p['difference']:+.1f} pp "
                     f"[{100 * lo:+.1f}, {100 * hi:+.1f}] item bootstrap, n={p['n_items']} items, "
                     f"sign test p={p['sign_test_p']:.3g} ({p['a_better_items']} single-only, "
                     f"{p['b_better_items']} cross-only)")
        power = data["power"][cls]
        lines.append(f"  power for planned {PLANNED_EFFECT[0]:.0%}->{PLANNED_EFFECT[1]:.0%}: "
                     f"needs {power['required_n_per_arm']}/arm, have {power['actual_n_per_arm']} -> {power['label']}")
    return lines


def scan():
    binary = os.environ["VETTALON_BIN"]
    config = os.environ["VETTALON_CONFIG"]
    cases = os.environ.get("CASES_DIR", "cases")
    report_dir = os.environ.get("REPORT_DIR", "reports")
    os.makedirs(report_dir, exist_ok=True)
    with open("sample.json") as handle:
        sample = json.load(handle)
    res = []
    for i, c in enumerate(sample):
        rep = f"{report_dir}/{c['id']}.json"
        if not os.path.exists(rep):
            with open(f"{report_dir}/{c['id']}.log", "w") as log:
                subprocess.run([binary, "scan", f"{cases}/{c['id']}", "--profile", "deep", "--config", config,
                                "--max-modules", "1", "--report", rep, "--no-prior"],
                               stdout=log, stderr=subprocess.STDOUT)
        fndr = nh = False
        if os.path.exists(rep):
            with open(rep) as handle:
                findings = json.load(handle).get("findings", [])
            for f in findings:
                if f.get("source_engine") == "ai_audit" and c["expect_class"] in f.get("rule_id", ""):
                    fndr = True
                    nh = nh or f.get("status") == "needs_human"
        res.append(dict(c, finder_pos=fndr, crossfamily_pos=nh))
        print(f"[{i+1}/{len(sample)}] {c['id']} {c['cat']} real={c['real']} finder={fndr} needs_human={nh}")
    with open("results.json", "w") as handle:
        json.dump(res, handle, indent=1)
    return res


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--summarize", type=Path, help="saved results JSON; no scan, no model calls")
    args = parser.parse_args(argv)
    if args.summarize:
        results = json.loads(args.summarize.read_text())
    else:
        results = scan()
    for line in summary_lines(results):
        print(line)


if __name__ == "__main__":
    main()
