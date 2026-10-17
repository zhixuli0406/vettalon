"""Self-contained synthetic specimens of actual legacy formats; offline unit tests."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("legacy_normalize", HERE / "normalize.py")
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)

TSV = "synthetic/targets.tsv"
SAMPLE = "synthetic/sample.json"
FOCUSED = "synthetic/focused.json"
WHOLE = "synthetic/whole.json"
OWASP = "synthetic/paired-a.json"
RANK = "synthetic/rank-a.json"


def synthetic_blobs():
    """Declared synthetic schema specimens; never historical execution evidence."""
    names = ["case1", "case2", "case3", "case4", "case5", "case6", "case7", "case8", "case9"]
    registry = "id\trepo\tvuln_ref\tcve\tclass\tvuln_file\n" + "".join(
        f"{name}\thttps://example.invalid/{name}\tdeclared-v1\tCVE-SYNTHETIC-{i}\tsynthetic\tfile{i}.py\n"
        for i, name in enumerate(names))
    sample = [dict(id=f"Synthetic{i}", cat="synthetic", real=i < 2, cwe="SYNTHETIC", expect_class="synthetic") for i in range(4)]
    finding = dict(id="synthetic-finding-1", rule_id="synthetic/rule", status="needs_human", file="file0.py", line=1,
                   file_hash="a" * 64, root_fingerprint="synthetic/root", evidence=[{"kind": "synthetic"}], snippet="not recopied")
    report = dict(schema_version=2, repo="synthetic", started_at="synthetic", profile="synthetic", engines_run=[], engines_missing=["synthetic-engine"],
                  findings=[finding], summary={}, run_status="complete", incomplete_reason=None,
                  coverage=[{"module_path": ".", "status": "candidate", "reason": None,
                             "reviewed_paths": ["file0.py"], "truncated_paths": [], "candidate_ids": ["synthetic-finding-1"]}],
                  verifier={"status": "not_run"}, ensemble=None)
    whole = copy.deepcopy(report)
    whole.update(findings=[], run_status="incomplete", incomplete_reason="units_failed")
    whole["coverage"][0].update(status="deferred", reason="synthetic failure")
    paired = [dict(row, finder_pos=i < 3, crossfamily_pos=i == 0) for i, row in enumerate(sample)]
    targets = []
    for i, name in enumerate(names):
        rankers = {arm: dict(status="ok", rank=i + 1, latency_ms=None, cost_usd=None, detail={})
                   for arm in ["baseline", "baseline-git-anchored", "metadata-llm", "jev"]}
        rankers["metadata-llm"].update(cost_usd=0.01, latency_ms=10)
        rankers["jev"].update(status="skipped: synthetic unavailable", rank=None)
        targets.append(dict(id=name, cve=f"CVE-SYNTHETIC-{i}", vuln_file=f"file{i}.py", code_files=1, modules=1, units=1, git={}, rankers=rankers))
    rank = dict(label="SYNTHETIC ONLY", walker={"git_head": "synthetic-a", "intake": {"sha256_12": "abcdef123456", "dirty": True}},
                summary={}, targets=targets)
    live = copy.deepcopy(rank)
    live["walker"]["git_head"] = "synthetic-b"
    for target in live["targets"]:
        del target["rankers"]["metadata-llm"]
        target["rankers"]["jev"].update(status="ok", rank=1, cost_usd=0.02)
    head = copy.deepcopy(rank)
    head["walker"] = {"git_head": "synthetic-a"}
    for target in head["targets"]:
        del target["rankers"]["metadata-llm"]
        del target["rankers"]["jev"]
    values = {SAMPLE: sample, FOCUSED: report, WHOLE: whole, OWASP: paired,
              "synthetic/paired-b.json": copy.deepcopy(paired), RANK: rank,
              "synthetic/rank-b.json": live, "synthetic/rank-c.json": head}
    blobs = {path: json.dumps(value, sort_keys=True).encode() for path, value in values.items()}
    blobs[TSV] = registry.encode()
    return blobs


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.blobs = synthetic_blobs()
        def ref(p, **extra):
            raw = self.blobs[p]
            return dict(path=p, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), **extra)
        configs = [
            ("focused", "recall-report-schema2-legacy", TSV, FOCUSED, ["recorded-scan"], "focused", "case1"),
            ("whole", "recall-report-schema2-legacy", TSV, WHOLE, ["recorded-scan"], "whole-repository", "case5"),
            ("owasp", "owasp-boolean-rows-legacy", SAMPLE, OWASP, ["finder-readout", "crossfamily-readout"], "single-file-synthetic-dataset", None),
            ("owasp-qwen", "owasp-boolean-rows-legacy", SAMPLE, "synthetic/paired-b.json", ["finder-readout", "crossfamily-readout"], "single-file-synthetic-dataset", None),
            ("rank", "ranking-target-rankers-legacy", TSV, RANK, ["baseline", "baseline-git-anchored", "metadata-llm", "jev"], "rank-only-audit-unit-order", None),
            ("rank-live", "ranking-target-rankers-legacy", TSV, "synthetic/rank-b.json", ["baseline", "baseline-git-anchored", "jev"], "rank-only-audit-unit-order", None),
            ("rank-head", "ranking-target-rankers-legacy", TSV, "synthetic/rank-c.json", ["baseline", "baseline-git-anchored"], "rank-only-audit-unit-order", None),
        ]
        self.manifest = {"schema": "vettalon-legacy-inputs-v1", "datasets": [
            dict(id=i, adapter=a, registry=ref(r), inputs=[ref(p, **({"case_id": c} if c else {}))],
                 arms=arms, scope=s, expected_cases=4 if r == SAMPLE else 9)
            for i, a, r, p, arms, s, c in configs]}

    def run_bundle(self):
        return n.normalize_bundle(self.manifest, self.blobs)

    def cohort(self, name):
        return next(c for c in self.run_bundle()["cohorts"] if c["id"] == name)

    def replace(self, path, value=None, raw=None):
        raw = json.dumps(value, allow_nan=False).encode() if raw is None else raw
        self.blobs[path] = raw
        for d in self.manifest["datasets"]:
            for r in [d["registry"], *d["inputs"]]:
                if r["path"] == path:
                    r.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))

    def mutate(self, path, change):
        obj = json.loads(self.blobs[path])
        change(obj)
        self.replace(path, obj)

    def test_01_self_contained_declared_synthetic_schemas(self):
        self.assertEqual(len(self.blobs), 9)
        self.assertTrue(all(path.startswith("synthetic/") for path in self.blobs))
        self.assertEqual(len(self.run_bundle()["cohorts"]), 7)
        self.assertIn(b"SYNTHETIC ONLY", self.blobs[RANK])

    def test_02_strict_json_duplicate_nonfinite(self):
        for raw in [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}']:
            with self.subTest(raw=raw), self.assertRaises(n.ReaderError):
                n.strict_json(raw)
        self.manifest["datasets"][0]["adapter"] = []
        with self.assertRaises(n.ReaderError):
            self.run_bundle()

    def test_03_registry_duplicate_empty_id(self):
        original = self.blobs[TSV]
        for raw in [original + original.splitlines(keepends=True)[1], original.replace(b"case1\t", b"\t", 1)]:
            self.replace(TSV, raw=raw)
            with self.assertRaises(n.ReaderError):
                self.run_bundle()

    def test_04_missing_input_retains_slots(self):
        self.manifest["datasets"][0]["inputs"] = []
        c = self.cohort("focused")
        self.assertEqual((c["case_denominator"], len(c["rows"]), c["missing_slots"]), (9, 9, 9))

    def test_05_secure_cli_bounds_paths_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            (base / "input").mkdir()
            (base / "input" / "ok").write_bytes(b"ok")
            (base / "alias").symlink_to(base / "input", target_is_directory=True)
            for path in ["../ok", "/ok", "a//b", "a/./b", "a\\b", "a/../b"]:
                with self.subTest(path=path), self.assertRaises(n.ReaderError):
                    n.relative_parts(path)
            with self.assertRaises((n.ReaderError, OSError)):
                n.read_absolute(str(base / "alias" / "ok"), 10)
            with self.assertRaises(n.ReaderError):
                n.read_absolute(str(base / "input" / "ok"), 1)
            n.write_exclusive(str(base / "out"), b"first")
            with self.assertRaises((n.ReaderError, OSError)):
                n.write_exclusive(str(base / "out"), b"second")
            self.assertEqual((base / "out").read_bytes(), b"first")
            (base / "input" / "leaf").symlink_to(base / "input" / "ok")
            with self.assertRaises((n.ReaderError, OSError)):
                n.read_absolute(str(base / "input" / "leaf"), 10)
            if hasattr(os, "mkfifo"):
                os.mkfifo(base / "input" / "pipe")
                with self.assertRaises(n.ReaderError):
                    n.read_absolute(str(base / "input" / "pipe"), 10)
            manifest = copy.deepcopy(self.manifest)
            manifest["datasets"] = manifest["datasets"][:1]
            for path in (TSV, FOCUSED):
                dest = base / "input" / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(self.blobs[path])
            (base / "manifest.json").write_text(json.dumps(manifest))
            args = ["--manifest", str(base / "manifest.json"), "--input-root", str(base / "input"), "--output", str(base / "normalized.json")]
            self.assertEqual(n.main(args), 0)
            self.assertEqual(json.loads((base / "normalized.json").read_bytes())["cohorts"][0]["case_denominator"], 9)
            with mock.patch("sys.stderr", new=__import__("io").StringIO()):
                self.assertEqual(n.main(args), 1)
            self.assertEqual((base / "input" / FOCUSED).read_bytes(), self.blobs[FOCUSED])
            # A false small declaration must bound the read before accumulation.
            (base / "input" / FOCUSED).write_bytes(b"x" * n.MAX_FILE)
            manifest["datasets"][0]["inputs"][0].update(bytes=1, sha256=hashlib.sha256(b"x").hexdigest())
            manifest_raw = json.dumps(manifest).encode()
            (base / "manifest.json").write_bytes(manifest_raw)
            args[-1] = str(base / "rejected.json")
            original_read, read_bytes = os.read, [0]
            def counted_read(fd, size):
                chunk = original_read(fd, size)
                read_bytes[0] += len(chunk)
                return chunk
            with mock.patch("os.read", side_effect=counted_read), \
                 mock.patch("sys.stderr", new=__import__("io").StringIO()):
                self.assertEqual(n.main(args), 1)
            self.assertLessEqual(read_bytes[0], len(manifest_raw) + len(self.blobs[TSV]))
            self.assertFalse((base / "rejected.json").exists())
            self.blobs[FOCUSED] += b" "
            with self.assertRaises(n.ReaderError):
                self.run_bundle()

    def test_06_recall_complete_is_reported_legacy_only(self):
        row = next(r for r in self.cohort("focused")["rows"] if r["case_id"] == "case1")
        self.assertEqual(row["reported"]["run_status"], "complete")
        self.assertIsNone(row["verified_completion"])
        self.assertFalse(row["modern_coverage_proven"])

    def test_07_incomplete_empty_is_not_safe(self):
        row = next(r for r in self.cohort("whole")["rows"] if r["case_id"] == "case5")
        self.assertEqual(row["reported"]["run_status"], "incomplete")
        self.assertEqual(row["reported"]["findings"], [])
        self.assertEqual(row["reported"]["incomplete_reason"], "units_failed")
        self.assertIsNone(row["adjudication"])

    def test_08_finding_identity_and_raw_pointers(self):
        row = next(r for r in self.cohort("focused")["rows"] if r["case_id"] == "case1")
        f = row["reported"]["findings"][0]
        self.assertEqual(f["id"], "synthetic-finding-1")
        self.assertEqual(f["raw_pointer"], "/findings/0")
        self.assertEqual(f["evidence_pointer"], "/findings/0/evidence")
        self.assertNotIn("snippet", f)
        self.assertEqual(row["lineage"]["input_sha256"], hashlib.sha256(self.blobs[FOCUSED]).hexdigest())
        self.mutate(FOCUSED, lambda x: x["findings"][0].update(line=None))
        row = next(r for r in self.cohort("focused")["rows"] if r["case_id"] == "case1")
        self.assertIsNone(row["reported"]["findings"][0]["line"])

    def test_09_duplicate_finding_and_foreign_case_reject(self):
        self.mutate(FOCUSED, lambda x: x["findings"].append(x["findings"][0]))
        with self.assertRaises(n.ReaderError):
            self.run_bundle()
        self.setUp()
        self.manifest["datasets"][0]["inputs"][0]["case_id"] = "foreign"
        with self.assertRaises(n.ReaderError):
            self.run_bundle()

    def test_10_reported_confirmed_is_not_human(self):
        self.mutate(FOCUSED, lambda x: x["findings"][0].update(status="confirmed"))
        row = next(r for r in self.cohort("focused")["rows"] if r["case_id"] == "case1")
        self.assertEqual(row["reported"]["findings"][0]["status"], "confirmed")
        self.assertIsNone(row["adjudication"])

    def test_11_focused_whole_cohorts_separate(self):
        out = self.run_bundle()
        self.assertNotEqual(out["cohorts"][0]["scope"], out["cohorts"][1]["scope"])
        self.assertNotIn("pooled_metrics", out)

    def test_12_owasp_declared_cases_and_paired_slots(self):
        c = self.cohort("owasp")
        self.assertEqual((c["case_denominator"], len(c["rows"])), (4, 8))
        self.assertEqual(c["declared_labels"], {"positive": 2, "safe": 2})
        self.assertEqual(c["comparison_design"], "paired-readouts-not-independent-runs")

    def test_13_owasp_booleans_only_proxies(self):
        c = self.cohort("owasp")
        raw = json.loads(self.blobs[OWASP])
        self.assertEqual(c["reported_boolean_counts"]["finder-readout"], sum(r["finder_pos"] for r in raw))
        self.assertTrue(all(r["verified_completion"] is None for r in c["rows"]))
        self.assertIsNone(c["adjudicated_metrics"])

    def test_14_owasp_missing_case_fixed_denominator(self):
        self.mutate(OWASP, lambda x: x.pop())
        c = self.cohort("owasp")
        self.assertEqual((c["case_denominator"], len(c["rows"]), c["missing_slots"]), (4, 8, 2))

    def test_15_owasp_duplicate_foreign_id_reject(self):
        for foreign in [False, True]:
            self.setUp()
            self.mutate(OWASP, lambda x: x[-1].update(id="unknown" if foreign else x[0]["id"]))
            with self.assertRaises(n.ReaderError):
                self.run_bundle()

    def test_16_owasp_metadata_mismatch_reject(self):
        for key, value in [("real", False), ("cwe", "other"), ("cat", "other"), ("expect_class", "other")]:
            self.setUp()
            obj = json.loads(self.blobs[OWASP])
            obj[0][key] = not obj[0][key] if key == "real" else value
            self.replace(OWASP, obj)
            with self.assertRaises(n.ReaderError):
                self.run_bundle()

    def test_17_owasp_exact_bool_and_impossible_pair(self):
        for update in [dict(finder_pos=1), dict(finder_pos=False, crossfamily_pos=True)]:
            self.setUp()
            self.mutate(OWASP, lambda x: x[0].update(update))
            with self.assertRaises(n.ReaderError):
                self.run_bundle()

    def test_18_summary_prose_unsupported(self):
        self.replace(OWASP, {"summary": "160 passed"})
        with self.assertRaises(n.ReaderError):
            self.run_bundle()

    def test_19_skipped_rankers_keep_nine_slots(self):
        c = self.cohort("rank")
        rows = [r for r in c["rows"] if r["arm_id"] == "jev"]
        self.assertEqual(len(rows), 9)
        self.assertTrue(all(r["observation_status"] == "skipped" for r in rows))
        self.assertEqual(c["rank_diagnostics"]["jev"]["n"], 9)
        self.assertIsNone(c["cost"]["jev"]["total_usd"])

    def test_20_producer_identity_variants_separate(self):
        self.assertEqual(self.cohort("rank")["reported_producer_identity"]["git_head"], "synthetic-a")
        self.assertEqual(self.cohort("rank-live")["reported_producer_identity"]["git_head"], "synthetic-b")
        self.assertIsNone(self.cohort("rank")["rows"][0]["source_identity"]["observed_revision"])

    def test_21_missing_target_keeps_nine(self):
        self.mutate(RANK, lambda x: x["targets"].pop())
        c = self.cohort("rank")
        self.assertEqual((c["case_denominator"], c["missing_slots"]), (9, 4))
        self.assertEqual(c["rank_diagnostics"]["baseline"]["n"], 9)

    def test_22_tampered_summary_does_not_override(self):
        before = self.cohort("rank")["rank_diagnostics"]
        self.mutate(RANK, lambda x: x["summary"].update(baseline={"n": 99, "hit@5": 99}))
        c = self.cohort("rank")
        self.assertEqual(c["rank_diagnostics"], before)
        self.assertFalse(c["summary_matches_diagnostics"])
        for summary in [{}, {"baseline": {k: before["baseline"][k] for k in ("n", "hit@5", "hit@10", "hit@40", "mrr")}}]:
            with self.subTest(missing_summary_arms=list(summary)):
                self.mutate(RANK, lambda x: x.update(summary=summary))
                self.assertFalse(self.cohort("rank")["summary_matches_diagnostics"])
        # Python equality must not let True/1.0 impersonate integer counts.
        self.setUp()
        self.manifest["datasets"] = [self.manifest["datasets"][4]]
        self.manifest["datasets"][0].update(expected_cases=1, arms=["baseline"])
        self.replace(TSV, raw=b"\n".join(self.blobs[TSV].splitlines()[:2]) + b"\n")
        report = json.loads(self.blobs[RANK])
        report["targets"] = report["targets"][:1]
        report["targets"][0]["rankers"] = {"baseline": report["targets"][0]["rankers"]["baseline"]}
        correct = {"n": 1, "hit@5": 1, "hit@10": 1, "hit@40": 1, "mrr": 1.0}
        report["summary"] = {"baseline": correct}
        self.replace(RANK, report)
        self.assertTrue(self.cohort("rank")["summary_matches_diagnostics"])
        for field, value in [("n", True), ("n", 1.0), ("hit@5", True), ("hit@10", 1.0), ("hit@40", True), ("mrr", True)]:
            with self.subTest(field=field, value_type=type(value).__name__):
                summary = dict(correct)
                summary[field] = value
                self.mutate(RANK, lambda x: x.update(summary={"baseline": summary}))
                c = self.cohort("rank")
                self.assertFalse(c["summary_matches_diagnostics"])
                self.assertEqual(type(c["reported_summary"]["baseline"][field]), type(value))

    def test_23_summary_without_targets_reject(self):
        self.mutate(RANK, lambda x: x.pop("targets"))
        with self.assertRaises(n.ReaderError):
            self.run_bundle()

    def test_24_duplicate_target_undeclared_arm_reject(self):
        self.mutate(RANK, lambda x: x["targets"].append(x["targets"][0]))
        with self.assertRaises(n.ReaderError):
            self.run_bundle()
        self.setUp()
        self.mutate(RANK, lambda x: x["targets"][0]["rankers"].update(unknown={}))
        with self.assertRaises(n.ReaderError):
            self.run_bundle()

    def test_25_rank_types_and_no_baseline_units_ceiling(self):
        for value in [True, 0, -1, 1.5, "1"]:
            self.setUp()
            self.mutate(RANK, lambda x: x["targets"][0]["rankers"]["baseline"].update(rank=value))
            with self.assertRaises(n.ReaderError):
                self.run_bundle()
        self.setUp()
        self.mutate(RANK, lambda x: x["targets"][0]["rankers"]["baseline"].update(rank=99999))
        self.assertEqual(self.cohort("rank")["rows"][0]["reported"]["rank"], 99999)

    def test_26_cost_unknown_failure_and_null_rank_preserved(self):
        self.mutate(RANK, lambda x: x["targets"][0]["rankers"]["baseline"].update(status="error: timed out", rank=None, cost_usd=0))
        c = self.cohort("rank")
        self.assertEqual(c["rows"][0]["observation_status"], "failed")
        self.assertEqual(c["cost"]["baseline"]["known_subtotal_usd"], 0)
        self.assertIsNone(c["cost"]["baseline"]["total_usd"])
        self.assertIsNone(c["cost"]["jev"]["known_subtotal_usd"])
        self.mutate(RANK, lambda x: x["targets"][0]["rankers"]["baseline"].update(status="ok"))
        self.assertEqual(self.cohort("rank")["rows"][0]["observation_status"], "not_observed")

    def test_27_fingerprint_binds_raw_and_cohort(self):
        before = next(r for r in self.cohort("focused")["rows"] if r["case_id"] == "case1")
        self.replace(FOCUSED, raw=self.blobs[FOCUSED] + b" ")
        after = next(r for r in self.cohort("focused")["rows"] if r["case_id"] == "case1")
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])
        self.manifest["datasets"][0]["id"] = "different"
        self.assertNotEqual(after["fingerprint"], next(r for r in self.cohort("different")["rows"] if r["case_id"] == "case1")["fingerprint"])

    def test_28_short_absent_identity_not_forged(self):
        c = self.cohort("rank-head")
        self.assertNotIn("intake", c["reported_producer_identity"])
        self.assertEqual(c["implementation_identity_quality"], "historical-declaration-not-attestation")
        self.assertIsNone(c["rows"][0]["source_identity"]["verified_source_sha256"])

    def test_29_normalization_no_io_process_network_measurement(self):
        with mock.patch("builtins.open", side_effect=AssertionError("unexpected IO")), \
             mock.patch("os.open", side_effect=AssertionError("unexpected IO")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("unexpected child")), \
             mock.patch("socket.socket", side_effect=AssertionError("unexpected network")):
            self.assertEqual(self.run_bundle()["normalization_status"], "complete")

    def test_30_absent_adjudicated_and_resource_metrics(self):
        for c in self.run_bundle()["cohorts"]:
            self.assertIsNone(c["adjudicated_metrics"])
            for r in c["rows"]:
                self.assertIsNone(r["adjudication"])
                self.assertEqual(r["resources"], {"cpu_seconds": None, "rss_bytes": None, "human_seconds": None, "tokens": None})

    def test_31_deterministic_no_mutation(self):
        m, b = copy.deepcopy(self.manifest), dict(self.blobs)
        self.assertEqual(self.run_bundle(), self.run_bundle())
        self.assertEqual((self.manifest, self.blobs), (m, b))

    def test_32_independent_schema_not_synthetic_adjudicated(self):
        out = self.run_bundle()
        self.assertEqual(out["schema"], "vettalon-legacy-observations-v1")
        self.assertNotEqual(out["schema"], "vettalon-synthetic-twins-v1")
        self.assertFalse(out["automatic_adjudicated_metric_feed"])
        self.assertNotIn("precision", out)


if __name__ == "__main__":
    unittest.main()
