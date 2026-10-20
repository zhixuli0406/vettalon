"""Offline checks for the reachability corpus; no Go, network or tool execution."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import adapter
import run_corpus

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
RESULTS = CORPUS / "RESULTS-2026-10-20.json"
EXPORT = ROOT.parents[1] / "scripts" / "export-oss.sh"


def row(host="h", klass="called", truth="executed", state="reachable", pinned="affected", latest="affected"):
    return {"host": host, "class": klass, "truth": truth, "adapter": state, "adapter_vex": "under_investigation",
            "vex_pinned": pinned, "vex_latest": latest}


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.advisories = run_corpus.load_manifest()

    def test_corpus_shape(self):
        self.assertTrue(12 <= len(self.advisories) <= 20)
        classes = {h["class"] for h in self.manifest["hosts"]}
        self.assertEqual(classes, {"called", "not-called", "reflection", "interface", "funcvalue", "unsafe"})
        self.assertEqual(sorted(p.name for p in (CORPUS / "hosts").iterdir()),
                         sorted(h["name"] for h in self.manifest["hosts"]))

    def test_hosts_pin_target_and_list_expected_advisories(self):
        for host in self.manifest["hosts"]:
            advisory = self.advisories[host["advisory"]]
            directory = CORPUS / "hosts" / host["name"]
            with self.subTest(host=host["name"]):
                module = (directory / "go.mod").read_text()
                self.assertIn(advisory["module"] + " " + advisory["version"], module)
                self.assertNotRegex(module, r"(?m)^\s*(replace|toolchain)\b")
                self.assertTrue((directory / "go.sum").is_file())
                ignored = (directory / "osv-scanner.toml").read_text()
                self.assertIn('id = "%s"' % advisory["id"], ignored)
                self.assertEqual(ignored.count("[[IgnoredVulns]]"), ignored.count("reason = \"Reachability corpus fixture"))

    def test_blind_spot_signals_match_host_classes(self):
        for host in self.manifest["hosts"]:
            signals = adapter.blind_spot_signals(CORPUS / "hosts" / host["name"])
            with self.subTest(host=host["name"]):
                if host["class"] == "reflection":
                    self.assertIn("reflect", signals)
                elif host["class"] == "unsafe":
                    self.assertIn("unsafe", signals)
                else:
                    # Plain, interface and function-value hosts must not lean on the downgrade rule.
                    self.assertEqual(signals, [])

    def test_snapshot_tamper_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            copy_root = Path(temp) / "corpus"
            (copy_root / "vulndb").mkdir(parents=True)
            (copy_root / "hosts").mkdir()
            (copy_root / "corpus.json").write_bytes((CORPUS / "corpus.json").read_bytes())
            for path in (CORPUS / "vulndb").iterdir():
                (copy_root / "vulndb" / path.name).write_bytes(path.read_bytes())
            first = sorted((copy_root / "vulndb").iterdir())[0]
            first.write_bytes(first.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "checksum"):
                run_corpus.load_manifest(copy_root)


class VersionRangeTests(unittest.TestCase):
    def entry(self, *events):
        return {"affected": [{"package": {"name": "m"}, "ranges": [{"type": "SEMVER", "events": list(events)}]}]}

    def test_reintroduced_ranges_and_pseudo_versions(self):
        logrus = self.entry({"introduced": "0"}, {"fixed": "1.8.3"}, {"introduced": "1.9.0"},
                            {"fixed": "1.9.1"}, {"introduced": "1.9.2"}, {"fixed": "1.9.3"})
        expected = {"v1.8.2": True, "v1.8.3": False, "v1.9.0": True, "v1.9.1": False, "v1.9.2": True, "v1.9.3": False}
        for version, value in expected.items():
            self.assertEqual(run_corpus.affected(logrus, "m", version), value, version)
        yaml = self.entry({"introduced": "0"}, {"fixed": "3.0.0-20220521103104-8f96da9f5d5e"})
        self.assertTrue(run_corpus.affected(yaml, "m", "v3.0.0-20210107192922-496545a6307b"))
        self.assertFalse(run_corpus.affected(yaml, "m", "v3.0.0"))
        self.assertTrue(run_corpus.affected(self.entry({"introduced": "0"}), "m", "v3.2.0+incompatible"))
        self.assertFalse(run_corpus.affected(self.entry({"introduced": "0"}), "other", "v1.0.0"))
        self.assertFalse(run_corpus.affected(self.entry({"introduced": "0"}, {"last_affected": "1.0.0"}), "m", "v1.0.1"))
        with self.assertRaises(ValueError):
            run_corpus.affected(self.entry({"limit": "1"}), "m", "v1.0.0")
        # OSV does not promise event order.
        shuffled = self.entry({"fixed": "1.9.1"}, {"introduced": "1.9.0"}, {"fixed": "1.8.3"}, {"introduced": "0"})
        self.assertTrue(run_corpus.affected(shuffled, "m", "v1.9.0"))
        self.assertFalse(run_corpus.affected(shuffled, "m", "v1.8.5"))


class TruthLabelTests(unittest.TestCase):
    SOURCE = """package p

func Parse(s string) error { return nil }

func (d *Decoder) Decode(v any) error {
	return nil
}

func (s stack[T]) push(v T) {}

func helper() {}
"""

    def test_symbol_index_and_coverage_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "p.go").write_text(self.SOURCE)
            (Path(temp) / "p_test.go").write_text("package p\n\nfunc Parse() {}\n")
            index = run_corpus.symbol_index(temp, "example.com/p")
        self.assertEqual(index, {("example.com/p/p.go", 3): "Parse", ("example.com/p/p.go", 5): "Decoder.Decode",
                                 ("example.com/p/p.go", 9): "stack.push", ("example.com/p/p.go", 11): "helper"})
        rows = run_corpus.parse_cover_func("example.com/p/p.go:3:\tParse\t\t0.0%\n"
                                           "example.com/p/p.go:5:\tDecode\t\t100.0%\ntotal:\t(statements)\t50.0%\n")
        advisory = {"symbols": {"example.com/p": ["Parse", "Decoder.Decode", "Gone"]}}
        truth, detail = run_corpus.label_truth(advisory, rows, {"example.com/p": index})
        self.assertEqual(truth, "executed")
        self.assertFalse(detail["example.com/p.Gone"]["declared"])
        rows[("example.com/p/p.go", 5)] = 0.0
        self.assertEqual(run_corpus.label_truth(advisory, rows, {"example.com/p": index})[0], "not-executed")
        self.assertEqual(run_corpus.label_truth({"symbols": {"example.com/p": ["Gone"]}}, rows,
                                                {"example.com/p": index})[0], "unknown")

    def test_linked_symbol_without_cover_row_is_unknown(self):
        index = {("example.com/p/p.go", 3): "Parse"}
        advisory = {"symbols": {"example.com/p": ["Parse"]}}
        self.assertEqual(run_corpus.label_truth(advisory, {}, {"example.com/p": index}, {"example.com/p"})[0], "unknown")
        self.assertEqual(run_corpus.label_truth(advisory, {}, {"example.com/p": index}, set())[0], "not-executed")

    def test_module_cache_path_escaping(self):
        self.assertEqual(run_corpus.module_dir("/c", "github.com/Masterminds/goutils", "v1.1.0").as_posix(),
                         "/c/github.com/!masterminds/goutils@v1.1.0")


class GroundTruthGuardTests(unittest.TestCase):
    """An empty or partial coverage profile must become unknown, never not-executed."""

    def run_truth(self, cover_text, deps_text):
        from test_process_supervisor import observed_run

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "cache" / "example.com" / "dep@v1.0.0" / "p"
            source.mkdir(parents=True)
            (source / "p.go").write_text("package p\n\nfunc Parse() {}\n")

            def fake(command, cwd, env, timeout):
                if "build" in command:
                    Path(command[command.index("-o") + 1]).write_bytes(b"binary")
                if command[-1].startswith("-func="):
                    return observed_run(command, cover_text)
                if "-deps" in command:
                    return observed_run(command, deps_text)
                return observed_run(command, "")

            advisory = {"module": "example.com/dep", "version": "v1.0.0", "symbols": {"example.com/dep/p": ["Parse"]}}
            with patch("run_corpus.adapter.invoke", side_effect=fake):
                return run_corpus.ground_truth("go", {"HOME": temp}, root, advisory, root / "cache", root / "out")

    def test_profile_guards(self):
        main_row = "example.com/host/main.go:5:\tmain\t\t100.0%\n"
        dep_row = "example.com/dep/p/p.go:3:\tParse\t\t0.0%\n"
        linked = "example.com/host\nexample.com/dep/p\n"
        self.assertEqual(self.run_truth("", linked)["reason"], "coverage-missing-main-package")
        self.assertEqual(self.run_truth(main_row, linked)["reason"], "coverage-missing-advisory-package")
        self.assertEqual(self.run_truth(main_row + dep_row, linked)["truth"], "not-executed")
        self.assertEqual(self.run_truth(main_row + dep_row.replace("0.0%", "50.0%"), linked)["truth"], "executed")
        # Not linked at all: the symbol cannot run in this binary.
        self.assertEqual(self.run_truth(main_row, "example.com/host\n")["truth"], "not-executed")


class OpenVexTests(unittest.TestCase):
    def test_statement_selection(self):
        document = {"statements": [{"vulnerability": {"name": "GO-1"}, "status": "not_affected",
                                    "justification": "vulnerable_code_not_in_execute_path"},
                                   {"vulnerability": {"name": "GO-2"}, "status": "affected"}]}
        raw = json.dumps(document)
        self.assertEqual(run_corpus.openvex_status(raw, "GO-1")["status"], "not_affected")
        self.assertEqual(run_corpus.openvex_status(raw, "GO-3")["status"], "absent")
        self.assertEqual(run_corpus.openvex_status("{", "GO-1")["status"], "invalid")
        document["statements"].append(document["statements"][0])
        self.assertEqual(run_corpus.openvex_status(json.dumps(document), "GO-1")["status"], "ambiguous")


class GateTests(unittest.TestCase):
    BLIND = {"reflection", "interface", "funcvalue", "unsafe"}

    def test_passing_rows(self):
        rows = [row(), row("n", "not-called", "not-executed", "not-observed", "not_affected", "not_affected"),
                row("r", "reflection", "executed", "unknown", "not_affected", "not_affected")]
        report = run_corpus.evaluate(rows, self.BLIND)
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["totals"]["vex_pinned_false_not_affected"], 1)
        self.assertEqual(report["classes"]["called"]["adapter_recall"], 1.0)

    def test_false_unreachable_fails(self):
        report = run_corpus.evaluate([row(state="not-observed")], self.BLIND)
        self.assertFalse(report["gates"]["false_unreachable_zero"])
        self.assertFalse(report["passed"])

    def test_blind_spot_not_observed_fails_even_without_execution(self):
        report = run_corpus.evaluate([row("u", "unsafe", "not-executed", "not-observed")], self.BLIND)
        self.assertEqual(report["blind_spot_violations"], ["u"])
        self.assertFalse(report["passed"])

    def test_incomplete_and_not_affected_emission_fail(self):
        for bad in (row(truth="unknown"), row(state="unknown"), row(pinned="tool-error"), row(latest="absent")):
            self.assertFalse(run_corpus.evaluate([bad], self.BLIND)["gates"]["complete_observation"], bad)
        emitted = row()
        emitted["adapter_vex"] = "not_affected"
        self.assertFalse(run_corpus.evaluate([emitted], self.BLIND)["gates"]["adapter_never_not_affected"])

    def test_false_reachable_hosts_listed(self):
        report = run_corpus.evaluate([row("n", "not-called", "not-executed", "reachable")], self.BLIND)
        self.assertEqual(report["false_reachable_hosts"], ["n"])

    def test_version_diffs_counted(self):
        report = run_corpus.evaluate([row(latest="not_affected")], self.BLIND)
        self.assertEqual(report["totals"]["vex_version_diffs"], 1)


class RecordedResultTests(unittest.TestCase):
    def test_recorded_summary_recomputes(self):
        summary = json.loads(RESULTS.read_text())
        manifest, _ = run_corpus.load_manifest()
        report = run_corpus.evaluate(summary["hosts"], set(manifest["blind_spot_classes"]))
        for key in ("classes", "totals", "gates", "passed"):
            self.assertEqual(report[key], summary[key], key)
        self.assertEqual(summary["corpus_sha256"], adapter.digest((CORPUS / "corpus.json").read_bytes()))
        self.assertEqual(len(summary["hosts"]), len(manifest["hosts"]))
        self.assertEqual(summary["govulncheck"]["pinned"], adapter.TOOL_VERSION)
        self.assertNotRegex(RESULTS.read_text(), r"/(Users|home|private|var/folders)/")

    def test_tampered_row_changes_gate(self):
        summary = json.loads(RESULTS.read_text())
        rows = copy.deepcopy(summary["hosts"])
        executed = next(r for r in rows if r["truth"] == "executed")
        executed["adapter"] = "not-observed"
        self.assertFalse(run_corpus.evaluate(rows, {"reflection", "interface", "funcvalue", "unsafe"})["passed"])


@unittest.skipUnless(EXPORT.is_file(), "export allowlist exists only in the private development tree")
class ExportAllowTests(unittest.TestCase):
    def test_every_corpus_file_is_allowlisted_individually(self):
        allow = set(re.findall(r"(?m)^\s+(benchmarks/reachability/\S+)$", EXPORT.read_text()))
        expected = {"benchmarks/reachability/run_corpus.py", "benchmarks/reachability/test_corpus.py"}
        expected |= {path.relative_to(ROOT.parents[1]).as_posix() for path in CORPUS.rglob("*") if path.is_file()}
        self.assertEqual(expected - allow, set())
        self.assertNotIn("benchmarks/reachability/corpus", allow)


if __name__ == "__main__":
    unittest.main()
