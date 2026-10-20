"""Offline SBOM differential and parser-confusion checks; no Syft, Cargo or network."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
import cargo_graph  # noqa: E402
import sbom_diff  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
RECORDED = REPO / "fixtures" / "sbom" / "differential"
CONFUSION = REPO / "fixtures" / "sbom" / "confusion"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

# Expected outcome per recorded case. "refused" and "matches-oracle" mean the
# adapter was not misled; Syft rows document observed upstream behavior.
EXPECTED = {
    "dependency-in-comment": {"adapter": "matches-oracle", "syft": "matches-oracle"},
    "string-smuggled-package": {"adapter": "matches-oracle", "syft": "matches-oracle"},
    "embedded-sbom-decoy": {"adapter": "matches-oracle", "syft": "matches-oracle"},
    "duplicate-key-lock": {"adapter": "refused", "syft": "accepted-invalid-input"},
    "duplicate-key-manifest": {"adapter": "refused", "syft": "accepted-invalid-input"},
    "multiple-manifests": {"adapter": "refused", "syft": "differs-from-oracle"},
    # Known limitation: the lock graph is not checked against manifest edits.
    "stale-lock": {"adapter": "accepted-invalid-input", "syft": "accepted-invalid-input"},
}


def load(case, name):
    return json.loads((RECORDED / case / name).read_text())


class CompareTests(unittest.TestCase):
    def test_precision_recall_version_and_license_are_separate(self):
        truth = {"a@1.0.0": {"license": "MIT"}, "b@2.0.0": {"license": "MIT/Apache-2.0"},
                 "c@1.0.0": {"license": None}, "d@1.0.0": {"license": "MIT"}}
        observed = {"a@1.0.0": {"licenses": ["MIT"]}, "b@2.0.0": {"licenses": ["MIT OR Apache-2.0"]},
                    "c@1.0.0": {"licenses": []}, "d@9.0.0": {"licenses": []}, "e@1.0.0": {"licenses": []}}
        result = sbom_diff.compare(truth, observed)
        self.assertEqual((result["precision"], result["recall"]), (0.6, 0.75))
        self.assertEqual((result["version_accuracy"], result["version_mismatch"]), (0.75, ["d"]))
        self.assertEqual((result["license_evaluated"], result["license_correct"], result["license_accuracy"]), (2, 2, 1.0))
        self.assertEqual(result["extra"], ["d@9.0.0", "e@1.0.0"])
        empty = sbom_diff.compare({}, {})
        self.assertIsNone(empty["precision"])
        self.assertIsNone(empty["license_accuracy"])

    def test_metadata_truth_excludes_dev_only_edges(self):
        metadata = {
            "workspace_members": ["root"],
            "packages": [{"id": i, "name": i, "version": "1.0.0", "license": "MIT",
                          "source": None if i == "root" else REGISTRY} for i in ("root", "lib", "build", "dev")],
            "resolve": {"nodes": [
                {"id": "root", "deps": [
                    {"pkg": "lib", "dep_kinds": [{"kind": None, "target": None}]},
                    {"pkg": "build", "dep_kinds": [{"kind": "build", "target": None}]},
                    {"pkg": "dev", "dep_kinds": [{"kind": "dev", "target": None}]}]},
                {"id": "lib", "deps": []}, {"id": "build", "deps": []}, {"id": "dev", "deps": []}]}}
        truth = sbom_diff.metadata_truth(metadata)
        self.assertEqual(sorted(truth["packages"]), ["build@1.0.0", "lib@1.0.0", "root@1.0.0"])
        self.assertEqual(truth["packages"]["root@1.0.0"]["origin"], "path")

    def test_precursor_ids_and_reachability(self):
        self.assertEqual(sbom_diff.parse_precursor_id(REGISTRY + "#itoa@1.0.15"), ("itoa@1.0.15", "registry"))
        self.assertEqual(sbom_diff.parse_precursor_id("path+file:///x/demo#0.1.0"), ("demo@0.1.0", "path"))
        with self.assertRaises(ValueError):
            sbom_diff.parse_precursor_id("nonsense")
        document = {"version": 1, "root": 0, "crates": [
            {"id": "path+file:///x/app#0.1.0", "dependencies": [{"index": 1, "kind": "normal"}]},
            {"id": REGISTRY + "#a@1.0.0", "dependencies": []},
            {"id": REGISTRY + "#orphan@1.0.0", "dependencies": []}]}
        self.assertEqual(sorted(sbom_diff.precursor_truth([document])["packages"]), ["a@1.0.0", "app@0.1.0"])
        with self.assertRaises(ValueError):
            sbom_diff.precursor_truth([{**document, "version": 2}])

    def test_bom_inventory_and_sanitizer(self):
        bom = {"metadata": {"timestamp": "t", "component": {"type": "file", "name": "/abs/root/"}},
               "serialNumber": "urn:x",
               "components": [{"purl": "pkg:cargo/a@1.0.0", "licenses": [{"license": {"id": "MIT"}}]},
                              {"purl": "pkg:cargo/a@1.0.0"}, {"name": "/abs/root/Cargo.lock", "type": "file"}]}
        inventory, duplicates = sbom_diff.bom_inventory(bom)
        self.assertEqual((sorted(inventory), duplicates), (["a@1.0.0"], ["a@1.0.0"]))
        clean = sbom_diff.sanitize_bom(bom, "/abs/root")
        self.assertEqual(clean["metadata"]["component"]["name"], "./")
        self.assertEqual(clean["components"][2]["name"], "./Cargo.lock")
        self.assertNotIn("timestamp", clean["metadata"])
        self.assertNotIn("serialNumber", clean)


class RecordedSnapshotTests(unittest.TestCase):
    def test_every_recorded_case_has_expected_verdicts(self):
        self.assertEqual(sorted(p.name for p in RECORDED.iterdir() if p.is_dir()), sorted([*EXPECTED, "rust"]))
        self.assertEqual(sorted(p.name for p in CONFUSION.iterdir()), sorted(EXPECTED))
        for case, expected in EXPECTED.items():
            with self.subTest(case=case):
                result = sbom_diff.report(load(case, "snapshot.json"))
                self.assertEqual(result["verdicts"], expected)

    def test_rust_fixture_metrics(self):
        snapshot = load("rust", "snapshot.json")
        result = sbom_diff.report(snapshot)
        self.assertEqual(result["oracle_status"], {"metadata": "ok", "precursor": "ok"})
        agreement = result["oracle_agreement"]
        self.assertEqual((agreement["precision"], agreement["recall"]), (1.0, 1.0))
        syft = result["comparisons"]["syft"]["metadata"]
        # Cargo.lock keeps serde_derive behind a never-true cfg; the build graph does not.
        self.assertEqual((syft["truth_count"], syft["observed_count"], syft["recall"]), (7, 12, 1.0))
        self.assertEqual(syft["extra"], ["proc-macro2@1.0.107", "quote@1.0.47", "serde_derive@1.0.229",
                                         "syn@3.0.9", "unicode-ident@1.0.27"])
        self.assertEqual((syft["version_accuracy"], syft["license_correct"]), (1.0, 0))
        adapter = result["comparisons"]["adapter"]["metadata"]
        self.assertEqual((adapter["precision"], adapter["license_correct"], adapter["license_evaluated"]), (0.5833, 6, 7))
        self.assertEqual(snapshot["tools"]["syft"], "1.34.2")

    def test_recordings_hold_no_absolute_paths(self):
        for path in RECORDED.rglob("*.json"):
            text = path.read_text()
            with self.subTest(path=path.name):
                self.assertNotRegex(text, r"/(Users|home|private|var/folders)/")
                self.assertNotIn("serialNumber", text)

    def test_recorded_syft_boms_are_cyclonedx_16(self):
        for path in RECORDED.glob("*/syft.cdx.json"):
            bom = json.loads(path.read_text())
            self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.6"), path)


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "no-follow source reading unavailable")
class AdapterReplayTests(unittest.TestCase):
    """Replay the recorded raw Syft BOM through the adapter's graph check."""

    def replay(self, case):
        return cargo_graph.verify_cargo_graph(load(case, "syft.cdx.json"), CONFUSION / case)

    def test_adapter_refuses_or_matches_confusion_inputs(self):
        for case, expected in EXPECTED.items():
            if case == "stale-lock":
                continue
            with self.subTest(case=case):
                if expected["adapter"] == "refused":
                    with self.assertRaises(ValueError):
                        self.replay(case)
                else:
                    verified = self.replay(case)
                    oracle = load(case, "snapshot.json")["metadata"]["packages"]
                    self.assertEqual(verified["package_count"], len(oracle))

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "pinned jsonschema venv required")
    def test_full_adapter_path_agrees_with_recorded_verdicts(self):
        import trust
        for case, expected in EXPECTED.items():
            with self.subTest(case=case):
                try:
                    sbom_diff.adapt_syft_bom(trust, load(case, "syft.cdx.json"), CONFUSION / case)
                    outcome = "accepted"
                except ValueError:
                    outcome = "refused"
                self.assertEqual(outcome, "refused" if expected["adapter"] == "refused" else "accepted")

    @unittest.expectedFailure
    def test_stale_lock_is_refused(self):
        # Known limitation: manifest dependency edits are not compared with the
        # lock graph, so a stale lock is accepted. Cargo --locked rejects it.
        with self.assertRaises(ValueError):
            self.replay("stale-lock")


if __name__ == "__main__":
    unittest.main()
