"""Ordinary correctness review regressions for native identity and failed runs."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import native
import trust
from test_operations import load

probe = load("probe_review", "dataflow-probe.py")


class ReviewRegressions(unittest.TestCase):
    def test_native_cannot_relabel_cargo_as_npm(self):
        for purl in (
            "pkg:cargo/a@1",
            "pkg:npm/other@1",
            "pkg:npm/a@2",
            "pkg:npm/a@1?source=unknown",
        ):
            bom = {
                "components": [
                    {"name": "a", "version": "1", "purl": purl, "bom-ref": "a"}
                ]
            }
            with self.assertRaises(ValueError, msg=purl):
                native.enrich(
                    bom, {("a", "1")}, set(), {("a", "1")}, "npm-lock-v3", "a" * 64
                )

    def test_mixed_ecosystems_bind_only_matching_purl_in_either_order(self):
        import copy

        foreign = {
            "name": "a",
            "version": "1",
            "purl": "pkg:cargo/a@1",
            "bom-ref": "cargo-ref",
        }
        wanted = {
            "name": "a",
            "version": "1",
            "purl": "pkg:npm/a@1",
            "bom-ref": "npm-ref",
        }
        for order in ([foreign, wanted], [wanted, foreign]):
            result = native.enrich(
                {"components": copy.deepcopy(order)},
                {("a", "1")},
                set(),
                {("a", "1")},
                "npm-lock-v3",
                "a" * 64,
            )
            foreign_result = next(
                c for c in result["components"] if c["bom-ref"] == "cargo-ref"
            )
            self.assertNotIn("properties", foreign_result)
            wanted_result = next(
                c for c in result["components"] if c["bom-ref"] == "npm-ref"
            )
            self.assertIn(
                {"name": "vettalon:dependency:role", "value": "direct"},
                wanted_result["properties"],
            )

    def test_selected_go_error_and_missing_version_rejected(self):
        for item in (
            {"Path": "a", "Version": "v1", "Error": {"Err": "unresolved"}},
            {"Path": "a"},
        ):
            with self.assertRaises(ValueError):
                native.selected_go_modules([item])

    def test_go_unknown_endpoint_is_not_silently_dropped(self):
        for graph in (
            "app missing/a@v1\n",
            "missing/a@v1 go@1.21\n",
            "known/a@v1 missing/a@v1\n",
        ):
            with self.assertRaises(ValueError, msg=graph):
                native.go_graph(
                    {"Module": {"Path": "app"}}, graph, {"app": None, "known/a": "v1"}
                )

    def test_go_replacements_are_explicitly_unsupported(self):
        with self.assertRaises(ValueError):
            native.go_graph(
                {
                    "Replace": [
                        {
                            "Old": {"Path": "a", "Version": "v1"},
                            "New": {"Path": "../local"},
                        }
                    ]
                },
                "",
                {"a": "v1"},
            )
        with self.assertRaises(ValueError):
            native.selected_go_modules(
                [
                    {
                        "Path": "a",
                        "Version": "v1",
                        "Replace": {"Path": "fork/a", "Version": "v2"},
                    }
                ]
            )

    def test_go_historical_exclusion_remains_explainable(self):
        excluded = []
        _, edges, _ = native.go_graph(
            {}, "a@v1 b@v1\na@v2 b@v1\n", {"a": "v2", "b": "v1"}, exclusions=excluded
        )
        self.assertEqual(edges, {(("a", "v2"), ("b", "v1"))})
        self.assertEqual(excluded, ["a@v1 b@v1"])

    def test_go_unselected_source_can_explain_unresolved_old_target(self):
        exclusions = []
        _, edges, _ = native.go_graph(
            {}, "a@v1 old-only@v0\n", {"a": "v2"}, exclusions=exclusions
        )
        self.assertEqual(edges, set())
        self.assertEqual(exclusions, ["a@v1 old-only@v0"])

    def test_cargo_manifest_name_version_alone_is_not_license_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = root / "registry/src/unrelated/a-1"
            cache.mkdir(parents=True)
            (cache / "Cargo.toml").write_text(
                '[package]\nname="a"\nversion="1"\nlicense="MIT"\n'
            )
            bom = {
                "components": [{"name": "a", "version": "1", "purl": "pkg:cargo/a@1"}]
            }
            with patch.dict(trust.os.environ, {"CARGO_HOME": str(root)}):
                trust.enrich_cargo_licenses(bom)
            self.assertNotIn("licenses", bom["components"][0])

    def test_existing_catalog_license_is_preserved_without_false_binding(self):
        bom = {
            "components": [
                {
                    "name": "a",
                    "version": "1",
                    "purl": "pkg:cargo/a@1",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                }
            ]
        }
        trust.enrich_cargo_licenses(bom)
        self.assertEqual(
            bom["components"][0]["licenses"], [{"license": {"id": "Apache-2.0"}}]
        )
        self.assertFalse(
            any(
                p["name"] == "vettalon:license:source"
                for p in bom["components"][0]["properties"]
            )
        )
        self.assertTrue(
            any("unknown" in p["value"] for p in bom["components"][0]["properties"])
        )

    def test_cargo_verified_registry_archive_binds_license_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = io.BytesIO()
            manifest = b'[package]\nname="a"\nversion="1"\nlicense="MIT"\n'
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                member = tarfile.TarInfo("a-1/Cargo.toml")
                member.size = len(manifest)
                archive.addfile(member, io.BytesIO(manifest))
            archive_bytes = data.getvalue()
            digest = hashlib.sha256(archive_bytes).hexdigest()
            cache = root / "registry/cache/correct"
            cache.mkdir(parents=True)
            (cache / "a-1.crate").write_bytes(archive_bytes)
            source = "registry+https://example.invalid/index"
            (root / "Cargo.lock").write_text(
                f'[[package]]\nname="a"\nversion="1"\nsource="{source}"\nchecksum="{digest}"\n'
            )

            def bom(url):
                return {
                    "components": [
                        {
                            "name": "a",
                            "version": "1",
                            "purl": "pkg:cargo/a@1",
                            "externalReferences": [
                                {"type": "distribution", "url": url}
                            ],
                        }
                    ]
                }

            good = bom(source)
            with patch.dict(trust.os.environ, {"CARGO_HOME": str(root)}):
                trust.enrich_cargo_licenses(good, root)
            self.assertEqual(good["components"][0]["licenses"], [{"expression": "MIT"}])
            wrong = bom("registry+https://other.invalid/index")
            with patch.dict(trust.os.environ, {"CARGO_HOME": str(root)}):
                trust.enrich_cargo_licenses(wrong, root)
            self.assertNotIn("licenses", wrong["components"][0])
            (cache / "a-1.crate").write_bytes(b"changed")
            damaged = bom(source)
            with patch.dict(trust.os.environ, {"CARGO_HOME": str(root)}):
                trust.enrich_cargo_licenses(damaged, root)
            self.assertNotIn("licenses", damaged["components"][0])

    def test_probe_timeout_preserves_captured_request_and_partial_output(self):
        import tomllib
        import urllib.request

        def timeout(command, *args, **kwargs):
            config = tomllib.loads(
                Path(command[command.index("--config") + 1]).read_text()
            )
            url = config["model"][0]["base_url"] + "/chat/completions"
            body = json.dumps({"messages": [{"content": probe.MARKER}]}).encode()
            with urllib.request.urlopen(
                urllib.request.Request(
                    url, data=body, headers={"Content-Type": "application/json"}
                )
            ) as reply:
                reply.read()
            return {"command": command, "returncode": None, "stdout": "partial stdout",
                    "stderr": "partial stderr", "error": "timeout", "timed_out": True,
                    "control_schema": 1, "control_complete": False, "cleanup_error": None,
                    "captures": {}, "seconds": .01}

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "capture"
            with (
                patch.object(
                    sys, "argv", ["probe", "/fixture/cli", "--output", str(output)]
                ),
                patch.object(probe, "invoke", side_effect=timeout),
                patch("sys.stdout", new_callable=io.StringIO),
                self.assertRaises(SystemExit),
            ):
                probe.main()
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["source_marker_observed"])
            self.assertEqual(result["error"]["kind"], "timeout")
            self.assertEqual((output / "stdout.txt").read_text(), "partial stdout")
            self.assertEqual((output / "stderr.txt").read_text(), "partial stderr")
            self.assertEqual(len(json.loads((output / "requests.json").read_text())), 1)

    def test_probe_start_failure_retains_incomplete_record(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "capture"
            with (
                patch.object(
                    sys, "argv", ["probe", "/fixture/missing", "--output", str(output)]
                ),
                patch.object(
                    probe,
                    "invoke",
                    return_value={"command": ["/fixture/missing"], "returncode": None,
                                  "stdout": "", "stderr": "", "error": "process-error",
                                  "timed_out": False, "control_schema": 1,
                                  "control_complete": True, "cleanup_error": None,
                                  "captures": {}, "seconds": .01},
                ),
                patch("sys.stdout", new_callable=io.StringIO),
                self.assertRaises(SystemExit),
            ):
                probe.main()
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["status"], "incomplete")
            self.assertFalse(result["timed_out"])
            self.assertEqual(result["error"]["kind"], "cli_start_error")
            self.assertEqual(result["requests"], 0)


if __name__ == "__main__":
    unittest.main()
