import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

NEGATIVE_FIXTURES = Path(__file__).parents[3] / "fixtures/sbom"
WORKSPACE_NEGATIVE = NEGATIVE_FIXTURES / "npm-negative-workspace"
LOCAL_FILE_NEGATIVE = NEGATIVE_FIXTURES / "npm-negative-local-file"
GIT_FILE_NEGATIVE = NEGATIVE_FIXTURES / "npm-negative-git-file"

SPEC = importlib.util.spec_from_file_location(
    "native", Path(__file__).parents[1] / "native.py"
)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


def marker_environment():
    return {
        "implementation_name": "cpython",
        "implementation_version": "3.12.0",
        "os_name": "nt",
        "platform_machine": "AMD64",
        "platform_release": "10",
        "platform_system": "Windows",
        "platform_version": "10.0",
        "python_full_version": "3.12.0",
        "platform_python_implementation": "CPython",
        "python_version": "3.12",
        "sys_platform": "win32",
    }


def pip_snapshot(requirements):
    return {
        "environment": marker_environment(),
        "installed": [
            {
                "metadata": {
                    "name": "app",
                    "version": "1",
                    "requires_dist": requirements,
                },
                "requested": True,
            },
            {"metadata": {"name": "dep", "version": "2"}, "requested": False},
        ],
    }


class NativeGraphTests(unittest.TestCase):
    def test_npm_git_file_lock_generated_by_npm_11_is_unsupported(self):
        lock = json.loads((GIT_FILE_NEGATIVE / "package-lock.json").read_text())
        self.assertNotIn("workspaces", lock["packages"][""])
        self.assertNotIn("link", lock["packages"]["node_modules/localgit"])
        self.assertTrue(
            lock["packages"]["node_modules/localgit"]["resolved"].startswith("git+file:///")
        )
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(lock)
        self.assertEqual(caught.exception.code, "npm-unsupported-protocol")

    def test_npm_unknown_dependency_protocols_are_unsupported(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1", "dependencies": {"a": "1"}},
                "node_modules/a": {
                    "version": "1",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.tgz",
                },
            },
        }
        native.npm_graph(lock)
        for spec in (
            "git+file:///tmp/a", "git+https://example.invalid/a.git",
            "git@github.com:owner/a.git", "owner/a#v1", "npm:other@1",
            "workspace:*", "ftp://example.invalid/a.tgz", "http://example.invalid/a.tgz",
        ):
            with self.subTest(spec=spec):
                variant = copy.deepcopy(lock)
                variant["packages"][""]["dependencies"]["a"] = spec
                with self.assertRaises(native.UnsupportedInventoryError) as caught:
                    native.npm_graph(variant)
                self.assertEqual(caught.exception.code, "npm-unsupported-protocol")
                variant = copy.deepcopy(lock)
                variant["packages"]["node_modules/a"]["resolved"] = spec
                with self.assertRaises(native.UnsupportedInventoryError) as caught:
                    native.npm_graph(variant)
                self.assertEqual(caught.exception.code, "npm-unsupported-protocol")
        variant = copy.deepcopy(lock)
        variant["packages"]["node_modules/a"]["version"] = "git+file:///tmp/a"
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(variant)
        self.assertEqual(caught.exception.code, "npm-unsupported-protocol")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_git_file_cli_emits_no_reconciled_bom(self):
        source = GIT_FILE_NEGATIVE / "package-lock.json"
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [],
            }))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)["code"], "npm-unsupported-protocol")
            self.assertFalse(output.exists())

    def test_npm_install_links_local_file_is_explicitly_unsupported(self):
        lock = json.loads((LOCAL_FILE_NEGATIVE / "package-lock.json").read_text())
        self.assertNotIn("workspaces", lock["packages"][""])
        self.assertNotIn("link", lock["packages"]["node_modules/local"])
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(lock)
        self.assertEqual(caught.exception.code, "npm-local-file")

    def test_npm_local_file_variants_fail_without_link_or_workspace(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1", "dependencies": {"local": "1"}},
                "node_modules/local": {"version": "1", "resolved": "https://registry.npmjs.org/local/-/local-1.tgz"},
            },
        }
        for value in (
            "file:../local", "file:/tmp/local", "file:///tmp/local",
            "../local", "./local", "/tmp/local", "C:\\local",
        ):
            with self.subTest(value=value):
                variant = copy.deepcopy(lock)
                variant["packages"]["node_modules/local"]["resolved"] = value
                with self.assertRaises(native.UnsupportedInventoryError) as caught:
                    native.npm_graph(variant)
                self.assertEqual(caught.exception.code, "npm-local-file")
                variant = copy.deepcopy(lock)
                variant["packages"][""]["dependencies"]["local"] = value
                with self.assertRaises(native.UnsupportedInventoryError) as caught:
                    native.npm_graph(variant)
                self.assertEqual(caught.exception.code, "npm-local-file")

    def test_npm_changed_manifest_cannot_omit_unlocked_local_dependency(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {"": {"name": "app", "version": "1"}},
        }
        manifest = {
            "name": "app", "version": "1",
            "dependencies": {"local": "file:packages/local"},
        }
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(lock, manifest=manifest)
        self.assertEqual(caught.exception.code, "npm-manifest-lock-mismatch")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_changed_manifest_cli_does_not_emit_reconciled_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1"}},
            }))
            manifest = directory / "package.json"
            manifest.write_text(json.dumps({
                "name": "app", "version": "1",
                "dependencies": {"local": "file:packages/local"},
            }))
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "library", "name": "app", "version": "1"}],
            }))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            status = json.loads(result.stdout)
            self.assertEqual(status["code"], "npm-manifest-lock-mismatch")
            self.assertEqual(status["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
            self.assertFalse(output.exists())

    def test_npm_matching_manifest_digest_is_bound_to_reconciled_bom(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("platform cannot open npm manifests without following links")
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1"}},
            }))
            manifest = directory / "package.json"
            manifest.write_text(json.dumps({"name": "app", "version": "1"}))
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "library", "name": "app", "version": "1",
                                "purl": "pkg:npm/app@1", "bom-ref": "app"}],
            }))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self.assertEqual(json.loads(result.stdout)["manifest_sha256"], manifest_hash)
            properties = json.loads(output.read_text())["metadata"]["properties"]
            self.assertIn(
                {"name": "vettalon:graph:manifest-sha256", "value": manifest_hash},
                properties,
            )

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_manifest_symlink_outside_source_is_not_read_or_hashed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source_dir = directory / "source"
            source_dir.mkdir()
            source = source_dir / "package-lock.json"
            source.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1"}},
            }))
            external = directory / "outside.json"
            external.write_text('{"name":"outside","version":"1","secret":"outside-marker"}')
            try:
                (source_dir / "package.json").symlink_to(external)
            except OSError as error:
                self.skipTest("symlinks unavailable: " + str(error))
            input_bom = directory / "syft.json"
            input_bom.write_text("{}")
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            status = json.loads(result.stdout)
            self.assertEqual(status["code"], "npm-manifest-file-unsafe")
            self.assertNotIn("manifest_sha256", status)
            self.assertNotIn(hashlib.sha256(external.read_bytes()).hexdigest(), result.stdout)
            self.assertNotIn("outside-marker", result.stdout + result.stderr)
            self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_manifest_nonregular_file_is_not_read(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "package.json").mkdir()
            source = directory / "package-lock.json"
            source.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1"}},
            }))
            input_bom = directory / "syft.json"
            input_bom.write_text("{}")
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)["code"], "npm-manifest-file-unsafe")
            self.assertFalse(output.exists())

    def test_npm_source_symlink_cannot_pair_external_lock_with_local_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source_dir = directory / "source"
            source_dir.mkdir()
            external_lock = directory / "outside-lock.json"
            external_lock.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1"}},
            }))
            source = source_dir / "package-lock.json"
            try:
                source.symlink_to(external_lock)
            except OSError as error:
                self.skipTest("symlinks unavailable: " + str(error))
            (source_dir / "package.json").write_text(
                json.dumps({"name": "app", "version": "1"})
            )
            input_bom = directory / "syft.json"
            input_bom.write_text("{}")
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            status = json.loads(result.stdout)
            self.assertEqual(status["code"], "npm-source-file-unsafe")
            self.assertNotIn("source_sha256", status)
            self.assertNotIn("manifest_sha256", status)
            self.assertNotIn(
                hashlib.sha256(external_lock.read_bytes()).hexdigest(), result.stdout
            )
            self.assertFalse(output.exists())

    def test_native_rejects_forged_syft_edge_when_source_has_zero_edges(self):
        bom = {
            "components": [
                {"name": name, "version": "1", "purl": f"pkg:npm/{name}@1",
                 "bom-ref": name}
                for name in ("app", "a")
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["a"]}],
        }
        with self.assertRaisesRegex(ValueError, "catalog dependency edge absent"):
            native.enrich(
                bom, {("app", "1"), ("a", "1")}, set(), set(), "npm-lock-v3", "a" * 64
            )

    def test_native_mixed_bom_preserves_only_source_bound_native_edges(self):
        bom = {
            "components": [
                {"name": name, "version": "1", "purl": f"pkg:npm/{name}@1",
                 "bom-ref": name}
                for name in ("app", "a")
            ] + [
                {"name": name, "version": "1", "purl": f"pkg:cargo/{name}@1",
                 "bom-ref": name}
                for name in ("cargo-one", "cargo-two")
            ],
            "dependencies": [{"ref": "cargo-one", "dependsOn": ["cargo-two"]}],
        }
        result = native.enrich(
            bom, {("app", "1"), ("a", "1")},
            {(("app", "1"), ("a", "1"))}, {("a", "1")}, "npm-lock-v3", "a" * 64,
        )
        self.assertEqual(
            {row["ref"]: row["dependsOn"] for row in result["dependencies"]},
            {"app": ["a"], "cargo-one": ["cargo-two"]},
        )

    def test_native_rejects_cross_ecosystem_catalog_edge_touching_native_ref(self):
        bom = {
            "components": [
                {"name": "app", "version": "1", "purl": "pkg:npm/app@1", "bom-ref": "app"},
                {"name": "cargo", "version": "1", "purl": "pkg:cargo/cargo@1", "bom-ref": "cargo"},
            ],
            "dependencies": [{"ref": "cargo", "dependsOn": ["app"]}],
        }
        with self.assertRaisesRegex(ValueError, "catalog dependency edge absent"):
            native.enrich(bom, {("app", "1")}, set(), set(), "npm-lock-v3", "a" * 64)

    def test_native_rejects_unmapped_same_ecosystem_components(self):
        for kind, ecosystem in (
            ("npm-lock-v3", "npm"),
            ("pip-inspect", "pypi"),
            ("go-native", "golang"),
        ):
            with self.subTest(kind=kind):
                bom = {
                    "components": [
                        {"name": name, "version": "1", "purl": f"pkg:{ecosystem}/{name}@1",
                         "bom-ref": name}
                        for name in ("app", "rogue-a", "rogue-b")
                    ],
                    "dependencies": [{"ref": "rogue-a", "dependsOn": ["rogue-b"]}],
                }
                with self.assertRaisesRegex(ValueError, "catalog component absent"):
                    native.enrich(
                        bom, {("app", "1")}, set(), set(), kind, "a" * 64
                    )

    def test_native_rejects_same_ecosystem_metadata_root(self):
        bom = {
            "metadata": {
                "component": {
                    "name": "rogue", "version": "1", "purl": "pkg:npm/rogue@1",
                    "bom-ref": "rogue",
                }
            },
            "components": [
                {"name": "app", "version": "1", "purl": "pkg:npm/app@1",
                 "bom-ref": "app"},
            ],
        }
        with self.assertRaisesRegex(ValueError, "metadata component requires"):
            native.enrich(bom, {("app", "1")}, set(), set(), "npm-lock-v3", "a" * 64)

    def test_native_rejects_no_purl_packages_and_unknown_catalog_refs(self):
        native_app = {"type": "library", "name": "app", "version": "1",
                      "purl": "pkg:npm/app@1", "bom-ref": "app"}
        rogue = [{"type": "library", "name": name, "version": "1", "bom-ref": name}
                 for name in ("rogue-a", "rogue-b")]
        for components, relation in (
            ([native_app, *rogue], {"ref": "rogue-a", "dependsOn": ["rogue-b"]}),
            ([native_app], {"ref": "rogue-a", "dependsOn": ["rogue-b"]}),
            ([native_app, {"type": "library", "name": "cargo", "version": "1",
                           "purl": "pkg:cargo/cargo@1", "bom-ref": "cargo"}],
             {"ref": "cargo", "dependsOn": ["rogue-b"]}),
        ):
            with self.subTest(components=components):
                with self.assertRaisesRegex(ValueError, "unclassified catalog component|unknown catalog dependency ref"):
                    native.enrich({"components": copy.deepcopy(components),
                                   "dependencies": [relation]},
                                  {("app", "1")}, set(), set(), "npm-lock-v3", "a" * 64)

    def test_native_excludes_no_purl_file_artifacts_without_edges(self):
        bom = {
            "metadata": {"component": {"type": "file", "name": "package-lock.json",
                                       "bom-ref": "root-file"}},
            "components": [
                {"type": "library", "name": "app", "version": "1",
                 "purl": "pkg:npm/app@1", "bom-ref": "app"},
                {"type": "file", "name": "package-lock.json", "bom-ref": "lock-file"},
            ],
        }
        result = native.enrich(bom, {("app", "1")}, set(), set(),
                               "npm-lock-v3", "a" * 64)
        self.assertEqual([component["bom-ref"] for component in result["components"]], ["app"])
        self.assertNotIn("component", result["metadata"])
        properties = {entry["name"]: entry["value"] for entry in result["metadata"]["properties"]}
        self.assertEqual(properties["vettalon:graph:excluded-unclassified-file-artifacts"], "2")

    def test_native_rejects_no_purl_metadata_root_dependency(self):
        bom = {
            "metadata": {"component": {"type": "file", "name": "package-lock.json",
                                       "bom-ref": "root-file"}},
            "components": [{"type": "library", "name": "app", "version": "1",
                            "purl": "pkg:npm/app@1", "bom-ref": "app"}],
            "dependencies": [{"ref": "root-file", "dependsOn": []}],
        }
        with self.assertRaisesRegex(ValueError, "excluded file artifact dependency"):
            native.enrich(bom, {("app", "1")}, set(), set(), "npm-lock-v3", "a" * 64)

    def test_native_rejects_unclassified_root_and_file_dependency_target(self):
        app = {"type": "library", "name": "app", "version": "1",
               "purl": "pkg:npm/app@1", "bom-ref": "app"}
        with self.assertRaisesRegex(ValueError, "unclassified metadata component"):
            native.enrich({"metadata": {"component": {"type": "library",
                                                       "name": "unknown", "bom-ref": "root"}},
                           "components": [copy.deepcopy(app)]},
                          {("app", "1")}, set(), set(), "npm-lock-v3", "a" * 64)
        with self.assertRaisesRegex(ValueError, "excluded file artifact dependency"):
            native.enrich({
                "components": [copy.deepcopy(app),
                               {"type": "file", "name": "lock", "bom-ref": "file"}],
                "dependencies": [{"ref": "app", "dependsOn": ["file"]}],
            }, {("app", "1")}, set(), set(), "npm-lock-v3", "a" * 64)

    def test_native_rejects_reserved_properties_in_nested_input(self):
        app = {"type": "library", "name": "app", "version": "1",
               "purl": "pkg:npm/app@1", "bom-ref": "app"}
        foreign = {"type": "library", "name": "cargo", "version": "1",
                   "purl": "pkg:cargo/cargo@1", "bom-ref": "cargo"}
        forged = {"name": "vettalon:graph:source", "value": "npm-lock-v3:" + "f" * 64}
        for variant in (
            {"components": [{**app, "properties": [{"name": "vettalon:dependency:role",
                                                    "value": "direct"}]}]},
            {"components": [app, {**foreign, "properties": [forged]}]},
            {"components": [app], "metadata": {"properties": [forged]}},
            {"components": [app], "metadata": {"component": {
                **foreign, "properties": [forged],
            }}},
            {"components": [app], "services": [{"name": "svc", "bom-ref": "svc",
                                                  "properties": [forged]}]},
        ):
            with self.subTest(variant=variant):
                with self.assertRaisesRegex(ValueError, "reserved vettalon property"):
                    native.enrich(copy.deepcopy(variant), {("app", "1")}, set(), set(),
                                  "npm-lock-v3", "a" * 64)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_reserved_property_cli_emits_no_reconciled_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({"lockfileVersion": 3,
                                          "packages": {"": {"name": "app", "version": "1"}}}))
            app = {"type": "library", "name": "app", "version": "1",
                   "purl": "pkg:npm/app@1", "bom-ref": "app"}
            variants = (
                {"components": [{**app, "properties": [
                    {"name": "vettalon:dependency:role", "value": "direct"}]}]},
                {"components": [app, {"type": "library", "name": "cargo",
                                     "version": "1", "purl": "pkg:cargo/cargo@1",
                                     "bom-ref": "cargo", "properties": [
                                         {"name": "vettalon:graph:source",
                                          "value": "npm-lock-v3:" + "f" * 64}]}]},
                {"components": [app], "metadata": {"properties": [
                    {"name": "vettalon:graph:scope", "value": "forged"}]}},
            )
            for index, fragment in enumerate(variants):
                with self.subTest(index=index):
                    input_bom = directory / f"syft-{index}.json"
                    input_bom.write_text(json.dumps({
                        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                        **fragment,
                    }))
                    output = directory / f"reconciled-{index}.json"
                    result = subprocess.run(
                        [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                         "--bom", str(input_bom), "--source", str(source),
                         "--output", str(output)], capture_output=True, text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("reserved vettalon property", result.stderr)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_no_purl_rogue_edge_cli_emits_no_reconciled_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({"lockfileVersion": 3,
                                          "packages": {"": {"name": "app", "version": "1"}}}))
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [
                    {"type": "library", "name": "app", "version": "1",
                     "purl": "pkg:npm/app@1", "bom-ref": "app"},
                    *[{"type": "library", "name": name, "version": "1", "bom-ref": name}
                      for name in ("rogue-a", "rogue-b")],
                ],
                "dependencies": [{"ref": "rogue-a", "dependsOn": ["rogue-b"]}],
            }))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("unclassified catalog component", result.stderr)
            self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_unclassified_metadata_and_unknown_ref_cli_emit_no_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({"lockfileVersion": 3,
                                          "packages": {"": {"name": "app", "version": "1"}}}))
            app = {"type": "library", "name": "app", "version": "1",
                   "purl": "pkg:npm/app@1", "bom-ref": "app"}
            foreign = {"type": "library", "name": "cargo", "version": "1",
                       "purl": "pkg:cargo/cargo@1", "bom-ref": "cargo"}
            cases = (
                ({"metadata": {"component": {"type": "file", "name": "root",
                                             "bom-ref": "root-file"}},
                  "components": [app],
                  "dependencies": [{"ref": "root-file", "dependsOn": []}]},
                 "excluded file artifact dependency"),
                ({"components": [app, foreign],
                  "dependencies": [{"ref": "cargo", "dependsOn": ["missing"]}]},
                 "unknown catalog dependency ref"),
            )
            for index, (fragment, error) in enumerate(cases):
                with self.subTest(index=index):
                    input_bom = directory / f"syft-{index}.json"
                    input_bom.write_text(json.dumps({
                        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                        **fragment,
                    }))
                    output = directory / f"reconciled-{index}.json"
                    result = subprocess.run(
                        [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                         "--bom", str(input_bom), "--source", str(source),
                         "--output", str(output)], capture_output=True, text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(error, result.stderr)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_unmapped_same_ecosystem_edge_cli_emits_no_reconciled_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1"}},
            }))
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [
                    {"type": "library", "name": name, "version": "1",
                     "purl": f"pkg:npm/{name}@1", "bom-ref": name}
                    for name in ("app", "rogue-a", "rogue-b")
                ],
                "dependencies": [{"ref": "rogue-a", "dependsOn": ["rogue-b"]}],
            }))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("catalog component absent", result.stderr)
            self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_forged_syft_edge_cli_emits_no_reconciled_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "package-lock.json"
            source.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1"},
                    "node_modules/a": {"version": "1"},
                },
            }))
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [
                    {"type": "library", "name": name, "version": "1",
                     "purl": f"pkg:npm/{name}@1", "bom-ref": name}
                    for name in ("app", "a")
                ],
                "dependencies": [{"ref": "app", "dependsOn": ["a"]}],
            }))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("catalog dependency edge absent", result.stderr)
            self.assertFalse(output.exists())

    def test_npm_workspace_lock_is_explicitly_unsupported(self):
        lock = json.loads((WORKSPACE_NEGATIVE / "package-lock.json").read_text())
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(lock)
        self.assertEqual(caught.exception.code, "npm-workspace-link")

    def test_npm_workspace_manifest_cannot_be_silent_without_link_entry(self):
        lock = json.loads((WORKSPACE_NEGATIVE / "package-lock.json").read_text())
        lock["packages"].pop("node_modules/local")
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(lock)
        self.assertEqual(caught.exception.code, "npm-workspace-link")

    def test_npm_local_package_path_cannot_be_silent_without_workspace_metadata(self):
        lock = json.loads((WORKSPACE_NEGATIVE / "package-lock.json").read_text())
        lock["packages"][""].pop("workspaces")
        lock["packages"].pop("node_modules/local")
        with self.assertRaises(native.UnsupportedInventoryError) as caught:
            native.npm_graph(lock)
        self.assertEqual(caught.exception.code, "npm-workspace-link")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "npm source snapshot unavailable")
    def test_npm_workspace_cli_does_not_write_a_reconciled_bom(self):
        source = WORKSPACE_NEGATIVE / "package-lock.json"
        bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "name": "local", "version": "1.0.0",
                 "purl": "pkg:npm/local@1.0.0", "bom-ref": "local"}
            ],
        }
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            input_bom = directory / "syft.json"
            input_bom.write_text(json.dumps(bom))
            output = directory / "reconciled.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SPEC.origin), "npm-lock-v3",
                 "--bom", str(input_bom), "--source", str(source),
                 "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            status = json.loads(result.stdout)
            self.assertEqual(status["status"], "unsupported")
            self.assertEqual(status["code"], "npm-workspace-link")
            self.assertEqual(status["source_kind"], "npm-lock-v3")
            self.assertEqual(
                status["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest()
            )
            self.assertFalse(output.exists())

    def test_npm_lock_nested_graph(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1", "dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1", "dependencies": {"b": "2"}},
                "node_modules/b": {"version": "2"},
            },
        }
        nodes, edges, direct = native.npm_graph(lock)
        self.assertIn(("a", "1"), direct)
        self.assertIn((("a", "1"), ("b", "2")), edges)

    def test_npm_missing_resolved_node_fails(self):
        with self.assertRaises(ValueError):
            native.npm_graph(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "app",
                            "version": "1",
                            "dependencies": {"missing": "1"},
                        }
                    },
                }
            )

    def test_pip_metadata_marker_and_requested(self):
        inspect = {
            "environment": marker_environment(),
            "installed": [
                {
                    "metadata": {
                        "name": "requests",
                        "version": "1",
                        "requires_dist": ["idna>=2", 'extra-only; extra == "x"'],
                    },
                    "requested": True,
                },
                {"metadata": {"name": "idna", "version": "3"}, "requested": False},
            ],
        }
        nodes, edges, direct = native.pip_graph(inspect)
        self.assertEqual(direct, {("requests", "1")})
        self.assertEqual(edges, {(("requests", "1"), ("idna", "3"))})

    def test_pip_missing_dependency_fails(self):
        with self.assertRaises(ValueError):
            native.pip_graph(
                {
                    "environment": marker_environment(),
                    "installed": [
                        {
                            "metadata": {
                                "name": "a",
                                "version": "1",
                                "requires_dist": ["absent"],
                            }
                        }
                    ]
                }
            )

    def test_go_native_missing_node_gets_explicit_native_provenance(self):
        bom = {"components": []}
        result = native.enrich(
            bom,
            {("example.com/a", "v1")},
            set(),
            {("example.com/a", "v1")},
            "go-native",
            "a" * 64,
        )
        self.assertEqual(result["components"][0]["purl"], "pkg:golang/example.com/a@v1")
        self.assertIn(
            {
                "name": "vettalon:license:status",
                "value": "unknown; native module metadata lacks license evidence",
            },
            result["components"][0]["properties"],
        )

    def test_npm_missing_inventory_still_fails(self):
        with self.assertRaises(ValueError):
            native.enrich(
                {"components": []}, {("a", "1")}, set(), set(), "npm-lock-v3", "b" * 64
            )

    def test_go_graph_ignores_unselected_source_edges(self):
        _, edges, _ = native.go_graph(
            {"Require": []}, "a@v1 b@v1\n", {"a": "v2", "b": "v1"}
        )
        self.assertEqual(edges, set())

    def test_go_graph_uses_selected_versions(self):
        nodes, edges, direct = native.go_graph(
            {
                "Module": {"Path": "app"},
                "Require": [
                    {"Path": "a", "Version": "v2"},
                    {"Path": "b", "Version": "v3", "Indirect": True},
                ],
            },
            "app a@v2\na@v2 b@v1\n",
            {"app": None, "a": "v2", "b": "v3"},
        )
        self.assertEqual(direct, {("a", "v2")})
        self.assertIn((("a", "v2"), ("b", "v3")), edges)


class PipMarkerSnapshotTests(unittest.TestCase):
    def test_marker_missing_environment_fails_instead_of_using_host(self):
        snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
        del snapshot["environment"]
        with self.assertRaises(ValueError):
            native.pip_graph(snapshot)

    def test_partial_malformed_and_empty_environment_fail(self):
        for value in (None, {}, [], {"sys_platform": "win32"}):
            with self.subTest(environment=value):
                snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
                snapshot["environment"] = value
                with self.assertRaises(ValueError):
                    native.pip_graph(snapshot)
        for key in marker_environment():
            for value in (None, True, 7, "", " \t"):
                with self.subTest(key=key, value=value):
                    snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
                    snapshot["environment"][key] = value
                    with self.assertRaises(ValueError):
                        native.pip_graph(snapshot)
        for key in ("implementation_version", "python_full_version", "python_version"):
            with self.subTest(version_key=key):
                snapshot = pip_snapshot(['dep; python_version >= "3"'])
                snapshot["environment"][key] = "not-a-version"
                with self.assertRaises(ValueError):
                    native.pip_graph(snapshot)

    def test_true_and_false_markers_use_snapshot_and_keep_exclusions(self):
        snapshot = pip_snapshot(['dep>=2; sys_platform == "win32"'])
        exclusions = []
        nodes, edges, direct = native.pip_graph(snapshot, exclusions=exclusions)
        self.assertEqual(nodes, {("app", "1"), ("dep", "2")})
        self.assertEqual(direct, {("app", "1")})
        self.assertEqual(edges, {(("app", "1"), ("dep", "2"))})
        self.assertEqual(exclusions, [])
        snapshot["environment"]["sys_platform"] = "linux"
        nodes, edges, direct = native.pip_graph(snapshot, exclusions=exclusions)
        self.assertEqual(edges, set())
        self.assertEqual(
            exclusions,
            [{
                "source_name": "app",
                "source_version": "1",
                "requirement": 'dep>=2; sys_platform == "win32"',
                "marker": 'sys_platform == "win32"',
                "outcome": "not-applicable",
            }],
        )

    def test_host_defaults_cannot_change_graph_or_leak_to_exclusions(self):
        snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
        original = copy.deepcopy(snapshot)
        results = []
        for platform in ("linux", "darwin"):
            host = {key: "HOST_PRIVATE_CANARY" for key in marker_environment()}
            host["sys_platform"] = platform
            exclusions = []
            with patch("packaging.markers.default_environment", return_value=host):
                results.append(native.pip_graph(snapshot, exclusions=exclusions))
            self.assertNotIn("HOST_PRIVATE_CANARY", json.dumps(exclusions))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0][1], {(("app", "1"), ("dep", "2"))})
        self.assertEqual(snapshot, original)

    def test_base_extra_scope_is_explicit_and_requested_extras_still_fail(self):
        snapshot = pip_snapshot(['absent; extra == "speedups"'])
        snapshot["environment"]["extra"] = "speedups"
        exclusions = []
        _, edges, _ = native.pip_graph(snapshot, exclusions=exclusions)
        self.assertEqual(edges, set())
        self.assertEqual(exclusions[0]["marker"], 'extra == "speedups"')
        for requirement in ("dep[fast]", "dep @ https://example.invalid/dep.whl"):
            with self.subTest(requirement=requirement):
                with self.assertRaises(ValueError):
                    native.pip_graph(pip_snapshot([requirement]))

    def test_unsupported_marker_context_does_not_become_false(self):
        with self.assertRaises(ValueError):
            native.pip_graph(pip_snapshot(['dep; "fast" in extras']))

    def test_true_missing_or_unsatisfied_dependency_still_fails(self):
        for requirement in (
            'missing; sys_platform == "win32"',
            'dep>=3; sys_platform == "win32"',
        ):
            with self.subTest(requirement=requirement):
                with self.assertRaises(ValueError):
                    native.pip_graph(pip_snapshot([requirement]))

    def test_cli_persists_snapshot_environment_and_marker_exclusions(self):
        snapshot = pip_snapshot(['absent; sys_platform == "linux"'])
        bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "name": name, "version": version,
                 "purl": f"pkg:pypi/{name}@{version}", "bom-ref": name}
                for name, version in (("app", "1"), ("dep", "2"))
            ],
        }
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "inspect.json"
            source.write_text(json.dumps(snapshot))
            input_bom = directory / "input.json"
            input_bom.write_text(json.dumps(bom))
            output = directory / "output.json"
            command = [sys.executable, "-B", str(SPEC.origin), "pip-inspect",
                       "--bom", str(input_bom), "--source", str(source),
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(len(summary["excluded_marker_requirements"]), 1)
            saved = json.loads(output.read_text())
            properties = {p["name"]: p["value"] for p in saved["metadata"]["properties"]}
            expected_environment = {**marker_environment(), "extra": ""}
            self.assertEqual(json.loads(properties["vettalon:graph:marker-environment"]), expected_environment)
            self.assertEqual(json.loads(properties["vettalon:graph:marker-exclusions"]), summary["excluded_marker_requirements"])
            self.assertEqual(len(saved["components"]), 2)
            self.assertEqual(summary["direct"], 1)


if __name__ == "__main__":
    unittest.main()
