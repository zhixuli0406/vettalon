"""Offline lock/BOM counterexamples; no Cargo, Syft, model, or provider calls."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import trust

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class CargoGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "Cargo.toml").write_text(
            '[package]\nname="root"\nversion="1.0.0"\n'
        )
        self.packages = [
            {"name": "root", "version": "1.0.0", "dependencies": ["direct"]},
            {"name": "direct", "version": "1.0.0", "source": REGISTRY,
             "checksum": "a" * 64, "dependencies": ["indirect"]},
            {"name": "indirect", "version": "2.0.0", "source": REGISTRY,
             "checksum": "b" * 64},
        ]
        self.bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [self.component(p) for p in self.packages],
            "dependencies": [
                {"ref": "root@1.0.0", "dependsOn": ["direct@1.0.0"]},
                {"ref": "direct@1.0.0", "dependsOn": ["indirect@2.0.0"]},
            ],
        }
        self.write_lock()

    def component(self, package):
        item = {"type": "library", "name": package["name"],
                "version": package["version"],
                "purl": f"pkg:cargo/{package['name']}@{package['version']}",
                "bom-ref": f"{package['name']}@{package['version']}"}
        if "source" in package:
            item["externalReferences"] = [{"type": "distribution", "url": package["source"]}]
        return item

    def write_lock(self, version=4):
        parts = [f"version = {version}"]
        for package in self.packages:
            parts.append("\n[[package]]")
            parts.extend(f"{key} = {json.dumps(value)}" for key, value in package.items())
        (self.root / "Cargo.lock").write_text("\n".join(parts) + "\n")

    def test_wrong_supplied_edge_cannot_be_laundered_into_roles(self):
        self.bom["dependencies"][0]["dependsOn"] = ["indirect@2.0.0"]
        before = copy.deepcopy(self.bom)
        with self.assertRaises(ValueError):
            trust.annotate_cargo_roles(self.bom, self.root)
        self.assertEqual(self.bom, before)

    def reject(self, bom=None):
        bom = self.bom if bom is None else bom
        before = copy.deepcopy(bom)
        with self.assertRaises(ValueError):
            trust.annotate_cargo_roles(bom, self.root)
        self.assertEqual(bom, before)

    def test_matching_lock_v3_v4_and_idempotent_verified_roles(self):
        for version in (3, 4):
            with self.subTest(version=version):
                self.write_lock(version)
                bom = copy.deepcopy(self.bom)
                proof = trust.cargo_graph.verify_cargo_graph(bom, self.root)
                self.assertEqual((proof["package_count"], proof["edge_count"]), (3, 2))
                self.assertEqual(proof["lockfile_sha256"], trust.sha256(self.root / "Cargo.lock"))
                trust.annotate_cargo_roles(bom, self.root)
                trust.annotate_cargo_roles(bom, self.root)
                self.assertEqual([c["properties"] for c in bom["components"]], [
                    [{"name": "vettalon:dependency:role", "value": role}]
                    for role in ("root", "direct", "transitive")])

    def add_second_version(self):
        package = {"name": "direct", "version": "2.0.0", "source": REGISTRY, "checksum": "c" * 64}
        self.packages.append(package)
        self.bom["components"].append(self.component(package))

    def test_qualified_and_versioned_edges_resolve_duplicate_names(self):
        self.add_second_version()
        self.packages[0]["dependencies"] = [f"direct 1.0.0 ({REGISTRY})", "direct 2.0.0"]
        self.packages[1]["dependencies"] = ["indirect 2.0.0"]
        self.bom["dependencies"][0]["dependsOn"].append("direct@2.0.0")
        self.write_lock()
        trust.annotate_cargo_roles(self.bom, self.root)
        self.assertEqual(self.bom["components"][-1]["properties"][0]["value"], "direct")

    def test_ambiguous_name_only_dependency_rejected(self):
        self.add_second_version()
        self.write_lock()
        self.reject()

    def test_missing_extra_and_duplicate_cargo_package_rejected(self):
        for kind in ("missing", "extra", "identity", "reference", "hidden-cargo"):
            with self.subTest(kind=kind):
                bom = copy.deepcopy(self.bom)
                if kind == "missing":
                    bom["components"].pop()
                    bom["dependencies"][1]["dependsOn"] = []
                elif kind == "extra":
                    bom["components"].append(self.component({"name": "extra", "version": "1.0.0"}))
                elif kind == "hidden-cargo":
                    bom["components"][0]["components"] = [self.component(self.packages[-1])]
                else:
                    duplicate = copy.deepcopy(bom["components"][1])
                    if kind == "identity": duplicate["bom-ref"] += "-other"
                    bom["components"].append(duplicate)
                self.reject(bom)

    def test_missing_extra_wrong_and_duplicate_edges_rejected(self):
        for kind in ("missing", "extra", "wrong", "duplicate-row", "duplicate-target", "dangling-row", "dangling-target"):
            with self.subTest(kind=kind):
                bom = copy.deepcopy(self.bom)
                rows = bom["dependencies"]
                if kind == "missing": rows.pop()
                elif kind == "extra": rows.append({"ref": "indirect@2.0.0", "dependsOn": ["root@1.0.0"]})
                elif kind == "wrong": rows[1]["dependsOn"] = ["root@1.0.0"]
                elif kind == "duplicate-row": rows.append(copy.deepcopy(rows[0]))
                elif kind == "duplicate-target": rows[0]["dependsOn"] *= 2
                elif kind == "dangling-row": rows.append({"ref": "not-found"})
                else: rows[0]["dependsOn"] = ["not-found"]
                self.reject(bom)

    def test_lock_duplicate_and_unknown_dependencies_rejected(self):
        for dependencies in (["unknown"], ["direct", "direct"], ["direct", "direct 1.0.0"],
                             ["direct 8.0.0"], [f"direct 1.0.0 (git+https://invalid.example/repo)"], "direct"):
            with self.subTest(dependencies=dependencies):
                self.packages[0]["dependencies"] = dependencies
                self.write_lock()
                self.reject()

    def test_unsupported_lock_versions_and_empty_inventory_rejected(self):
        for version in (2, 5, True):
            (self.root / "Cargo.lock").write_text(f"version={str(version).lower()}\n")
            self.reject()
        (self.root / "Cargo.lock").write_text("version=4\npackage=[]\n")
        self.reject()

    def test_unsupported_sources_and_multiple_origin_identity_rejected(self):
        for source in ("git+https://invalid.example/repo#abcd", "registry+https://invalid.example/index", ""):
            with self.subTest(source=source):
                self.packages[1]["source"] = source
                self.write_lock()
                self.reject()
        self.packages[1]["source"] = REGISTRY
        duplicate = {"name": "direct", "version": "1.0.0"}
        self.packages.append(duplicate)
        self.write_lock()
        self.reject()
        self.packages[-1] = copy.deepcopy(self.packages[1])
        self.write_lock()
        self.reject()

    def test_purl_and_origin_cannot_contradict_lock_or_component(self):
        for purl in ("pkg:cargo/direct@9.0.0", "pkg:cargo/other@1.0.0", "pkg:cargo/direct@1",
                     "pkg:cargo/direct@1.0.0?repository_url=https%3A%2F%2Finvalid.example%2Findex",
                     "pkg:cargo/direct@1.0.0#subdir", "pkg:Cargo/direct@1.0.0",
                     "pkg:cargo/name/direct@1.0.0", "pkg:cargo/%64irect@1.0.0"):
            with self.subTest(purl=purl):
                bom = copy.deepcopy(self.bom)
                bom["components"][1]["purl"] = purl
                self.reject(bom)
        for index, origin in ((1, "registry+https://invalid.example/index"), (0, REGISTRY)):
            bom = copy.deepcopy(self.bom)
            bom["components"][index]["externalReferences"] = [{"type": "distribution", "url": origin}]
            self.reject(bom)

    def test_plain_crates_io_purl_and_leaf_empty_row_supported(self):
        for item in self.bom["components"]: item.pop("externalReferences", None)
        self.bom["dependencies"].append({"ref": "indirect@2.0.0", "dependsOn": []})
        trust.annotate_cargo_roles(self.bom, self.root)

    def test_non_cargo_relationships_are_separate_from_cargo_edges(self):
        self.bom["metadata"] = {"component": {"type": "application", "name": "inventory", "bom-ref": "inventory"}}
        self.bom["components"].append({"type": "file", "name": "Cargo.lock", "bom-ref": "lock-file"})
        self.bom["dependencies"].extend([
            {"ref": "inventory", "dependsOn": ["root@1.0.0", "lock-file"]},
            {"ref": "lock-file", "dependsOn": ["indirect@2.0.0"]},
        ])
        trust.annotate_cargo_roles(self.bom, self.root)
        self.assertNotIn("properties", self.bom["components"][-1])
        self.assertEqual(self.bom["components"][2]["properties"][0]["value"], "transitive")

    def test_cargo_outgoing_non_package_edge_is_not_hidden_by_matching_cargo_subgraph(self):
        self.bom["components"].append({"type": "file", "name": "unknown", "bom-ref": "unknown-file"})
        self.bom["dependencies"][0]["dependsOn"].append("unknown-file")
        self.reject()

    def test_manifest_exact_version_and_workspace_version_inheritance(self):
        (self.root / "Cargo.toml").write_text('[package]\nname="root"\nversion="9.0.0"\n')
        self.reject()
        (self.root / "Cargo.toml").write_text('[workspace]\nmembers=["crates/*"]\n[workspace.package]\nversion="1.0.0"\n')
        member = self.root / "crates/root/Cargo.toml"
        member.parent.mkdir(parents=True)
        member.write_text('[package]\nname="root"\nversion.workspace=true\n')
        trust.annotate_cargo_roles(self.bom, self.root)
        self.assertEqual(self.bom["components"][0]["properties"][0]["value"], "root")
        member.write_text('[package]\nname="root"\nversion.workspace=1\n')
        self.reject()

    def test_local_path_package_can_be_direct_without_registry_origin(self):
        self.packages[1].pop("source")
        self.packages[1].pop("checksum")
        self.bom["components"][1].pop("externalReferences")
        self.write_lock()
        trust.annotate_cargo_roles(self.bom, self.root)
        self.assertEqual(self.bom["components"][1]["properties"][0]["value"], "direct")

    def test_missing_lock_or_manifest_never_accepts_cargo(self):
        for filename in ("Cargo.lock", "Cargo.toml"):
            path = self.root / filename
            data = path.read_bytes()
            path.unlink()
            self.reject()
            path.write_bytes(data)
        self.reject({"components": []})

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "no-follow file reads unavailable")
    def test_cli_rejects_outside_symlinked_lock_and_manifest(self):
        with tempfile.TemporaryDirectory() as outside:
            bom_path = self.root / "catalog.json"
            bom_path.write_text(json.dumps(self.bom))
            argv = [sys.executable, "-B", str(Path(__file__).parents[1] / "trust.py"),
                    "validate-cargo-graph", str(self.root), str(bom_path)]
            for filename in ("Cargo.lock", "Cargo.toml"):
                with self.subTest(filename=filename):
                    path = self.root / filename
                    original = path.read_bytes()
                    target = Path(outside) / filename
                    target.write_bytes(original)
                    path.unlink()
                    path.symlink_to(target)
                    try:
                        result = subprocess.run(argv, capture_output=True, timeout=15)
                        self.assertEqual(result.returncode, 1, result.stderr.decode())
                        self.assertEqual(result.stdout, b"")
                        self.assertIn(b"regular file", result.stderr)
                    finally:
                        path.unlink()
                        path.write_bytes(original)
            alias = Path(outside) / "source-alias"
            alias.symlink_to(self.root, target_is_directory=True)
            result = subprocess.run(argv[:4] + [str(alias), str(bom_path)],
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1, result.stderr.decode())
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"source root must not be a symlink", result.stderr)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "no-follow file reads unavailable")
    def test_workspace_member_parent_symlink_is_rejected(self):
        self.public_workspace()
        member = self.root / "crates/vettalon"
        moved = self.root / "member-target"
        shutil.move(member, moved)
        member.symlink_to(moved, target_is_directory=True)
        # The target remains physically inside the source tree, so this tests
        # the no-follow parent boundary rather than the earlier outside check.
        self.reject()

    def test_non_cargo_inventory_without_cargo_source_is_unchanged(self):
        (self.root / "Cargo.lock").unlink()
        (self.root / "Cargo.toml").unlink()
        bom = {"components": [{"name": "npm-package", "purl": "pkg:npm/npm-package@1"}]}
        original = copy.deepcopy(bom)
        trust.annotate_cargo_roles(bom, self.root)
        self.assertEqual(original, bom)

    def test_cargo_metadata_component_binds_same_lock_package(self):
        self.bom["metadata"] = {"component": self.bom["components"].pop(0)}
        trust.annotate_cargo_roles(self.bom, self.root)
        self.assertEqual(self.bom["metadata"]["component"]["properties"][0]["value"], "root")

    def test_run_syft_rejects_bad_graph_before_enrichment_or_output(self):
        self.bom["dependencies"][1]["dependsOn"] = []
        def fake_catalog(command, **kwargs):
            Path(command[-1].split("=", 1)[1]).write_text(json.dumps(self.bom))
        output = self.root / "should-not-exist.json"
        with (patch.object(trust.shutil, "which", return_value="/synthetic/syft"),
              patch.object(trust.subprocess, "run", side_effect=fake_catalog),
              patch.object(trust, "enrich_cargo_licenses") as enrich,
              self.assertRaises(ValueError)):
            trust.run_syft(self.root, output)
        enrich.assert_not_called()
        self.assertFalse(output.exists())

    def public_workspace(self):
        (self.root / "Cargo.toml").write_text('[workspace]\nmembers=["crates/vettalon","crates/vettalon-contract"]\n')
        packages = []
        for name in ("vettalon", "vettalon-contract"):
            manifest = self.root / "crates" / name / "Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(f'[package]\nname="{name}"\nversion="1.0.0"\n')
            packages.append({"name": name, "version": "1.0.0"})
        self.packages = packages
        self.write_lock()
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [self.component(p) for p in packages], "dependencies": []}

    def test_release_caller_rejects_injected_invalid_catalog_without_final_files(self):
        bom = self.public_workspace()
        bom["components"].pop()
        asset = self.root / "vettalon-darwin-arm64.tar.gz"
        asset.write_bytes(b"synthetic")
        output = self.root / "final.json"
        def catalog(source, staged, executable):
            self.assertNotEqual(staged, output)
            Path(staged).write_text(json.dumps(bom))
            return bom
        with patch.object(trust, "run_syft", side_effect=catalog), self.assertRaises(ValueError):
            trust.release_sbom(self.root, asset, output, "a" * 40, "aarch64-apple-darwin", True, "unused")
        self.assertFalse(output.exists())
        self.assertFalse(Path(str(asset) + ".build-record.json").exists())

    def test_release_validates_graph_and_preserves_existing_output(self):
        bom = self.public_workspace()
        asset = self.root / "vettalon-darwin-arm64.tar.gz"
        asset.write_bytes(b"synthetic")
        output = self.root / "final.json"
        output.write_text("preserve")
        with patch.object(trust, "run_syft") as catalog, self.assertRaises(ValueError):
            trust.release_sbom(self.root, asset, output, "a" * 40, "aarch64-apple-darwin", True, "unused")
        catalog.assert_not_called()
        self.assertEqual(output.read_text(), "preserve")
        output.unlink()
        with patch.object(trust, "run_syft", return_value=bom):
            trust.release_sbom(self.root, asset, output, "a" * 40, "aarch64-apple-darwin", True, "unused")
        emitted = json.loads(output.read_text())
        trust.validate_bom(emitted)
        self.assertTrue(all(item["properties"] == [{"name": "vettalon:dependency:role", "value": "root"}]
                            for item in emitted["components"]))

    def test_release_detects_source_lock_change_before_final_output(self):
        bom = self.public_workspace()
        asset = self.root / "vettalon-darwin-arm64.tar.gz"
        asset.write_bytes(b"synthetic")
        def catalog(*args):
            (self.root / "Cargo.lock").write_text("changed during inventory")
            return bom
        output = self.root / "final.json"
        with patch.object(trust, "run_syft", side_effect=catalog), self.assertRaises(ValueError):
            trust.release_sbom(self.root, asset, output, "a" * 40, "aarch64-apple-darwin", True, "unused")
        self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "no-follow file reads unavailable")
    def test_release_rejects_symlinked_source_slice_without_outputs(self):
        bom = self.public_workspace()
        asset = self.root / "vettalon-darwin-arm64.tar.gz"
        asset.write_bytes(b"synthetic")
        output = self.root / "final.json"
        with tempfile.TemporaryDirectory() as outside:
            for relative in ("Cargo.lock", "crates/vettalon/Cargo.toml"):
                with self.subTest(relative=relative):
                    path = self.root / relative
                    original = path.read_bytes()
                    target = Path(outside) / path.name
                    target.write_bytes(original)
                    path.unlink()
                    path.symlink_to(target)
                    try:
                        with patch.object(trust, "run_syft") as catalog, self.assertRaises(ValueError):
                            trust.release_sbom(self.root, asset, output, "a" * 40,
                                               "aarch64-apple-darwin", True, "unused")
                        catalog.assert_not_called()
                        self.assertFalse(output.exists())
                        self.assertFalse(Path(str(asset) + ".build-record.json").exists())
                    finally:
                        path.unlink()
                        path.write_bytes(original)

    def test_release_removes_new_bom_when_build_record_write_fails(self):
        bom = self.public_workspace()
        asset = self.root / "vettalon-darwin-arm64.tar.gz"
        asset.write_bytes(b"synthetic")
        output = self.root / "final.json"
        record_path = Path(str(asset) + ".build-record.json")
        original_open = Path.open

        def fail_record_open(path, mode="r", *args, **kwargs):
            if path == record_path and mode == "x":
                raise OSError("injected build-record write failure")
            return original_open(path, mode, *args, **kwargs)

        with patch.object(trust, "run_syft", return_value=bom), \
             patch.object(Path, "open", fail_record_open), \
             self.assertRaisesRegex(OSError, "injected build-record"):
            trust.release_sbom(self.root, asset, output, "a" * 40,
                               "aarch64-apple-darwin", True, "unused")
        self.assertFalse(output.exists())
        self.assertFalse(record_path.exists())

    def test_standalone_cli_from_unrelated_cwd_accepts_then_rejects_bad_edge(self):
        installed = self.root / "installed"
        installed.mkdir()
        base = Path(__file__).parents[1]
        for filename in ("trust.py", "cargo_graph.py"):
            shutil.copyfile(base / filename, installed / filename)
        shutil.copytree(base / "schemas", installed / "schemas")
        bom_path = self.root / "catalog.json"
        bom_path.write_text(json.dumps(self.bom))
        argv = [sys.executable, "-B", str(installed / "trust.py"), "validate-cargo-graph", str(self.root), str(bom_path)]
        success = subprocess.run(argv, cwd=installed, capture_output=True, timeout=15)
        self.assertEqual(success.returncode, 0, success.stderr.decode())
        result = json.loads(success.stdout)
        self.assertEqual((result["package_count"], result["edge_count"]), (3, 2))
        self.assertEqual(result["bom_sha256"], trust.sha256(bom_path))
        self.bom["dependencies"][1]["dependsOn"] = []
        bom_path.write_text(json.dumps(self.bom))
        before = bom_path.read_bytes()
        failure = subprocess.run(argv, cwd=self.root, capture_output=True, timeout=15)
        self.assertEqual(failure.returncode, 1)
        self.assertEqual(failure.stdout, b"")
        self.assertEqual(bom_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
