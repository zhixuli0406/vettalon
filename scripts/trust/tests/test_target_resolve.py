"""Offline contract tests for target-filtered Cargo metadata reconciliation."""

import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
import target_resolve


class TargetResolveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name).resolve()
        (self.source / "Cargo.toml").write_text('[package]\nname="root"\nversion="1.0.0"\n')
        checksum = "a" * 64
        self.nodes = {
            ("root", "1.0.0"): {"name": "root", "version": "1.0.0"},
            ("direct", "1.0.0"): {"name": "direct", "version": "1.0.0",
                                  "source": target_resolve.cargo_graph.REGISTRY, "checksum": checksum},
            ("platform", "1.0.0"): {"name": "platform", "version": "1.0.0",
                                    "source": target_resolve.cargo_graph.REGISTRY, "checksum": checksum},
        }
        self.verified = {
            "nodes": self.nodes,
            "roots": {("root", "1.0.0")},
            "edges": {(("root", "1.0.0"), ("direct", "1.0.0")),
                      (("direct", "1.0.0"), ("platform", "1.0.0"))},
        }
        self.metadata = {
            "version": 1,
            "workspace_root": str(self.source),
            "workspace_members": ["root-id"],
            "packages": [
                {"id": "root-id", "name": "root", "version": "1.0.0",
                 "source": None, "manifest_path": str(self.source / "Cargo.toml")},
                {"id": "direct-id", "name": "direct", "version": "1.0.0",
                 "source": target_resolve.cargo_graph.REGISTRY},
            ],
            "resolve": {"nodes": [
                {"id": "root-id", "features": [], "deps": [
                    {"pkg": "direct-id", "name": "direct", "dep_kinds": [{"kind": None, "target": None}]}
                ]},
                {"id": "direct-id", "features": ["default"], "deps": []},
            ]},
        }

    def validate(self, metadata=None):
        return target_resolve.validate_metadata(
            metadata or self.metadata, self.verified, self.source, "aarch64-apple-darwin"
        )

    def test_target_subset_is_not_all_lock_or_binary_scope(self):
        result = self.validate()
        self.assertEqual(result["selected_packages"], 2)
        self.assertEqual(result["source_lock_packages"], 3)
        self.assertEqual(result["selected_edges"], 1)
        self.assertEqual(result["unselected_lock_edges"], 1)
        self.assertEqual(result["activated_feature_entries"], 1)
        self.assertIn("not exact release build", result["scope"])

    def test_dev_dependency_is_counted_not_hidden(self):
        self.metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        self.assertEqual(self.validate()["selected_dev_edges"], 1)

    def test_rejects_non_lock_target_edge(self):
        self.metadata["packages"].append({
            "id": "platform-id", "name": "platform", "version": "1.0.0",
            "source": target_resolve.cargo_graph.REGISTRY,
        })
        self.metadata["resolve"]["nodes"].append({"id": "platform-id", "features": [], "deps": []})
        self.metadata["resolve"]["nodes"][0]["deps"].append({
            "pkg": "platform-id", "name": "platform", "dep_kinds": [{"kind": None}]
        })
        with self.assertRaisesRegex(ValueError, "absent from source lock"):
            self.validate()

    def test_rejects_origin_mismatch_and_path_escape(self):
        wrong = copy.deepcopy(self.metadata)
        wrong["packages"][1]["source"] = None
        with self.assertRaisesRegex(ValueError, "origin"):
            self.validate(wrong)
        wrong = copy.deepcopy(self.metadata)
        wrong["packages"][0]["manifest_path"] = "/outside/Cargo.toml"
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.validate(wrong)

    def test_rejects_wrong_workspace_and_omitted_root(self):
        wrong = copy.deepcopy(self.metadata)
        wrong["workspace_root"] = "/outside"
        with self.assertRaisesRegex(ValueError, "workspace root"):
            self.validate(wrong)
        wrong = copy.deepcopy(self.metadata)
        wrong["workspace_members"] = []
        with self.assertRaisesRegex(ValueError, "workspace roots"):
            self.validate(wrong)

    def test_rejects_missing_or_duplicate_resolve_edges(self):
        wrong = copy.deepcopy(self.metadata)
        wrong["resolve"]["nodes"] = wrong["resolve"]["nodes"][:1]
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.validate(wrong)
        wrong = copy.deepcopy(self.metadata)
        wrong["resolve"]["nodes"][0]["deps"].append(copy.deepcopy(wrong["resolve"]["nodes"][0]["deps"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate.*edge"):
            self.validate(wrong)

    def test_release_binding_property_must_be_unique(self):
        bom = {"metadata": {"properties": [
            {"name": "vettalon:target", "value": "aarch64-apple-darwin"}
        ]}}
        self.assertEqual(target_resolve._property(bom, "vettalon:target"), "aarch64-apple-darwin")
        bom["metadata"]["properties"].append({"name": "vettalon:target", "value": "x86_64-apple-darwin"})
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            target_resolve._property(bom, "vettalon:target")

    def test_extracted_registry_source_drift_is_rejected(self):
        prefix = "fake-1.0.0"
        home = self.source / "isolated"
        archive = home / "registry/cache" / target_resolve.REGISTRY_CACHE_ID / f"{prefix}.crate"
        manifest = home / "registry/src" / target_resolve.REGISTRY_CACHE_ID / prefix / "Cargo.toml"
        archive.parent.mkdir(parents=True)
        manifest.parent.mkdir(parents=True)
        content = b'[package]\nname="fake"\nversion="1.0.0"\n'
        with tarfile.open(archive, "w:gz") as tar:
            member = tarfile.TarInfo(f"{prefix}/Cargo.toml")
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
        manifest.write_bytes(content)
        nodes = {("fake", "1.0.0"): {"source": target_resolve.cargo_graph.REGISTRY,
                                     "checksum": hashlib.sha256(archive.read_bytes()).hexdigest()}}
        metadata = {"packages": [{"name": "fake", "version": "1.0.0",
                                  "manifest_path": str(manifest)}]}
        self.assertEqual(target_resolve._verify_extracted_registry_sources(
            metadata, nodes, home, {("fake", "1.0.0")}
        )["extracted_regular_files_verified"], 1)
        manifest.write_text('tampered\n')
        with self.assertRaisesRegex(ValueError, "differs from verified archive"):
            target_resolve._verify_extracted_registry_sources(
                metadata, nodes, home, {("fake", "1.0.0")}
            )


@unittest.skipUnless(shutil.which("git") and shutil.which("cargo"), "Git and Cargo required")
class TargetRunIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "Cargo.toml").write_text(
            '[workspace]\nresolver="2"\nmembers=["crates/vettalon", "crates/vettalon-contract"]\n'
        )
        for name in ("vettalon", "vettalon-contract"):
            member = self.source / "crates" / name
            (member / "src").mkdir(parents=True)
            (member / "src/lib.rs").write_text("pub fn fixture() {}\n")
            manifest = f'[package]\nname="{name}"\nversion="0.2.0"\nedition="2021"\n'
            if name == "vettalon":
                manifest += '[dependencies]\nvettalon-contract={path="../vettalon-contract"}\n'
            (member / "Cargo.toml").write_text(manifest)
        def check(*args):
            subprocess.run(args, cwd=self.source, check=True, capture_output=True, timeout=20)
        check("cargo", "generate-lockfile", "--offline")
        check("git", "init", "-q")
        check("git", "add", ".")
        check("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
              "commit", "-qm", "fixture")
        self.sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.source,
                                  check=True, capture_output=True, text=True).stdout.strip()
        lock_sha = hashlib.sha256((self.source / "Cargo.lock").read_bytes()).hexdigest()
        self.bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"properties": [
                {"name": "vettalon:target", "value": "aarch64-apple-darwin"},
                {"name": "vettalon:source:commit", "value": self.sha},
                {"name": "vettalon:lockfile:sha256", "value": lock_sha},
            ]},
            "components": [
                {"type": "library", "name": name, "version": "0.2.0",
                 "purl": f"pkg:cargo/{name}@0.2.0", "bom-ref": name}
                for name in ("vettalon", "vettalon-contract")
            ],
            "dependencies": [
                {"ref": "vettalon", "dependsOn": ["vettalon-contract"]},
                {"ref": "vettalon-contract", "dependsOn": []},
            ],
        }
        self.bom_path = self.root / "fixture.cdx.json"
        self.bom_path.write_text(json.dumps(self.bom))

    def invoke(self, **kwargs):
        return target_resolve.run(
            self.source, self.bom_path, "aarch64-apple-darwin", self.sha, **kwargs
        )

    def test_clean_source_runs_actual_frozen_cargo_and_saves_raw(self):
        output = self.root / "metadata.json"
        result = self.invoke(metadata_output=output)
        self.assertEqual(result["status"], "local_cache_target_metadata_only")
        self.assertEqual((result["selected_packages"], result["selected_edges"]), (2, 1))
        self.assertIn("--frozen", result["cargo_command"])
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), result["cargo_metadata_sha256"])
        with self.assertRaisesRegex(ValueError, "exists"):
            self.invoke(metadata_output=output)

    def test_wrong_sha_or_dirty_checkout_fails_before_cargo(self):
        with self.assertRaisesRegex(ValueError, "commit differs"):
            target_resolve.run(self.source, self.bom_path, "aarch64-apple-darwin", "f" * 40)
        (self.source / "crates/vettalon/src/lib.rs").write_text("pub fn changed() {}\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            self.invoke()

    def test_lock_bom_disagreement_fails_before_cargo(self):
        self.bom["dependencies"][0]["dependsOn"] = []
        self.bom_path.write_text(json.dumps(self.bom))
        with self.assertRaisesRegex(ValueError, "edges differ"):
            self.invoke()

    def test_post_cargo_source_mutation_is_rejected(self):
        cargo = shutil.which("cargo")
        wrapper = self.root / "cargo-wrapper.py"
        marker = self.root / "args.json"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, subprocess, sys\n"
            f"args=sys.argv[1:]; pathlib.Path({str(marker)!r}).write_text(json.dumps(args))\n"
            f"result=subprocess.run([{cargo!r}, *args], capture_output=True)\n"
            "sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)\n"
            f"path=pathlib.Path({str(self.source / 'Cargo.toml')!r})\n"
            "path.write_text(path.read_text() + '# changed after metadata\\n')\n"
            "sys.exit(result.returncode)\n"
        )
        wrapper.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "changed during target resolution"):
            self.invoke(cargo_binary=str(wrapper))
        self.assertIn("--frozen", json.loads(marker.read_text()))

    def test_post_cargo_clean_commit_switch_is_rejected(self):
        cargo = shutil.which("cargo")
        wrapper = self.root / "cargo-commit-wrapper.py"
        source_file = self.source / "crates/vettalon/src/lib.rs"
        before = target_resolve._source_hashes(self.source)
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, subprocess, sys\n"
            f"source=pathlib.Path({str(self.source)!r})\n"
            f"result=subprocess.run([{cargo!r}, *sys.argv[1:]], capture_output=True)\n"
            "sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)\n"
            "if result.returncode: sys.exit(result.returncode)\n"
            f"path=pathlib.Path({str(source_file)!r})\n"
            "path.write_text('pub fn new_commit() {}\\n')\n"
            "subprocess.run(['git', 'add', str(path)], cwd=source, check=True, capture_output=True)\n"
            "subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', "
            "'commit', '-qm', 'switch clean commit'], cwd=source, check=True, capture_output=True)\n"
        )
        wrapper.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "commit changed during target resolution"):
            self.invoke(cargo_binary=str(wrapper))
        self.assertEqual(target_resolve._source_hashes(self.source), before)
        self.assertNotEqual(subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.source, text=True
        ).strip(), self.sha)
        self.assertEqual(subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=self.source, text=True
        ).strip(), "")

    def test_wrong_archive_checksum_rejected_before_metadata(self):
        cache = self.root / "cargo-home"
        (cache / "registry/index" / target_resolve.REGISTRY_CACHE_ID).mkdir(parents=True)
        archive_dir = cache / "registry/cache" / target_resolve.REGISTRY_CACHE_ID
        archive_dir.mkdir(parents=True)
        (archive_dir / "fake-1.0.0.crate").write_bytes(b"wrong")
        nodes = {("fake", "1.0.0"): {
            "name": "fake", "version": "1.0.0",
            "source": target_resolve.cargo_graph.REGISTRY, "checksum": "a" * 64,
        }}
        with self.assertRaisesRegex(ValueError, "checksum differs"):
            target_resolve._isolated_cargo_cache(nodes, cache, self.root / "isolated")


if __name__ == "__main__":
    unittest.main()
