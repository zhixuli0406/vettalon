import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "trust", Path(__file__).parents[1] / "trust.py"
)
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.asset = self.root / "vettalon-linux-x64.tar.gz"
        self.asset.write_bytes(b"archive fixture")
        for suffix in (".sig", ".pem", ".sigstore.json"):
            Path(str(self.asset) + suffix).write_text("fixture only")
        self.record = trust.build_record(
            self.asset, "a" * 40, "b" * 64, "x86_64-unknown-linux-gnu", True
        )
        Path(str(self.asset) + ".build-record.json").write_text(json.dumps(self.record))
        Path(str(self.asset) + ".sha256").write_text(
            trust.sha256(self.asset) + "  " + self.asset.name + "\n"
        )
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "vettalon",
                    "bom-ref": "root",
                }
            },
            "components": [],
            "dependencies": [{"ref": "root", "dependsOn": []}],
        }
        self.bom["metadata"]["properties"] = [
            {"name": "vettalon:asset:sha256", "value": trust.sha256(self.asset)},
            {"name": "vettalon:source:commit", "value": "a" * 40},
            {"name": "vettalon:lockfile:sha256", "value": "b" * 64},
            {"name": "vettalon:target", "value": "x86_64-unknown-linux-gnu"},
            {"name": "vettalon:source:dirty", "value": "true"},
        ]
        Path(str(self.asset) + ".cdx.json").write_text(json.dumps(self.bom))

    def test_complete_assets(self):
        trust.verify_assets(self.asset)

    def test_missing_every_sidecar_fails(self):
        for suffix in (
            ".sig",
            ".pem",
            ".sigstore.json",
            ".sha256",
            ".build-record.json",
            ".cdx.json",
        ):
            sidecar = Path(str(self.asset) + suffix)
            data = sidecar.read_bytes()
            sidecar.unlink()
            with self.assertRaises(ValueError, msg=suffix):
                trust.verify_assets(self.asset)
            sidecar.write_bytes(data)

    def test_tamper_archive_rejected(self):
        self.asset.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            trust.verify_assets(self.asset)

    def test_wrong_subject_and_target_rejected(self):
        for key, value in [("sha256", "c" * 64), ("name", "../other")]:
            bad = json.loads(json.dumps(self.record))
            bad["subject"][key] = value
            Path(str(self.asset) + ".build-record.json").write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                trust.verify_assets(self.asset)

    def test_wrong_target_rejected(self):
        self.record["target"] = "aarch64-apple-darwin"
        Path(str(self.asset) + ".build-record.json").write_text(json.dumps(self.record))
        with self.assertRaises(ValueError):
            trust.verify_assets(self.asset)

    def test_bom_subject_tamper_rejected(self):
        self.bom["metadata"]["properties"][0]["value"] = "f" * 64
        Path(str(self.asset) + ".cdx.json").write_text(json.dumps(self.bom))
        with self.assertRaises(ValueError):
            trust.verify_assets(self.asset)

    def test_unsupported_or_empty_bom_rejected(self):
        for bad in ({}, {"bomFormat": "CycloneDX", "specVersion": "9", "version": 1}):
            with self.assertRaises(ValueError):
                trust.validate_bom(bad)

    def test_official_schema_rejects_invalid_component_type(self):
        self.bom["components"] = [{"type": "made-up", "name": "bad"}]
        with self.assertRaises(ValueError):
            trust.validate_bom(self.bom)

    def test_dangling_relationship_rejected(self):
        self.bom["dependencies"][0]["dependsOn"] = ["missing"]
        with self.assertRaises(ValueError):
            trust.validate_bom(self.bom)

    def test_missing_syft_fails_without_output(self):
        with self.assertRaises(ValueError):
            trust.run_syft(self.root, self.root / "bom.json", "/does/not/exist")
        self.assertFalse((self.root / "bom.json").exists())

    def test_private_workspace_rejected(self):
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers=["crates/private"]\n'
        )
        with self.assertRaises(ValueError):
            trust.assert_public_workspace(self.root)


if __name__ == "__main__":
    unittest.main()
