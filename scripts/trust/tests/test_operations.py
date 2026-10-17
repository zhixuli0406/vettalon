"""Exercise adapters/CLI and disposable HTTP harness without a real cloud model."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).parents[1]
sys.path.insert(0, str(BASE))
import trust
import native


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, BASE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("installer", "install-syft.py")
probe = load("probe", "dataflow-probe.py")


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "a",
                    "version": "1",
                    "purl": "pkg:npm/a@1",
                    "bom-ref": "a",
                }
            ],
        }

    def invoke(self, module, args):
        with (
            patch.object(sys, "argv", ["tool", *map(str, args)]),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            module.main()

    def test_installer_checksum_and_safe_single_member(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            member = tarfile.TarInfo("syft")
            member.size = 7
            archive.addfile(member, io.BytesIO(b"fixture"))
        data = data.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        with (
            patch.dict(
                installer.HASHES, {("Darwin", "arm64"): ("darwin_arm64", digest)}
            ),
            patch.object(installer.platform, "system", return_value="Darwin"),
            patch.object(installer.platform, "machine", return_value="arm64"),
            patch.object(
                installer.urllib.request, "urlopen", return_value=io.BytesIO(data)
            ),
        ):
            self.invoke(installer, [self.root / "syft"])
        self.assertEqual((self.root / "syft").read_bytes(), b"fixture")
        with self.assertRaises(SystemExit):
            self.invoke(installer, [self.root / "syft"])
        with (
            patch.object(installer.platform, "system", return_value="unsupported"),
            self.assertRaises(SystemExit),
        ):
            self.invoke(installer, [self.root / "other"])
        with (
            patch.object(installer.platform, "system", return_value="Darwin"),
            patch.object(installer.platform, "machine", return_value="arm64"),
            patch.object(
                installer.urllib.request, "urlopen", return_value=io.BytesIO(b"bad")
            ),
            self.assertRaises(SystemExit),
        ):
            self.invoke(installer, [self.root / "bad"])
        self.assertFalse((self.root / "bad").exists())

    def test_syft_adapter_uses_bounded_argv_and_refuses_empty(self):
        def call(command, **kwargs):
            self.assertEqual(kwargs["timeout"], 300)
            self.assertTrue(kwargs["check"])
            self.assertEqual(
                kwargs["env"]["SYFT_GOLANG_SEARCH_REMOTE_LICENSES"], "false"
            )
            Path(command[-1].split("=", 1)[1]).write_text(json.dumps(self.bom))

        output = self.root / "bom.json"
        with (
            patch.object(trust.shutil, "which", return_value="/fixture/syft"),
            patch.object(trust.subprocess, "run", side_effect=call),
        ):
            trust.run_syft(self.root, output)
        self.assertTrue(output.exists())
        self.bom["components"] = []
        with (
            patch.object(trust.shutil, "which", return_value="/fixture/syft"),
            patch.object(trust.subprocess, "run", side_effect=call),
            self.assertRaises(ValueError),
        ):
            trust.run_syft(self.root, self.root / "empty.json")
        self.assertFalse((self.root / "empty.json").exists())

    def test_public_release_slice_excludes_unrelated_files(self):
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers=["crates/vettalon","crates/vettalon-contract"]\n'
        )
        (self.root / "Cargo.lock").write_text("version=4\n")
        for name in ("vettalon", "vettalon-contract"):
            folder = self.root / "crates" / name
            folder.mkdir(parents=True)
            (folder / "Cargo.toml").write_text(
                f'[package]\nname="{name}"\nversion="1"\n'
            )
        (self.root / "private-report.json").write_text("must not be inventoried")
        asset = self.root / "vettalon-darwin-arm64.tar.gz"
        asset.write_bytes(b"fixture archive")

        def inventory(source, output, executable):
            self.assertFalse((source / "private-report.json").exists())
            return json.loads(json.dumps(self.bom))

        with patch.object(trust, "run_syft", side_effect=inventory):
            trust.release_sbom(
                self.root,
                asset,
                self.root / "release.cdx.json",
                "a" * 40,
                "aarch64-apple-darwin",
                True,
                "syft",
            )
        record = json.loads(Path(str(asset) + ".build-record.json").read_text())
        self.assertTrue(record["source"]["dirty"])
        self.assertEqual(record["subject"]["sha256"], trust.sha256(asset))

    def test_cargo_metadata_roles_and_license_unknown(self):
        (self.root / "Cargo.toml").write_text('[package]\nname="root"\nversion="1"\n')
        bom = {
            "components": [
                {
                    "name": name,
                    "version": "1",
                    "purl": "pkg:cargo/" + name + "@1",
                    "bom-ref": name,
                }
                for name in ("root", "direct", "indirect")
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["direct"]},
                {"ref": "direct", "dependsOn": ["indirect"]},
            ],
        }
        cached = self.root / "registry/src/registry/direct-1"
        cached.mkdir(parents=True)
        (cached / "Cargo.toml").write_text('[package]\nlicense="MIT"\n')
        with patch.dict(os.environ, {"CARGO_HOME": str(self.root)}):
            trust.enrich_cargo_licenses(bom)
        trust.annotate_cargo_roles(bom, self.root)
        self.assertNotIn("licenses", bom["components"][1])
        for component, role in zip(bom["components"], ("root", "direct", "transitive")):
            self.assertIn(
                {"name": "vettalon:dependency:role", "value": role},
                component["properties"],
            )
        self.assertTrue(
            any(
                p["name"] == "vettalon:license:status"
                for p in bom["components"][2]["properties"]
            )
        )

    def test_cargo_cache_identity_cannot_traverse(self):
        with self.assertRaises(ValueError):
            trust.enrich_cargo_licenses(
                {
                    "components": [
                        {
                            "name": "../../outside",
                            "version": "1",
                            "purl": "pkg:cargo/evil@1",
                        }
                    ]
                }
            )

    def test_workspace_member_cannot_read_outside_source(self):
        source = self.root / "source"
        source.mkdir()
        (source / "Cargo.toml").write_text('[workspace]\nmembers=["../outside"]\n')
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "Cargo.toml").write_text('[package]\nname="hidden"\n')
        with self.assertRaises(ValueError):
            trust.annotate_cargo_roles({"components": []}, source)

    def test_native_cli_emits_schema_valid_graph_and_refuses_overwrite(self):
        source = self.root / "lock.json"
        source.write_text(
            json.dumps(
                {"lockfileVersion": 3, "packages": {"": {"name": "a", "version": "1"}}}
            )
        )
        bom = self.root / "bom.json"
        bom.write_text(json.dumps(self.bom))
        output = self.root / "output.json"
        args = ["npm-lock-v3", "--bom", bom, "--source", source, "--output", output]
        self.invoke(native, args)
        trust.validate_bom(json.loads(output.read_text()))
        with self.assertRaises(SystemExit):
            self.invoke(native, args)
        sequence = self.root / "sequence.json"
        sequence.write_text('{"Path":"app"}\n{"Path":"dependency","Version":"v1"}\n')
        self.assertEqual(len(native.read_json_sequence(sequence)), 2)

    def test_http_probe_real_loopback_with_disposable_fake_cli(self):
        # This exercises the probe harness only. Production CLI acceptance is
        # recorded separately by the root agent against the real final binary.
        fake = self.root / "fake-vettalon"
        fake.write_text(
            "#!"
            + sys.executable
            + "\n"
            + """import json, pathlib, sys, tomllib, urllib.request
args=sys.argv
root=pathlib.Path(args[2]);config=tomllib.loads(pathlib.Path(args[args.index('--config')+1]).read_text())
url=config['model'][0]['base_url']+'/chat/completions'
body=json.dumps({'messages':[{'content':(root/'app.py').read_text()}]}).encode()
with urllib.request.urlopen(urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'})) as response: response.read()
pathlib.Path(args[args.index('--report')+1]).write_text('{}')
"""
        )
        fake.chmod(0o755)
        output = self.root / "probe"
        self.invoke(probe, [fake, "--output", output])
        result = json.loads((output / "result.json").read_text())
        self.assertTrue(result["source_marker_observed"])
        self.assertEqual(result["requests"], 1)
        with self.assertRaises(SystemExit):
            self.invoke(probe, [fake, "--output", output])

    def test_trust_cli_schema_and_customer_dispatch(self):
        path = self.root / "bom.json"
        path.write_text(json.dumps(self.bom))
        self.invoke(trust, ["validate-sbom", path])
        with patch.object(trust, "run_syft", return_value=self.bom):
            self.invoke(
                trust,
                ["customer-sbom", self.root, "--output", self.root / "customer.json"],
            )
        bad = self.root / "bad.json"
        bad.write_text("{}")
        with self.assertRaises(SystemExit):
            self.invoke(trust, ["validate-sbom", bad])


if __name__ == "__main__":
    unittest.main()
