import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ENTRY = Path(__file__).with_name("readback.py")
SPEC = importlib.util.spec_from_file_location("public_trust_readback", ENTRY)
readback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readback)


def assets():
    return [
        {
            "id": name,
            "name": name,
            "size": 1,
            "digest": "sha256:" + "a" * 64,
            "url": f"https://github.com/{readback.REPO}/releases/download/{readback.TAG}/{name}",
        }
        for name in sorted(readback.EXPECTED_NAMES)
    ]


class PublicReadbackTests(unittest.TestCase):
    def test_metadata_identity_includes_mutable_release_state(self):
        original = {
            "tagName": readback.TAG,
            "publishedAt": "2026-10-17T15:08:11Z",
            "url": f"https://github.com/{readback.REPO}/releases/tag/{readback.TAG}",
            "isDraft": False,
            "isPrerelease": False,
            "assets": assets(),
        }
        for key, replacement in (
            ("tagName", "v0.2.1"), ("publishedAt", "2026-10-18T00:00:00Z"),
            ("isDraft", True), ("isPrerelease", True), ("url", "https://example.invalid"),
        ):
            changed = dict(original, **{key: replacement})
            with self.subTest(key=key):
                self.assertNotEqual(readback.metadata_identity(original), readback.metadata_identity(changed))
        changed_assets = [dict(item) for item in original["assets"]]
        changed_assets[0]["digest"] = "sha256:" + "b" * 64
        self.assertNotEqual(
            readback.metadata_identity(original),
            readback.metadata_identity(dict(original, assets=changed_assets)),
        )

    def test_asset_set_and_bounds_fail_closed(self):
        good = assets()
        readback.validate_asset_set(good)
        bads = [
            good[:-1],
            good[:-1] + [good[0]],
            [dict(item, size=readback.MAX_ASSET_BYTES + 1) if i == 0 else item
             for i, item in enumerate(good)],
            [dict(item, size=2 * 1024 * 1024) for item in good],
            [dict(item, url="https://example.invalid") if i == 0 else item
             for i, item in enumerate(good)],
            [dict(item, digest="sha256:bad") if i == 0 else item
             for i, item in enumerate(good)],
        ]
        for index, bad in enumerate(bads):
            with self.subTest(index=index), self.assertRaises(ValueError):
                readback.validate_asset_set(bad)

    def test_snapshot_detects_dependency_drift_and_extra_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "schemas").mkdir()
            for relative in readback.SNAPSHOT_FILES:
                path = source / relative
                path.write_bytes(relative.encode())
            (source / "schemas" / "LICENSE").write_text("schema license")
            (source / "schemas" / "SOURCE.md").write_text("schema source")
            target = root / "snapshot"
            manifest = readback.snapshot_verifier(source, target)
            self.assertEqual(set(manifest), set(readback.SNAPSHOT_FILES))
            self.assertTrue(readback.snapshot_matches(target, manifest))
            dependency = target / "cargo_graph.py"
            dependency.chmod(0o600)
            dependency.write_bytes(b"changed")
            self.assertFalse(readback.snapshot_matches(target, manifest))
            dependency.write_bytes(b"cargo_graph.py")
            self.assertTrue(readback.snapshot_matches(target, manifest))
            (target / "schemas" / "unexpected.schema.json").write_text("{}")
            self.assertFalse(readback.snapshot_matches(target, manifest))
            (source / "schemas" / "unexpected.schema.json").write_text("{}")
            with self.assertRaises(ValueError):
                readback.snapshot_verifier(source, root / "another-snapshot")

    def test_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.write_text("data")
            alias = root / "alias"
            alias.symlink_to(real)
            with self.assertRaises(ValueError):
                readback.read_regular_nofollow(alias, 1024)

    def test_output_requires_private_new_file_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private"
            private.mkdir(mode=0o700)
            victim = root / "victim"
            victim.write_text("unchanged")
            alias = private / "receipt.json"
            alias.symlink_to(victim)
            with self.assertRaises(FileExistsError):
                readback.open_private_output(alias)
            self.assertEqual(victim.read_text(), "unchanged")
            alias.unlink()
            fd = readback.open_private_output(alias)
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
            os.close(fd)
            with self.assertRaises(FileExistsError):
                readback.open_private_output(alias)
            public = root / "public"
            public.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                readback.open_private_output(public / "receipt.json")

    def test_deadline_rejects_before_transport(self):
        with patch.object(readback.subprocess, "run") as run:
            with self.assertRaises(TimeoutError):
                readback.stream_asset(
                    f"https://github.com/{readback.REPO}/releases/download/{readback.TAG}/vettalon-linux-x64.tar.gz",
                    Path("unused"), 1, "a" * 64, deadline=time.monotonic() - 1,
                )
            run.assert_not_called()

    def test_transport_passes_size_and_time_limits_to_curl(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "asset"
            url = f"https://github.com/{readback.REPO}/releases/download/{readback.TAG}/vettalon-linux-x64.tar.gz"

            def fake_curl(args, **kwargs):
                self.assertIn("--max-time", args)
                self.assertEqual(args[args.index("--max-filesize") + 1], "3")
                self.assertLessEqual(kwargs["timeout"], readback.MAX_ASSET_SECONDS)
                self.assertNotIn("GH_TOKEN", kwargs["env"])
                Path(args[args.index("--output") + 1]).write_bytes(b"abc")
                return SimpleNamespace(returncode=0)

            with patch.object(readback.subprocess, "run", side_effect=fake_curl):
                result = readback.stream_asset(
                    url, target, 3, hashlib.sha256(b"abc").hexdigest(),
                    deadline=time.monotonic() + 60,
                )
            self.assertEqual(result["size"], 3)
            self.assertTrue(result["metadata_digest_match"])

    def test_untrusted_process_environment_removed(self):
        with patch.dict(os.environ, {
            "BASH_ENV": "bad", "ENV": "bad", "PYTHONPATH": "bad",
            "PYTHONSTARTUP": "bad", "PYTHONHOME": "bad", "GH_TOKEN": "test-auth",
        }):
            result = readback.safe_env()
            for name in ("BASH_ENV", "ENV", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME"):
                self.assertNotIn(name, result)
            self.assertEqual(result["GH_TOKEN"], "test-auth")
            self.assertNotIn("GH_TOKEN", readback.safe_env(include_auth=False))

    def test_archived_receipt_consistency_only(self):
        """Offline data/source consistency; no signature or attestation re-verification."""
        root = Path(__file__).resolve().parents[3]
        receipt = json.loads(Path(__file__).with_name("receipt.json").read_text())
        self.assertEqual(receipt["schema"], "vettalon-cli-public-trust-readback-v1")
        self.assertEqual(receipt["status"], "public_cli_release_verification_pass")
        self.assertEqual(receipt["asset_counts"], {"archives": 4, "required_sidecars": 24, "total": 28})
        self.assertEqual(set(receipt["assets"]), readback.EXPECTED_NAMES)
        for name, asset in receipt["assets"].items():
            with self.subTest(asset=name):
                self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]))
                self.assertGreater(asset["size"], 0)
                self.assertLessEqual(asset["size"], readback.MAX_ASSET_BYTES)
                self.assertTrue(asset["metadata_digest_match"])
        self.assertEqual(set(receipt["verification"]), set(readback.ARCHIVES))
        for name, result in receipt["verification"].items():
            with self.subTest(archive=name):
                self.assertEqual(result["verifier_exit_code"], 0)
                self.assertEqual(result["status"], "pass")
                self.assertEqual(result["github_attestation_subjects_expected"], 2)
        self.assertTrue(receipt["metadata_pre_post_match"])
        self.assertTrue(receipt["verifier"]["snapshot_pre_post_match"])
        self.assertTrue(receipt["negative_control"]["one_byte_archive_tamper_rejected"])
        dependencies = receipt["verifier"]["dependencies"]
        self.assertEqual(set(dependencies), set(readback.SNAPSHOT_FILES))
        self.assertEqual(receipt["verifier"]["sha256"], dependencies["verify-release.sh"]["sha256"])
        for name, expected in dependencies.items():
            with self.subTest(name=name):
                data = readback.read_regular_nofollow(root / "scripts" / "trust" / name, readback.MAX_SOURCE_FILE_BYTES)
                self.assertEqual(len(data), expected["size"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected["sha256"])


if __name__ == "__main__":
    unittest.main()
