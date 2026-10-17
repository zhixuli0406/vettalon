from pathlib import Path
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorkflowContractTests(unittest.TestCase):
    def test_actual_tag_guard_rejects_branch_dispatch_and_mismatch(self):
        text = (ROOT / ".github/workflows/release.yml").read_text()
        block = text.split("      - name: Validate tag\n", 1)[1].split(
            "      - uses:", 1
        )[0]
        script = "\n".join(
            line[10:] for line in block.split("        run: |\n", 1)[1].splitlines()
        )
        for tag, ref, expected in [
            ("v0.1.2", "refs/tags/v0.1.2", 0),
            ("v0.1.2", "refs/heads/main", 1),
            ("v0.1.2", "refs/tags/v0.1.3", 1),
            ("bad;echo no", "refs/tags/bad", 1),
        ]:
            result = subprocess.run(
                ["bash", "-c", script],
                env={**os.environ, "TAG": tag, "WORKFLOW_REF": ref},
                capture_output=True,
            )
            self.assertEqual(result.returncode, expected, (tag, ref, result.stderr))

    def test_new_sidecars_survive_existing_artifact_glob(self):
        from fnmatch import fnmatch

        for suffix in (
            "",
            ".sig",
            ".pem",
            ".sha256",
            ".sigstore.json",
            ".build-record.json",
            ".cdx.json",
        ):
            self.assertTrue(
                fnmatch("vettalon-linux-x64.tar.gz" + suffix, "vettalon-*.tar.gz*")
            )

    def test_release_verifier_requires_exact_identity_source_and_issuer(self):
        text = (ROOT / "scripts/trust/verify-release.sh").read_text()
        for token in (
            '--certificate-identity "$identity"',
            "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
            '--source-ref "refs/tags/$tag"',
            '--source-digest "$source_sha"',
            "--deny-self-hosted-runners",
            '--cert-identity "$identity"',
        ):
            self.assertIn(token, text)
        self.assertNotIn("ignore-tlog", text)
        self.assertNotIn("--certificate-identity-regexp", text)


if __name__ == "__main__":
    unittest.main()
