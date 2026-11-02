"""Opt-in integration tests using real gh, npm and Sigstore TUF (network required)."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
import registry_alert as ra  # noqa: E402

PACKAGE = "vettalon"
VERSION = "0.7.0"
INTEGRITY = ("sha512-JvA/uR3r3Nmea7X+6T0RAQLMWNE1qT47aTMTcWaaKPPmIFbzKKlBCEBKsGyeubic"
             "vc3KUGWSNggkBjhDzHW4Nw==")
TARBALL = "https://registry.npmjs.org/vettalon/-/vettalon-0.7.0.tgz"
SIGNATURE_PROBLEM = "(c) provenance signature or signer identity did not verify"


class GateTests(unittest.TestCase):
    def test_registry_alert_requires_integration_gate_and_version(self):
        if "/.github/workflows/registry-alert.yml@" in os.environ.get("GITHUB_WORKFLOW_REF", ""):
            self.assertEqual(os.environ.get("VETTALON_GH_INTEGRATION"), "1")
            self.assertTrue(os.environ.get("VETTALON_GH_VERSION"))


@unittest.skipUnless(os.environ.get("VETTALON_GH_INTEGRATION") == "1",
                     "set VETTALON_GH_INTEGRATION=1 to run real gh integration tests")
class GhIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        expected = os.environ.get("VETTALON_GH_VERSION")
        if expected is not None:
            result = subprocess.run(["gh", "--version"], capture_output=True, text=True,
                                    check=True, timeout=30)
            if not result.stdout.splitlines() or f"gh version {expected} " not in result.stdout.splitlines()[0]:
                raise AssertionError("gh version does not match VETTALON_GH_VERSION")
        cls.statement, cls.bundle, count = ra.Checker(ra.HttpFetcher(), None).load_provenance(
            PACKAGE, VERSION)
        if count != 1:
            raise AssertionError(f"expected one SLSA provenance, found {count}")
        cls.dist = {"tarball": TARBALL, "integrity": INTEGRITY}

    def reject(self, *, version=VERSION, dist=None, bundle=None, statement=None,
               repo=ra.REPO, download=None, issuer=None):
        results = []

        def run(argv, **kwargs):
            argv = list(argv)
            if issuer is not None and "--cert-oidc-issuer" in argv:
                argv[argv.index("--cert-oidc-issuer") + 1] = issuer
            result = subprocess.run(argv, **kwargs)
            results.append((argv, result))
            return result

        with ra.ProvenanceVerifier(repo=repo, download=download, runner=run) as verifier:
            problems = verifier.verify(version, self.dist if dist is None else dist,
                                       self.bundle if bundle is None else bundle,
                                       self.statement if statement is None else statement)
        self.assertEqual(problems, [SIGNATURE_PROBLEM])
        verify_results = [(argv, result) for argv, result in results
                          if argv[1:3] == ["attestation", "verify"]]
        self.assertTrue(verify_results, "gh attestation verify must actually run")
        for argv, result in verify_results:
            self.assertIn("--custom-trusted-root", argv)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("unknown flag", result.stderr)
            self.assertNotIn("Usage:", result.stderr)

    def test_known_good(self):
        with ra.ProvenanceVerifier() as verifier:
            self.assertEqual(verifier.verify(VERSION, self.dist, self.bundle, self.statement), [])

    def test_wrong_tag_identity(self):
        self.reject(version="0.6.1")

    def test_wrong_repository(self):
        self.reject(repo="cli/cli")

    def test_tampered_tarball(self):
        dist = dict(self.dist)

        def download(url, path):
            ra.HttpFetcher().get_bytes(url, path)
            data = path.read_bytes() + b"tampered tarball"
            path.write_bytes(data)
            dist["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

        self.reject(dist=dist, download=download)

    def test_tampered_bundle(self):
        bundle = copy.deepcopy(self.bundle)
        signature = bundle["dsseEnvelope"]["signatures"][0]
        data = bytearray(base64.b64decode(signature["sig"]))
        data[0] ^= 1
        signature["sig"] = base64.b64encode(data).decode()
        self.reject(bundle=bundle)

    def test_tampered_payload(self):
        bundle = copy.deepcopy(self.bundle)
        statement = copy.deepcopy(self.statement)
        statement["subject"][0]["name"] += "-tampered"
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
        self.reject(bundle=bundle, statement=statement)

    def test_wrong_issuer(self):
        self.reject(issuer="https://accounts.google.com")


if __name__ == "__main__":
    unittest.main()
