"""Offline tests for the npm registry alert (recorded fixture; no network)."""

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))
import registry_alert as ra  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).parent / "fixtures" / "registry_alert" / "live-20261021.json"
PACKAGES = ("vettalon", "@vettalon/darwin-arm64")
API = f"{ra.GITHUB_API}/repos/{ra.REPO}"
PKG = f"{ra.NPM}/vettalon"
RUNS = f"{API}/actions/workflows/release.yml/runs?branch=v0.3.1&per_page=100"
JOBS = f"{API}/actions/runs/39545317385/attempts/1/jobs?per_page=100"
ATT = f"{ra.NPM}/-/npm/v1/attestations/vettalon@0.3.1"


class FixtureFetcher:
    """Serve recorded responses; an unknown URL is a test bug, not a 404."""

    def __init__(self, responses):
        self.responses = responses

    def get_json(self, url):
        if url not in self.responses:
            raise AssertionError(f"unexpected request {url}")
        return copy.deepcopy(self.responses[url])


def load():
    return json.loads(FIXTURE.read_text())


def statement(responses, url=ATT):
    bundle = responses[url]["attestations"][0]["bundle"]["dsseEnvelope"]
    return json.loads(base64.b64decode(bundle["payload"]))


def set_statement(responses, data, url=ATT):
    bundle = responses[url]["attestations"][0]["bundle"]["dsseEnvelope"]
    bundle["payload"] = base64.b64encode(json.dumps(data).encode()).decode()


class FakeVerifier:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def verify(self, version, dist, bundle, decoded):
        assert json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"])) == decoded
        return []


def check(responses):
    rows, skipped = ra.Checker(FixtureFetcher(responses), FakeVerifier()).run(packages=PACKAGES)
    return {(r.package, r.version): r for r in rows}, skipped


class RecordedRegistryTests(unittest.TestCase):
    def test_verifier_required_and_problems_propagate_once_per_package_version(self):
        responses = load()
        # Expand the recorded platform response to all five packages offline.
        source = "@vettalon/darwin-arm64"
        for package in ra.PACKAGES:
            if package in PACKAGES:
                continue
            for url, value in list(responses.items()):
                if source.replace("/", "%2F") in url:
                    target = url.replace(source.replace("/", "%2F"), package.replace("/", "%2F"))
                    responses[target] = copy.deepcopy(value)
                    if "/attestations/" in target:
                        decoded = statement(responses, target)
                        for subject in decoded["subject"]:
                            subject["name"] = subject["name"].replace("darwin-arm64", package.split("/")[1])
                        set_statement(responses, decoded, target)
        verifier = mock.Mock()
        verifier.verify.return_value = ["(c) test signature failure"]
        with self.assertRaises(TypeError):
            ra.Checker(FixtureFetcher(responses))
        rows, _ = ra.Checker(FixtureFetcher(responses), verifier).run()
        scoped = [row for row in rows if row.version in ("0.3.0", "0.3.1")]
        self.assertEqual(len(scoped), 10)
        self.assertEqual(verifier.verify.call_count, 10)
        identities = [args.args[3]["subject"][0]["name"] for args in verifier.verify.call_args_list]
        self.assertEqual(set(identities), {ra.purl(p, v) for p in ra.PACKAGES for v in ("0.3.0", "0.3.1")})
        self.assertTrue(all(row.problems == ("(c) test signature failure",) for row in scoped))

    def test_recorded_releases_pass_and_old_versions_are_skipped(self):
        rows, skipped = check(load())
        self.assertEqual(set(rows), {(p, v) for p in PACKAGES for v in ("0.3.0", "0.3.1")})
        self.assertTrue(all(not r.problems for r in rows.values()), rows)
        self.assertIn(("vettalon", "0.2.1"), skipped)
        self.assertIn(("vettalon", "0.0.0-stage"), skipped)

    def test_provenance_from_rerun_attempt_passes_with_note(self):
        rows, _ = check(load())
        note = rows[("@vettalon/darwin-arm64", "0.3.0")].notes
        self.assertEqual(len(note), 1)
        self.assertIn("attempt 4", note[0])
        self.assertIn("succeeded on attempt 3", note[0])
        self.assertEqual(rows[("vettalon", "0.3.1")].notes, ())

    def test_provenance_from_nonexistent_attempt_fails(self):
        for attempt in (0, 2):
            with self.subTest(attempt=attempt):
                responses = load()
                data = statement(responses)
                data["predicate"]["runDetails"]["metadata"]["invocationId"] = (
                    f"https://github.com/{ra.REPO}/actions/runs/39545317385/attempts/{attempt}")
                set_statement(responses, data)
                row = check(responses)[0][("vettalon", "0.3.1")]
                self.assertIn(
                    f"(b/c) provenance names attempt {attempt}, which run 39545317385 never had",
                    row.problems)
                self.assertFalse(row.notes)

    def test_malformed_runs_cannot_check(self):
        valid = load()[RUNS]
        cases = [None, [], {}, {"workflow_runs": []},
                 {"total_count": "1", "workflow_runs": []},
                 {"total_count": True, "workflow_runs": []},
                 {"total_count": -1, "workflow_runs": []},
                 {"total_count": 0, "workflow_runs": {}},
                 {"total_count": 1, "workflow_runs": [None]}]
        for key, values in {
                "id": (None, True, 0, -1, "1"),
                "run_attempt": (None, True, 0, -1, "1"),
                "head_branch": (None, 1), "head_sha": (None, 1),
                "path": (None, 1),
                "repository": (None, [], {}, {"full_name": 1}),
        }.items():
            for value in values:
                page = copy.deepcopy(valid)
                page["workflow_runs"][0][key] = value
                cases.append(page)
            page = copy.deepcopy(valid)
            del page["workflow_runs"][0][key]
            cases.append(page)
        # Validate even runs that would otherwise be filtered out.
        page = copy.deepcopy(valid)
        page["workflow_runs"][0].update(head_branch="other", head_sha=None)
        cases.append(page)
        for page in cases:
            with self.subTest(page=page):
                responses = load()
                responses[RUNS] = page
                with self.assertRaisesRegex(ra.CheckError, "malformed runs response"):
                    check(responses)

    def test_runs_count_smaller_than_list_cannot_check(self):
        responses = load()
        responses[RUNS]["total_count"] = 0
        with self.assertRaisesRegex(ra.CheckError, "malformed runs response"):
            check(responses)

    def test_duplicate_run_ids_cannot_check(self):
        responses = load()
        page = responses[RUNS]
        duplicate = copy.deepcopy(page["workflow_runs"][0])
        duplicate["run_attempt"] += 1
        page["workflow_runs"].append(duplicate)
        page["total_count"] = len(page["workflow_runs"])
        with self.assertRaisesRegex(ra.CheckError, "malformed runs response"):
            check(responses)

    def test_paginated_runs_cannot_check(self):
        responses = load()
        responses[RUNS]["total_count"] = 2
        with self.assertRaisesRegex(ra.CheckError, "release runs; pagination not supported"):
            check(responses)

    def test_unreleased_version_fails_every_check(self):
        responses = load()
        responses[PKG]["versions"]["0.3.2"] = {"dist": {"integrity": "sha512-AAAA"}}
        responses[f"{API}/commits/refs/tags/v0.3.2"] = None
        responses[f"{API}/releases/tags/v0.3.2"] = None
        problems = " ".join(check(responses)[0][("vettalon", "0.3.2")].problems)
        self.assertIn("(a) no tag", problems)
        self.assertIn("(a) no published GitHub release", problems)
        self.assertIn("(c) no npm provenance", problems)

    def test_prerelease_in_scope_and_nonsemver_flagged(self):
        self.assertTrue(ra.in_scope("0.3.0-rc.1"))
        self.assertTrue(ra.in_scope("1.0.0"))
        self.assertFalse(ra.in_scope("0.2.9"))
        self.assertTrue(ra.in_scope("latest"))
        responses = load()
        responses[PKG]["versions"]["not-a-version"] = {"dist": {}}
        row = check(responses)[0][("vettalon", "not-a-version")]
        self.assertEqual(row.problems, ("version is not a release version",))

    def test_new_version_below_scope_is_a_mismatch(self):
        responses = load()
        responses[PKG]["versions"]["0.2.99"] = {"dist": {"integrity": "sha512-AAAA"}}
        rows, skipped = check(responses)
        self.assertIn("unexpected version below 0.3.0", rows[("vettalon", "0.2.99")].problems[0])
        self.assertNotIn(("vettalon", "0.2.99"), skipped)
        self.assertEqual({v for n, v in skipped if n == "vettalon"}, set(ra.LEGACY_VERSIONS))

    def test_draft_release_fails(self):
        responses = load()
        responses[f"{API}/releases/tags/v0.3.1"]["draft"] = True
        row = check(responses)[0][("vettalon", "0.3.1")]
        self.assertIn("(a) no published GitHub release for `v0.3.1`", row.problems)

    def test_failed_run_fails(self):
        responses = load()
        responses[JOBS]["jobs"][0]["conclusion"] = "failure"
        problems = " ".join(check(responses)[0][("vettalon", "0.3.1")].problems)
        self.assertIn("(b) no successful npm-publish job in a release.yml run", problems)
        self.assertIn("(b/c) provenance run", problems)

    def test_v060_failed_run_with_successful_npm_publish_passes(self):
        # Reuse the recorded release bindings for the 0.6.0 two-attempt shape.
        responses = json.loads(json.dumps(load()).replace("0.3.1", "0.6.0")
                               .replace("39545317385", "40805388383"))
        for url in responses:
            if "/attestations/" in url and url.endswith("@0.6.0"):
                data = json.loads(json.dumps(statement(responses, url))
                                  .replace("0.3.1", "0.6.0")
                                  .replace("39545317385/attempts/1", "40805388383/attempts/2"))
                set_statement(responses, data, url)
        url = f"{API}/actions/workflows/release.yml/runs?branch=v0.6.0&per_page=100"
        responses[url]["workflow_runs"][0].update(conclusion="failure", run_attempt=2)
        jobs = f"{API}/actions/runs/40805388383/attempts/1/jobs?per_page=100"
        responses[jobs]["jobs"][0]["conclusion"] = "failure"
        responses[jobs.replace("/attempts/1/", "/attempts/2/")] = {
            "total_count": 2,
            "jobs": [{"name": "npm-publish", "conclusion": "success"},
                     {"name": "images / Publish agents-base", "conclusion": "failure"}],
        }
        row = check(responses)[0][("vettalon", "0.6.0")]
        self.assertFalse(row.problems)
        self.assertFalse(row.notes)

    def test_no_npm_publish_job_is_a_mismatch(self):
        for name in ("other", "prefix npm-publish", "npm-publish suffix"):
            with self.subTest(name=name):
                responses = load()
                responses[JOBS]["jobs"][0]["name"] = name
                row = check(responses)[0][("vettalon", "0.3.1")]
                self.assertTrue(any(p.startswith("(b)") for p in row.problems))

    def test_jobs_404_cannot_check(self):
        responses = load()
        responses[JOBS] = None
        with self.assertRaises(ra.CheckError):
            check(responses)

    def test_paginated_jobs_cannot_check(self):
        responses = load()
        responses[JOBS]["total_count"] = 2
        with self.assertRaisesRegex(ra.CheckError, "jobs; pagination not supported"):
            check(responses)

    def test_malformed_jobs_cannot_check(self):
        cases = [[], {}, {"total_count": "1", "jobs": []},
                 {"total_count": 0, "jobs": {}}, {"total_count": 1, "jobs": [None]},
                 {"total_count": 1, "jobs": [{"name": "npm-publish"}]},
                 {"total_count": 1, "jobs": [{"name": "npm-publish", "conclusion": 1}]}]
        for page in cases:
            with self.subTest(page=page):
                responses = load()
                responses[JOBS] = page
                with self.assertRaises(ra.CheckError):
                    check(responses)

    def test_successful_run_with_failed_npm_publish_is_a_mismatch(self):
        responses = load()
        responses[JOBS]["jobs"][0]["conclusion"] = "failure"
        row = check(responses)[0][("vettalon", "0.3.1")]
        self.assertTrue(any(p.startswith("(b)") for p in row.problems))
        self.assertIn("with a successful npm-publish job", " ".join(row.problems))

    def test_run_from_other_commit_or_workflow_is_ignored(self):
        for key, value in (("head_sha", "0" * 40), ("path", ".github/workflows/x.yml")):
            responses = load()
            url = f"{API}/actions/workflows/release.yml/runs?branch=v0.3.1&per_page=100"
            responses[url]["workflow_runs"][0][key] = value
            row = check(responses)[0][("vettalon", "0.3.1")]
            self.assertTrue(any(p.startswith("(b)") for p in row.problems), (key, row))

    def test_provenance_mismatches_fail(self):
        cases = {
            "repository": ("buildDefinition", "externalParameters", "workflow", "repository",
                           "https://github.com/someone/fork", "provenance workflow repository"),
            "path": ("buildDefinition", "externalParameters", "workflow", "path",
                     ".github/workflows/other.yml", "provenance workflow path"),
            "ref": ("buildDefinition", "externalParameters", "workflow", "ref",
                    "refs/heads/main", "provenance workflow ref"),
        }
        for label, (a, b, c, key, value, expected) in cases.items():
            responses = load()
            data = statement(responses)
            data["predicate"][a][b][c][key] = value
            set_statement(responses, data)
            problems = " ".join(check(responses)[0][("vettalon", "0.3.1")].problems)
            self.assertIn(expected, problems, label)

    def test_builder_commit_and_invocation_mismatches_fail(self):
        edits = [
            (lambda p: p["runDetails"]["builder"].update(id="https://example.test/self-hosted"),
             "not a GitHub-hosted runner"),
            (lambda p: p["buildDefinition"]["resolvedDependencies"][0]["digest"].update(
                gitCommit="1" * 40), "source commit is not the tag commit"),
            (lambda p: p["runDetails"]["metadata"].update(
                invocationId="https://github.com/someone/fork/actions/runs/1/attempts/1"),
             "is not a run of this repo"),
            (lambda p: p["runDetails"]["metadata"].update(
                invocationId=f"https://github.com/{ra.REPO}/actions/runs/1/attempts/1"),
             "(b/c) provenance run 1"),
        ]
        for edit, expected in edits:
            responses = load()
            data = statement(responses)
            edit(data["predicate"])
            set_statement(responses, data)
            problems = " ".join(check(responses)[0][("vettalon", "0.3.1")].problems)
            self.assertIn(expected, problems)

    def test_tarball_digest_mismatch_fails(self):
        responses = load()
        responses[PKG]["versions"]["0.3.1"]["dist"]["integrity"] = "sha512-" + "A" * 88
        row = check(responses)[0][("vettalon", "0.3.1")]
        self.assertIn("(c) provenance subject does not match the registry tarball digest",
                      row.problems)

    def test_missing_or_duplicate_provenance_fails(self):
        responses = load()
        del responses[PKG]["versions"]["0.3.1"]["dist"]["attestations"]
        self.assertIn("(c) no npm provenance attestation",
                      check(responses)[0][("vettalon", "0.3.1")].problems)
        responses = load()
        entries = responses[ATT]["attestations"]
        entries.append(copy.deepcopy(entries[0]))
        self.assertIn("(c) expected one SLSA v1 provenance, found 2",
                      check(responses)[0][("vettalon", "0.3.1")].problems)

    def test_malformed_attestations_cannot_check(self):
        for body in (None, [], "invalid", {}, {"attestations": None},
                     {"attestations": {}}, {"attestations": "invalid"},
                     {"attestations": [None]}):
            with self.subTest(body=body):
                responses = load()
                responses[ATT] = body
                with self.assertRaisesRegex(ra.CheckError, "malformed provenance"):
                    check(responses)

    def test_malformed_statement_fields_cannot_check(self):
        paths = [
            (), ("predicate",), ("predicate", "buildDefinition"),
            ("predicate", "runDetails"), ("subject",), ("subject", 0),
            ("subject", 0, "name"), ("subject", 0, "digest"),
            ("subject", 0, "digest", "sha512"),
            ("predicate", "buildDefinition", "externalParameters"),
            ("predicate", "buildDefinition", "externalParameters", "workflow"),
            ("predicate", "buildDefinition", "resolvedDependencies"),
            ("predicate", "buildDefinition", "resolvedDependencies", 0),
            ("predicate", "buildDefinition", "resolvedDependencies", 0, "digest"),
            ("predicate", "buildDefinition", "resolvedDependencies", 0, "digest", "gitCommit"),
            ("predicate", "runDetails", "builder"),
            ("predicate", "runDetails", "metadata"),
            ("predicate", "runDetails", "metadata", "invocationId"),
        ]
        for path in paths:
            for value in (None, [], "invalid", 1):
                responses = load()
                data = statement(responses)
                original = data
                for key in path:
                    original = original[key]
                # Strings are valid leaf shapes; empty lists are valid collections.
                if isinstance(original, type(value)):
                    continue
                with self.subTest(path=path, value=value):
                    if path:
                        parent = data
                        for key in path[:-1]:
                            parent = parent[key]
                        parent[path[-1]] = value
                    else:
                        data = value
                    set_statement(responses, data)
                    with self.assertRaisesRegex(ra.CheckError, "malformed provenance"):
                        check(responses)

    def test_malformed_provenance_and_missing_package_cannot_check(self):
        responses = load()
        responses[ATT]["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = "!!"
        with self.assertRaises(ra.CheckError):
            check(responses)
        responses = load()
        responses[PKG] = None
        with self.assertRaises(ra.CheckError):
            check(responses)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.data = b"test tarball bytes"
        self.decoded = statement(load())
        self.bundle = load()[ATT]["attestations"][0]["bundle"]
        self.dist = {"tarball": f"{ra.NPM}/vettalon/-/vettalon-0.3.1.tgz",
                     "integrity": "sha512-" + base64.b64encode(
                         hashlib.sha512(self.data).digest()).decode()}
        self.download = mock.Mock(side_effect=lambda url, path: path.write_bytes(self.data))
        self.runner = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, json.dumps([{"verificationResult": {"statement": self.decoded}}]), ""))
        self.which = mock.patch.object(ra.shutil, "which", return_value="/usr/bin/gh").start()
        self.addCleanup(mock.patch.stopall)
        self.verifier = ra.ProvenanceVerifier(download=self.download, runner=self.runner)
        self.addCleanup(self.verifier.close)

    def verify(self, **kwargs):
        return self.verifier.verify(kwargs.get("version", "0.3.1"),
                                    kwargs.get("dist", self.dist), self.bundle, self.decoded)

    def assert_clean(self):
        self.assertFalse((self.verifier.home / "tarball.tgz").exists())
        self.assertFalse((self.verifier.home / "bundle.json").exists())

    def test_argv_environment_permissions_and_cleanup(self):
        self.verifier.repo = "owner/custom-repo"
        home = self.verifier.home

        def run(argv, **kwargs):
            self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
            bundle = Path(argv[argv.index("--bundle") + 1])
            self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o600)
            self.assertEqual(json.loads(bundle.read_text()), self.bundle)
            self.assertEqual(Path(argv[3]).read_bytes(), self.data)
            return subprocess.CompletedProcess(argv, 0, json.dumps([
                {"verificationResult": {"statement": self.decoded}}]), "")

        self.runner.side_effect = run
        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret", "GITHUB_TOKEN": "also-secret",
                                          "GH_HOST": "evil.test", "GH_DEBUG": "api"}):
            self.assertEqual(self.verify(), [])
        argv = self.runner.call_args.args[0]
        self.assertEqual(argv, ["/usr/bin/gh", "attestation", "verify", str(home / "tarball.tgz"),
                               "--bundle", str(home / "bundle.json"), "--repo", "owner/custom-repo",
                               "--digest-alg", "sha512", "--predicate-type", ra.SLSA_V1,
                               "--cert-identity", "https://github.com/owner/custom-repo/"
                               ".github/workflows/release.yml@refs/tags/v0.3.1",
                               "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
                               "--format", "json"])
        options = self.runner.call_args.kwargs
        self.assertEqual(options["timeout"], 120)
        self.assertFalse(options.get("shell", False))
        self.assertEqual(options["env"], {"PATH": os.environ.get("PATH", os.defpath),
                                         "HOME": str(home), "GH_CONFIG_DIR": str(home),
                                         "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"})
        self.which.assert_called_once_with("gh")
        self.assert_clean()
        with self.verifier:
            self.assertEqual(self.verify(), [])
        self.assertFalse(home.exists())

    def test_untrusted_urls_never_download_or_run_gh(self):
        for url in ("https://evil.test/a", "http://registry.npmjs.org/a",
                    "https://registry.npmjs.org.evil.test/a", "file:///tmp/a",
                    "https://user:password@registry.npmjs.org/a", "https://[broken", None):
            with self.subTest(url=url):
                self.assertIn("tarball URL", " ".join(self.verify(dist={**self.dist, "tarball": url})))
        self.download.assert_not_called()
        self.runner.assert_not_called()

    def test_integrity_mismatch_never_runs_gh(self):
        for integrity in ("sha512-AAAA", None, "sha512-!", "sha256-AAAA"):
            self.dist["integrity"] = integrity
            self.assertEqual(self.verify(), ["(c) downloaded tarball does not match the registry integrity"])
        self.runner.assert_not_called()
        self.assert_clean()

    def test_failed_verification_retries_once_without_stderr(self):
        self.runner.return_value = subprocess.CompletedProcess([], 1, "", "secret stderr")
        self.assertEqual(self.verify(), ["(c) provenance signature or signer identity did not verify"])
        self.assertEqual(self.runner.call_count, 2)
        self.assertEqual(self.download.call_count, 1)
        self.assert_clean()

    def test_second_verification_can_succeed(self):
        self.runner.side_effect = [subprocess.CompletedProcess([], 1, "", ""), self.runner.return_value]
        self.assertEqual(self.verify(), [])
        self.assertEqual(self.runner.call_count, 2)
        self.assert_clean()

    def test_timeout_and_missing_gh_raise(self):
        self.runner.side_effect = subprocess.TimeoutExpired("gh", 120)
        with self.assertRaisesRegex(ra.CheckError, "timed out"):
            self.verify()
        self.assertEqual(self.runner.call_count, 1)
        self.assert_clean()
        self.which.return_value = None
        with self.assertRaisesRegex(ra.CheckError, "gh is required"):
            self.verify()
        self.assertEqual(self.runner.call_count, 1)

    def test_malformed_verifier_output_raises(self):
        for output in ("not JSON", "[]", "[{}, {}]", "{}", "[null]", "[{}]",
                       '[{"verificationResult":{"statement":null}}]'):
            with self.subTest(output=output):
                self.runner.return_value = subprocess.CompletedProcess([], 0, output, "")
                with self.assertRaisesRegex(ra.CheckError, "malformed JSON"):
                    self.verify()
                self.assert_clean()

    def test_verified_statement_must_match(self):
        changed = copy.deepcopy(self.decoded)
        changed["subject"] = []
        self.runner.return_value.stdout = json.dumps([{"verificationResult": {"statement": changed}}])
        self.assertEqual(self.verify(), ["(c) verified provenance statement does not match the decoded bundle"])
        self.assert_clean()

    def test_invalid_version_never_reaches_argv(self):
        for version in ("--help", "0.3.1\n", "0.3.1/evil", "$(command)"):
            self.assertEqual(self.verify(version=version), ["version is not a release version"])
        self.download.assert_not_called()
        self.runner.assert_not_called()

    def test_download_failure_cleans_partial_file(self):
        def fail(url, path):
            path.write_bytes(b"partial")
            raise ra.CheckError("download failed")

        self.download.side_effect = fail
        with self.assertRaises(ra.CheckError):
            self.verify()
        self.assert_clean()
        self.runner.assert_not_called()


class TarballDownloadTests(unittest.TestCase):
    url = f"{ra.NPM}/vettalon/-/vettalon-0.3.1.tgz"

    def response(self, data, url=None):
        response = io.BytesIO(data)
        response.geturl = lambda: url or self.url
        return response

    def test_stream_limit_and_no_authorization(self):
        self.assertEqual(ra.MAX_TARBALL_BYTES, 256 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ra.urllib.request, "build_opener") as build, \
                mock.patch.object(ra, "MAX_TARBALL_BYTES", 8):
            target = Path(directory) / "tarball.tgz"
            build.return_value.open.return_value = self.response(b"12345678")
            fetcher = ra.HttpFetcher("secret-token", timeout=7)
            fetcher.get_bytes(self.url, target)
            self.assertEqual(target.read_bytes(), b"12345678")
            request = build.return_value.open.call_args.args[0]
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 7)
            self.assertIsInstance(build.call_args.args[0], ra.NpmRedirectHandler)
            build.return_value.open.return_value = self.response(b"123456789")
            with self.assertRaisesRegex(ra.CheckError, "size cap"):
                fetcher.get_bytes(self.url, target)
            self.assertFalse(target.exists())

    def test_redirect_is_refused_and_final_url_is_checked(self):
        request = ra.urllib.request.Request(self.url)
        for url in ("https://evil.test/a", "http://registry.npmjs.org/a"):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ra.CheckError, "redirect"):
                    ra.NpmRedirectHandler().redirect_request(request, None, 302, "", {}, url)
                with tempfile.TemporaryDirectory() as directory, \
                        mock.patch.object(ra.urllib.request, "build_opener") as build:
                    target = Path(directory) / "tarball.tgz"
                    build.return_value.open.return_value = self.response(b"data", url)
                    with self.assertRaisesRegex(ra.CheckError, "response"):
                        ra.HttpFetcher().get_bytes(self.url, target)
                    self.assertFalse(target.exists())

    def test_transient_failures_retry_three_times_and_reset_partial_bytes(self):
        class Interrupted(io.BytesIO):
            geturl = lambda self: TarballDownloadTests.url

            def read(self, size):
                if self.tell():
                    raise TimeoutError("interrupted download")
                return super().read(3)

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ra.urllib.request, "build_opener") as build, \
                mock.patch.object(ra.time, "sleep") as sleep:
            target = Path(directory) / "tarball.tgz"
            build.return_value.open.side_effect = [Interrupted(b"partial"),
                ra.urllib.error.HTTPError(self.url, 503, "unavailable", {}, None),
                self.response(b"complete")]
            ra.HttpFetcher().get_bytes(self.url, target)
            self.assertEqual(target.read_bytes(), b"complete")
            self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(4)])
            build.return_value.open.side_effect = ra.urllib.error.URLError("offline")
            with self.assertRaises(ra.CheckError):
                ra.HttpFetcher().get_bytes(self.url, target)
            self.assertEqual(build.return_value.open.call_count, 6)
            self.assertFalse(target.exists())

    def test_client_http_error_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ra.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = ra.urllib.error.HTTPError(
                self.url, 404, "not found", {}, None)
            with self.assertRaises(ra.CheckError):
                ra.HttpFetcher().get_bytes(self.url, Path(directory) / "tarball.tgz")
            self.assertEqual(build.return_value.open.call_count, 1)

    def test_stream_connection_errors_retry_and_raise_check_error(self):
        for error in (ConnectionResetError("reset"), ra.http.client.IncompleteRead(b"partial")):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(ra.urllib.request, "build_opener") as build, \
                    mock.patch.object(ra.time, "sleep") as sleep:
                response = build.return_value.open.return_value.__enter__.return_value
                response.geturl.return_value = self.url
                response.read.side_effect = error
                target = Path(directory) / "tarball.tgz"
                with self.assertRaises(ra.CheckError):
                    ra.HttpFetcher().get_bytes(self.url, target)
                self.assertEqual(build.return_value.open.call_count, 3)
                self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(4)])
                self.assertFalse(target.exists())


class ReportAndCliTests(unittest.TestCase):
    def test_safe_neutralizes_markdown(self):
        rendered = ra.safe("`x`\n| <img src=a> [l](u)")
        self.assertNotRegex(rendered, r"[`\n|<>\[\]() ]")

    def test_report_title_and_exit_codes(self):
        responses = load()
        with mock.patch.object(ra, "HttpFetcher", lambda token: FixtureFetcher(responses)), \
                mock.patch.object(ra, "ProvenanceVerifier", lambda repo: FakeVerifier()), \
                mock.patch.object(ra, "PACKAGES", PACKAGES), \
                mock.patch("sys.stdout"):
            self.assertEqual(ra.main([]), 0)
            responses[f"{API}/releases/tags/v0.3.1"]["draft"] = True
            self.assertEqual(ra.main([]), 1)

            def broken(token):
                fetcher = mock.Mock()
                fetcher.get_json.side_effect = ra.CheckError("offline")
                return fetcher

            with mock.patch.object(ra, "HttpFetcher", broken), mock.patch("sys.stderr"):
                self.assertEqual(ra.main([]), 2)
        rows, skipped = check(responses)
        self.assertTrue(ra.render(list(rows.values()), skipped).startswith(f"# {ra.ISSUE_TITLE}"))

    def test_cli_writes_inert_error_report_and_cleans_up(self):
        error = "offline error `code`\n<img> @everyone [link](https://bad.test) " + "x" * 400
        homes = []

        def broken(checker):
            homes.append(checker.verifier.home)
            raise ra.CheckError(error)

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ra.Checker, "run", broken), mock.patch("sys.stderr") as stderr:
            report = Path(directory) / "report.md"
            self.assertEqual(ra.main(["--report", str(report)]), 2)
            body = report.read_text()
        self.assertTrue(body.startswith(f"# {ra.ERROR_TITLE}\n\n"))
        rendered_error = body.split("The check did not finish: ", 1)[1].rstrip("\n")
        self.assertIn("offline error ", rendered_error)
        self.assertNotRegex(rendered_error, r"[\r\n`<>@\[\]()]")
        self.assertLessEqual(len(rendered_error), 300)
        self.assertTrue(stderr.write.called)
        self.assertFalse(homes[0].exists())

    def test_unexpected_exception_writes_error_report(self):
        error = RuntimeError("unexpected `error` @everyone <tag>")
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ra.Checker, "run", side_effect=error), \
                mock.patch("sys.stderr") as stderr:
            report = Path(directory) / "report.md"
            self.assertEqual(ra.main(["--report", str(report)]), 2)
            self.assertEqual(report.read_text(),
                             f"# {ra.ERROR_TITLE}\n\nThe check did not finish: {ra.safe_error(error)}\n")
            self.assertTrue(stderr.write.called)

    def test_json_redirect_blocks_before_authorization_is_copied(self):
        url = f"{API}/releases/tags/v0.3.1"
        for token in (None, "secret-token"):
            for target in ("https://evil.test/x", "http://api.github.com/x",
                           "https://api.github.com:444/x"):
                with self.subTest(token=token, target=target), \
                        mock.patch.object(ra.urllib.request, "build_opener") as build, \
                        mock.patch.object(ra.urllib.request.HTTPRedirectHandler,
                                          "redirect_request") as redirected:
                    def open_request(request, timeout):
                        self.assertEqual(request.get_header("Authorization"),
                                         f"Bearer {token}" if token else None)
                        handler = build.call_args.args[0]
                        return handler.redirect_request(request, None, 302, "", {}, target)

                    build.return_value.open.side_effect = open_request
                    with self.assertRaisesRegex(ra.CheckError, "JSON redirect"):
                        ra.HttpFetcher(token).get_json(url)
                    # urllib must never construct a redirected request carrying the token.
                    redirected.assert_not_called()
                    self.assertEqual(build.return_value.open.call_count, 1)

    def test_json_same_origin_redirect_follows(self):
        url = f"{API}/old"
        request = ra.urllib.request.Request(url, headers={"Authorization": "Bearer secret-token"})
        target = f"{API}/new"
        redirected = ra.JsonRedirectHandler(url).redirect_request(
            request, None, 302, "", {}, target)
        self.assertEqual(redirected.full_url, target)
        self.assertEqual(redirected.get_header("Authorization"), "Bearer secret-token")

    def test_json_404_and_transient_retries_are_preserved(self):
        url = f"{API}/example"
        with mock.patch.object(ra.urllib.request, "build_opener") as build, \
                mock.patch.object(ra.time, "sleep") as sleep:
            not_found = ra.urllib.error.HTTPError(url, 404, "not found", {}, None)
            self.addCleanup(not_found.close)
            build.return_value.open.side_effect = not_found
            self.assertIsNone(ra.HttpFetcher().get_json(url))
            self.assertEqual(build.return_value.open.call_count, 1)
            sleep.assert_not_called()
            build.return_value.open.reset_mock()
            unavailable = ra.urllib.error.HTTPError(url, 503, "unavailable", {}, None)
            self.addCleanup(unavailable.close)
            build.return_value.open.side_effect = [
                unavailable, ra.urllib.error.URLError("offline"), io.BytesIO(b"{}")]
            self.assertEqual(ra.HttpFetcher().get_json(url), {})
            self.assertEqual(build.return_value.open.call_count, 3)
            self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(4)])

    def test_token_is_sent_to_github_api_only(self):
        seen = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, *args):
                return b"{}"

        def fake_urlopen(request, timeout):
            seen.append((request.full_url, request.get_header("Authorization")))
            return Response()

        fetcher = ra.HttpFetcher("secret-token")
        with mock.patch("urllib.request.build_opener") as build:
            build.return_value.open.side_effect = fake_urlopen
            fetcher.get_json(f"{ra.NPM}/vettalon")
            fetcher.get_json(f"{API}/releases/tags/v0.3.1")
            fetcher.get_json("https://api.github.com.example.test/x")
        self.assertEqual(seen[0][1], None)
        self.assertEqual(seen[1][1], "Bearer secret-token")
        self.assertEqual(seen[2][1], None)


class WorkflowContractTests(unittest.TestCase):
    text = (ROOT / ".github/workflows/registry-alert.yml").read_text()

    def test_least_privilege_and_public_repo_only(self):
        self.assertIn("\npermissions: {}\n", self.text)
        check, issue = self.text.split("\n  issue:\n")
        self.assertIn("if: github.repository == 'zhixuli0406/vettalon'", check)
        self.assertIn("      contents: read\n      actions: read\n", check)
        self.assertNotIn("write", check)
        self.assertIn("    permissions:\n      issues: write\n    steps:", issue)
        self.assertNotIn("checkout", issue)
        self.assertNotIn("secrets.", self.text)
        self.assertIn("schedule:", self.text)
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("    timeout-minutes: 20\n", check)
        self.assertIn("if: always() && github.repository == 'zhixuli0406/vettalon' "
                      "&& needs.check.result != 'cancelled' && needs.check.result != 'skipped' "
                      "&& (needs.check.result != 'success' || needs.check.outputs.status != 'ok')", issue)
        title = ("TITLE: ${{ needs.check.outputs.status == 'mismatch' && '"
                 + ra.ISSUE_TITLE + "' || '" + ra.ERROR_TITLE + "' }}\n")
        self.assertIn(title, issue.split("        run: |", 1)[0])
        self.assertIn('if [ -z "$REPORT" ]; then', issue)
        self.assertIn("The check did not finish.", issue)
        self.assertIn('printf \'Failed check: %s\\n\\n\' "$RUN_URL"', issue)

    def test_actions_pinned_and_expressions_kept_out_of_scripts(self):
        for ref in re.findall(r"uses: (\S+)", self.text):
            self.assertRegex(ref, r"@[0-9a-f]{40}$")
        for block in re.findall(r"run: \|\n((?:          .*\n|\n)+)", self.text):
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
