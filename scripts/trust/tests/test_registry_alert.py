"""Offline tests for the npm registry alert (recorded fixture; no network)."""

import base64
import copy
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))
import registry_alert as ra  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).parent / "fixtures" / "registry_alert" / "live-20261021.json"
PACKAGES = ("vettalon", "@vettalon/darwin-arm64")
API = f"{ra.GITHUB_API}/repos/{ra.REPO}"
PKG = f"{ra.NPM}/vettalon"
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


def check(responses):
    rows, skipped = ra.Checker(FixtureFetcher(responses)).run(packages=PACKAGES)
    return {(r.package, r.version): r for r in rows}, skipped


class RecordedRegistryTests(unittest.TestCase):
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
        url = f"{API}/actions/workflows/release.yml/runs?branch=v0.3.1&per_page=100"
        responses[url]["workflow_runs"][0]["conclusion"] = "failure"
        problems = " ".join(check(responses)[0][("vettalon", "0.3.1")].problems)
        self.assertIn("(b) no successful release.yml run", problems)
        self.assertIn("(b/c) provenance run", problems)

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

    def test_malformed_provenance_and_missing_package_cannot_check(self):
        responses = load()
        responses[ATT]["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = "!!"
        with self.assertRaises(ra.CheckError):
            check(responses)
        responses = load()
        responses[PKG] = None
        with self.assertRaises(ra.CheckError):
            check(responses)


class ReportAndCliTests(unittest.TestCase):
    def test_safe_neutralizes_markdown(self):
        rendered = ra.safe("`x`\n| <img src=a> [l](u)")
        self.assertNotRegex(rendered, r"[`\n|<>\[\]() ]")

    def test_report_title_and_exit_codes(self):
        responses = load()
        with mock.patch.object(ra, "HttpFetcher", lambda token: FixtureFetcher(responses)), \
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
        with mock.patch("urllib.request.urlopen", fake_urlopen):
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
        self.assertIn(f"TITLE: {ra.ISSUE_TITLE}\n", issue)

    def test_actions_pinned_and_expressions_kept_out_of_scripts(self):
        for ref in re.findall(r"uses: (\S+)", self.text):
            self.assertRegex(ref, r"@[0-9a-f]{40}$")
        for block in re.findall(r"run: \|\n((?:          .*\n|\n)+)", self.text):
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
