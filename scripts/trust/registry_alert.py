#!/usr/bin/env python3
"""Alert when an npm version has no matching public release run.

For each package and each published version in scope, require:
  (a) a tag v<version> and a published GitHub release for it in the public repo;
  (b) a release.yml run for that tag, built from the tag commit, with at least
      one successful attempt;
  (c) an npm SLSA provenance statement naming this repository's release.yml at
      that tag and commit, built on a GitHub-hosted runner by a run from (b),
      for the exact tarball digest the registry serves.

A provenance statement from a later attempt of a run whose earlier attempt
succeeded passes with a note: re-running npm-publish restages the packages that
are not yet live and then fails on the one that already is.

Scope: versions whose major.minor.patch is >= 0.3.0 (prereleases included).
The known earlier versions (LEGACY_VERSIONS) were published by hand or with a
token before trusted publishing, so they have no provenance and are listed as
not checked. Any other version below 0.3.0 is a mismatch: a new one cannot
legitimately appear.

Read-only: GET requests only; the GitHub token is sent to api.github.com only.
It reads the provenance statement but does not verify its Sigstore signature
(npm verifies provenance on publish; `npm audit signatures` re-checks it).

Exit codes: 0 every in-scope version matched, 1 mismatch, 2 could not check.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

REPO = "zhixuli0406/vettalon"
PACKAGES = (
    "vettalon",
    "@vettalon/darwin-arm64",
    "@vettalon/darwin-x64",
    "@vettalon/linux-x64",
    "@vettalon/linux-arm64",
)
MIN_VERSION = (0, 3, 0)
# Published before trusted publishing (2026-10-16 .. 2026-10-20), same set for
# every package. Frozen: nothing new below MIN_VERSION may ever be published.
LEGACY_VERSIONS = frozenset({"0.0.0-stage", "0.1.0", "0.1.1", "0.2.0", "0.2.1"})
WORKFLOW_PATH = ".github/workflows/release.yml"
SLSA_V1 = "https://slsa.dev/provenance/v1"
GITHUB_HOSTED = "https://github.com/actions/runner/github-hosted"
NPM = "https://registry.npmjs.org"
GITHUB_API = "https://api.github.com"
ISSUE_TITLE = "Registry version without a matching release run"
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


class CheckError(Exception):
    """The check itself could not run (network, HTTP or malformed data)."""


class TagState(NamedTuple):
    sha: str | None
    published: bool
    runs: dict  # run id -> frozenset of successful attempt numbers


class Row(NamedTuple):
    package: str
    version: str
    problems: tuple
    notes: tuple


def safe(value: object, limit: int = 120) -> str:
    """Render untrusted registry/API text inertly for a Markdown issue body."""
    text = re.sub(r"[^0-9A-Za-z@/._:+#=%-]", "?", str(value))
    return text[:limit] + ("..." if len(text) > limit else "")


class HttpFetcher:
    """GET JSON; returns None on 404. Retries transient failures."""

    def __init__(self, token: str | None = None, timeout: float = 30.0):
        self.token = token
        self.timeout = timeout

    def get_json(self, url: str):
        headers = {"Accept": "application/json", "User-Agent": "vettalon-registry-alert"}
        if self.token and url.startswith(GITHUB_API + "/"):
            headers["Authorization"] = f"Bearer {self.token}"
            headers["Accept"] = "application/vnd.github+json"
        for attempt in range(3):
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    return None
                if err.code < 500 or attempt == 2:
                    raise CheckError(f"GET {url}: HTTP {err.code}") from err
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
                if attempt == 2:
                    raise CheckError(f"GET {url}: {err}") from err
            time.sleep(2 * (attempt + 1))
        raise CheckError(f"GET {url}: retries exhausted")


def in_scope(version: str) -> bool:
    match = VERSION_RE.match(version)
    if not match:
        return True  # unparseable: never silently skipped
    return tuple(int(part) for part in match.groups()) >= MIN_VERSION


def purl(name: str, version: str) -> str:
    return f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"


def sha512_hex(integrity: str) -> str | None:
    if not integrity.startswith("sha512-"):
        return None
    try:
        return base64.b64decode(integrity[7:], validate=True).hex()
    except ValueError:
        return None


class Checker:
    def __init__(self, fetcher, repo: str = REPO):
        self.fetch = fetcher
        self.repo = repo
        self._tags: dict[str, TagState] = {}

    def api(self, path: str):
        return self.fetch.get_json(f"{GITHUB_API}/repos/{self.repo}/{path}")

    def tag_state(self, tag: str) -> TagState:
        if tag not in self._tags:
            q = urllib.parse.quote(tag, safe="")
            commit = self.api(f"commits/refs/tags/{q}")
            release = self.api(f"releases/tags/{q}")
            sha = commit.get("sha") if commit else None
            self._tags[tag] = TagState(
                sha=sha,
                published=bool(release) and release.get("draft") is False,
                runs=self.release_runs(tag, sha) if sha else {},
            )
        return self._tags[tag]

    def release_runs(self, tag: str, sha: str) -> dict:
        """Map each release.yml run for the tag commit to its successful attempts."""
        q = urllib.parse.quote(tag, safe="")
        page = self.api(f"actions/workflows/release.yml/runs?branch={q}&per_page=100") or {}
        runs = page.get("workflow_runs", [])
        if page.get("total_count", 0) > len(runs):
            raise CheckError(f"{tag}: more than {len(runs)} release runs; pagination not supported")
        found = {}
        for run in runs:
            if (run.get("head_branch") != tag or run.get("head_sha") != sha
                    or run.get("path") != WORKFLOW_PATH
                    or run.get("repository", {}).get("full_name") != self.repo):
                continue
            latest = int(run.get("run_attempt") or 1)
            ok = set()
            for n in range(1, latest + 1):
                detail = run if n == latest else self.api(f"actions/runs/{run['id']}/attempts/{n}")
                if (detail or {}).get("conclusion") == "success":
                    ok.add(n)
            found[int(run["id"])] = frozenset(ok)
        return found

    def load_provenance(self, name: str, version: str):
        url = f"{NPM}/-/npm/v1/attestations/{urllib.parse.quote(name, safe='@')}@{version}"
        body = self.fetch.get_json(url) or {}
        slsa = [a for a in body.get("attestations", []) if a.get("predicateType") == SLSA_V1]
        if len(slsa) != 1:
            return None, len(slsa)
        try:
            statement = json.loads(base64.b64decode(slsa[0]["bundle"]["dsseEnvelope"]["payload"]))
            predicate = statement["predicate"]
            if not (isinstance(predicate["buildDefinition"], dict)
                    and isinstance(predicate["runDetails"], dict)):
                raise TypeError("buildDefinition/runDetails must be objects")
        except (KeyError, ValueError, TypeError) as err:
            raise CheckError(f"{name}@{version}: malformed provenance ({err})") from err
        return statement, 1

    def provenance(self, name: str, version: str, meta: dict, state: TagState):
        """Return (problems, notes) for check (c) and its link to (b)."""
        dist = meta.get("dist", {})
        if not dist.get("attestations"):
            return ["(c) no npm provenance attestation"], []
        statement, count = self.load_provenance(name, version)
        if statement is None:
            return [f"(c) expected one SLSA v1 provenance, found {count}"], []
        build = statement["predicate"]["buildDefinition"]
        details = statement["predicate"]["runDetails"]
        problems = []
        subjects = {(s.get("name"), s.get("digest", {}).get("sha512"))
                    for s in statement.get("subject", [])}
        if (purl(name, version), sha512_hex(dist.get("integrity", ""))) not in subjects:
            problems.append("(c) provenance subject does not match the registry tarball digest")
        workflow = build.get("externalParameters", {}).get("workflow", {})
        expected = {"repository": f"https://github.com/{self.repo}", "path": WORKFLOW_PATH,
                    "ref": f"refs/tags/v{version}"}
        for key, want in expected.items():
            if workflow.get(key) != want:
                problems.append(f"(c) provenance workflow {key} is `{safe(workflow.get(key))}`")
        commits = {d.get("digest", {}).get("gitCommit") for d in build.get("resolvedDependencies", [])}
        if not state.sha or state.sha not in commits:
            problems.append("(c) provenance source commit is not the tag commit")
        if details.get("builder", {}).get("id") != GITHUB_HOSTED:
            problems.append("(c) provenance builder is not a GitHub-hosted runner")
        run_problems, notes = self.invocation(details.get("metadata", {}).get("invocationId", ""), state)
        return problems + run_problems, notes

    def invocation(self, invocation: str, state: TagState):
        match = re.fullmatch(
            rf"https://github\.com/{re.escape(self.repo)}/actions/runs/(\d+)/attempts/(\d+)",
            invocation)
        if not match:
            return [f"(c) provenance invocation `{safe(invocation)}` is not a run of this repo"], []
        run_id, attempt = int(match[1]), int(match[2])
        successful = state.runs.get(run_id)
        if not successful:
            return [f"(b/c) provenance run {run_id} is not a release.yml run for the tag "
                    "with a successful attempt"], []
        if attempt in successful:
            return [], []
        tried = ", ".join(str(n) for n in sorted(successful))
        return [], [f"provenance from run {run_id} attempt {attempt}; "
                    f"that run succeeded on attempt {tried}"]

    def check_version(self, name: str, version: str, meta: dict) -> Row:
        if not VERSION_RE.match(version):
            return Row(name, version, ("version is not a release version",), ())
        tag = f"v{version}"
        state = self.tag_state(tag)
        problems = []
        if not state.sha:
            problems.append(f"(a) no tag `{safe(tag)}` in {self.repo}")
        if not state.published:
            problems.append(f"(a) no published GitHub release for `{safe(tag)}`")
        if state.sha and not any(state.runs.values()):
            problems.append(f"(b) no successful release.yml run for `{safe(tag)}`")
        more, notes = self.provenance(name, version, meta, state)
        return Row(name, version, tuple(problems + more), tuple(notes))

    def run(self, packages=None):
        rows, skipped = [], []
        for name in packages or PACKAGES:
            doc = self.fetch.get_json(f"{NPM}/{urllib.parse.quote(name, safe='@')}")
            if not doc or not isinstance(doc.get("versions"), dict):
                raise CheckError(f"{name}: package not found on npm")
            for version, meta in sorted(doc["versions"].items()):
                if in_scope(version):
                    rows.append(self.check_version(name, version, meta))
                elif version in LEGACY_VERSIONS:
                    skipped.append((name, version))
                else:
                    rows.append(Row(name, version, (
                        "unexpected version below 0.3.0 (not a known pre-trusted-publishing release)",), ()))
        return rows, skipped


def render(rows, skipped, repo: str = REPO) -> str:
    failed = any(row.problems for row in rows)
    lines = [f"# {ISSUE_TITLE}" if failed else "# Registry alert: every version matched", "",
             f"Repository `{repo}`, workflow `{WORKFLOW_PATH}`.", "",
             "| Package | Version | Result |", "|---|---|---|"]
    for row in rows:
        result = "<br>".join(row.problems) if row.problems else "ok"
        if row.notes:
            result += " (" + "; ".join(row.notes) + ")"
        lines.append(f"| `{safe(row.package)}` | `{safe(row.version)}` | {result} |")
    if skipped:
        lines += ["", "Not checked (before 0.3.0: published by hand or with a token before "
                  "trusted publishing, so no provenance exists): "
                  + ", ".join(f"`{safe(n)}@{safe(v)}`" for n, v in skipped)]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--report", help="also write the Markdown report to this file")
    args = parser.parse_args(argv)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        rows, skipped = Checker(HttpFetcher(token), args.repo).run()
    except CheckError as err:
        print(f"registry-alert: could not check: {err}", file=sys.stderr)
        return 2
    report = render(rows, skipped, args.repo)
    print(report, end="")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if any(row.problems for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
