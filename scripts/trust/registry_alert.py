#!/usr/bin/env python3
"""Alert when an npm version has no matching public release run.

For each package and each published version in scope, require:
  (a) a tag v<version> on main and a published GitHub release in the public repo;
  (b) a release.yml run for that tag, built from the tag commit, with at least
      one successful npm-publish job;
  (c) an npm SLSA provenance statement naming this repository's release.yml at
      that tag and commit, built on a GitHub-hosted runner by a run from (b),
      for the exact tarball digest the registry serves.

A provenance statement from a later attempt of a run with a successful
npm-publish job on an earlier attempt passes with a note: re-running npm-publish
restages the packages that are not yet live and then fails on the one that already is.

Scope: versions whose major.minor.patch is >= 0.3.0 (prereleases included).
The known earlier versions (LEGACY_VERSIONS) were published by hand or with a
token before trusted publishing, so they have no provenance and are listed as
not checked. Any other version below 0.3.0 is a mismatch: a new one cannot
legitimately appear.

Read-only: GET requests only; the GitHub token is sent to api.github.com only.
It downloads each tarball and verifies its digest, provenance signature, exact
workflow/tag certificate identity and GitHub OIDC issuer. Transparency-log and
signature checks are delegated to `gh attestation verify`, whose trust root
comes from Sigstore's TUF repository through gh once per run, then verification is offline.

Exit codes: 0 every in-scope version matched, 1 mismatch, 2 could not check.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

REPO = "zhixuli0406/vettalon"
DEFAULT_BRANCH = "main"
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
PUBLISH_JOB = "npm-publish"
SLSA_V1 = "https://slsa.dev/provenance/v1"
GITHUB_HOSTED = "https://github.com/actions/runner/github-hosted"
NPM = "https://registry.npmjs.org"
GITHUB_API = "https://api.github.com"
ISSUE_TITLE = "Registry version without a matching release run"
ERROR_TITLE = "Registry alert could not check"
MAX_TARBALL_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_VERSIONS = 1000
VERIFY_TIMEOUT = 120
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class CheckError(Exception):
    """The check itself could not run (network, HTTP or malformed data)."""


class RunState(NamedTuple):
    successful: frozenset[int]
    latest: int


class TagState(NamedTuple):
    sha: str | None
    published: bool
    on_default_branch: bool
    runs: dict[int, RunState]  # run id -> successful npm-publish attempts and latest attempt


class Row(NamedTuple):
    package: str
    version: str
    problems: tuple
    notes: tuple


def safe(value: object, limit: int = 120) -> str:
    """Render untrusted registry/API text inertly for a Markdown issue body."""
    text = re.sub(r"[^0-9A-Za-z@/._:+#=%-]", "?", str(value))
    return text[:limit] + ("..." if len(text) > limit else "")


def safe_error(value: object) -> str:
    """Keep error prose readable without Markdown, HTML or mentions."""
    return re.sub(r"[^0-9A-Za-z /._:+=%-]", "?", str(value))[:300]


def npm_tarball_url(url: object) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname == "registry.npmjs.org"
                and parsed.port in (None, 443) and parsed.username is None
                and parsed.password is None)
    except ValueError:
        return False


class NpmRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not npm_tarball_url(newurl):
            raise CheckError("tarball redirect is not HTTPS on registry.npmjs.org")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class JsonRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, url: str):
        self.origin = urllib.parse.urlsplit(url)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme, target.netloc) != (self.origin.scheme, self.origin.netloc):
            raise CheckError("JSON redirect is not on the original scheme and host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
        opener = urllib.request.build_opener(JsonRedirectHandler(url))
        for attempt in range(3):
            try:
                request = urllib.request.Request(url, headers=headers)
                with opener.open(request, timeout=self.timeout) as response:
                    data = response.read(MAX_JSON_BYTES + 1)
                    if len(data) > MAX_JSON_BYTES:
                        raise CheckError("JSON response exceeds the download size cap")
                    result = json.loads(data)
                    if result is None:
                        raise CheckError(f"GET {url}: response body is null")
                    return result
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

    def get_bytes(self, url: str, destination: Path):
        """Stream an npm tarball to disk, without credentials, with bounded size."""
        if not npm_tarball_url(url):
            raise CheckError("tarball URL is not HTTPS on registry.npmjs.org")
        opener = urllib.request.build_opener(NpmRedirectHandler())
        for attempt in range(3):
            complete = False
            try:
                request = urllib.request.Request(
                    url, headers={"User-Agent": "vettalon-registry-alert"})
                with opener.open(request, timeout=self.timeout) as response:
                    if not npm_tarball_url(response.geturl()):
                        raise CheckError("tarball response is not HTTPS on registry.npmjs.org")
                    size = 0
                    with destination.open("wb") as handle:
                        while chunk := response.read(64 * 1024):
                            size += len(chunk)
                            if size > MAX_TARBALL_BYTES:
                                raise CheckError("tarball exceeds the download size cap")
                            handle.write(chunk)
                complete = True
                return
            except urllib.error.HTTPError as err:
                err.close()
                if err.code < 500 or attempt == 2:
                    raise CheckError(f"GET {url}: HTTP {err.code}") from err
            except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException) as err:
                if attempt == 2:
                    raise CheckError(f"GET {url}: {err}") from err
            finally:
                # Failed attempts must not leave partial downloads behind.
                if not complete:
                    destination.unlink(missing_ok=True)
            time.sleep(2 * (attempt + 1))
        raise CheckError(f"GET {url}: retries exhausted")


class ProvenanceVerifier:
    """Verify bundles with gh in an isolated, credential-free home directory."""

    def __init__(self, repo: str = REPO, *, download=None, runner=None):
        self.repo = repo
        self.download = download if download is not None else HttpFetcher().get_bytes
        self.runner = runner if runner is not None else subprocess.run
        self._temp = tempfile.TemporaryDirectory(prefix="registry-alert-")
        self.home = Path(self._temp.name)  # TemporaryDirectory creates mode 0700.
        self._trusted_root_path: Path | None = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._temp.cleanup()

    def _env(self):
        return {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.home),
                "GH_CONFIG_DIR": str(self.home), "GH_PROMPT_DISABLED": "1",
                "GH_NO_UPDATE_NOTIFIER": "1"}

    def _trusted_root(self, gh: str) -> Path:
        if self._trusted_root_path is not None:
            return self._trusted_root_path
        message = "could not fetch the Sigstore trusted root"
        try:
            for _ in range(2):
                result = self.runner([gh, "attestation", "trusted-root"], capture_output=True,
                                     text=True, env=self._env(), timeout=VERIFY_TIMEOUT, check=False)
                if result.returncode == 0:
                    break
            else:
                raise CheckError(message)
            lines = [line for line in result.stdout.splitlines() if line.strip()]
            if not lines or any(not isinstance(json.loads(line), dict) for line in lines):
                raise CheckError(message)
            path = self.home / "trusted_root.jsonl"
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                           "w", encoding="utf-8") as handle:
                handle.write(result.stdout)
        except (subprocess.TimeoutExpired, OSError, UnicodeError, ValueError) as err:
            raise CheckError(message) from err
        self._trusted_root_path = path
        return path

    def verify(self, version: str, dist: dict, bundle: dict, statement: dict) -> list[str]:
        if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
            return ["version is not a release version"]
        url = dist.get("tarball")
        if not npm_tarball_url(url):
            return ["(c) tarball URL is not HTTPS on registry.npmjs.org"]
        gh = shutil.which("gh")
        if gh is None:
            raise CheckError("gh is required to verify npm provenance")
        trusted_root = self._trusted_root(gh)
        tarball = self.home / "tarball.tgz"
        bundle_path = self.home / "bundle.json"
        try:
            self.download(url, tarball)
            digest = hashlib.sha512()
            with tarball.open("rb") as handle:
                while chunk := handle.read(64 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != sha512_hex(dist.get("integrity", "")):
                return ["(c) downloaded tarball does not match the registry integrity"]
            with os.fdopen(os.open(bundle_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                           "w", encoding="utf-8") as handle:
                json.dump(bundle, handle)
            argv = [gh, "attestation", "verify", str(tarball), "--bundle", str(bundle_path),
                    "--custom-trusted-root", str(trusted_root),
                    "--repo", self.repo, "--digest-alg", "sha512", "--predicate-type", SLSA_V1,
                    "--cert-identity", f"https://github.com/{self.repo}/{WORKFLOW_PATH}"
                    f"@refs/tags/v{version}", "--cert-oidc-issuer", OIDC_ISSUER, "--format", "json"]
            env = self._env()
            for _ in range(2):
                try:
                    result = self.runner(argv, capture_output=True, text=True, env=env,
                                         timeout=VERIFY_TIMEOUT, check=False)
                except subprocess.TimeoutExpired as err:
                    raise CheckError("gh attestation verify timed out") from err
                except (OSError, UnicodeError) as err:
                    raise CheckError("gh attestation verify could not run") from err
                if result.returncode == 0:
                    break
            else:
                return ["(c) provenance signature or signer identity did not verify"]
            try:
                verified = json.loads(result.stdout)
                if not isinstance(verified, list) or len(verified) != 1:
                    raise ValueError("expected exactly one verification result")
                verified_statement = verified[0]["verificationResult"]["statement"]
                if not isinstance(verified_statement, dict):
                    raise ValueError("expected a verified statement object")
            except (ValueError, KeyError, TypeError) as err:
                raise CheckError("gh attestation verify returned malformed JSON results") from err
            if verified_statement != statement:
                return ["(c) verified provenance statement does not match the decoded bundle"]
            return []
        finally:
            tarball.unlink(missing_ok=True)
            bundle_path.unlink(missing_ok=True)


def in_scope(version: str) -> bool:
    match = VERSION_RE.fullmatch(version)
    if not match:
        return True  # unparseable: never silently skipped
    return tuple(int(part) for part in match.groups()) >= MIN_VERSION


def purl(name: str, version: str) -> str:
    return f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"


def sha512_hex(integrity: str) -> str | None:
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        return None
    try:
        return base64.b64decode(integrity[7:], validate=True).hex()
    except ValueError:
        return None


def validate_runs(page, tag: str) -> list[dict]:
    """Validate the complete runs response before filtering release bindings."""
    if (not isinstance(page, dict)
            or type(page.get("total_count")) is not int
            or page["total_count"] < 0
            or not isinstance(page.get("workflow_runs"), list)):
        raise CheckError(f"{tag}: malformed runs response")
    runs = page["workflow_runs"]
    if any(not isinstance(run, dict)
           or any(type(run.get(key)) is not int or run[key] < 1
                  for key in ("id", "run_attempt"))
           or any(not isinstance(run.get(key), str)
                  for key in ("head_branch", "head_sha", "path"))
           or not isinstance(run.get("repository"), dict)
           or not isinstance(run["repository"].get("full_name"), str)
           for run in runs):
        raise CheckError(f"{tag}: malformed runs response")
    if page["total_count"] > len(runs):
        raise CheckError(f"{tag}: more than {len(runs)} release runs; pagination not supported")
    if (page["total_count"] < len(runs)
            or len({run["id"] for run in runs}) != len(runs)):
        raise CheckError(f"{tag}: malformed runs response")
    return runs


def validate_statement(statement: object) -> None:
    """Validate the provenance statement shape used by the checker."""
    def object_field(parent, key, default):
        value = parent.get(key, default)
        if not isinstance(value, dict):
            raise TypeError(f"{key} must be an object")
        return value

    def object_entries(parent, key):
        value = parent.get(key, [])
        if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
            raise TypeError(f"{key} must be a list of objects")
        return value

    def string_field(parent, key):
        if key in parent and not isinstance(parent[key], str):
            raise TypeError(f"{key} must be a string")

    if not isinstance(statement, dict):
        raise TypeError("statement must be an object")
    predicate = object_field(statement, "predicate", None)
    build = object_field(predicate, "buildDefinition", None)
    details = object_field(predicate, "runDetails", None)
    for subject in object_entries(statement, "subject"):
        string_field(subject, "name")
        string_field(object_field(subject, "digest", {}), "sha512")
    external = object_field(build, "externalParameters", {})
    workflow = object_field(external, "workflow", {})
    for key in ("repository", "path", "ref"):
        string_field(workflow, key)
    for dependency in object_entries(build, "resolvedDependencies"):
        string_field(object_field(dependency, "digest", {}), "gitCommit")
    string_field(object_field(details, "builder", {}), "id")
    string_field(object_field(details, "metadata", {}), "invocationId")


class Checker:
    def __init__(self, fetcher, verifier, repo: str = REPO):
        self.fetch = fetcher
        self.verifier = verifier
        self.repo = repo
        self._tags: dict[str, TagState] = {}

    def api(self, path: str):
        return self.fetch.get_json(f"{GITHUB_API}/repos/{self.repo}/{path}")

    def tag_state(self, tag: str) -> TagState:
        if tag not in self._tags:
            q = urllib.parse.quote(tag, safe="")
            ref = self.api(f"git/ref/tags/{q}")
            if ref is not None and (
                    not isinstance(ref, dict)
                    or ref.get("ref") != f"refs/tags/{tag}"
                    or not isinstance(ref.get("object"), dict)
                    or ref["object"].get("type") not in ("commit", "tag")
                    or not isinstance(ref["object"].get("sha"), str)
                    or not SHA_RE.fullmatch(ref["object"]["sha"])):
                raise CheckError(f"{tag}: malformed tag ref response")
            commit = self.api(f"commits/refs/tags/{q}") if ref is not None else None
            if ref is not None and (
                    not isinstance(commit, dict)
                    or not isinstance(commit.get("sha"), str)
                    or not SHA_RE.fullmatch(commit["sha"])):
                raise CheckError(f"{tag}: malformed commit response")
            release = self.api(f"releases/tags/{q}")
            sha = commit["sha"] if ref is not None else None
            on_default_branch = False
            if sha:
                comparison = self.api(f"compare/{sha}...{DEFAULT_BRANCH}?per_page=1")
                if comparison is not None:
                    if (not isinstance(comparison, dict)
                            or comparison.get("status") not in ("ahead", "identical", "behind", "diverged")):
                        raise CheckError(f"{tag}: malformed compare response")
                    on_default_branch = comparison["status"] in ("ahead", "identical")
            self._tags[tag] = TagState(
                sha=sha,
                published=bool(release) and release.get("draft") is False,
                on_default_branch=on_default_branch,
                runs=self.release_runs(tag, sha) if sha else {},
            )
        return self._tags[tag]

    def release_runs(self, tag: str, sha: str) -> dict[int, RunState]:
        """Map each release.yml run to successful attempts and its latest attempt."""
        q = urllib.parse.quote(tag, safe="")
        runs = validate_runs(
            self.api(f"actions/workflows/release.yml/runs?branch={q}&per_page=100"), tag)
        found = {}
        for run in runs:
            if (run.get("head_branch") != tag or run.get("head_sha") != sha
                    or run.get("path") != WORKFLOW_PATH
                    or run["repository"]["full_name"] != self.repo):
                continue
            latest = run["run_attempt"]
            ok = {n for n in range(1, latest + 1)
                  if self.publish_succeeded(tag, run["id"], n)}
            found[run["id"]] = RunState(frozenset(ok), latest)
        return found

    def publish_succeeded(self, tag: str, run_id: int, attempt: int) -> bool:
        page = self.api(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
        prefix = f"{tag}: run {run_id} attempt {attempt}: "
        if (not isinstance(page, dict)
                or type(page.get("total_count")) is not int
                or page["total_count"] < 0
                or not isinstance(page.get("jobs"), list)):
            raise CheckError(f"{prefix}malformed jobs response")
        jobs = page["jobs"]
        if page["total_count"] > len(jobs):
            raise CheckError(f"{prefix}more than {len(jobs)} jobs; pagination not supported")
        if (page["total_count"] != len(jobs)
                or any(not isinstance(job, dict)
                       or not isinstance(job.get("name"), str)
                       or "conclusion" not in job
                       or (job["conclusion"] is not None
                           and not isinstance(job["conclusion"], str)) for job in jobs)):
            raise CheckError(f"{prefix}malformed jobs response")
        return any(job["name"] == PUBLISH_JOB and job["conclusion"] == "success"
                   for job in jobs)

    def load_provenance(self, name: str, version: str):
        url = f"{NPM}/-/npm/v1/attestations/{urllib.parse.quote(name, safe='@')}@{version}"
        body = self.fetch.get_json(url)
        if (not isinstance(body, dict)
                or not isinstance(body.get("attestations"), list)
                or any(not isinstance(entry, dict) for entry in body["attestations"])):
            raise CheckError(f"{name}@{version}: malformed provenance")
        slsa = [a for a in body["attestations"] if a.get("predicateType") == SLSA_V1]
        if len(slsa) != 1:
            return None, None, len(slsa)
        try:
            statement = json.loads(base64.b64decode(slsa[0]["bundle"]["dsseEnvelope"]["payload"]))
            validate_statement(statement)
        except (KeyError, ValueError, TypeError) as err:
            raise CheckError(f"{name}@{version}: malformed provenance ({err})") from err
        return statement, slsa[0]["bundle"], 1

    def provenance(self, name: str, version: str, meta: dict, state: TagState):
        """Return (problems, notes) for check (c) and its link to (b)."""
        dist = meta.get("dist", {})
        if not dist.get("attestations"):
            return ["(c) no npm provenance attestation"], []
        statement, bundle, count = self.load_provenance(name, version)
        if statement is None:
            return [f"(c) expected one SLSA v1 provenance, found {count}"], []
        build = statement["predicate"]["buildDefinition"]
        details = statement["predicate"]["runDetails"]
        problems = self.verifier.verify(version, dist, bundle, statement)
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
        run = state.runs.get(run_id)
        if run is not None and not 1 <= attempt <= run.latest:
            return [f"(b/c) provenance names attempt {attempt}, which run {run_id} never had"], []
        if run is None or not run.successful:
            return [f"(b/c) provenance run {run_id} is not a release.yml run for the tag "
                    "with a successful npm-publish job"], []
        if attempt in run.successful:
            return [], []
        tried = ", ".join(str(n) for n in sorted(run.successful))
        return [], [f"provenance from run {run_id} attempt {attempt}; "
                    f"its npm-publish job succeeded on attempt {tried}"]

    def check_version(self, name: str, version: str, meta: dict) -> Row:
        if not VERSION_RE.fullmatch(version):
            return Row(name, version, ("version is not a release version",), ())
        tag = f"v{version}"
        state = self.tag_state(tag)
        problems = []
        if not state.sha:
            problems.append(f"(a) no tag `{safe(tag)}` in {self.repo}")
        elif not state.on_default_branch:
            problems.append(f"(a) tag commit for `{safe(tag)}` is not on main")
        if not state.published:
            problems.append(f"(a) no published GitHub release for `{safe(tag)}`")
        if state.sha and not any(run.successful for run in state.runs.values()):
            problems.append(f"(b) no successful npm-publish job in a release.yml run for `{safe(tag)}`")
        more, notes = self.provenance(name, version, meta, state)
        return Row(name, version, tuple(problems + more), tuple(notes))

    def run(self, packages=None):
        rows, skipped = [], []
        for name in packages or PACKAGES:
            doc = self.fetch.get_json(f"{NPM}/{urllib.parse.quote(name, safe='@')}")
            if not doc or not isinstance(doc.get("versions"), dict):
                raise CheckError(f"{name}: package not found on npm")
            if len(doc["versions"]) > MAX_VERSIONS:
                raise CheckError(f"{name}: more than {MAX_VERSIONS} versions")
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
        with ProvenanceVerifier(args.repo) as verifier:
            rows, skipped = Checker(HttpFetcher(token), verifier, args.repo).run()
    except Exception as err:
        print(f"registry-alert: could not check: {err}", file=sys.stderr)
        if args.report:
            with open(args.report, "w", encoding="utf-8") as handle:
                handle.write(f"# {ERROR_TITLE}\n\nThe check did not finish: {safe_error(err)}\n")
        return 2
    report = render(rows, skipped, args.repo)
    print(report, end="")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if any(row.problems for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
