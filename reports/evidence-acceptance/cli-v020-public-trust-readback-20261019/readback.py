#!/usr/bin/env python3
"""Bounded public CLI release readback; emits only sanitized receipts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


REPO = "zhixuli0406/vettalon"
TAG = "v0.2.0"
SOURCE_SHA = "e3493f620487d23dbbd6a13021c216f415974585"
ARCHIVES = (
    "vettalon-darwin-arm64.tar.gz",
    "vettalon-darwin-x64.tar.gz",
    "vettalon-linux-arm64.tar.gz",
    "vettalon-linux-x64.tar.gz",
)
SUFFIXES = ("", ".sha256", ".sig", ".pem", ".sigstore.json", ".cdx.json", ".build-record.json")
EXPECTED_NAMES = {archive + suffix for archive in ARCHIVES for suffix in SUFFIXES}
MAX_ASSET_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
SNAPSHOT_FILES = (
    "verify-release.sh", "trust.py", "cargo_graph.py",
    "schemas/bom-1.6.schema.json", "schemas/jsf-0.82.schema.json",
    "schemas/spdx.schema.json",
)
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_ASSET_SECONDS = 45
MAX_RUN_SECONDS = 300
SAFE_ENV_KEYS = (
    "PATH", "HOME", "XDG_CONFIG_HOME", "GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN",
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
)


def safe_env(*, include_auth=True):
    result = {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}
    if not include_auth:
        result.pop("GH_TOKEN", None)
        result.pop("GITHUB_TOKEN", None)
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    return result


def time_left(deadline, cap):
    remaining = deadline - time.monotonic()
    if remaining < 0.1:
        raise TimeoutError("readback deadline expired")
    return min(remaining, cap)


def open_private_output(path):
    parent = path.parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("output parent must be an owned real 0700 directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600:
        os.close(fd)
        raise ValueError("output is not a private regular file")
    return fd


def command(args, *, env, deadline, timeout=90):
    result = subprocess.run(
        args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=time_left(deadline, timeout), check=False,
    )
    # Never put unreviewed command output, local paths or credentials in a receipt.
    return result.returncode


def command_json(args, *, deadline):
    result = subprocess.run(
        args, env=safe_env(), capture_output=True, timeout=time_left(deadline, 30), check=True,
    )
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("GitHub metadata output exceeds bound")
    return json.loads(result.stdout)


def stream_asset(url, destination, expected_size, expected_digest, *, deadline):
    if not url.startswith(f"https://github.com/{REPO}/releases/download/{TAG}/"):
        raise ValueError("unexpected release download URL")
    asset_time = time_left(deadline, MAX_ASSET_SECONDS)
    result = subprocess.run([
        "curl", "-q", "--fail", "--location", "--silent", "--show-error",
        "--proto", "=https", "--proto-redir", "=https", "--max-time", f"{asset_time:.3f}",
        "--max-filesize", str(expected_size), "--output", str(destination), "--url", url,
    ], env=safe_env(include_auth=False), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=time_left(deadline, asset_time), check=False)
    if result.returncode != 0:
        raise ValueError("bounded asset download failed")
    digest = hashlib.sha256()
    size = 0
    before = destination.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("download is not a regular file")
    with os.fdopen(os.open(destination, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        opened = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("download file changed during open")
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("readback deadline expired")
            block = source.read(min(1024 * 1024, expected_size - size + 1))
            if not block:
                break
            size += len(block)
            if size > expected_size or size > MAX_ASSET_BYTES:
                raise ValueError("download exceeded asset size bound")
            digest.update(block)
        after = os.fstat(source.fileno())
    stable = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if stable(before) != stable(opened) or stable(opened) != stable(after):
        raise ValueError("download file changed during hash")
    actual = digest.hexdigest()
    if size != expected_size or actual != expected_digest:
        raise ValueError("download differs from GitHub asset metadata")
    return {"size": size, "sha256": actual, "metadata_digest_match": True}


def metadata_identity(release):
    return (
        release["tagName"], release["publishedAt"], release["url"],
        release["isDraft"], release["isPrerelease"],
        tuple(sorted(
            (asset["id"], asset["name"], asset["size"], asset.get("digest"), asset["url"])
            for asset in release["assets"]
        )),
    )


def validate_asset_set(assets):
    names = [asset["name"] for asset in assets]
    if len(names) != len(set(names)) or set(names) != EXPECTED_NAMES:
        raise ValueError("release asset set differs from 4 archives and 24 required sidecars")
    if any(type(asset.get("size")) is not int for asset in assets):
        raise ValueError("release asset size malformed")
    if sum(asset["size"] for asset in assets) > MAX_TOTAL_BYTES:
        raise ValueError("release assets exceed total download bound")
    if any(asset["size"] < 1 or asset["size"] > MAX_ASSET_BYTES for asset in assets):
        raise ValueError("release asset size outside bounds")
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", "")) for asset in assets):
        raise ValueError("GitHub asset digest missing or malformed")
    if any(asset.get("url") != f"https://github.com/{REPO}/releases/download/{TAG}/{asset['name']}" for asset in assets):
        raise ValueError("release asset URL mismatch")


def read_regular_nofollow(path, limit):
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("no-follow file opening unavailable")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("verifier dependency is not a bounded regular file")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("verifier dependency changed during open")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
    stable = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(data) > limit or stable(before) != stable(opened) or stable(opened) != stable(after):
        raise ValueError("verifier dependency changed during read")
    return data


def snapshot_verifier(source_dir, target_dir):
    source_dir = source_dir.resolve(strict=True)
    schema_source = source_dir / "schemas"
    if not stat.S_ISDIR(schema_source.lstat().st_mode):
        raise ValueError("verifier schema parent is not a real directory")
    if {path.name for path in schema_source.glob("*.schema.json")} != {Path(name).name for name in SNAPSHOT_FILES if name.startswith("schemas/")}:
        raise ValueError("verifier schema set changed")
    target_dir.mkdir(mode=0o700)
    (target_dir / "schemas").mkdir(mode=0o700)
    manifest = {}
    for relative in SNAPSHOT_FILES:
        data = read_regular_nofollow(source_dir / relative, MAX_SOURCE_FILE_BYTES)
        destination = target_dir / relative
        with destination.open("xb") as output:
            output.write(data)
        destination.chmod(0o400)
        manifest[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return manifest


def snapshot_matches(target_dir, manifest):
    if set(manifest) != set(SNAPSHOT_FILES):
        return False
    try:
        if ({path.name for path in target_dir.iterdir()} !=
                {"verify-release.sh", "trust.py", "cargo_graph.py", "schemas"}):
            return False
        if ({path.name for path in (target_dir / "schemas").iterdir()} !=
                {Path(name).name for name in SNAPSHOT_FILES if name.startswith("schemas/")}):
            return False
        for relative, expected in manifest.items():
            data = read_regular_nofollow(target_dir / relative, MAX_SOURCE_FILE_BYTES)
            if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                return False
    except (OSError, ValueError):
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    output_fd = open_private_output(args.output)
    deadline = time.monotonic() + MAX_RUN_SECONDS
    receipt = {
        "schema": "vettalon-cli-public-trust-readback-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "release_url": f"https://github.com/{REPO}/releases/tag/{TAG}",
        "repo": REPO,
        "tag": TAG,
        "expected_source_sha": SOURCE_SHA,
        "status": "incomplete",
        "limits": {
            "maximum_single_download_bytes": MAX_ASSET_BYTES,
            "maximum_total_download_bytes": MAX_TOTAL_BYTES,
            "maximum_single_download_seconds": MAX_ASSET_SECONDS,
            "maximum_run_seconds": MAX_RUN_SECONDS,
            "public_release_assets_only": True,
            "desktop_pro_not_in_scope": True,
        },
        "assets": {},
        "verification": {},
    }
    try:
        release = command_json([
            "gh", "release", "view", TAG, "-R", REPO,
            "--json", "assets,tagName,publishedAt,url,isDraft,isPrerelease",
        ], deadline=deadline)
        ref = command_json(["gh", "api", f"repos/{REPO}/git/ref/tags/{TAG}"], deadline=deadline)
        if (release["tagName"] != TAG or release["isDraft"] or release["isPrerelease"]
                or ref["object"]["type"] != "commit" or ref["object"]["sha"] != SOURCE_SHA):
            raise ValueError("release or source-tag mismatch")
        receipt["published_at_utc"] = release["publishedAt"]
        receipt["observed_tag_sha"] = ref["object"]["sha"]
        assets = release["assets"]
        validate_asset_set(assets)
        receipt["asset_counts"] = {"archives": len(ARCHIVES), "required_sidecars": 24, "total": len(assets)}
        with tempfile.TemporaryDirectory(prefix="vettalon-cli-v020-public-") as temp:
            directory = Path(temp)
            for asset in sorted(assets, key=lambda item: item["name"]):
                expected = asset.get("digest", "")
                name = asset["name"]
                receipt["assets"][name] = stream_asset(
                    asset["url"], directory / name, asset["size"], expected.removeprefix("sha256:"),
                    deadline=deadline,
                )
            verifier_source = args.verifier.resolve(strict=True)
            if verifier_source.name != "verify-release.sh":
                raise ValueError("unexpected verifier entrypoint")
            snapshot = directory / "verifier-snapshot"
            manifest = snapshot_verifier(verifier_source.parent, snapshot)
            if not snapshot_matches(snapshot, manifest):
                raise ValueError("verifier snapshot drifted before execution")
            verifier = snapshot / "verify-release.sh"
            receipt["verifier"] = {
                "sha256": manifest["verify-release.sh"]["sha256"],
                "dependencies": manifest,
                "snapshot_pre_post_match": False,
                "command": "PYTHON=<python> verify-release.sh <archive> v0.2.0 <expected-source-sha>",
                "checks": "local sidecars/SBOM, Cosign exact identity/issuer, GitHub archive and BOM attestations",
            }
            env = safe_env()
            env["PYTHON"] = args.python
            for archive in ARCHIVES:
                if not snapshot_matches(snapshot, manifest):
                    raise ValueError("verifier snapshot drifted before archive validation")
                code = command(
                    ["bash", str(verifier), str(directory / archive), TAG, SOURCE_SHA],
                    env=env, deadline=deadline, timeout=150,
                )
                if not snapshot_matches(snapshot, manifest):
                    raise ValueError("verifier snapshot drifted after archive validation")
                receipt["verification"][archive] = {
                    "verifier_exit_code": code,
                    "status": "pass" if code == 0 else "fail",
                    "github_attestation_subjects_expected": 2,
                }
            tamper_dir = directory / "tamper-control"
            tamper_dir.mkdir()
            tamper_archive = ARCHIVES[-1]
            for suffix in SUFFIXES:
                shutil.copyfile(directory / (tamper_archive + suffix), tamper_dir / (tamper_archive + suffix))
            altered = tamper_dir / tamper_archive
            with altered.open("r+b") as output:
                first = output.read(1)
                output.seek(0)
                output.write(bytes([first[0] ^ 1]))
            tamper_code = command([
                args.python, str(verifier.parent / "trust.py"), "verify-assets", str(altered),
            ], env=env, deadline=deadline, timeout=30)
            if not snapshot_matches(snapshot, manifest):
                raise ValueError("verifier snapshot drifted after negative control")
            receipt["negative_control"] = {
                "one_byte_archive_tamper_rejected": tamper_code != 0,
                "local_verify_assets_exit_code": tamper_code,
            }
            if tamper_code == 0:
                raise ValueError("tampered archive passed local validation")
            release_after = command_json([
                "gh", "release", "view", TAG, "-R", REPO,
                "--json", "assets,tagName,publishedAt,url,isDraft,isPrerelease",
            ], deadline=deadline)
            ref_after = command_json(["gh", "api", f"repos/{REPO}/git/ref/tags/{TAG}"], deadline=deadline)
            if (metadata_identity(release) != metadata_identity(release_after)
                    or ref_after["object"]["type"] != "commit"
                    or ref_after["object"]["sha"] != SOURCE_SHA):
                raise ValueError("release assets or tag changed during readback")
            receipt["metadata_pre_post_match"] = True
            receipt["verifier"]["snapshot_pre_post_match"] = True
            time_left(deadline, 1)
            if all(item["status"] == "pass" for item in receipt["verification"].values()):
                receipt["status"] = "public_cli_release_verification_pass"
            else:
                receipt["status"] = "verification_failed"
    except Exception as error:
        receipt["status"] = "incomplete"
        receipt["error_type"] = type(error).__name__
    with os.fdopen(output_fd, "w") as output:
        output.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0 if receipt["status"] == "public_cli_release_verification_pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
