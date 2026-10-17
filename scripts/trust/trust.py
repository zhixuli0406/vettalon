#!/usr/bin/env python3
"""Local supply-chain evidence helpers. No publishing or signing side effects."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
import tomllib
from datetime import datetime, timezone

SCHEMAS = Path(__file__).with_name("schemas")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_bom(bom):
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        raise ValueError("expected CycloneDX JSON 1.6 (use syft -o cyclonedx-json@1.6)")
    try:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
    except ImportError as error:
        raise ValueError(
            "jsonschema missing; install scripts/trust/requirements.txt in a venv"
        ) from error
    registry = Registry()
    for path in SCHEMAS.glob("*.schema.json"):
        data = json.loads(path.read_text())
        resource = Resource.from_contents(data)
        for uri in (
            data.get("$id"),
            f"http://cyclonedx.org/schema/{path.name}",
            f"https://cyclonedx.org/schema/{path.name}",
        ):
            if uri:
                registry = registry.with_resource(uri, resource)
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
    errors = sorted(
        Draft7Validator(schema, registry=registry).iter_errors(bom),
        key=lambda error: str(error.path),
    )
    if errors:
        raise ValueError("official CycloneDX schema: " + errors[0].message)
    components = bom.get("components", [])
    root = bom.get("metadata", {}).get("component", {})
    refs = [c["bom-ref"] for c in components + [root] if "bom-ref" in c]
    if len(refs) != len(set(refs)):
        raise ValueError("duplicate component bom-ref")
    for relation in bom.get("dependencies", []):
        if relation["ref"] not in refs or any(
            r not in refs for r in relation.get("dependsOn", [])
        ):
            raise ValueError("dangling dependency reference")


def build_record(asset, source_sha, lock_hash, target, dirty=False):
    if not re.fullmatch("[0-9a-f]{40}", source_sha) or not re.fullmatch(
        "[0-9a-f]{64}", lock_hash
    ):
        raise ValueError("source SHA and lock hash must be full hexadecimal digests")
    return {
        "kind": "unsigned-local-build-record",
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "source": {"commit": source_sha, "dirty": dirty, "lockfile_sha256": lock_hash},
        "target": target,
        "subject": {"name": Path(asset).name, "sha256": sha256(asset)},
        "limitations": [
            "not a signed provenance attestation",
            "lock graph includes conditional/platform dependencies; not binary reachability",
        ],
    }


def verify_assets(asset):
    asset = Path(asset)
    for suffix in (
        ".sha256",
        ".sig",
        ".pem",
        ".sigstore.json",
        ".build-record.json",
        ".cdx.json",
    ):
        path = Path(str(asset) + suffix)
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing or empty sidecar: " + path.name)
    checksum = Path(str(asset) + ".sha256").read_text().split()
    if (
        len(checksum) != 2
        or checksum[0] != sha256(asset)
        or checksum[1].lstrip("*") != asset.name
    ):
        raise ValueError("checksum mismatch or wrong asset name")
    record = json.loads(Path(str(asset) + ".build-record.json").read_text())
    if record.get("kind") != "unsigned-local-build-record" or record.get("subject") != {
        "name": asset.name,
        "sha256": sha256(asset),
    }:
        raise ValueError("build-record subject mismatch")
    if not record.get("target") or not re.fullmatch(
        "[0-9a-f]{40}", record.get("source", {}).get("commit", "")
    ):
        raise ValueError("invalid build-record source/target")
    targets = {
        "vettalon-linux-x64.tar.gz": "x86_64-unknown-linux-gnu",
        "vettalon-linux-arm64.tar.gz": "aarch64-unknown-linux-gnu",
        "vettalon-darwin-x64.tar.gz": "x86_64-apple-darwin",
        "vettalon-darwin-arm64.tar.gz": "aarch64-apple-darwin",
    }
    if asset.name not in targets or record["target"] != targets[asset.name]:
        raise ValueError("archive name/target mismatch")
    bom = json.loads(Path(str(asset) + ".cdx.json").read_text())
    validate_bom(bom)
    properties = {
        p["name"]: p["value"] for p in bom.get("metadata", {}).get("properties", [])
    }
    expected = {
        "vettalon:asset:sha256": sha256(asset),
        "vettalon:source:commit": record["source"]["commit"],
        "vettalon:lockfile:sha256": record["source"]["lockfile_sha256"],
        "vettalon:target": record["target"],
        "vettalon:source:dirty": str(record["source"]["dirty"]).lower(),
    }
    if any(properties.get(key) != value for key, value in expected.items()):
        raise ValueError("SBOM source/lock/target/asset binding mismatch")
    # Presence is deliberately separate from cryptographic verification.
    return {
        "asset": asset.name,
        "sha256": sha256(asset),
        "sidecars": "present",
        "signature_verified": False,
    }


def assert_public_workspace(source):
    manifest = tomllib.loads((Path(source) / "Cargo.toml").read_text())
    members = manifest.get("workspace", {}).get("members")
    if set(members or []) != {"crates/vettalon", "crates/vettalon-contract"}:
        raise ValueError(
            "release SBOM requires the standalone public workspace; stage the OSS export first"
        )


def enrich_cargo_licenses(bom, source=None):
    # A same-name/version source directory is not origin evidence. Only a
    # registry archive matching both the lock source and package checksum can
    # supply license metadata. Git/local/uncached/ambiguous origins stay unknown.
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    cache = cargo_home / "registry" / "cache"
    lock_path = Path(source) / "Cargo.lock" if source is not None else None
    packages = (
        tomllib.loads(lock_path.read_text()).get("package", [])
        if lock_path and lock_path.is_file()
        else []
    )
    for component in bom.get("components", []):
        if not component.get("purl", "").startswith("pkg:cargo/"):
            continue
        name, version = component.get("name"), component.get("version")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", name)
            or not isinstance(version, str)
            or not re.fullmatch(r"[0-9A-Za-z.+_-]+", version)
        ):
            raise ValueError(
                "invalid Cargo package identity; refusing cache path traversal"
            )
        supplied_licenses = component.get("licenses")
        source_bound = False
        distribution_sources = {
            item.get("url")
            for item in component.get("externalReferences", [])
            if item.get("type") == "distribution"
        }
        matching = [
            item
            for item in packages
            if item.get("name") == name
            and item.get("version") == version
            and item.get("source") in distribution_sources
            and str(item.get("source", "")).startswith("registry+")
            and re.fullmatch(r"[0-9a-f]{64}", item.get("checksum", ""))
        ]
        if len(matching) == 1:
            package_source = matching[0]
            for archive_path in sorted(cache.glob(f"*/{name}-{version}.crate")):
                if (
                    not archive_path.resolve().is_relative_to(cache.resolve())
                    or archive_path.stat().st_size > 32 * 1024 * 1024
                ):
                    continue
                if sha256(archive_path) != package_source["checksum"]:
                    continue
                try:
                    with tarfile.open(archive_path) as archive:
                        member = archive.getmember(f"{name}-{version}/Cargo.toml")
                        if not member.isfile() or member.size > 1024 * 1024:
                            continue
                        manifest = archive.extractfile(member).read()
                    package = tomllib.loads(manifest.decode("utf-8")).get("package", {})
                except (
                    OSError,
                    KeyError,
                    UnicodeError,
                    tarfile.TarError,
                    tomllib.TOMLDecodeError,
                ):
                    continue
                if package.get("name") != name or package.get("version") != version:
                    continue
                license_id = package.get("license")
                if isinstance(license_id, str):
                    if supplied_licenses:
                        declared = {
                            item.get("expression") or item.get("license", {}).get("id")
                            for item in supplied_licenses
                        }
                        if declared != {license_id}:
                            raise ValueError(
                                "input catalog license disagrees with checksum-bound Cargo manifest; inventory incomplete"
                            )
                    else:
                        component["licenses"] = [{"expression": license_id}]
                    source_bound = True
                    component.setdefault("properties", []).append(
                        {
                            "name": "vettalon:license:source",
                            "value": json.dumps(
                                {
                                    "lock_source": package_source["source"],
                                    "archive_sha256": package_source["checksum"],
                                    "manifest_sha256": hashlib.sha256(
                                        manifest
                                    ).hexdigest(),
                                },
                                sort_keys=True,
                            ),
                        }
                    )
                break
        if not source_bound:
            component.setdefault("properties", []).append(
                {
                    "name": "vettalon:license:status",
                    "value": (
                        "input catalog license retained; source binding unknown"
                        if supplied_licenses
                        else "unknown; no matching lock source and checksum-verified registry archive license evidence"
                    ),
                }
            )


def annotate_cargo_roles(bom, source):
    manifest_path = Path(source) / "Cargo.toml"
    if not manifest_path.is_file():
        return
    manifest = tomllib.loads(manifest_path.read_text())
    manifests = [manifest]
    for member in manifest.get("workspace", {}).get("members", []):
        for path in Path(source).glob(member + "/Cargo.toml"):
            if not path.resolve().is_relative_to(Path(source).resolve()):
                raise ValueError("Cargo workspace member escapes inventory source")
            manifests.append(tomllib.loads(path.read_text()))
    roots = {
        item["package"]["name"]
        for item in manifests
        if isinstance(item.get("package", {}).get("name"), str)
    }
    components = bom.get("components", [])
    root_refs = {
        item["bom-ref"]
        for item in components
        if item.get("name") in roots and item.get("purl", "").startswith("pkg:cargo/")
    }
    direct = {
        ref
        for edge in bom.get("dependencies", [])
        if edge["ref"] in root_refs
        for ref in edge.get("dependsOn", [])
    }
    for item in components:
        if not item.get("purl", "").startswith("pkg:cargo/"):
            continue
        role = (
            "root"
            if item["bom-ref"] in root_refs
            else ("direct" if item["bom-ref"] in direct else "transitive")
        )
        item.setdefault("properties", []).append(
            {"name": "vettalon:dependency:role", "value": role}
        )


def run_syft(source, output, executable="syft"):
    binary = shutil.which(executable)
    if not binary:
        raise ValueError(
            "Syft missing: install a checksum-verified official Syft binary; no empty BOM will be emitted"
        )
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("SBOM output already exists; refusing overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vettalon-sbom-") as temp:
        staged = Path(temp) / "bom.json"
        env = os.environ.copy()
        env.update(
            {
                "SYFT_CHECK_FOR_APP_UPDATE": "false",
                "SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES": "false",
                "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
                "SYFT_JAVA_USE_NETWORK": "false",
            }
        )
        subprocess.run(
            [
                binary,
                "scan",
                "dir:" + str(source),
                "-o",
                "cyclonedx-json@1.6=" + str(staged),
            ],
            env=env,
            check=True,
            timeout=300,
        )
        if staged.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("SBOM exceeds 64 MiB adapter limit; inventory incomplete")
        bom = json.loads(staged.read_text())
        enrich_cargo_licenses(bom, source)
        annotate_cargo_roles(bom, source)
        validate_bom(bom)
        if not bom.get("components"):
            raise ValueError(
                "Syft found no components; incomplete inventory, refusing success"
            )
        with output.open("x") as stream:
            stream.write(json.dumps(bom, indent=2) + "\n")
    return bom


def release_sbom(source, asset, output, source_sha, target, dirty, executable):
    source = Path(source).resolve()
    if Path(str(asset) + ".build-record.json").exists():
        raise ValueError("build-record already exists; refusing overwrite")
    assert_public_workspace(source)
    # Inventory only reviewed manifests/lock: never scan target/, customer reports
    # or a sibling application's assets through a broad directory scan.
    with tempfile.TemporaryDirectory(prefix="vettalon-public-lock-") as temp:
        lock_source = Path(temp)
        for relative in (
            "Cargo.toml",
            "Cargo.lock",
            "crates/vettalon/Cargo.toml",
            "crates/vettalon-contract/Cargo.toml",
        ):
            destination = lock_source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)
        bom = run_syft(lock_source, output, executable)
    record = build_record(
        asset, source_sha, sha256(source / "Cargo.lock"), target, dirty
    )
    props = bom.setdefault("metadata", {}).setdefault("properties", [])
    props.extend(
        [
            {"name": "vettalon:source:commit", "value": source_sha},
            {"name": "vettalon:source:dirty", "value": str(dirty).lower()},
            {
                "name": "vettalon:lockfile:sha256",
                "value": record["source"]["lockfile_sha256"],
            },
            {"name": "vettalon:asset:sha256", "value": record["subject"]["sha256"]},
            {"name": "vettalon:target", "value": target},
            {
                "name": "vettalon:scope",
                "value": "public source lock inventory; all locked target/optional dependencies; not linked binary inventory",
            },
        ]
    )
    validate_bom(bom)
    Path(output).write_text(json.dumps(bom, indent=2) + "\n")
    Path(str(asset) + ".build-record.json").write_text(
        json.dumps(record, indent=2) + "\n"
    )
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify-assets")
    verify.add_argument("asset", type=Path)
    validate = commands.add_parser("validate-sbom")
    validate.add_argument("bom", type=Path)
    customer = commands.add_parser("customer-sbom")
    customer.add_argument("source", type=Path)
    customer.add_argument("--output", type=Path, required=True)
    customer.add_argument("--syft", default="syft")
    release = commands.add_parser("release-sbom")
    release.add_argument("source", type=Path)
    release.add_argument("asset", type=Path)
    release.add_argument("--output", type=Path, required=True)
    release.add_argument("--source-sha", required=True)
    release.add_argument("--target", required=True)
    release.add_argument("--dirty", action="store_true")
    release.add_argument("--syft", default="syft")
    args = parser.parse_args()
    try:
        if args.command == "verify-assets":
            print(json.dumps(verify_assets(args.asset)))
        elif args.command == "validate-sbom":
            validate_bom(json.loads(args.bom.read_text()))
            print("official CycloneDX 1.6 schema and dependency references: valid")
        elif args.command == "customer-sbom":
            run_syft(args.source, args.output, args.syft)
        else:
            print(
                json.dumps(
                    release_sbom(
                        args.source,
                        args.asset,
                        args.output,
                        args.source_sha,
                        args.target,
                        args.dirty,
                        args.syft,
                    )
                )
            )
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
