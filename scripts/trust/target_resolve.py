#!/usr/bin/env python3
"""Reconcile a frozen Cargo target metadata snapshot with a verified lock BOM.

Cargo metadata includes dependency kinds used by non-release commands. This
tool records target-filtered source resolution, never binary linkage or runtime
reachability.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

import cargo_graph
import trust


TARGETS = {
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
}
MAX_BOM = 64 * 1024 * 1024
MAX_METADATA = 32 * 1024 * 1024
MAX_INDEX_BYTES = 160 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
REGISTRY_CACHE_ID = "index.crates.io-1949cf8c6b5b557f"
SOURCE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/vettalon/Cargo.toml",
    "crates/vettalon-contract/Cargo.toml",
)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _source_hashes(source):
    return {
        relative: _digest(cargo_graph.read_source_bytes(
            source, relative, 16 * 1024 * 1024 if relative == "Cargo.lock" else 1024 * 1024
        ))
        for relative in SOURCE_FILES
    }


def _property(bom, name):
    properties = bom.get("metadata", {}).get("properties", [])
    if type(properties) is not list or any(type(item) is not dict for item in properties):
        raise ValueError("invalid release BOM metadata properties")
    values = [item.get("value") for item in properties if item.get("name") == name]
    if len(values) != 1 or type(values[0]) is not str:
        raise ValueError("missing or ambiguous release BOM property: " + name)
    return values[0]


def _git(source, *args):
    result = subprocess.run(
        ["git", "-C", str(source), *args], capture_output=True, text=True,
        check=True, timeout=15,
    )
    return result.stdout.strip()


def _isolated_cargo_cache(nodes, cache_home, isolated_home):
    """Copy only lock-checksum-verified archives and a bounded sparse index."""
    cache_home = Path(cache_home).resolve()
    index = cache_home / "registry/index" / REGISTRY_CACHE_ID
    archive_dir = cache_home / "registry/cache" / REGISTRY_CACHE_ID
    if not index.is_dir() or not archive_dir.is_dir():
        raise ValueError("local Cargo registry index/cache missing")
    index_bytes = 0
    index_files = 0
    for path in index.rglob("*"):
        if path.is_symlink():
            raise ValueError("Cargo registry index contains a symlink")
        if path.is_file():
            index_files += 1
            index_bytes += path.stat().st_size
        elif not path.is_dir():
            raise ValueError("Cargo registry index contains a special file")
        if index_files > 20000 or index_bytes > MAX_INDEX_BYTES:
            raise ValueError("Cargo registry index exceeds copy limit")
    shutil.copytree(index, isolated_home / "registry/index" / REGISTRY_CACHE_ID)
    destination = isolated_home / "registry/cache" / REGISTRY_CACHE_ID
    destination.mkdir(parents=True)
    copied = set()
    missing = []
    for (name, version), package in sorted(nodes.items()):
        if package.get("source") is None:
            continue
        archive = archive_dir / f"{name}-{version}.crate"
        if not archive.is_file() or archive.is_symlink():
            missing.append(f"{name}@{version}")
            continue
        if archive.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Cargo archive exceeds per-package cache limit")
        data = archive.read_bytes()
        if _digest(data) != package["checksum"]:
            raise ValueError("Cargo cached archive checksum differs from lock")
        (destination / archive.name).write_bytes(data)
        copied.add((name, version))
    return {"copied_lock_archives": len(copied), "missing_lock_archives": missing,
            "index_file_count": index_files, "index_bytes": index_bytes}, copied


def _verify_extracted_registry_sources(metadata, nodes, isolated_home, copied):
    """Bind every selected registry source file to its checksum-verified archive."""
    source_dir = isolated_home / "registry/src" / REGISTRY_CACHE_ID
    cache_dir = isolated_home / "registry/cache" / REGISTRY_CACHE_ID
    registry_count = 0
    verified_files = 0
    verified_bytes = 0
    for package in metadata["packages"]:
        identity = package["name"], package["version"]
        if nodes[identity].get("source") is None:
            continue
        if identity not in copied:
            raise ValueError("selected Cargo registry archive missing from verified cache")
        prefix = f"{identity[0]}-{identity[1]}"
        root = source_dir / prefix
        resolved_root = root.resolve()
        if package.get("manifest_path") != str(root / "Cargo.toml"):
            raise ValueError("Cargo used registry source outside isolated verified cache")
        archive = cache_dir / f"{prefix}.crate"
        if trust.sha256(archive) != nodes[identity]["checksum"]:
            raise ValueError("isolated Cargo archive changed after metadata")
        expected = set()
        unpacked_bytes = 0
        with tarfile.open(archive, "r:gz") as stream:
            members = stream.getmembers()
            if len(members) > 20000:
                raise ValueError("Cargo archive has too many members")
            for member in members:
                parts = Path(member.name).parts
                if len(parts) < 2 or parts[0] != prefix or ".." in parts:
                    raise ValueError("Cargo archive has invalid member path")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError("Cargo archive has unsupported member type")
                relative = Path(*parts[1:])
                if str(relative) in expected:
                    raise ValueError("Cargo archive has duplicate member path")
                expected.add(str(relative))
                unpacked_bytes += member.size
                if unpacked_bytes > MAX_UNPACKED_BYTES:
                    raise ValueError("Cargo archive exceeds unpacked limit")
                path = root / relative
                if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(resolved_root):
                    raise ValueError(f"Cargo extracted source file missing or escaped: {prefix}/{relative}")
                archived = stream.extractfile(member)
                if archived is None or _digest(archived.read()) != trust.sha256(path):
                    raise ValueError("Cargo extracted source differs from verified archive")
                verified_files += 1
                verified_bytes += member.size
        actual = set()
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValueError("Cargo extracted source contains a symlink")
            if path.is_file():
                actual.add(str(path.relative_to(root)))
        if actual - {".cargo-ok"} != expected:
            raise ValueError("Cargo extracted source file set differs from archive")
        registry_count += 1
    return {"selected_registry_archives_verified": registry_count,
            "extracted_regular_files_verified": verified_files,
            "extracted_regular_bytes_verified": verified_bytes}


def validate_metadata(metadata, verified, source, target):
    """Check selected Cargo IDs/edges/features against the all-lock graph."""
    if type(metadata) is not dict or type(metadata.get("version")) is not int or metadata["version"] != 1:
        raise ValueError("Cargo metadata format version 1 required")
    if metadata.get("workspace_root") != str(source):
        raise ValueError("Cargo metadata workspace root disagrees with source")
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if type(packages) is not list or type(resolve) is not dict or type(resolve.get("nodes")) is not list:
        raise ValueError("Cargo metadata packages/resolve missing")
    package_ids = {}
    identities = set()
    for package in packages:
        if type(package) is not dict or type(package.get("id")) is not str:
            raise ValueError("invalid Cargo metadata package")
        identity = cargo_graph._identity(package.get("name"), package.get("version"))
        if package["id"] in package_ids or identity in identities or identity not in verified["nodes"]:
            raise ValueError("duplicate or non-lock Cargo metadata package")
        lock_source = verified["nodes"][identity].get("source")
        if package.get("source") != lock_source:
            raise ValueError("Cargo metadata package origin disagrees with lock")
        if lock_source is None:
            manifest = package.get("manifest_path")
            if type(manifest) is not str or not Path(manifest).resolve().is_relative_to(source):
                raise ValueError("local Cargo metadata manifest escapes source")
        package_ids[package["id"]] = identity
        identities.add(identity)
    workspace = metadata.get("workspace_members")
    if type(workspace) is not list or len(workspace) != len(set(workspace)) or any(
        member not in package_ids for member in workspace
    ):
        raise ValueError("invalid Cargo metadata workspace members")
    if {package_ids[member] for member in workspace} != verified["roots"]:
        raise ValueError("Cargo metadata workspace roots disagree with source manifests")
    selected = set()
    feature_count = 0
    selected_edges = set()
    dev_edges = set()
    for node in resolve["nodes"]:
        if type(node) is not dict or node.get("id") not in package_ids or node["id"] in selected:
            raise ValueError("duplicate or unknown Cargo metadata resolve node")
        selected.add(node["id"])
        features, deps = node.get("features"), node.get("deps")
        if type(features) is not list or len(features) != len(set(features)) or any(
            type(feature) is not str or not feature for feature in features
        ) or type(deps) is not list:
            raise ValueError("invalid Cargo metadata feature/dependency list")
        feature_count += len(features)
        parent = package_ids[node["id"]]
        for dep in deps:
            if type(dep) is not dict or dep.get("pkg") not in package_ids:
                raise ValueError("Cargo metadata dependency references unknown package")
            kinds = dep.get("dep_kinds")
            if type(kinds) is not list or not kinds or any(
                type(kind) is not dict or kind.get("kind") not in (None, "build", "dev")
                for kind in kinds
            ):
                raise ValueError("invalid Cargo metadata dependency kind")
            edge = (parent, package_ids[dep["pkg"]])
            if edge in selected_edges:
                raise ValueError("duplicate Cargo metadata resolved edge")
            selected_edges.add(edge)
            if any(kind["kind"] == "dev" for kind in kinds):
                dev_edges.add(edge)
    if selected != set(package_ids):
        raise ValueError("Cargo metadata package inventory differs from resolved nodes")
    if not {package_ids[member] for member in workspace} <= {package_ids[item] for item in selected}:
        raise ValueError("Cargo metadata omitted a workspace root")
    if not selected_edges <= verified["edges"]:
        raise ValueError("target-filtered Cargo edge absent from source lock")
    selected_identities = {package_ids[item] for item in selected}
    result = {
        "status": "target_metadata_verified",
        "scope": "Cargo target-filtered metadata with default feature selection; includes dev/build kinds; not exact release build, linked inventory or reachability",
        "target": target,
        "source_lock_packages": len(verified["nodes"]),
        "source_lock_edges": len(verified["edges"]),
        "selected_packages": len(selected_identities),
        "selected_edges": len(selected_edges),
        "selected_dev_edges": len(dev_edges),
        "activated_feature_entries": feature_count,
        "unselected_lock_packages": len(verified["nodes"]) - len(selected_identities),
        "unselected_lock_edges": len(verified["edges"]) - len(selected_edges),
    }
    return result


def run(source, bom_path, target, expected_source_sha, cargo_binary="cargo",
        metadata_output=None, verified_cache_home=None):
    source, bom_path = cargo_graph._source_root(source), bom_path.resolve()
    if metadata_output is not None:
        metadata_output = Path(metadata_output).absolute()
        if metadata_output.resolve().is_relative_to(source):
            raise ValueError("Cargo metadata output must be outside source checkout")
        if metadata_output.exists() or metadata_output.is_symlink():
            raise ValueError("Cargo metadata output exists; refusing overwrite")
    if target not in TARGETS or re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise ValueError("unsupported target or invalid expected source SHA")
    if _git(source, "rev-parse", "HEAD") != expected_source_sha:
        raise ValueError("source checkout commit differs from independently reviewed SHA")
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout is dirty")
    before = _source_hashes(source)
    if not bom_path.is_file() or bom_path.stat().st_size > MAX_BOM:
        raise ValueError("missing or oversized release BOM")
    bom_bytes = bom_path.read_bytes()
    if len(bom_bytes) > MAX_BOM:
        raise ValueError("release BOM exceeds input limit")
    bom = json.loads(bom_bytes)
    trust.validate_bom(bom)
    graph = cargo_graph.verify_cargo_graph(bom, source)
    if graph is None:
        raise ValueError("verified Cargo source-lock graph required")
    lock, _ = cargo_graph._read_toml(source, "Cargo.lock", 16 * 1024 * 1024)
    nodes, edges = cargo_graph.lock_graph(lock)
    roots, _ = cargo_graph.manifest_roots(source, nodes)
    verified = {"nodes": nodes, "edges": edges, "roots": roots}
    if _property(bom, "vettalon:target") != target:
        raise ValueError("release BOM target label differs from requested target")
    if (_property(bom, "vettalon:source:commit") != expected_source_sha
            or _property(bom, "vettalon:lockfile:sha256") != before["Cargo.lock"]):
        raise ValueError("release BOM source/lock binding differs from checkout")
    command = [cargo_binary, "metadata", "--frozen", "--format-version", "1",
               "--filter-platform", target]
    env = os.environ.copy()
    env["CARGO_NET_OFFLINE"] = "true"
    with tempfile.TemporaryDirectory(prefix="vettalon-target-metadata-") as temp:
        env["CARGO_TARGET_DIR"] = str(Path(temp) / "target")
        cache_evidence = None
        copied = None
        if verified_cache_home is not None:
            for key in list(env):
                if key.startswith("CARGO_"):
                    del env[key]
            env["CARGO_NET_OFFLINE"] = "true"
            env["CARGO_TARGET_DIR"] = str(Path(temp) / "target")
            env["CARGO_HOME"] = str(Path(temp) / "cargo-home")
            cache_evidence, copied = _isolated_cargo_cache(
                nodes, verified_cache_home, Path(env["CARGO_HOME"])
            )
        with (Path(temp) / "metadata.json").open("wb") as output:
            process = subprocess.run(command, cwd=source, env=env, stdout=output,
                                     stderr=subprocess.PIPE, timeout=90, check=False)
        metadata_path = Path(temp) / "metadata.json"
        if process.returncode != 0:
            raise ValueError("frozen Cargo metadata failed: " + process.stderr[:2048].decode("utf-8", "replace"))
        if metadata_path.stat().st_size > MAX_METADATA:
            raise ValueError("Cargo metadata exceeds input limit")
        metadata_bytes = metadata_path.read_bytes()
        metadata = json.loads(metadata_bytes)
        result = validate_metadata(metadata, verified, source, target)
        if copied is not None:
            cache_evidence.update(_verify_extracted_registry_sources(
                metadata, nodes, Path(env["CARGO_HOME"]), copied
            ))
    if _git(source, "rev-parse", "HEAD") != expected_source_sha:
        raise ValueError("source checkout commit changed during target resolution")
    if (_source_hashes(source) != before or trust.sha256(bom_path) != _digest(bom_bytes)
            or _git(source, "status", "--porcelain", "--untracked-files=all")):
        raise ValueError("Cargo source or BOM changed during target resolution")
    if metadata_output is not None:
        metadata_output.parent.mkdir(parents=True, exist_ok=True)
        with metadata_output.open("xb") as output:
            output.write(metadata_bytes)
    result.update({
        "expected_source_sha": expected_source_sha,
        "source_inputs_sha256": before,
        "bom_sha256": _digest(bom_bytes),
        "cargo_metadata_sha256": _digest(metadata_bytes),
        "cargo_command": command,
        "cargo_exit_code": process.returncode,
        "source_cache": cache_evidence,
    })
    if cache_evidence is None:
        result["status"] = "local_cache_target_metadata_only"
        result["scope"] += "; registry cache manifest/extracted source bytes not independently bound to lock archives"
    else:
        result["status"] = "checksum_archive_target_metadata_verified"
        result["scope"] += "; selected extracted registry source bytes match lock-checksum archives in isolated CARGO_HOME; sparse index contents not independently authenticated"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("bom", type=Path)
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--metadata-output", type=Path)
    parser.add_argument("--verified-cache-home", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.source, args.bom, args.target, args.source_sha,
                             args.cargo, args.metadata_output, args.verified_cache_home),
                         sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
