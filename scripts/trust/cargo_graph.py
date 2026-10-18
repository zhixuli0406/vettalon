"""Offline Cargo v3/v4 source-lock reconciliation, not target/binary reachability.

Supported origins are the canonical crates.io registry and unique local/path
packages. Git, alternate registries, qualified purls and origin collisions are
intentionally refused. No metadata resolution, source execution or BOM repair.
"""

import hashlib
from contextlib import ExitStack
import os
from pathlib import Path
import re
import stat
import tomllib
from urllib.parse import quote, unquote

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
NAME = r"[A-Za-z0-9_-]+"
NUMBER = r"(?:0|[1-9][0-9]*)"
VERSION = rf"{NUMBER}\.{NUMBER}\.{NUMBER}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"


def _identity(name, version):
    if (type(name) is not str or re.fullmatch(NAME, name) is None
            or type(version) is not str or re.fullmatch(VERSION, version) is None):
        raise ValueError("unsupported or invalid Cargo name/version")
    prerelease = version.split("+", 1)[0].partition("-")[2]
    if any(part.isdigit() and len(part) > 1 and part[0] == "0" for part in prerelease.split(".")):
        raise ValueError("noncanonical Cargo semantic version")
    return name, version


def _source_root(source):
    source = Path(source).absolute()
    if source.is_symlink():
        raise ValueError("Cargo source root must not be a symlink")
    root = source.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Cargo source root must be a directory")
    return root


def _read_source_bytes(source, relative, limit):
    """Read a regular in-tree source file through no-follow directory handles."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("safe Cargo source file reading unavailable on this platform")
    root = _source_root(source)
    relative = Path(relative)
    if (relative.is_absolute() or not relative.parts
            or any(part in (".", "..") for part in relative.parts)):
        raise ValueError("Cargo source path escapes source root")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC
    with ExitStack() as stack:
        directory = os.open(root, directory_flags)
        stack.callback(os.close, directory)
        root_stat = root.lstat()
        opened_root = os.fstat(directory)
        if (not stat.S_ISDIR(root_stat.st_mode)
                or (root_stat.st_dev, root_stat.st_ino) !=
                (opened_root.st_dev, opened_root.st_ino)):
            raise ValueError("Cargo source root changed during read")
        for part in relative.parts[:-1]:
            entry = os.stat(part, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISDIR(entry.st_mode):
                raise ValueError("Cargo source parent must be a real directory")
            child = os.open(part, directory_flags, dir_fd=directory)
            stack.callback(os.close, child)
            opened = os.fstat(child)
            if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("Cargo source parent changed during read")
            directory = child
        entry = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
                or entry.st_size > limit):
            raise ValueError("Cargo source manifest/lock must be a bounded regular file")
        fd = os.open(relative.name, file_flags, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino)
                    or opened.st_size > limit):
                raise ValueError("Cargo source file changed during read")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if (len(data) > limit or
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                     opened.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                     after.st_ctime_ns)):
                raise ValueError("Cargo source file changed during read")
    return data


def read_source_bytes(source, relative, limit):
    try:
        return _read_source_bytes(source, relative, limit)
    except OSError as error:
        raise ValueError("Cargo source manifest/lock is missing or unsafe") from error


def _read_toml(source, relative, limit):
    data = read_source_bytes(source, relative, limit)
    return tomllib.loads(data.decode("utf-8")), hashlib.sha256(data).hexdigest()


def lock_graph(lock):
    """Resolve each dependency against lock identities only; never supplied BOM."""
    if type(lock.get("version")) is not int or lock["version"] not in (3, 4):
        raise ValueError("Cargo lock versions 3 and 4 only")
    packages = lock.get("package")
    if type(packages) is not list or not packages:
        raise ValueError("Cargo lock requires a nonempty package inventory")
    nodes = {}
    for package in packages:
        if type(package) is not dict or set(package) - {"name", "version", "source", "checksum", "dependencies"}:
            raise ValueError("unsupported Cargo lock package fields")
        identity = _identity(package.get("name"), package.get("version"))
        source = package.get("source")
        if source is not None and source != REGISTRY:
            raise ValueError("unsupported Cargo origin; only canonical crates.io/local supported")
        if source is None and "source" in package:
            raise ValueError("invalid local Cargo source")
        if source == REGISTRY:
            checksum = package.get("checksum")
            if type(checksum) is not str or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
                raise ValueError("registry Cargo package requires a canonical checksum")
        elif "checksum" in package:
            raise ValueError("unexpected checksum on local Cargo package")
        if identity in nodes:
            raise ValueError("duplicate or multiple-origin Cargo name/version identity")
        nodes[identity] = package
    by_name = {}
    for identity in nodes:
        by_name.setdefault(identity[0], []).append(identity)
    edges = set()
    for parent, package in nodes.items():
        dependencies = package.get("dependencies", [])
        if type(dependencies) is not list:
            raise ValueError("Cargo dependencies must be an array")
        resolved = set()
        for dependency in dependencies:
            if type(dependency) is not str:
                raise ValueError("invalid Cargo dependency identifier")
            match = re.fullmatch(rf"({NAME})(?: ({VERSION})(?: \(([^()]+)\))?)?", dependency)
            if match is None:
                raise ValueError("unsupported Cargo dependency identifier")
            name, version, source = match.groups()
            if source is not None and source != REGISTRY:
                raise ValueError("unsupported Cargo dependency origin")
            if version is not None:
                _identity(name, version)
            # The tuple-keyed nodes map already indexes exact name/version.
            candidates = by_name.get(name, []) if version is None else ([(name, version)] if (name, version) in nodes else [])
            if len(candidates) != 1:
                raise ValueError("dangling or ambiguous Cargo lock dependency")
            target = candidates[0]
            if source is not None and nodes[target].get("source") != source:
                raise ValueError("Cargo dependency source does not match lock identity")
            if target in resolved:
                raise ValueError("duplicate resolved Cargo dependency")
            resolved.add(target)
            edges.add((parent, target))
    return nodes, edges


def manifest_roots(source, nodes):
    """Bind root package names AND versions, including workspace inheritance."""
    source = _source_root(source)
    manifest, manifest_sha = _read_toml(source, "Cargo.toml", 1024 * 1024)
    workspace = manifest.get("workspace", {})
    if type(workspace) is not dict:
        raise ValueError("invalid Cargo workspace")
    members, excluded = workspace.get("members", []), workspace.get("exclude", [])
    if any(type(values) is not list or any(type(p) is not str or not p or Path(p).is_absolute()
           or ".." in Path(p).parts for p in values) for values in (members, excluded)):
        raise ValueError("unsupported Cargo workspace member/exclude path")
    excluded_paths = {path.resolve() for pattern in excluded for path in source.glob(pattern)}
    manifests = {source / "Cargo.toml": manifest}
    hashes = {"Cargo.toml": manifest_sha}
    for member in members:
        paths = sorted(source.glob(member + "/Cargo.toml"))
        if not paths:
            raise ValueError("Cargo workspace member has no manifest")
        for path in paths:
            if not path.resolve().is_relative_to(source):
                raise ValueError("Cargo workspace member escapes inventory source")
            if path.parent.resolve() in excluded_paths:
                continue
            document, digest = _read_toml(source, path.relative_to(source), 1024 * 1024)
            if path.resolve() in {p.resolve() for p in manifests}:
                if path != source / "Cargo.toml":
                    raise ValueError("duplicate Cargo workspace member manifest")
                continue
            manifests[path] = document
            hashes[str(path.relative_to(source))] = digest
    roots = set()
    for document in manifests.values():
        if "package" not in document:
            if document is not manifest:
                raise ValueError("Cargo member must declare a package")
            continue
        package = document["package"]
        if type(package) is not dict or "workspace" in package:
            raise ValueError("unsupported Cargo package workspace override")
        version = package.get("version")
        if type(version) is dict:
            if set(version) != {"workspace"} or version["workspace"] is not True:
                raise ValueError("unsupported Cargo version inheritance")
            shared = workspace.get("package", {})
            if type(shared) is not dict:
                raise ValueError("invalid Cargo workspace package inheritance")
            version = shared.get("version")
        identity = _identity(package.get("name"), version)
        if identity in roots or identity not in nodes or nodes[identity].get("source") is not None:
            raise ValueError("Cargo manifest root name/version does not bind a unique local lock package")
        roots.add(identity)
    if not roots:
        raise ValueError("no Cargo manifest package roots")
    return roots, hashes


def _cargo_component(component):
    purl = component.get("purl", "")
    if type(purl) is not str:
        raise ValueError("invalid component purl")
    if purl.lower().startswith("pkg:cargo"):
        if not purl.startswith("pkg:cargo/"):
            raise ValueError("noncanonical Cargo purl type")
        return True
    return False


def component_identity(component, nodes):
    purl = component["purl"]
    if "?" in purl or "#" in purl:
        raise ValueError("Cargo purl qualifiers/subpaths are unsupported; origin cannot be guessed")
    match = re.fullmatch(r"pkg:cargo/([^/@]+)@([^/@]+)", purl)
    if match is None:
        raise ValueError("invalid Cargo purl")
    name, raw_version = match.groups()
    version = unquote(raw_version, errors="strict")
    identity = _identity(name, version)
    if raw_version not in (version, quote(version, safe=".-_~")):
        raise ValueError("noncanonical Cargo purl encoding")
    if identity != (component.get("name"), component.get("version")):
        raise ValueError("Cargo purl name/version disagrees with component")
    if identity not in nodes:
        raise ValueError("extra or wrong Cargo BOM package")
    references = component.get("externalReferences", [])
    if type(references) is not list or any(type(ref) is not dict for ref in references):
        raise ValueError("invalid Cargo origin references")
    distributions = [ref.get("url") for ref in references if ref.get("type") == "distribution"]
    if distributions and distributions != [nodes[identity].get("source")]:
        raise ValueError("Cargo distribution origin disagrees with lock")
    return identity


def verify_cargo_graph(bom, source):
    """Return verified roles without mutating BOM; refuse mismatched graph wholesale."""
    source = Path(source)
    components = bom.get("components", [])
    if type(components) is not list or any(type(c) is not dict for c in components):
        raise ValueError("invalid Cargo inventory component list")
    root_component = bom.get("metadata", {}).get("component")
    all_components = components + ([root_component] if root_component else [])
    for item in all_components:
        if type(item) is not dict:
            raise ValueError("invalid inventory root")
        pending = list(item.get("components", []))
        while pending:
            child = pending.pop()
            if type(child) is not dict or _cargo_component(child):
                raise ValueError("nested Cargo components are unsupported")
            pending.extend(child.get("components", []))
    cargo = [item for item in all_components if _cargo_component(item)]
    if not cargo and not (source / "Cargo.lock").exists() and not (source / "Cargo.toml").exists():
        return None
    lock, lock_sha = _read_toml(source, "Cargo.lock", 16 * 1024 * 1024)
    nodes, expected_edges = lock_graph(lock)
    roots, manifests = manifest_roots(source, nodes)
    by_ref = {}
    by_identity = {}
    known_refs = set()
    for item in all_components:
        ref = item.get("bom-ref")
        if ref is None and not _cargo_component(item):
            continue
        if type(ref) is not str or not ref or ref in known_refs:
            raise ValueError("missing or duplicate inventory component reference")
        known_refs.add(ref)
    for item in cargo:
        identity = component_identity(item, nodes)
        if identity in by_identity:
            raise ValueError("duplicate Cargo BOM package identity")
        by_identity[identity] = item["bom-ref"]
        by_ref[item["bom-ref"]] = identity
    if set(by_identity) != set(nodes):
        raise ValueError("Cargo BOM package coverage differs from lock")
    relationships = bom.get("dependencies", [])
    if type(relationships) is not list:
        raise ValueError("invalid BOM dependency rows")
    seen_rows, actual_edges = set(), set()
    for relation in relationships:
        if type(relation) is not dict:
            raise ValueError("invalid BOM dependency row")
        ref, targets = relation.get("ref"), relation.get("dependsOn", [])
        if type(ref) is not str or ref not in known_refs or ref in seen_rows:
            raise ValueError("dangling or duplicate BOM dependency row")
        seen_rows.add(ref)
        if type(targets) is not list or any(type(target) is not str or target not in known_refs for target in targets):
            raise ValueError("dangling or invalid BOM dependency target")
        if len(targets) != len(set(targets)):
            raise ValueError("duplicate BOM dependency edge")
        if ref in by_ref:
            if any(target not in by_ref for target in targets):
                raise ValueError("Cargo dependency targets a non-lock package node")
            actual_edges.update((by_ref[ref], by_ref[target]) for target in targets)
    if actual_edges != expected_edges:
        raise ValueError("Cargo BOM dependency edges differ from source lock")
    direct = {target for parent, target in expected_edges if parent in roots}
    roles = {ref: "root" if identity in roots else "direct" if identity in direct else "transitive"
             for ref, identity in by_ref.items()}
    for relative, expected in {"Cargo.lock": lock_sha, **manifests}.items():
        current = hashlib.sha256(read_source_bytes(source, relative, 16 * 1024 * 1024)).hexdigest()
        if current != expected:
            raise ValueError("Cargo source changed during graph verification")
    return {"roles": roles, "lockfile_sha256": lock_sha, "manifest_sha256": manifests,
            "package_count": len(nodes), "edge_count": len(expected_edges)}
