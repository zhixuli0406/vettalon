#!/usr/bin/env python3
"""Bounded source-graph adapters; never execute target build hooks or infer reachability."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import quote, unquote, urlsplit


class UnsupportedInventoryError(ValueError):
    """A source feature that cannot be reconciled without more resolution."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def is_local_npm_reference(value):
    return isinstance(value, str) and (
        value.startswith(("file:", "/", "./", "../"))
        or bool(re.match(r"^[a-zA-Z]:[\\/]", value))
    )


def is_unsupported_npm_spec(value):
    return not isinstance(value, str) or not value.strip() or bool(
        re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value)
        or any(character in value for character in ("/", "\\", "#", "@"))
    )


def is_supported_npm_resolved(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


def read_npm_file_bytes(path, kind, max_bytes, required=False):
    code = "npm-" + kind + "-file-unsafe"
    label = "package-lock.json" if kind == "source" else "package.json"
    try:
        expected = path.lstat()
    except FileNotFoundError:
        if required:
            raise ValueError("npm " + label + " is missing")
        return None
    except OSError as error:
        raise UnsupportedInventoryError(
            code, "cannot inspect npm " + label + " safely"
        ) from error
    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_nlink != 1
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise UnsupportedInventoryError(
            code, "npm " + label + " must be a regular in-directory file"
        )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise UnsupportedInventoryError(
            code, "cannot open npm " + label + " without following links"
        ) from error
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise UnsupportedInventoryError(
                code, "npm " + label + " changed during safe read"
            )
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            content = stream.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise UnsupportedInventoryError(
                code, "npm " + label + " exceeds the safe size limit"
            )
        return content
    finally:
        if fd >= 0:
            os.close(fd)


def npm_graph(lock, manifest=None):
    if lock.get("lockfileVersion") != 3:
        raise ValueError("native npm graph supports lock v3 only")
    packages = lock["packages"]
    root = packages.get("", {})
    if manifest is not None:
        if not isinstance(manifest, dict):
            raise ValueError("npm package.json must be an object")
        dependency_keys = ("dependencies", "devDependencies", "optionalDependencies")
        for key in ("name", "version", "workspaces", *dependency_keys):
            default = {} if key in dependency_keys else None
            if manifest.get(key, default) != root.get(key, default):
                raise UnsupportedInventoryError(
                    "npm-manifest-lock-mismatch",
                    "npm package.json and lock root disagree on " + key,
                )
    if (
        root.get("workspaces")
        or any(entry.get("link") for entry in packages.values())
        or any(path and not path.startswith("node_modules/") for path in packages)
    ):
        raise UnsupportedInventoryError(
            "npm-workspace-link",
            "npm workspace links require separate source resolution",
        )
    for entry in packages.values():
        version = entry.get("version")
        if version is not None and (
            is_local_npm_reference(version) or is_unsupported_npm_spec(version)
        ):
            raise UnsupportedInventoryError(
                "npm-unsupported-protocol",
                "npm package versions must be plain registry versions",
            )
        resolved = entry.get("resolved")
        if is_local_npm_reference(resolved):
            raise UnsupportedInventoryError(
                "npm-local-file",
                "npm local file dependencies require separate source resolution",
            )
        if resolved is not None and not is_supported_npm_resolved(resolved):
            raise UnsupportedInventoryError(
                "npm-unsupported-protocol",
                "npm source resolution supports HTTPS package URLs only",
            )
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            for spec in entry.get(key, {}).values():
                if is_local_npm_reference(spec):
                    raise UnsupportedInventoryError(
                        "npm-local-file",
                        "npm local file dependencies require separate source resolution",
                    )
                if is_unsupported_npm_spec(spec):
                    raise UnsupportedInventoryError(
                        "npm-unsupported-protocol",
                        "npm dependency specs must be registry versions or tags "
                        "without protocols or paths",
                    )
    nodes = {}
    edges = set()
    direct = set()
    for path, entry in packages.items():
        if any(
            entry.get(key)
            for key in ("link", "optional", "peerDependencies", "os", "cpu")
        ):
            raise ValueError(
                "peers/conditional npm nodes require separate resolution"
            )
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        if name and entry.get("version"):
            nodes[path] = (name, entry["version"])
    if "" not in nodes:
        raise ValueError("missing npm root identity")
    for path, entry in packages.items():
        for kind in ("dependencies", "devDependencies", "optionalDependencies"):
            for dep in entry.get(kind, {}):
                base = path
                while True:
                    candidate = (base + "/" if base else "") + "node_modules/" + dep
                    if candidate in nodes:
                        break
                    if not base:
                        raise ValueError("unresolved npm dependency " + dep)
                    base = (
                        base.rsplit("/node_modules/", 1)[0]
                        if "/node_modules/" in base
                        else ""
                    )
                edges.add((nodes[path], nodes[candidate]))
                if path == "":
                    direct.add(nodes[candidate])
    return set(nodes.values()), edges, direct


PIP_ENVIRONMENT_KEYS = (
    "implementation_name",
    "implementation_version",
    "os_name",
    "platform_machine",
    "platform_release",
    "platform_system",
    "platform_version",
    "python_full_version",
    "platform_python_implementation",
    "python_version",
    "sys_platform",
)


def pip_marker_environment(inspect):
    from packaging.version import InvalidVersion, Version

    supplied = inspect.get("environment")
    if not isinstance(supplied, dict):
        raise ValueError("pip inspect requires a complete source environment")
    environment = {}
    for key in PIP_ENVIRONMENT_KEYS:
        value = supplied.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("missing or invalid pip source environment field: " + key)
        environment[key] = value
    for key in ("implementation_version", "python_full_version", "python_version"):
        try:
            Version(environment[key])
        except InvalidVersion as error:
            raise ValueError("invalid pip source environment version: " + key) from error
    # Base installed scope only; a source 'extra' override is not activation evidence.
    environment["extra"] = ""
    return environment


def pip_graph(inspect, exclusions=None):
    try:
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
    except ImportError as error:
        raise ValueError("packaging missing; install trust requirements") from error
    environment = pip_marker_environment(inspect)
    distributions = inspect["installed"]
    nodes = {
        canonicalize_name(d["metadata"]["name"]): (
            canonicalize_name(d["metadata"]["name"]),
            d["metadata"]["version"],
        )
        for d in distributions
    }
    edges = set()
    direct = set()
    for dist in distributions:
        src = nodes[canonicalize_name(dist["metadata"]["name"])]
        if dist.get("requested"):
            direct.add(src)
        for raw in dist["metadata"].get("requires_dist", []):
            requirement = Requirement(raw)
            if requirement.extras or requirement.url:
                raise ValueError(
                    "requested extras/direct URLs need separate resolution"
                )
            if requirement.marker:
                try:
                    # All standard keys are source-bound; packaging cannot fill gaps
                    # from the analysis host. Extra/group activation stays unsupported.
                    applicable = requirement.marker.evaluate(environment, context="metadata")
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError("unsupported or invalid pip marker context") from error
                if not applicable:
                    if exclusions is not None:
                        exclusions.append(
                            {
                                "source_name": src[0],
                                "source_version": src[1],
                                "requirement": raw,
                                "marker": str(requirement.marker),
                                "outcome": "not-applicable",
                            }
                        )
                    continue
            target = nodes.get(canonicalize_name(requirement.name))
            if not target or not requirement.specifier.contains(
                target[1], prereleases=True
            ):
                raise ValueError("unresolved/unsatisfied pip dependency " + raw)
            edges.add((src, target))
    return set(nodes.values()), edges, direct


def selected_go_modules(items):
    selected = {}
    for item in items:
        if item.get("Error") is not None:
            raise ValueError("native Go selected-module error: inventory incomplete")
        if item.get("Replace") is not None:
            raise ValueError(
                "Go replacement source is unsupported; original module identity cannot be assumed"
            )
        name, version = item["Path"], item.get("Version")
        if name in selected or (not version and not item.get("Main")):
            raise ValueError("duplicate or unresolved native Go module identity")
        selected[name] = version
    return selected


def go_graph(manifest, graph, selected, exclusions=None):
    # Native `go list -m -json all` supplies MVS-selected versions. A raw mod
    # graph may reference older versions; edges bind the selected module, not
    # an unselected historical version. This is module scope, not call reachability.
    if manifest.get("Replace"):
        raise ValueError(
            "Go replace directives require separate source resolution; unsupported"
        )
    nodes = {(name, version) for name, version in selected.items() if version}
    direct = {
        (r["Path"], r["Version"])
        for r in manifest.get("Require", [])
        if not r.get("Indirect")
    }
    edges = set()

    def node(raw):
        name = raw.rsplit("@", 1)[0]
        if name in ("go", "toolchain") and "@" in raw:
            return None  # Go's native graph includes these non-package pseudo-nodes.
        if name not in selected:
            raise ValueError(
                "unknown Go graph endpoint absent from selected inventory: " + raw
            )
        if selected[name] is None:
            if raw != name:
                raise ValueError(
                    "versioned Go main module endpoint cannot be resolved: " + raw
                )
            return None
        if "@" not in raw:
            raise ValueError("Go dependency endpoint lacks version: " + raw)
        return (name, selected[name])

    for line in graph.splitlines():
        words = line.split()
        if len(words) != 2:
            raise ValueError("invalid native Go graph line")
        left = node(words[0])
        if left and words[0] != left[0] + "@" + left[1]:
            if exclusions is not None:
                exclusions.append(line)
            continue  # Recorded exclusion of an unselected historical source version.
        right = node(words[1])
        if left and right:
            edges.add((left, right))
    if not direct <= nodes:
        raise ValueError("Go manifest and selected modules disagree")
    return nodes, edges, direct


def reject_reserved_bom_properties(bom):
    pending = [bom]
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            properties = value.get("properties")
            if properties is not None:
                if not isinstance(properties, list):
                    raise ValueError("input BOM properties must be an array")
                for property_entry in properties:
                    if not isinstance(property_entry, dict):
                        raise ValueError("input BOM property must be an object")
                    name = property_entry.get("name")
                    if isinstance(name, str) and name.strip().casefold().startswith("vettalon:"):
                        raise ValueError("input BOM contains reserved vettalon property")
            pending.extend(value.values())


def enrich(bom, nodes, edges, direct, kind, source_hash):
    expected_type = {
        "npm-lock-v3": "npm",
        "pip-inspect": "pypi",
        "go-native": "golang",
    }.get(kind)
    if not expected_type:
        raise ValueError("unsupported native inventory kind")
    reject_reserved_bom_properties(bom)
    def package_type(purl):
        match = re.match(r"^pkg:([a-z][a-z0-9.+-]*)/", purl) if isinstance(purl, str) else None
        if not match:
            raise ValueError("catalog component lacks an explicit package ecosystem purl")
        return match.group(1)

    metadata = bom.setdefault("metadata", {})
    metadata_component = metadata.get("component")
    excluded_refs = set()
    excluded_count = 0
    foreign_refs = set()
    if metadata_component:
        root_purl = metadata_component.get("purl")
        if not root_purl:
            if metadata_component.get("type") != "file":
                raise ValueError("unclassified metadata component has no purl")
            if metadata_component.get("bom-ref"):
                excluded_refs.add(metadata_component["bom-ref"])
            excluded_count += 1
            del metadata["component"]
        elif package_type(root_purl) == expected_type:
            raise ValueError("native ecosystem metadata component requires separate reconciliation")
        elif metadata_component.get("bom-ref"):
            foreign_refs.add(metadata_component["bom-ref"])
    mapping = {}
    retained_components = []
    for component in bom.get("components", []):
        purl = component.get("purl")
        if not purl:
            if component.get("type") != "file":
                raise ValueError("unclassified catalog component has no purl")
            if component.get("bom-ref"):
                excluded_refs.add(component["bom-ref"])
            excluded_count += 1
            continue
        ecosystem = package_type(purl)
        retained_components.append(component)
        name = component["name"]
        if expected_type == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
        key = (name, component.get("version"))
        if ecosystem != expected_type:
            if component.get("bom-ref"):
                foreign_refs.add(component["bom-ref"])
            continue  # Preserve explicit unrelated ecosystems as unverified catalog nodes.
        if key not in nodes:
            raise ValueError("catalog component absent from native source graph")
        if key in nodes:
            expected_identity = f"pkg:{expected_type}/{name}@{component.get('version')}"
            if "?" in purl or "#" in purl or unquote(purl) != expected_identity:
                raise ValueError(
                    "native source and component ecosystem/purl identity disagree: "
                    + str(purl)
                )
            if key in mapping:
                raise ValueError("ambiguous duplicate native component identity")
            mapping[key] = component["bom-ref"]
            component.setdefault("properties", []).extend(
                [
                    {
                        "name": "vettalon:dependency:role",
                        "value": "direct" if key in direct else "transitive-or-root",
                    },
                    {
                        "name": "vettalon:graph:source",
                        "value": kind + ":" + source_hash,
                    },
                ]
            )
    bom["components"] = retained_components
    missing = nodes - set(mapping)
    if missing and kind != "go-native":
        raise ValueError(
            "native graph nodes absent from Syft inventory: " + str(sorted(missing))
        )
    # Go's own MVS-selected inventory is authoritative even where a Syft lock
    # catalog omits test-only module nodes. Preserve that native evidence and
    # license uncertainty instead of dropping the nodes or inventing a license.
    for name, version in sorted(missing):
        purl = "pkg:golang/" + quote(name, safe="/") + "@" + quote(version, safe="")
        bom.setdefault("components", []).append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "bom-ref": purl,
                "properties": [
                    {
                        "name": "vettalon:cataloger",
                        "value": "native go list -m -json all",
                    },
                    {
                        "name": "vettalon:graph:source",
                        "value": kind + ":" + source_hash,
                    },
                    {
                        "name": "vettalon:dependency:role",
                        "value": "direct"
                        if (name, version) in direct
                        else "transitive",
                    },
                    {
                        "name": "vettalon:license:status",
                        "value": "unknown; native module metadata lacks license evidence",
                    },
                ],
            }
        )
        mapping[(name, version)] = purl
    native_refs = set(mapping.values())
    native_edges = {(mapping[left], mapping[right]) for left, right in edges}
    allowed_refs = native_refs | foreign_refs
    existing = {}
    for row in bom.get("dependencies", []):
        ref = row["ref"]
        targets = row.get("dependsOn", [])
        if ref in excluded_refs or any(target in excluded_refs for target in targets):
            raise ValueError("excluded file artifact dependency cannot be reconciled")
        if ref not in allowed_refs or any(target not in allowed_refs for target in targets):
            raise ValueError("unknown catalog dependency ref cannot be reconciled")
        for target in targets:
            if ref in native_refs or target in native_refs:
                if (ref, target) not in native_edges:
                    raise ValueError("catalog dependency edge absent from native source graph")
            else:
                existing.setdefault(ref, set()).add(target)
        if ref not in native_refs and not row.get("dependsOn"):
            existing.setdefault(ref, set())
    for ref, target in native_edges:
        existing.setdefault(ref, set()).add(target)
    bom["dependencies"] = [
        {"ref": ref, "dependsOn": sorted(targets)}
        for ref, targets in sorted(existing.items())
    ]
    bom.setdefault("metadata", {}).setdefault("properties", []).append(
        {
            "name": "vettalon:graph:scope",
            "value": kind
            + "; module/package metadata only; not binary reachability; explicit input snapshot "
            + source_hash,
        }
    )
    bom["metadata"]["properties"].append(
        {
            "name": "vettalon:graph:edge-policy",
            "value": "native refs source-authoritative; unproven catalog edges fail; explicit foreign-purl edges unverified",
        }
    )
    if excluded_count:
        bom["metadata"]["properties"].append(
            {
                "name": "vettalon:graph:excluded-unclassified-file-artifacts",
                "value": str(excluded_count),
            }
        )
    return bom


def read_json_sequence(path):
    raw = path.read_text()
    decoder = json.JSONDecoder()
    result = []
    while raw.strip():
        item, end = decoder.raw_decode(raw.lstrip())
        result.append(item)
        raw = raw.lstrip()[end:]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["npm-lock-v3", "pip-inspect", "go-native"])
    parser.add_argument("--bom", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go-graph", type=Path)
    parser.add_argument("--go-selected", type=Path)
    args = parser.parse_args()
    try:
        exclusions = []
        marker_exclusions = []
        marker_environment = None
        digest = None
        manifest_digest = None
        if args.kind == "npm-lock-v3":
            source = read_npm_file_bytes(args.source, "source", 64 * 1024 * 1024, required=True)
        else:
            source = args.source.read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        if args.kind == "npm-lock-v3":
            manifest_path = args.source.with_name("package.json")
            manifest = None
            manifest_bytes = read_npm_file_bytes(manifest_path, "manifest", 4 * 1024 * 1024)
            if manifest_bytes is not None:
                manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
                manifest = json.loads(manifest_bytes)
            nodes, edges, direct = npm_graph(json.loads(source), manifest=manifest)
        elif args.kind == "pip-inspect":
            inspect = json.loads(source)
            nodes, edges, direct = pip_graph(inspect, exclusions=marker_exclusions)
            marker_environment = pip_marker_environment(inspect)
        else:
            if not args.go_graph or not args.go_selected:
                raise ValueError(
                    "Go requires native mod graph and selected module JSON"
                )
            selected = selected_go_modules(read_json_sequence(args.go_selected))
            nodes, edges, direct = go_graph(
                json.loads(source),
                args.go_graph.read_text(),
                selected,
                exclusions=exclusions,
            )
            digest = hashlib.sha256(
                source + args.go_graph.read_bytes() + args.go_selected.read_bytes()
            ).hexdigest()
        bom = enrich(
            json.loads(args.bom.read_text()), nodes, edges, direct, args.kind, digest
        )
        if manifest_digest is not None:
            bom["metadata"]["properties"].append(
                {"name": "vettalon:graph:manifest-sha256", "value": manifest_digest}
            )
        if marker_environment is not None:
            bom["metadata"]["properties"].extend(
                [
                    {
                        "name": "vettalon:graph:marker-environment",
                        "value": json.dumps(marker_environment, sort_keys=True),
                    },
                    {
                        "name": "vettalon:graph:marker-exclusions",
                        "value": json.dumps(marker_exclusions, sort_keys=True),
                    },
                ]
            )
        from trust import validate_bom

        validate_bom(bom)
        with args.output.open("x") as stream:
            json.dump(bom, stream, indent=2)
            stream.write("\n")
        print(
            json.dumps(
                {
                    "source_kind": args.kind,
                    "source_sha256": digest,
                    **({"manifest_sha256": manifest_digest} if manifest_digest else {}),
                    "nodes": len(nodes),
                    "edges": len(edges),
                    "direct": len(direct),
                    "excluded_historical_source_edges": exclusions,
                    "excluded_marker_requirements": marker_exclusions,
                    "boundary": "selected native source snapshot only; not general ecosystem acceptance",
                }
            )
        )
    except UnsupportedInventoryError as error:
        print(
            json.dumps(
                {
                    "status": "unsupported",
                    "code": error.code,
                    "source_kind": args.kind,
                    **({"source_sha256": digest} if digest else {}),
                    **({"manifest_sha256": manifest_digest} if manifest_digest else {}),
                    "boundary": "no reconciled BOM emitted; Syft catalog alone is not a resolved npm source graph",
                }
            )
        )
        parser.exit(2)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
