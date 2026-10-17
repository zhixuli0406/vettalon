#!/usr/bin/env python3
"""Bounded source-graph adapters; never execute target build hooks or infer reachability."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote, unquote


def npm_graph(lock):
    if lock.get("lockfileVersion") != 3:
        raise ValueError("native npm graph supports lock v3 only")
    packages = lock["packages"]
    nodes = {}
    edges = set()
    direct = set()
    for path, entry in packages.items():
        if any(
            entry.get(key)
            for key in ("link", "optional", "peerDependencies", "os", "cpu")
        ):
            raise ValueError(
                "workspace links/peers/conditional npm nodes require separate resolution"
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


def enrich(bom, nodes, edges, direct, kind, source_hash):
    mapping = {}
    for component in bom.get("components", []):
        purl = component.get("purl", "")
        name = component["name"]
        expected_type = {
            "npm-lock-v3": "npm",
            "pip-inspect": "pypi",
            "go-native": "golang",
        }.get(kind)
        if not expected_type:
            raise ValueError("unsupported native inventory kind")
        if expected_type == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
        key = (name, component.get("version"))
        if purl and not purl.startswith(f"pkg:{expected_type}/"):
            continue  # Preserve unrelated ecosystems without relabeling their nodes.
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
    existing = {
        r["ref"]: set(r.get("dependsOn", [])) for r in bom.get("dependencies", [])
    }
    for left, right in edges:
        existing.setdefault(mapping[left], set()).add(mapping[right])
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
        source = args.source.read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        if args.kind == "npm-lock-v3":
            nodes, edges, direct = npm_graph(json.loads(source))
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
                    "nodes": len(nodes),
                    "edges": len(edges),
                    "direct": len(direct),
                    "excluded_historical_source_edges": exclusions,
                    "excluded_marker_requirements": marker_exclusions,
                    "boundary": "selected native source snapshot only; not general ecosystem acceptance",
                }
            )
        )
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
