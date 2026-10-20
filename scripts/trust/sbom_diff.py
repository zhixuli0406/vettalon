#!/usr/bin/env python3
"""Cargo SBOM differential test: Syft CycloneDX vs `cargo metadata --locked`.

`collect` (live, needs Syft/cargo; optional nightly) records one case as a
sanitized snapshot: the raw Syft BOM, the adapter outcome, the resolved graph
from `cargo metadata --locked --offline --filter-platform <target>` (normal and
build edges from the workspace members, dev-only edges excluded) and, when a
nightly toolchain is named, the unstable Cargo SBOM precursor (`-Zsbom`) as a
second test oracle only. `report` recomputes metrics offline from a snapshot.

Metrics are reported separately: component precision/recall on name@version,
version accuracy on shared names, and license accuracy on matched components.
Output BOMs are unchanged CycloneDX 1.6; this module never repairs a BOM.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))

SCHEMA = 1
BUILD_KINDS = (None, "build")
PRECURSOR_ID = re.compile(r"^(?P<source>[a-z]+)\+(?P<url>[^#]+)#(?:(?P<name>[A-Za-z0-9_-]+)@)?(?P<version>[^@#]+)$")


# ---------------------------------------------------------------- inventories


def adapt_syft_bom(trust, bom, source):
    """Apply trust.py's Syft adapter checks to one raw catalog, in run_syft's order.

    trust.py stays byte-identical to the archived CLI v0.2.0 readback snapshot,
    so the sequence is mirrored here instead of refactoring run_syft.
    """
    trust.validate_bom(bom)
    trust.cargo_graph.verify_cargo_graph(bom, source)
    trust.enrich_cargo_licenses(bom, source)
    trust.annotate_cargo_roles(bom, source)
    trust.validate_bom(bom)
    if not bom.get("components"):
        raise ValueError("Syft found no components; incomplete inventory, refusing success")
    return bom

def bom_inventory(bom):
    """name@version -> sorted license strings for pkg:cargo components."""
    inventory, duplicates = {}, []
    components = list(bom.get("components", []))
    if bom.get("metadata", {}).get("component"):
        components.append(bom["metadata"]["component"])
    for component in components:
        purl = component.get("purl", "")
        if not isinstance(purl, str) or not purl.startswith("pkg:cargo/"):
            continue
        match = re.fullmatch(r"pkg:cargo/([^/@?#]+)@([^?#]+)(?:[?#].*)?", purl)
        if match is None:
            raise ValueError("invalid Cargo purl in BOM")
        key = match.group(1) + "@" + unquote(match.group(2))
        licenses = sorted(_license_text(item) for item in component.get("licenses", []))
        if key in inventory:
            duplicates.append(key)
        inventory[key] = {"licenses": [item for item in licenses if item]}
    return inventory, sorted(set(duplicates))


def _license_text(item):
    if item.get("expression"):
        return item["expression"]
    license_ = item.get("license", {})
    return license_.get("id") or license_.get("name") or ""


def metadata_truth(metadata):
    """Resolved build graph from `cargo metadata` JSON; dev-only edges excluded."""
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = metadata.get("workspace_default_members") or metadata["workspace_members"]
    seen, pending, edges = set(), list(roots), set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind.get("kind") in BUILD_KINDS for kind in dep["dep_kinds"]):
                edges.add((current, dep["pkg"]))
                pending.append(dep["pkg"])

    def key(package_id):
        package = packages[package_id]
        return package["name"] + "@" + package["version"]

    result = {}
    for package_id in sorted(seen):
        package = packages[package_id]
        source = package.get("source") or "path"
        result[key(package_id)] = {"license": package.get("license"),
                                   "origin": source.split("+", 1)[0]}
    return {"packages": result, "edges": sorted(key(a) + " -> " + key(b) for a, b in edges),
            "roots": sorted(key(root) for root in roots)}


def parse_precursor_id(identifier):
    match = PRECURSOR_ID.match(identifier)
    if match is None:
        raise ValueError("unsupported precursor package id")
    name = match.group("name") or match.group("url").rstrip("/").rsplit("/", 1)[-1]
    return name + "@" + match.group("version"), match.group("source")


def precursor_truth(documents):
    """Union of crates reachable from each precursor root (all are build edges)."""
    packages = {}
    for document in documents:
        if document.get("version") != 1:
            raise ValueError("unsupported Cargo SBOM precursor version")
        crates = document["crates"]
        seen, pending = set(), [document["root"]]
        while pending:
            index = pending.pop()
            if index in seen:
                continue
            seen.add(index)
            pending.extend(dep["index"] for dep in crates[index].get("dependencies", []))
        for index in seen:
            key, origin = parse_precursor_id(crates[index]["id"])
            packages[key] = {"license": None, "origin": origin}
    return {"packages": dict(sorted(packages.items()))}


# ---------------------------------------------------------------- metrics

def _norm_license(text):
    if not text:
        return None
    text = re.sub(r"\s*/\s*", " OR ", text.strip())
    return re.sub(r"\s+", " ", text)


def compare(truth, observed):
    """Precision/recall on name@version; version and license accuracy separate."""
    truth_keys, observed_keys = set(truth), set(observed)
    matched = truth_keys & observed_keys
    by_name = {}
    for label, keys in (("truth", truth_keys), ("observed", observed_keys)):
        for key in keys:
            name, version = key.rsplit("@", 1)
            by_name.setdefault(name, {"truth": set(), "observed": set()})[label].add(version)
    shared = {name: item for name, item in by_name.items() if item["truth"] and item["observed"]}
    version_ok = sorted(name for name, item in shared.items() if item["truth"] == item["observed"])
    evaluated, correct, missing = 0, 0, 0
    for key in matched:
        expected = _norm_license(truth[key].get("license"))
        if expected is None:
            continue
        evaluated += 1
        found = [_norm_license(item) for item in observed[key].get("licenses", [])]
        if not found:
            missing += 1
        elif found == [expected]:
            correct += 1

    def ratio(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else None

    return {"truth_count": len(truth_keys), "observed_count": len(observed_keys), "matched": len(matched),
            "precision": ratio(len(matched), len(observed_keys)), "recall": ratio(len(matched), len(truth_keys)),
            "extra": sorted(observed_keys - truth_keys), "missing": sorted(truth_keys - observed_keys),
            "version_accuracy": ratio(len(version_ok), len(shared)), "version_shared_names": len(shared),
            "version_mismatch": sorted(set(shared) - set(version_ok)),
            "license_evaluated": evaluated, "license_correct": correct, "license_absent": missing,
            "license_accuracy": ratio(correct, evaluated)}


def verdict(oracle, observed):
    """refused | matches-oracle | differs-from-oracle | accepted-invalid-input."""
    if observed["status"] != "ok":
        return "refused"
    if oracle["status"] != "ok":
        # Cargo itself rejects this input; any successful inventory is misleading.
        return "accepted-invalid-input"
    return "matches-oracle" if set(oracle["packages"]) == set(observed["packages"]) else "differs-from-oracle"


def report(snapshot):
    """Offline metrics for every observed inventory against every available oracle."""
    oracles = {name: snapshot[name] for name in ("metadata", "precursor") if snapshot[name]["status"] == "ok"}
    result = {"case": snapshot["case"], "target": snapshot["target"], "features": snapshot["features"],
              "oracle_status": {name: snapshot[name]["status"] for name in ("metadata", "precursor")},
              "comparisons": {}, "verdicts": {}}
    for observed_name in ("syft", "adapter"):
        observed = snapshot[observed_name]
        if observed["status"] != "ok":
            result["comparisons"][observed_name] = {"status": observed["status"], "error": observed.get("error")}
            result["verdicts"][observed_name] = "refused"
            continue
        result["comparisons"][observed_name] = {
            oracle: compare(data["packages"], observed["packages"]) for oracle, data in oracles.items()}
        result["verdicts"][observed_name] = verdict(snapshot["metadata"], observed)
    if set(oracles) == {"metadata", "precursor"}:
        result["oracle_agreement"] = compare(oracles["metadata"]["packages"],
                                             {k: {"licenses": []} for k in oracles["precursor"]["packages"]})
    return result


# ---------------------------------------------------------------- collection

def sanitize_bom(bom, root):
    """Drop absolute scan paths so a recorded BOM can be published."""
    clean = copy.deepcopy(bom)
    prefix = str(Path(root).resolve())

    def scrub(value):
        if isinstance(value, str):
            for base in (prefix + "/", prefix):
                if value.startswith(base):
                    return "./" + value[len(base):]
            return value
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        return value

    clean = scrub(clean)
    clean.get("metadata", {}).pop("timestamp", None)
    clean.pop("serialNumber", None)
    return clean


def _scrub_text(text, root):
    return text.replace(str(Path(root).resolve()), ".").replace(str(Path.home()), "~")


def tool_env(**extra):
    """Minimal child environment: no inherited tokens, proxies or registry credentials."""
    keep = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env.update({"LANG": "C.UTF-8", "CARGO_NET_OFFLINE": "true"}, **extra)
    return env


def run_metadata(source, target, features, cargo="cargo"):
    command = [cargo, "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", target]
    command += ["--features", features] if features else []
    run = subprocess.run(command, cwd=source, env=tool_env(), capture_output=True, text=True, timeout=300)
    if run.returncode:
        lines = [line for line in run.stderr.splitlines() if line.strip()]
        return {"status": "error", "error": _scrub_text(" | ".join(lines[-3:]), source)}
    return {"status": "ok", **metadata_truth(json.loads(run.stdout))}


def run_precursor(source, target, toolchain):
    # --locked forbids lockfile writes; build output goes to a disposable target dir.
    with tempfile.TemporaryDirectory(prefix="vettalon-sbom-precursor-") as temp:
        env = tool_env(CARGO_BUILD_SBOM="true", CARGO_TARGET_DIR=str(Path(temp) / "target"))
        command = ["cargo", "+" + toolchain, "build", "--locked", "--offline", "-Zsbom", "--target", target]
        run = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True, timeout=1800)
        if run.returncode:
            lines = [line for line in run.stderr.splitlines() if line.strip()]
            return {"status": "error", "error": _scrub_text(" | ".join(lines[-3:]), source)}
        output = Path(temp) / "target" / target / "debug"
        documents = [json.loads(path.read_text()) for path in sorted(output.glob("*.cargo-sbom.json"))]
        if not documents:
            return {"status": "error", "error": "no top-level precursor SBOM emitted"}
        rustc = documents[0].get("rustc", {}).get("version")
        return {"status": "ok", "toolchain": toolchain, "rustc": rustc, **precursor_truth(documents)}


def stage_lock_only(source, destination):
    """Copy only Cargo manifests and lockfile so Syft sees the build inputs alone."""
    source = Path(source)
    for relative in ["Cargo.toml", "Cargo.lock"] + [str(p.relative_to(source)) for p in sorted(source.glob("crates/*/Cargo.toml"))]:
        target = Path(destination) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


def collect(args):
    import trust  # requires the pinned jsonschema venv for adapter validation

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError("output exists; refusing overwrite")
    output.mkdir(parents=True)
    env = tool_env(SYFT_CHECK_FOR_APP_UPDATE="false", SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES="false",
                   SYFT_GOLANG_SEARCH_REMOTE_LICENSES="false", SYFT_JAVA_USE_NETWORK="false")
    syft_version = subprocess.run([args.syft, "version"], capture_output=True, text=True, timeout=60, env=env).stdout
    with tempfile.TemporaryDirectory(prefix="vettalon-sbom-diff-") as temp:
        scan_root = source
        if args.lock_only:
            scan_root = Path(temp) / "slice"
            stage_lock_only(source, scan_root)
        raw_path = Path(temp) / "raw.cdx.json"
        run = subprocess.run([args.syft, "scan", "dir:" + str(scan_root), "-q", "-o", "cyclonedx-json@1.6=" + str(raw_path)],
                             capture_output=True, text=True, timeout=300, env=env)
        if run.returncode or not raw_path.is_file():
            syft = {"status": "error", "error": _scrub_text(run.stderr[-500:], scan_root)}
            raw = None
        else:
            raw = json.loads(raw_path.read_text())
            inventory, duplicates = bom_inventory(raw)
            syft = {"status": "ok", "packages": inventory, "duplicates": duplicates}
            if args.record_bom:
                (output / "syft.cdx.json").write_text(json.dumps(sanitize_bom(raw, scan_root), indent=2) + "\n")
        if raw is None:
            adapted = {"status": "not-run", "error": "no Syft BOM"}
        else:
            try:
                bom = adapt_syft_bom(trust, copy.deepcopy(raw), source)
                inventory, _ = bom_inventory(bom)
                adapted = {"status": "ok", "packages": inventory}
            except ValueError as error:  # includes TOML decode errors
                adapted = {"status": "refused", "error": _scrub_text(str(error), source)}
    metadata = run_metadata(source, args.target, args.features)
    precursor = (run_precursor(source, args.target, args.precursor_toolchain)
                 if args.precursor_toolchain else {"status": "not-run"})
    cargo_version = subprocess.run(["cargo", "--version"], env=tool_env(), capture_output=True, text=True,
                                   timeout=60).stdout.strip()
    lock = source / "Cargo.lock"
    snapshot = {"schema": SCHEMA, "case": args.case, "target": args.target, "features": args.features or "default",
                "tools": {"syft": _syft_version(syft_version), "cargo": cargo_version},
                "lockfile_sha256": hashlib.sha256(lock.read_bytes()).hexdigest() if lock.is_file() else None,
                "syft_scope": "lock-only slice" if args.lock_only else "directory",
                "metadata": metadata, "precursor": precursor, "syft": syft, "adapter": adapted}
    (output / "snapshot.json").write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    result = report(snapshot)
    (output / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary_rows(result), indent=2))
    return 0


def _syft_version(text):
    match = re.search(r"^Version:\s+(\S+)", text, re.M)
    return match.group(1) if match else "unknown"


def summary_rows(result):
    rows = []
    for observed, oracles in result["comparisons"].items():
        if "status" in oracles:
            rows.append({"observed": observed, "status": oracles["status"], "error": oracles.get("error")})
            continue
        for oracle, metrics in oracles.items():
            rows.append({"observed": observed, "oracle": oracle, **{k: metrics[k] for k in (
                "precision", "recall", "version_accuracy", "license_accuracy", "extra", "missing")}})
    return {"case": result["case"], "oracles": result["oracle_status"], "verdicts": result["verdicts"], "rows": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    gather = commands.add_parser("collect", help="live: run Syft, adapter, cargo metadata (and optional precursor)")
    gather.add_argument("--source", required=True)
    gather.add_argument("--case", required=True)
    gather.add_argument("--syft", required=True)
    gather.add_argument("--target", required=True, help="target triple for --filter-platform and the precursor build")
    gather.add_argument("--features", default="", help="comma list passed to cargo metadata (default features if empty)")
    gather.add_argument("--precursor-toolchain", help="nightly toolchain name; omit to skip the precursor oracle")
    gather.add_argument("--lock-only", action="store_true", help="Syft scans a staged manifests+lock slice")
    gather.add_argument("--record-bom", action="store_true", help="also save the sanitized raw Syft BOM")
    gather.add_argument("--output", required=True)
    offline = commands.add_parser("report", help="offline: recompute metrics from a snapshot")
    offline.add_argument("snapshot")
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            return collect(args)
        result = report(json.loads(Path(args.snapshot).read_text()))
        print(json.dumps(summary_rows(result), indent=2))
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print("sbom-diff error: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
