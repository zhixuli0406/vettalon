#!/usr/bin/env python3
"""Reachability corpus: execution ground truth vs adapter states vs govulncheck OpenVEX.

`prepare` is the only networked step: it fills a dedicated module cache through
the Go proxy and checksum database. `run` is offline (GOPROXY=off,
GOFLAGS=-mod=mod): it builds each self-authored host with coverage on the
advisory packages, executes it once to label ground truth, runs the adapter
with the pinned govulncheck, then both pinned and latest govulncheck in
OpenVEX mode. The adapter never emits not_affected; OpenVEX is only compared.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapter  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus"
PROXY = "https://proxy.golang.org"
SUMDB = "sum.golang.org"
STATES = ("reachable", "not-observed", "unknown")
TOTAL_BUDGET_SECONDS = 3600
FUNC_DECL = re.compile(
    r"^func\s+(?:\(\s*(?:\w+\s+)?\*?\s*(\w+)(?:\[[^\]]*\])?\s*\)\s*)?(\w+)\s*[\[(]", re.M)
COVER_LINE = re.compile(r"^(.+\.go):(\d+):\s+(\S+)\s+([0-9.]+)%$")


# ---------------------------------------------------------------- manifest

def _version_key(version):
    """Semantic-version precedence for Go module versions (build metadata ignored)."""
    core, _, pre = version.lstrip("v").split("+", 1)[0].partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    if len(numbers) != 3:
        raise ValueError("unsupported version " + version)
    if not pre:
        return numbers, (1,)
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return numbers, (0, ids)


def affected(entry, module, version):
    """OSV SEMVER range evaluation for one module; introduced inclusive, fixed exclusive."""
    key = _version_key(version)
    for item in entry["affected"]:
        if item["package"]["name"] != module:
            continue
        for rng in item["ranges"]:
            if rng["type"] != "SEMVER":
                raise ValueError("unsupported range type")
            # Sort events (introduced "0" first); the last one at or below the version decides.
            def order(event):
                value = next(iter(event.values()))
                return ((0, 0, 0), (0,)) if value == "0" else _version_key(value)
            inside = False
            for event in sorted(rng["events"], key=order):
                if "introduced" in event:
                    start = event["introduced"]
                    if start == "0" or key >= _version_key(start):
                        inside = True
                elif "fixed" in event:
                    if key >= _version_key(event["fixed"]):
                        inside = False
                elif "last_affected" in event:
                    if key > _version_key(event["last_affected"]):
                        inside = False
                else:
                    raise ValueError("unsupported range event")
            if inside:
                return True
    return False


def symbols(entry, module):
    found = {}
    for item in entry["affected"]:
        if item["package"]["name"] == module:
            for imp in item.get("ecosystem_specific", {}).get("imports", []):
                found.setdefault(imp["path"], []).extend(imp.get("symbols", []))
    return found


def load_manifest(corpus=CORPUS):
    manifest = json.loads((corpus / "corpus.json").read_text())
    if manifest.get("schema") != 1:
        raise ValueError("unsupported corpus schema")
    snapshot = corpus / "vulndb"
    files = {p.name for p in snapshot.iterdir()}
    if files != set(manifest["snapshot"]["files"]):
        raise ValueError("vulndb snapshot file set differs from manifest")
    for name, expected in manifest["snapshot"]["files"].items():
        path = snapshot / name
        if path.is_symlink() or adapter.digest(path.read_bytes()) != expected:
            raise ValueError("vulndb snapshot checksum mismatch: " + name)
    advisories = {}
    for item in manifest["advisories"]:
        entry = json.loads((snapshot / (item["id"] + ".json")).read_text())
        if entry["id"] != item["id"] or not affected(entry, item["module"], item["version"]):
            raise ValueError(item["id"] + " does not affect the pinned module version")
        if not any(symbols(entry, item["module"]).values()):
            raise ValueError(item["id"] + " lists no symbols")
        advisories[item["id"]] = {**item, "symbols": symbols(entry, item["module"])}
    if not 12 <= len(advisories) <= 20:
        raise ValueError("corpus must hold 12-20 advisories")
    classes = set(manifest["blind_spot_classes"])
    for host in manifest["hosts"]:
        if host["advisory"] not in advisories or host["class"] not in classes | {"called", "not-called"}:
            raise ValueError("invalid host entry " + host["name"])
        if not re.fullmatch(r"[a-z0-9-]+", host["name"]) or not (corpus / "hosts" / host["name"]).is_dir():
            raise ValueError("missing host directory " + host["name"])
    for advisory in advisories:
        kinds = {h["class"] for h in manifest["hosts"] if h["advisory"] == advisory}
        if not {"called", "not-called"} <= kinds:
            raise ValueError(advisory + " needs a called and a not-called host")
    for klass in classes:
        if not any(h["class"] == klass for h in manifest["hosts"]):
            raise ValueError("no host for blind-spot class " + klass)
    return manifest, advisories


# ---------------------------------------------------------------- environment

def go_env(modcache, gocache, home, online=False):
    go = shutil.which("go")
    if not go:
        raise ValueError("go toolchain missing")
    return go, {"PATH": str(Path(go).parent) + os.pathsep + os.defpath, "HOME": str(home),
                "TMPDIR": tempfile.gettempdir(), "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off",
                "GOFLAGS": "-mod=readonly" if online else "-mod=mod", "CGO_ENABLED": "0",
                "GOTELEMETRY": "off", "GOPROXY": PROXY if online else "off",
                "GOSUMDB": SUMDB if online else "off", "GOMODCACHE": str(modcache), "GOCACHE": str(gocache)}


def module_dir(modcache, module, version):
    escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)
    return Path(modcache) / (escaped + "@" + version)


def tool_version(go, tool, env):
    run = adapter.invoke([go, "version", "-m", str(tool)], Path.cwd(), env, 20)
    match = re.search(r"^\s*mod\s+golang\.org/x/vuln\s+(v\S+)", run.get("stdout", ""), re.M)
    if not adapter.successful_run(run) or not match:
        raise ValueError("cannot read govulncheck build info: " + str(tool))
    return match.group(1)


# ---------------------------------------------------------------- ground truth

def symbol_index(package_dir, import_path):
    """Map (import_path/file.go, decl line) -> advisory-style symbol name."""
    index = {}
    for path in sorted(Path(package_dir).glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(errors="replace")
        for match in FUNC_DECL.finditer(text):
            receiver, name = match.groups()
            line = text.count("\n", 0, match.start()) + 1
            index[(import_path + "/" + path.name, line)] = (receiver + "." + name) if receiver else name
    return index


def parse_cover_func(text):
    rows = {}
    for line in text.splitlines():
        match = COVER_LINE.match(line.strip())
        if match:
            rows[(match.group(1), int(match.group(2)))] = float(match.group(4))
    return rows


def label_truth(advisory, cover_rows, indexes, linked=None):
    """executed if any listed symbol has nonzero statement coverage.

    A declared symbol in a linked package with no coverage row is a mapping
    failure, so the host becomes unknown rather than not-executed.
    """
    detail = {}
    for package, names in advisory["symbols"].items():
        index = indexes.get(package, {})
        in_binary = linked is None or package in linked
        for name in names:
            locations = [loc for loc, symbol in index.items() if symbol == name]
            if not locations:
                detail[package + "." + name] = {"declared": False}
                continue
            if in_binary and not any(loc in cover_rows for loc in locations):
                detail[package + "." + name] = {"declared": True, "covered_percent": None}
                continue
            percent = max(cover_rows.get(loc, 0.0) for loc in locations)
            detail[package + "." + name] = {"declared": True, "covered_percent": percent, "linked": in_binary}
    declared = [d for d in detail.values() if d["declared"]]
    if not declared or any(d["covered_percent"] is None for d in declared):
        return "unknown", detail
    return ("executed" if any(d["covered_percent"] > 0 for d in declared) else "not-executed"), detail


def ground_truth(go, env, host_dir, advisory, modcache, out):
    out.mkdir(parents=True)
    binary, covdir = out / "host-bin", out / "covdata"
    covdir.mkdir()
    # Go 1.27 writes no coverage meta-data unless a main-module package is
    # also instrumented, so ./... rides along with the advisory packages.
    packages = ",".join(sorted(advisory["symbols"]))
    steps = {}
    steps["build"] = adapter.invoke([go, "build", "-cover", "-covermode=count", "-coverpkg=./...," + packages,
                                     "-o", str(binary), "."], host_dir, env, 120)
    if not adapter.successful_run(steps["build"]):
        return {"truth": "unknown", "reason": "coverage-build-failed", "steps": steps}
    run_env = {"PATH": os.defpath, "HOME": env["HOME"], "GOCOVERDIR": str(covdir), "LANG": "C"}
    # cwd is the disposable output directory, not the repository. There is no
    # network sandbox: hosts are self-authored, use fixed in-memory input and
    # make no network calls.
    steps["execute"] = adapter.invoke([str(binary)], out, run_env, 30)
    binary_sha256 = adapter.digest(binary.read_bytes())
    binary.unlink()  # bounded disk use; the digest is retained
    if not adapter.successful_run(steps["execute"]):
        return {"truth": "unknown", "reason": "host-execution-failed", "steps": steps}
    profile = out / "cover.out"
    steps["textfmt"] = adapter.invoke([go, "tool", "covdata", "textfmt", "-i=" + str(covdir), "-o=" + str(profile)],
                                      host_dir, env, 60)
    steps["func"] = adapter.invoke([go, "tool", "cover", "-func=" + str(profile)], host_dir, env, 60)
    if not (adapter.successful_run(steps["textfmt"]) and adapter.successful_run(steps["func"])):
        return {"truth": "unknown", "reason": "coverage-report-failed", "steps": steps}
    steps["deps"] = adapter.invoke([go, "list", "-deps", "."], host_dir, env, 60)
    if not adapter.successful_run(steps["deps"]):
        return {"truth": "unknown", "reason": "dependency-listing-failed", "steps": steps}
    rows = parse_cover_func(steps["func"]["stdout"])
    covered_packages = {path.rsplit("/", 1)[0] for path, _ in rows}
    linked = set(steps["deps"]["stdout"].split())
    # An empty or partial profile must never read as "not executed": the main
    # package and every linked advisory package need coverage rows.
    if not any(package not in advisory["symbols"] and package in linked for package in covered_packages):
        return {"truth": "unknown", "reason": "coverage-missing-main-package", "steps": steps}
    missing = sorted(package for package in advisory["symbols"] if package in linked and package not in covered_packages)
    if missing:
        return {"truth": "unknown", "reason": "coverage-missing-advisory-package", "missing": missing, "steps": steps}
    base = module_dir(modcache, advisory["module"], advisory["version"])
    indexes = {}
    for package in advisory["symbols"]:
        relative = package[len(advisory["module"]):].lstrip("/")
        indexes[package] = symbol_index(base / relative, package)
    truth, detail = label_truth(advisory, rows, indexes, linked)
    return {"truth": truth, "reason": "go build -cover execution" if truth != "unknown" else "symbol-coverage-unmapped",
            "symbols": detail, "linked_advisory_packages": sorted(set(advisory["symbols"]) & linked), "host_binary_sha256": binary_sha256, "steps": {k: {"returncode": v["returncode"], "seconds": v["seconds"]} for k, v in steps.items()}}


# ---------------------------------------------------------------- OpenVEX

def openvex_status(raw, advisory_id):
    try:
        document = json.loads(raw)
        statements = [s for s in document.get("statements", [])
                      if s.get("vulnerability", {}).get("name") == advisory_id]
    except (ValueError, AttributeError, TypeError):
        return {"status": "invalid", "justification": None}
    if len(statements) != 1:
        return {"status": "absent" if not statements else "ambiguous", "justification": None}
    return {"status": statements[0].get("status"), "justification": statements[0].get("justification")}


def run_openvex(tool, host_dir, env, db, advisory_id, out):
    run = adapter.invoke([str(tool), "-format", "openvex", "-db", db.as_uri(), "./..."], host_dir, env, 120)
    out.write_text(run.get("stdout", ""))
    if not adapter.successful_run(run):
        return {"status": "tool-error", "justification": None, "error": run.get("error")}
    return {**openvex_status(run["stdout"], advisory_id), "raw_sha256": adapter.digest(run["stdout"].encode())}


# ---------------------------------------------------------------- metrics

def evaluate(rows, blind_classes):
    classes = {}
    for row in rows:
        stats = classes.setdefault(row["class"], {
            "hosts": 0, "truth_executed": 0, "truth_not_executed": 0, "truth_unknown": 0,
            **{"adapter_" + s.replace("-", "_"): 0 for s in STATES},
            "false_unreachable": 0, "false_reachable": 0,
            "vex_pinned_false_not_affected": 0, "vex_latest_false_not_affected": 0,
            "vex_pinned_affected": 0, "vex_latest_affected": 0, "vex_version_diffs": 0})
        stats["hosts"] += 1
        stats["truth_" + row["truth"].replace("-", "_")] += 1
        stats["adapter_" + row["adapter"].replace("-", "_")] += 1
        executed = row["truth"] == "executed"
        if executed and row["adapter"] == "not-observed":
            stats["false_unreachable"] += 1
        if row["truth"] == "not-executed" and row["adapter"] == "reachable":
            stats["false_reachable"] += 1
        for version in ("pinned", "latest"):
            status = row["vex_" + version]
            stats["vex_%s_affected" % version] += status == "affected"
            stats["vex_%s_false_not_affected" % version] += executed and status == "not_affected"
        stats["vex_version_diffs"] += row["vex_pinned"] != row["vex_latest"]
    for stats in classes.values():
        executed = stats["truth_executed"]
        stats["adapter_recall"] = round(stats["adapter_reachable"] / executed, 4) if executed else None
    totals = {key: sum(c[key] for c in classes.values()) for key in
              ("hosts", "false_unreachable", "false_reachable", "vex_pinned_false_not_affected",
               "vex_latest_false_not_affected", "vex_version_diffs")}
    false_reachable = [r["host"] for r in rows if r["truth"] == "not-executed" and r["adapter"] == "reachable"]
    blind_bad = [r["host"] for r in rows if r["class"] in blind_classes and r["adapter"] == "not-observed"]
    incomplete = [r["host"] for r in rows if r["truth"] == "unknown"
                  or (r["class"] not in blind_classes and r["adapter"] == "unknown")
                  or r["vex_pinned"] not in ("affected", "not_affected", "under_investigation", "fixed")
                  or r["vex_latest"] not in ("affected", "not_affected", "under_investigation", "fixed")]
    emitted = [r["host"] for r in rows if r.get("adapter_vex") != "under_investigation"]
    gates = {"false_unreachable_zero": totals["false_unreachable"] == 0,
             "blind_spots_never_not_observed": not blind_bad,
             "complete_observation": not incomplete,
             "adapter_never_not_affected": not emitted}
    return {"classes": classes, "totals": totals, "gates": gates, "blind_spot_violations": blind_bad,
            "false_reachable_hosts": false_reachable,
            "incomplete_hosts": incomplete, "not_affected_emitted": emitted, "passed": all(gates.values())}


# ---------------------------------------------------------------- commands

def prepare(args):
    manifest, _ = load_manifest()
    modcache = Path(args.modcache).resolve() / "pkg" / "mod"
    modcache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vettalon-corpus-prepare-") as home:
        go, env = go_env(modcache, Path(home) / "gocache", home, online=True)
        failures = []
        for host in manifest["hosts"]:
            directory = CORPUS / "hosts" / host["name"]
            for command in ([go, "mod", "download"], [go, "mod", "verify"]):
                run = adapter.invoke(command, directory, env, 120)
                if not adapter.successful_run(run):
                    failures.append({"host": host["name"], "command": command[1:], "stderr": run.get("stderr", "")[-2000:]})
    print(json.dumps({"modcache": str(modcache), "hosts": len(manifest["hosts"]), "failures": failures}, indent=2))
    return 1 if failures else 0


def run(args):
    manifest, advisories = load_manifest()
    output = Path(args.output).resolve()
    if output.exists() or CORPUS in output.parents or output == CORPUS:
        print("output exists or overlaps the corpus; nothing written")
        return 2
    modcache = Path(args.modcache).resolve() / "pkg" / "mod"
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="vettalon-corpus-") as scratch:
        # Build cache and HOME are disposable; only labelled evidence is kept.
        go, env = go_env(modcache, Path(scratch) / "gocache", Path(scratch) / "home")
        Path(env["HOME"]).mkdir()
        return _run(args, manifest, advisories, output, modcache, go, env)


def _run(args, manifest, advisories, output, modcache, go, env):
    tools = {"pinned": Path(args.tool).resolve(), "latest": Path(args.latest_tool).resolve()}
    versions = {name: tool_version(go, path, env) for name, path in tools.items()}
    if versions["pinned"] != manifest["pinned_govulncheck"] or versions["pinned"] != adapter.TOOL_VERSION:
        raise ValueError("pinned govulncheck must be " + adapter.TOOL_VERSION)
    toolchain = adapter.invoke([go, "version"], Path.cwd(), env, 20)["stdout"].strip()
    db = CORPUS / "vulndb"
    selected = [h for h in manifest["hosts"] if not args.host or h["name"] in args.host]
    unknown_names = sorted(set(args.host or []) - {h["name"] for h in manifest["hosts"]})
    if not selected or unknown_names:
        raise ValueError("no hosts selected or unknown host names: " + ", ".join(unknown_names))
    partial = len(selected) != len(manifest["hosts"])
    rows, started = [], time.monotonic()
    for host in selected:
        advisory = advisories[host["advisory"]]
        host_dir = CORPUS / "hosts" / host["name"]
        out = output / "hosts" / host["name"]
        before = adapter.tree_hash(host_dir)
        row = {"host": host["name"], "class": host["class"], "advisory": advisory["id"],
               "module": advisory["module"], "version": advisory["version"]}
        if time.monotonic() - started > TOTAL_BUDGET_SECONDS:
            rows.append({**row, "truth": "unknown", "adapter": "unknown", "adapter_reason": "total-budget-exceeded",
                         "adapter_vex": "under_investigation", "vex_pinned": "not-run", "vex_latest": "not-run"})
            continue
        truth = ground_truth(go, env, host_dir, advisory, modcache, out / "truth")
        adapter.write_json(out / "truth" / "truth.json", truth)
        candidate = {"id": advisory["id"], "module": advisory["module"], "version": advisory["version"],
                     "purl": "pkg:golang/%s@%s" % (advisory["module"], advisory["version"])}
        result = adapter.scan(host_dir, out / "adapter", tools["pinned"], dependency=module_dir(
            modcache, advisory["module"], advisory["version"]), db=db, candidate=candidate, goflags="-mod=mod")
        vex = {name: run_openvex(tool, host_dir, env, db, advisory["id"], out / ("openvex-%s.json" % name))
               for name, tool in tools.items()}
        if adapter.tree_hash(host_dir) != before:
            truth = {"truth": "unknown", "reason": "host-source-changed"}
        rows.append({**row, "truth": truth["truth"], "truth_reason": truth["reason"],
                     "executed_symbols": sorted(k for k, v in truth.get("symbols", {}).items() if v.get("covered_percent", 0) > 0),
                     "adapter": result["status"], "adapter_reason": result["reason"],
                     "adapter_vex": result["vex"]["status"], "vex_pinned": vex["pinned"]["status"],
                     "vex_pinned_justification": vex["pinned"]["justification"], "vex_latest": vex["latest"]["status"],
                     "vex_latest_justification": vex["latest"]["justification"]})
        print("%-34s truth=%-12s adapter=%-12s vex(v1.4.0)=%-12s vex(%s)=%s" % (
            host["name"], rows[-1]["truth"], rows[-1]["adapter"], rows[-1]["vex_pinned"], versions["latest"], rows[-1]["vex_latest"]))
    report = evaluate(rows, set(manifest["blind_spot_classes"]))
    if partial:
        # A subset run is a diagnostic; it can never pass the corpus gates.
        report["passed"] = False
    summary = {"partial": partial, "schema": 1, "toolchain": toolchain, "govulncheck": versions,
               "tool_sha256": {n: adapter.digest(p.read_bytes()) for n, p in tools.items()},
               "adapter_version": adapter.ADAPTER_VERSION, "corpus_sha256": hashlib.sha256(
                   (CORPUS / "corpus.json").read_bytes()).hexdigest(),
               "environment": {k: v for k, v in env.items() if k in ("GOFLAGS", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "CGO_ENABLED")},
               "seconds": round(time.monotonic() - started, 1), "hosts": rows, **report,
               "limitations": ["self-authored hosts; results describe this corpus only",
                               "ground truth is one execution with fixed benign input",
                               "blind-spot rule was designed with this corpus (not a held-out evaluation)",
                               "adapter output never authorizes VEX not_affected"]}
    adapter.write_json(output / "summary.json", summary)
    print(json.dumps({"totals": report["totals"], "gates": report["gates"]}, indent=2))
    return 0 if report["passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="networked: fill the dedicated module cache via the Go proxy")
    prep.add_argument("--modcache", required=True, help="cache root; modules land in <root>/pkg/mod")
    execute = commands.add_parser("run", help="offline: truth, adapter and OpenVEX comparison")
    execute.add_argument("--modcache", required=True)
    execute.add_argument("--tool", required=True, help="govulncheck built from x/vuln v1.4.0")
    execute.add_argument("--latest-tool", required=True, help="govulncheck latest; version is recorded")
    execute.add_argument("--output", required=True, help="new directory; existing paths are refused")
    execute.add_argument("--host", action="append", help="limit to named hosts (repeatable)")
    args = parser.parse_args(argv)
    try:
        return prepare(args) if args.command == "prepare" else run(args)
    except (ValueError, OSError, KeyError) as error:
        print("corpus error: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
