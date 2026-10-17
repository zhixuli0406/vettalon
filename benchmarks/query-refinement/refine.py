#!/usr/bin/env python3
"""Finite, opt-in query experiment. Fixtures are data and are never executed."""
import argparse
import base64
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RULE_ID = "python-eval-exec-usage"
CONTRACT = "finite-input-to-dynamic-evaluation-v1"
RULE_SOURCE = ROOT / "crates/vettalon/src/audit/scanners/semgrep.rs"
INSTALL = ROOT / "reports/evidence-acceptance/semgrep-live-20261016/installation-v1/venv"
LAUNCHER = INSTALL / "bin/semgrep"
CORE = INSTALL / "lib/python3.12/site-packages/semgrep/bin/semgrep-core"
POLICY = ROOT / "reports/evidence-acceptance/root/semgrep-live-20261016/deny-network.sb"
ADAPTER = ROOT / "benchmarks/reachability/adapter.py"
SUPERVISOR = ADAPTER.with_name("process_supervisor.py")
PINS = {
    LAUNCHER: "696c6efcf900846d7c8b622d23820c4ecc14d274c43180c96346977f431488e4",
    CORE: "7636986e9277763a842700ad6f60b9acfc62871c084df1daf31d9bec2089f5f2",
    POLICY: "5c358b8d847211333e7ba22df82d84f796b5f30a41a2682209a949d783adbd08",
}
HEX = re.compile(r"[0-9a-f]{64}\Z")
STDOUT_CAP, STDERR_CAP = 1024 * 1024, 256 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite-json")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=invalid)
    except RecursionError as error:
        raise ValueError("json-depth") from error


def ordinary(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("not-ordinary-file")
    # Reject symlinks in source parents; interpreter is resolved separately.
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("symlink-parent")
    return path


def valid_hash(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def extract_rules(source):
    match = re.search(rb'pub const BUNDLED_RULES_YAML: &str = r#"(.*?)"#;', source, re.S)
    if match is None:
        raise ValueError("bundled-rules-not-found")
    full = match.group(1)
    blocks = list(re.finditer(rb"(?m)^  - id: ([^\r\n]+)", full))
    ids = [item.group(1).decode("ascii") for item in blocks]
    if len(ids) != 6 or len(set(ids)) != 6 or ids.count(RULE_ID) != 1:
        raise ValueError("unexpected-bundled-rule-scope")
    position = ids.index(RULE_ID)
    end = blocks[position + 1].start() if position + 1 < len(blocks) else len(full)
    block = full[blocks[position].start():end].rstrip(b"\n") + b"\n"
    required = (b"languages: [python]", b"      - pattern-either:",
                b"          - pattern: eval(...)", b"          - pattern: exec(...)")
    if not all(part in block for part in required):
        raise ValueError("baseline-changed-requires-review")
    return full, b"rules:\n" + block


def validate_observation(value):
    allowed = {"label", "split", "complete", "query_sha256", "manifest_sha256", "oracle_sha256",
               "tool_binding_sha256", "raw_sha256", "cases", "scheduled", "attempted", "reason", "result_count"}
    if (not isinstance(value, dict) or value.get("split") != "dev"
            or value.get("complete") is not True or not set(value) <= allowed):
        raise ValueError("selector-requires-complete-dev-only")
    for field in ("query_sha256", "manifest_sha256", "oracle_sha256", "tool_binding_sha256", "raw_sha256"):
        if not valid_hash(value.get(field)):
            raise ValueError("unbound-observation")
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("empty-cases")
    seen = set()
    for case in cases:
        if (not isinstance(case, dict) or not isinstance(case.get("id"), str)
                or set(case) != {"id", "source_sha256", "status", "relation", "hit", "oracle_trace_sha256", "sinks"}
                or case["id"] in seen or case.get("status") != "complete"
                or case.get("relation") not in ("input_dependent", "input_independent", "no_sink")
                or type(case.get("hit")) is not bool or not valid_hash(case.get("source_sha256"))
                or not valid_hash(case.get("oracle_trace_sha256"))):
            raise ValueError("invalid-case-observation")
        seen.add(case["id"])
    return cases


def revise_query(parent, observation, used_opcodes):
    cases = validate_observation(observation)
    if not isinstance(parent, bytes) or len(parent) > 8192:
        raise ValueError("query-bound")
    if observation["query_sha256"] != sha(parent):
        raise ValueError("parent-query-binding-mismatch")
    if not isinstance(used_opcodes, set) or not used_opcodes <= {"eval", "exec"}:
        raise ValueError("invalid-operator-history")
    eligible = []
    for case in cases:
        sinks = case.get("sinks")
        if (case["hit"] and case["relation"] == "input_independent" and isinstance(sinks, list)
                and len(sinks) == 1 and sinks[0].get("operand_literal") is True
                and sinks[0].get("opcode") in {"eval", "exec"} - used_opcodes):
            eligible.append((sinks[0]["opcode"], case["id"], case))
    if not eligible:
        return None
    opcode, _, trigger = sorted(eligible, key=lambda item: item[:2])[0]
    child = parent.rstrip(b"\n") + f'\n      - pattern-not: {opcode}("...")\n'.encode()
    if len(child) > 8192:
        raise ValueError("query-bound")
    return {"query": child, "opcode": opcode, "operator": "exclude_literal_operand",
            "parent_sha256": sha(parent), "child_sha256": sha(child),
            "trigger": {key: trigger[key] for key in ("id", "source_sha256", "oracle_trace_sha256")},
            "trigger_raw_sha256": observation["raw_sha256"],
            "diff": "".join(difflib.unified_diff(parent.decode().splitlines(True),
                                                   child.decode().splitlines(True), "parent.yml", "child.yml"))}


def accept_revision(parent, child):
    result = {"accepted": False, "reason": "incomplete-or-changed-scope"}
    try:
        before, after = validate_observation(parent), validate_observation(child)
        if parent["query_sha256"] == child["query_sha256"] or parent["raw_sha256"] == child["raw_sha256"]:
            return {"accepted": False, "reason": "unchanged-query-or-raw-binding"}
        if any(parent[key] != child[key] for key in ("manifest_sha256", "oracle_sha256", "tool_binding_sha256")):
            return result
        old, new = {c["id"]: c for c in before}, {c["id"]: c for c in after}
        if old.keys() != new.keys():
            return result
        for key, case in old.items():
            other = new[key]
            if any(case[field] != other[field] for field in ("source_sha256", "relation", "oracle_trace_sha256")):
                return result
            if case["relation"] == "input_dependent" and case["hit"] and not other["hit"]:
                return {"accepted": False, "reason": "sensitive-hit-loss"}
        mismatch = lambda rows: {key for key, c in rows.items() if c["hit"] and c["relation"] != "input_dependent"}
        old_mismatch, new_mismatch = mismatch(old), mismatch(new)
        if not new_mismatch < old_mismatch:
            return {"accepted": False, "reason": "no-strict-subset-improvement"}
        return {"accepted": True, "reason": "strict-dev-contract-improvement",
                "before_mismatches": sorted(old_mismatch), "after_mismatches": sorted(new_mismatch)}
    except (ValueError, KeyError, TypeError):
        return result


class Store:
    def __init__(self, root, cap=16 * 1024 * 1024):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or any(parent.is_symlink() for parent in self.root.parents):
            raise ValueError("symlink-output")
        self.root.mkdir(parents=True, exist_ok=False)
        self.cap, self.written = cap, 0

    def put(self, relative, raw):
        path = Path(relative)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("invalid-artifact-path")
        target = self.root / path
        if target.exists() or target.is_symlink():
            raise FileExistsError(target)
        if type(raw) is not bytes or self.written + len(raw) > self.cap:
            raise ValueError("artifact-cap")
        target.parent.mkdir(parents=True, exist_ok=True)
        if any(parent.is_symlink() for parent in target.parents):
            raise ValueError("symlink-output")
        with target.open("xb") as stream:
            stream.write(raw)
        self.written += len(raw)
        return sha(raw)

    def json(self, relative, value):
        return self.put(relative, encoded(value))


class Budget:
    def __init__(self, clock=time.monotonic, max_calls=15):
        self.clock, self.started = clock, clock()
        self.deadline, self.max_calls, self.attempts = self.started + 120.0, max_calls, []

    def admit(self, stage):
        remaining = self.deadline - self.clock()
        if len(self.attempts) >= self.max_calls or remaining <= 1.1:
            raise ValueError("budget_stop")
        item = {"attempt": len(self.attempts) + 1, "stage": stage,
                "elapsed_before": self.clock() - self.started,
                "timeout": min(15.0, remaining - 1.1)}
        self.attempts.append(item)
        return dict(item)

    def status(self):
        return {"attempted": len(self.attempts), "maximum": self.max_calls,
                "elapsed": self.clock() - self.started, "deadline_seconds": 120,
                "control": "budget-control-incomplete", "hard_spawn_deadline": False,
                "reason": "blocking-spawn-and-OS-termination-not-hard-bounded",
                "cpu": None, "peak_rss": None}


def checked_manifest(directory, descriptors=None):
    directory = Path(directory).absolute()
    if not directory.is_dir() or directory.is_symlink() or any(p.is_symlink() for p in directory.parents):
        raise ValueError("invalid-source-directory")
    actual = sorted(directory.iterdir())
    if descriptors is None:
        descriptors = [{"id": p.stem, "name": p.name, "sha256": sha(ordinary(p).read_bytes())} for p in actual]
    if not descriptors or len(descriptors) > 32:
        raise ValueError("source-count")
    manifest, seen, names, size = [], set(), set(), 0
    for item in descriptors:
        if (not isinstance(item, dict) or set(item) != {"id", "name", "sha256"}
                or not isinstance(item["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item["id"])
                or not isinstance(item["name"], str)
                or not re.fullmatch(r"(?:cases/)?[A-Za-z0-9_-]{1,64}\.py", item["name"])
                or not valid_hash(item["sha256"]) or item["id"] in seen or item["name"] in names):
            raise ValueError("invalid-source-manifest")
        path = ordinary(directory / item["name"])
        raw = path.read_bytes(); size += len(raw)
        if not raw or len(raw) > 2048 or size > 65536 or sha(raw) != item["sha256"]:
            raise ValueError("source-bound-or-hash")
        seen.add(item["id"]); names.add(item["name"])
        manifest.append({"id": item["id"], "path": str(path), "sha256": item["sha256"]})
    parents = {Path(c["path"]).parent for c in manifest}
    if len(parents) != 1:
        raise ValueError("mixed-source-directories")
    scan_directory = next(iter(parents))
    if {p.name for p in scan_directory.iterdir()} != {Path(name).name for name in names}:
        raise ValueError("unmanifested-source-entry")
    return manifest


def parse_scan(raw, manifest, oracle_rows=None, scanner_cwd=None):
    if not raw or len(raw) > STDOUT_CAP:
        raise ValueError("empty-or-large-payload")
    data = strict_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list) or data.get("errors") != []:
        raise ValueError("scanner-error-or-schema")
    paths = data.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        raise ValueError("missing-scanned-scope")
    expected = {str(Path(case["path"]).absolute()): case for case in manifest}
    if len(expected) != len(manifest):
        raise ValueError("duplicate-manifest-path")
    for path, case in expected.items():
        if sha(ordinary(path).read_bytes()) != case["sha256"]:
            raise ValueError("source-drift")
    def exact_path(value):
        if not isinstance(value, str) or ".." in Path(value).parts:
            raise ValueError("invalid-scanner-path")
        candidate = Path(value)
        path = str((Path(scanner_cwd or Path.cwd()) / candidate).absolute())
        if path not in expected:
            raise ValueError("nonmanifest-scanner-path")
        return path
    scanned = [exact_path(p) for p in paths["scanned"]]
    if len(scanned) != len(set(scanned)) or set(scanned) != set(expected):
        raise ValueError("incomplete-scanned-scope")
    if paths.get("skipped"):
        raise ValueError("skipped-scope")
    hits = set()
    oracle_by_id = {case["id"]: row for case, row in zip(manifest, oracle_rows or [])}
    for finding in data["results"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("check_id"), str):
            raise ValueError("invalid-finding")
        if finding["check_id"].split(".")[-1] != RULE_ID:
            raise ValueError("unexpected-rule-id")
        path = exact_path(finding.get("path"))
        if oracle_rows is not None:
            row = oracle_by_id[expected[path]["id"]]
            sinks = row.get("sinks", [])
            start, end = finding.get("start"), finding.get("end")
            if (len(sinks) != 1 or not isinstance(start, dict) or not isinstance(end, dict)
                    or type(start.get("offset")) is not int or type(end.get("offset")) is not int
                    or not 0 <= start["offset"] < end["offset"] <= len(ordinary(path).read_bytes())
                    or not (start["offset"] < sinks[0]["byte_end"] and end["offset"] > sinks[0]["byte_start"])):
                raise ValueError("finding-sink-range-mismatch")
        hits.add(expected[path]["id"])
    return {"hits": sorted(hits), "result_count": len(data["results"]), "scanned": scanned}


class HoldoutGate:
    def __init__(self, store, seal):
        if (not isinstance(seal, dict) or set(seal) != {"schema", "created_by", "split", "cases"}
                or type(seal["schema"]) is not int or seal["schema"] != 1
                or seal["split"] != "holdout" or not isinstance(seal["created_by"], str)
                or not seal["created_by"] or not isinstance(seal["cases"], list) or len(seal["cases"]) != 4):
            raise ValueError("invalid-holdout-seal")
        ids, names = set(), set()
        for case in seal["cases"]:
            if (not isinstance(case, dict) or set(case) != {"id", "name", "sha256"}
                    or not isinstance(case["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case["id"])
                    or not isinstance(case["name"], str) or not re.fullmatch(r"(?:cases/)?[A-Za-z0-9_-]{1,64}\.py", case["name"])
                    or not valid_hash(case["sha256"]) or case["id"] in ids or case["name"] in names):
                raise ValueError("invalid-holdout-case")
            ids.add(case["id"]); names.add(case["name"])
        self.store, self.seal, self.opened = store, seal, False
        self.store.json("holdout-seal.json", seal)

    def open(self, selection):
        if (self.opened or not isinstance(selection, dict) or selection.get("split") != "dev"
                or selection.get("frozen") is not True or not valid_hash(selection.get("query_sha256"))):
            raise ValueError("holdout-event-not-admissible")
        # Exclusive durable selection precedes any holdout source read.
        self.store.json("selection.json", selection)
        self.store.json("holdout-event.json", {"schema": 1, "single_use": True,
                                              "selection_sha256": sha(encoded(selection)),
                                              "seal_sha256": sha(encoded(self.seal))})
        self.opened = True


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_lock(lock):
    if (not isinstance(lock, dict) or set(lock) != {"schema", "files"}
            or type(lock["schema"]) is not int or lock["schema"] != 1
            or not isinstance(lock["files"], dict) or not lock["files"]):
        raise ValueError("invalid-approved-lock")
    required = {str(path.absolute()) for path in (Path(__file__), HERE / "oracle.py", ADAPTER,
                                                 SUPERVISOR, RULE_SOURCE, LAUNCHER, CORE, POLICY)}
    required |= {str(path.absolute()) for path in (HERE / "fixtures/dev").glob("*.py")}
    # The launcher shebang is the only permitted interpreter origin.
    shebang = ordinary(LAUNCHER).read_bytes().splitlines()[0].decode("ascii")
    if not shebang.startswith("#!/") or " " in shebang:
        raise ValueError("unsupported-launcher-shebang")
    interpreter = Path(shebang[2:]).resolve(strict=True)
    required.add(str(interpreter))
    required.add(str(Path(sys.executable).resolve(strict=True)))
    if not required <= set(lock["files"]):
        raise ValueError("missing-approved-bindings")
    for name, digest in lock["files"].items():
        if not isinstance(name, str) or not Path(name).is_absolute() or not valid_hash(digest):
            raise ValueError("invalid-lock-entry")
        if sha(ordinary(name).read_bytes()) != digest:
            raise ValueError("approved-source-drift")
    for path, digest in PINS.items():
        if lock["files"].get(str(path)) != digest:
            raise ValueError("fixed-tool-pin-mismatch")
    return {"sha256": sha(encoded(lock)), "interpreter": str(interpreter),
            "controller_interpreter": str(Path(sys.executable).resolve(strict=True)),
            "files": dict(lock["files"]), "dependency_attestation": "explicit-files-only"}


class Experiment:
    def __init__(self, run_dir, approved_lock, seal, holdout_dir, *, store=None, budget=None):
        self.budget = budget if budget is not None else Budget()
        self.store = store if store is not None else Store(run_dir)
        self.lock = approved_lock
        self.binding = verify_lock(approved_lock)
        self.adapter = load_module("finite_query_process_adapter", ADAPTER)
        self.oracle = load_module("finite_query_oracle", HERE / "oracle.py")
        self.gate = HoldoutGate(self.store, seal)
        self.holdout_dir = Path(holdout_dir).absolute()
        self.dev = checked_manifest(HERE / "fixtures/dev")
        if len(self.dev) != 6:
            raise ValueError("dev-scope-must-be-six")
        if any(Path(c["path"]).parent == self.holdout_dir for c in self.dev):
            raise ValueError("holdout-overlaps-dev")
        self.store.json("approved-lock.json", approved_lock)
        self.store.json("dev-manifest.json", self.dev)
        for case in self.dev:
            self.store.put(f"sources/dev/{case['id']}.py", ordinary(case["path"]).read_bytes())
        self.store.json("budget-contract.json", {"scanner_attempt_limit": 15, "deadline_seconds": 120,
                                                 "per_call_seconds": 15, "cleanup_reserve_seconds": 1.1,
                                                 "outer_retry": 0, "models": 0, "downloads": 0,
                                                 "target_execution": 0, "control": "budget-control-incomplete"})
        self.observations = []
        self.stop_reason = None

    def scan(self, label, query, manifest, split):
        if self.stop_reason is not None:
            return self.not_attempted(label, query, manifest, split, self.stop_reason)
        prefix = f"scans/{label}"
        query_path = self.store.root / f"{prefix}/query.yml"
        self.store.put(f"{prefix}/query.yml", query)
        oracle_rows = []
        for case in manifest:
            result = self.oracle.observe(ordinary(case["path"]).read_bytes())
            oracle_rows.append(result)
        self.store.json(f"{prefix}/oracle.json", oracle_rows)
        obs = {"label": label, "split": split, "query_sha256": sha(query),
               "manifest_sha256": sha(encoded(manifest)), "oracle_sha256": self.lock["files"][str(HERE / "oracle.py")],
               "tool_binding_sha256": self.binding["sha256"], "raw_sha256": sha(b""),
               "scheduled": len(manifest), "attempted": 0, "complete": False, "reason": None,
               "cases": [{"id": case["id"], "source_sha256": case["sha256"], "status": "not_attempted",
                          "relation": row.get("relation"), "hit": None,
                          "oracle_trace_sha256": sha(encoded(row)), "sinks": row.get("sinks", [])}
                         for case, row in zip(manifest, oracle_rows)]}
        try:
            verify_lock(self.lock)
            if ordinary(query_path).read_bytes() != query:
                raise ValueError("query-drift")
            if any(row.get("status") != "complete" or row.get("complete") is not True
                   or row.get("source_sha256") != case["sha256"] or row.get("contract") != CONTRACT
                   for case, row in zip(manifest, oracle_rows)):
                raise ValueError("oracle_unsupported")
            admission = self.budget.admit(label)
            # The debit is persisted before the invocation; a failed write prevents launch.
            self.store.json(f"attempts/{admission['attempt']:02d}.json", admission)
            obs["attempted"] = len(manifest)
            home = self.store.root / f"{prefix}/home"; home.mkdir()
            env = {"PATH": os.defpath, "HOME": str(home), "LANG": "C.UTF-8",
                   "PYTHONDONTWRITEBYTECODE": "1", "SEMGREP_SEND_METRICS": "off",
                   "SEMGREP_ENABLE_VERSION_CHECK": "0"}
            command = ["/usr/bin/sandbox-exec", "-f", str(POLICY), str(LAUNCHER), "scan", "--json",
                       "--metrics=off", "--disable-version-check", "--config", str(query_path),
                       str(Path(manifest[0]["path"]).parent)]
            if any(Path(c["path"]).parent != Path(manifest[0]["path"]).parent for c in manifest):
                raise ValueError("mixed-source-directories")
            self.store.json(f"{prefix}/invocation.json", {"argv": command, "env": env,
                                                         "cwd": str(self.store.root), "admission": admission})
            run = self.adapter.invoke(command, self.store.root, env, admission["timeout"],
                                      stdout_cap=STDOUT_CAP, stderr_cap=STDERR_CAP)
            raw = {}
            for stream in ("stdout", "stderr"):
                capture = run.get("captures", {}).get(stream, {})
                if "raw_base64" in capture:
                    raw[stream] = base64.b64decode(capture["raw_base64"], validate=True)
                else:
                    raw[stream] = run.get(stream, "").encode("utf-8", "strict")
                self.store.put(f"{prefix}/{stream}.raw", raw[stream])
            receipt = {key: value for key, value in run.items() if key not in ("stdout", "stderr")}
            self.store.json(f"{prefix}/receipt.json", receipt)
            obs["raw_sha256"] = sha(raw["stdout"])
            verify_lock(self.lock)
            if ordinary(query_path).read_bytes() != query:
                raise ValueError("query-drift")
            if not self.adapter.successful_run(run):
                raise ValueError("timeout" if run.get("timed_out") else "scanner_error")
            if len(raw["stdout"]) > STDOUT_CAP or len(raw["stderr"]) > STDERR_CAP:
                raise ValueError("capture-cap")
            result = parse_scan(raw["stdout"], manifest, oracle_rows, scanner_cwd=self.store.root)
            for case in obs["cases"]:
                case.update(status="complete", hit=case["id"] in result["hits"])
            obs.update(complete=True, result_count=result["result_count"], reason="complete-finite-contract")
            if self.budget.clock() >= self.budget.deadline:
                raise ValueError("budget_stop")
        except Exception as error:
            reason = str(error)
            allowed = {"budget_stop", "oracle_unsupported", "timeout", "scanner_error", "capture-cap",
                       "approved-source-drift", "source-drift", "incomplete-scanned-scope"}
            obs["reason"] = reason if reason in allowed else "harness_failure"
            obs["complete"] = False
            for case in obs["cases"]:
                case.update(status="unknown", hit=None)
            self.stop_reason = obs["reason"]
        self.store.json(f"{prefix}/observation.json", obs)
        self.observations.append(obs)
        return obs

    def not_attempted(self, label, query, manifest, split, reason):
        value = {"label": label, "split": split, "query_sha256": sha(query), "complete": False,
                 "scheduled": len(manifest), "attempted": 0, "reason": reason,
                 "cases": [{"id": c["id"], "source_sha256": c["sha256"],
                            "status": "not_attempted", "hit": None, "relation": None} for c in manifest]}
        self.store.json(f"scans/{label}/observation.json", value)
        self.observations.append(value)
        return value

    def run(self):
        full, baseline = extract_rules(ordinary(RULE_SOURCE).read_bytes())
        self.store.put("queries/bundled-six.yml", full)
        self.store.put("queries/baseline.yml", baseline)
        original = self.scan("dev-baseline", baseline, self.dev, "dev")
        selected, selected_obs, used, revisions = baseline, original, set(), []
        for index in range(2):
            if not selected_obs["complete"]:
                break
            candidate = revise_query(selected, selected_obs, used)
            if candidate is None:
                break
            used.add(candidate["opcode"])
            self.store.put(f"queries/revision-{index + 1}.yml", candidate["query"])
            self.store.put(f"queries/revision-{index + 1}.diff", candidate["diff"].encode())
            metadata = {key: value for key, value in candidate.items() if key not in ("query", "diff")}
            self.store.json(f"queries/revision-{index + 1}-lineage.json", metadata)
            observed = self.scan(f"dev-revision-{index + 1}", candidate["query"], self.dev, "dev")
            decision = accept_revision(selected_obs, observed)
            self.store.json(f"queries/revision-{index + 1}-decision.json", decision)
            revisions.append({**metadata, **decision})
            if not decision["accepted"]:
                break
            selected, selected_obs = candidate["query"], observed
        selection = {"split": "dev", "frozen": True, "query_sha256": sha(selected),
                     "baseline_sha256": sha(baseline), "dev_observation_sha256": sha(encoded(selected_obs)),
                     "selection_method": "strict-dev-contract-subset", "candidate_accepted": selected != baseline}
        self.store.put("queries/selected.yml", selected)
        holdout_result = {"status": "not_attempted", "reason": "no-accepted-complete-candidate"}
        if selected != baseline and self.stop_reason is None:
            self.gate.open(selection)
            holdout = checked_manifest(self.holdout_dir, self.gate.seal["cases"])
            if {c["sha256"] for c in holdout} & {c["sha256"] for c in self.dev}:
                raise ValueError("holdout-dev-byte-overlap")
            self.store.json("holdout-manifest-after-selection.json", holdout)
            for case in holdout:
                self.store.put(f"sources/holdout/{case['id']}.py", ordinary(case["path"]).read_bytes())
            before = self.scan("holdout-baseline", baseline, holdout, "holdout")
            after = self.scan("holdout-selected", selected, holdout, "holdout")
            # Holdout requires non-regression, not strict improvement; equal is acceptable.
            nonregression = self.holdout_nonregression(before, after)
            mismatch_count = lambda observation: sum(c["hit"] is True and c["relation"] != "input_dependent"
                                                      for c in observation["cases"])
            holdout_result = {"status": "complete" if before["complete"] and after["complete"] else "incomplete",
                              "nonregression": nonregression,
                              "strict_gain": nonregression and mismatch_count(after) < mismatch_count(before),
                              "single_event": True}
        else:
            self.store.json("selection.json", selection)
            self.store.json("holdout-skipped.json", holdout_result)
        replay = []
        if selected != baseline and self.stop_reason is None:
            for name, query, expected in (("baseline", baseline, original), ("selected", selected, selected_obs)):
                actual = self.scan(f"replay-{name}", query, self.dev, "dev")
                replay.append({"arm": name, "same": self.same_replay(expected, actual)})
        minimized = self.minimize(original, baseline) if self.stop_reason is None else {"status": "not_attempted", "reason": self.stop_reason}
        verify_lock(self.lock)
        batch_complete = self.stop_reason is None and original["complete"]
        query_evaluated = bool(revisions) and all(observation.get("complete") is True
            for observation in self.observations if observation["label"].startswith("dev-revision-"))
        validation_complete = (selected != baseline and holdout_result["status"] == "complete"
            and len(replay) == 2 and all(item["same"] for item in replay))
        summary = {"schema": 1, "status": "PARTIAL", "contract": CONTRACT,
                   "batch_completed_without_control_error": batch_complete,
                   "query_revision_evaluated": query_evaluated,
                   "accepted_query_validation_complete": validation_complete,
                   "experiment_complete": batch_complete and query_evaluated and (selected == baseline or validation_complete),
                   "stop_reason": self.stop_reason, "revisions": revisions, "selection": selection,
                   "holdout": holdout_result, "replay": replay, "minimize": minimized,
                   "budget": self.budget.status(), "observations": self.observations,
                   "storage": {"managed_artifact_cap_bytes": self.store.cap,
                               "managed_written_bytes_before_summary": self.store.written,
                               "scanner_home_disk_cap": None, "external_writes_cap": None,
                               "whole_run_os_disk_cap": False},
                   "stage_denominators": stage_denominators(self.observations),
                   "adoption_eligible": False, "models": 0, "downloads": 0, "target_execution": 0,
                   "human_decision": None, "human_confirmed": 0, "unique_root_causes": None,
                   "cost_usd": None, "per_human_confirmed_cost": None,
                   "limitations": ["finite-synthetic-contract", "not-security-ground-truth",
                                   "same-family-holdout", "no-complete-R27-acceptance",
                                   "budget-control-incomplete", "no-product-rule-change"]}
        self.store.json("summary.json", summary)
        return summary

    @staticmethod
    def same_replay(before, after):
        fields = ("query_sha256", "manifest_sha256", "oracle_sha256", "tool_binding_sha256")
        return (before.get("complete") is True and after.get("complete") is True
                and all(before.get(k) == after.get(k) for k in fields)
                and before.get("cases") == after.get("cases"))

    @staticmethod
    def holdout_nonregression(before, after):
        if before.get("complete") is not True or after.get("complete") is not True:
            return False
        if any(before.get(key) != after.get(key) for key in ("manifest_sha256", "oracle_sha256", "tool_binding_sha256")):
            return False
        old, new = before["cases"], after["cases"]
        if len(old) != len(new):
            return False
        for first, second in zip(old, new):
            if any(first[k] != second[k] for k in ("id", "source_sha256", "relation", "oracle_trace_sha256")):
                return False
            if first["relation"] == "input_dependent" and first["hit"] and not second["hit"]:
                return False
            if first["relation"] != "input_dependent" and not first["hit"] and second["hit"]:
                return False
        return True

    def minimize(self, original, query):
        if not original.get("complete"):
            return {"status": "not_applicable", "reason": "no-complete-baseline"}
        eligible = [c for c in original["cases"] if c["hit"] and c["relation"] == "input_independent"]
        original_paths = {c["id"]: c for c in self.dev}
        chosen = next((c for c in eligible if self.oracle.deletion_candidates(
            ordinary(original_paths[c["id"]]["path"]).read_bytes())), None)
        if chosen is None:
            return {"status": "not_applicable", "reason": "no-independent-mismatch-with-deletable-statement"}
        source = ordinary(original_paths[chosen["id"]]["path"]).read_bytes()
        origin, attempts, accepted = None, 0, []
        while attempts < 8 and self.stop_reason is None:
            candidates = self.oracle.deletion_candidates(source)
            if not candidates:
                break
            changed = False
            for candidate in candidates:
                if attempts >= 8:
                    break
                child = candidate["source"]
                mapping = self.oracle.map_sink(source, child, origin)
                if mapping.get("status") != "mapped":
                    return {"status": "minimize_mapping_unknown", "attempts": attempts, "steps": accepted}
                origin = mapping["origin"]
                if candidate["parent_source_sha256"] != sha(source) or candidate["source_sha256"] != sha(child):
                    return {"status": "minimize_mapping_unknown", "attempts": attempts, "steps": accepted}
                attempts += 1
                prefix = f"minimize/step-{attempts}"
                self.store.put(f"{prefix}/source/case.py", child)
                self.store.put(f"{prefix}/parent.py", source)
                self.store.put(f"{prefix}/source.diff", "".join(difflib.unified_diff(
                    source.decode().splitlines(True), child.decode().splitlines(True), "parent.py", "child.py")).encode())
                self.store.json(f"{prefix}/mapping.json", mapping)
                manifest = checked_manifest(self.store.root / f"{prefix}/source")
                observation = self.scan(f"minimize-{attempts}", query, manifest, "minimize")
                kept = (observation["complete"] and observation["cases"][0]["relation"] == chosen["relation"]
                        and observation["cases"][0]["hit"] is True)
                decision = {"attempt": attempts, "accepted": kept, "parent_sha256": sha(source),
                            "child_sha256": sha(child), "sink_lineage_id": mapping["sink_lineage_id"]}
                self.store.json(f"{prefix}/decision.json", decision)
                accepted.append(decision)
                if kept:
                    source, changed = child, True
                    break
            if not changed:
                break
        return {"status": "budget-limited" if attempts >= 8 or self.stop_reason else "bounded-local-result",
                "attempts": attempts, "steps": accepted, "final_source_sha256": sha(source),
                "global_minimum": False, "unique_root_cause": None}


def stage_denominators(observations, reason="conditional-stage-not-needed"):
    stages = [("dev-baseline", 6), ("dev-revision-1", 6), ("dev-revision-2", 6),
              ("holdout-baseline", 4), ("holdout-selected", 4),
              ("replay-baseline", 6), ("replay-selected", 6)] + [(f"minimize-{i}", 1) for i in range(1, 9)]
    by_name = {item["label"]: item for item in observations}
    return [{"stage": name, "maximum_cases": count,
             "scheduled": by_name[name]["scheduled"] if name in by_name else 0,
             "attempted": by_name[name]["attempted"] if name in by_name else 0,
             "complete": sum(c["status"] == "complete" for c in by_name[name]["cases"]) if name in by_name else 0,
             "unknown": sum(c["status"] == "unknown" for c in by_name[name]["cases"]) if name in by_name else 0,
             "not_attempted": count if name not in by_name else sum(c["status"] == "not_attempted" for c in by_name[name]["cases"]),
             "reason": by_name[name]["reason"] if name in by_name else reason}
            for name, count in stages]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--approved-lock", type=Path, required=True)
    parser.add_argument("--seal", type=Path, required=True)
    parser.add_argument("--holdout-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    budget, store, experiment = Budget(), None, None
    # No default paths to another experiment or hidden target; all gates explicit.
    try:
        store = Store(args.run_dir)
        lock = strict_json(ordinary(args.approved_lock).read_bytes())
        seal = strict_json(ordinary(args.seal).read_bytes())
        experiment = Experiment(args.run_dir, lock, seal, args.holdout_dir, store=store, budget=budget)
        summary = experiment.run()
        print(json.dumps({"run_dir": str(experiment.store.root), "status": summary["status"],
                          "stop_reason": summary["stop_reason"], "attempted": summary["budget"]["attempted"],
                          "control": summary["budget"]["control"]}, sort_keys=True))
        return 0 if summary["experiment_complete"] else 2
    except Exception as error:
        if store is not None:
            observations = experiment.observations if experiment is not None else []
            failed = {"schema": 1, "status": "incomplete", "reason": type(error).__name__,
                      "observations": observations, "budget": budget.status(),
                      "stage_denominators": stage_denominators(observations, "preflight-or-harness-failure"),
                      "human_decision": None, "adoption_eligible": False,
                      "models": 0, "downloads": 0, "target_execution": 0}
            try:
                store.json("failed-run.json", failed)
            except (ValueError, OSError):
                pass  # The caller must retain stderr; never overwrite artifacts to fit a receipt.
        print(json.dumps({"status": "incomplete", "reason": type(error).__name__,
                          "note": "preserve-existing-run; no-retry"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
