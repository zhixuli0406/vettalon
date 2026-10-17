#!/usr/bin/env python3
"""Explicit-runtime public query experiment; historical experiments stay frozen."""
import argparse
import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("public_v2_frozen_refine", HERE / "refine.py")
frozen = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(frozen)
CONTROLLER_CONTRACT = "query-refinement-public-v2"


runtime = frozen.load_module("public_v2_runtime_profile", HERE / "runtime_profile.py")


def failure_reason(error):
    """Preserve bounded failure classes without printing source or credentials."""
    reason = str(error)
    known = {
        "budget_stop", "oracle_unsupported", "timeout", "scanner_error", "capture-cap",
        "source-drift", "incomplete-scanned-scope", "query-drift", "artifact-cap",
        "scanner-version-mismatch", "runtime-binding-drift", "approved-source-drift",
    }
    if reason in known:
        return reason
    if isinstance(error, FileNotFoundError):
        return "preflight-file-missing"
    if isinstance(error, ValueError):
        # Profile parser emits short machine-readable categories, never file contents.
        if reason and len(reason) <= 100 and all(c.isalnum() or c in "-_" for c in reason):
            return reason
        return "invalid-preflight-or-harness-data"
    return "harness_failure"


class PublicExperiment(frozen.Experiment):
    def __init__(self, run_dir, binding, seal, holdout_dir, *, store=None, budget=None):
        self.budget = budget if budget is not None else frozen.Budget()
        self.store = store if store is not None else frozen.Store(run_dir)
        binding.verify()
        approved_seal = binding.read_seal()
        if frozen.encoded(seal) != frozen.encoded(approved_seal):
            raise ValueError("seal-binding-mismatch")
        self.binding = binding
        self.adapter = frozen.load_module("public_v2_process_adapter", frozen.ADAPTER)
        self.oracle = frozen.load_module("public_v2_oracle", binding.oracle)
        self.gate = frozen.HoldoutGate(self.store, approved_seal)
        self.holdout_dir = Path(holdout_dir).absolute()
        self.dev = frozen.checked_manifest(HERE / "fixtures/dev")
        if len(self.dev) != 6:
            raise ValueError("dev-scope-must-be-six")
        if any(Path(c["path"]).parent == self.holdout_dir for c in self.dev):
            raise ValueError("holdout-overlaps-dev")
        self.store.put("runtime-profile.json", binding.profile_bytes)
        self.store.put("approved-lock.json", binding.lock_bytes)
        self.store.json("runtime-binding.json", {
            "controller_contract": CONTROLLER_CONTRACT,
            "sha256": binding.binding_sha256,
            "dependency_attestation": "explicit-files-only",
            "files": dict(binding.files),
        })
        self.store.json("dev-manifest.json", self.dev)
        for case in self.dev:
            self.store.put(f"sources/dev/{case['id']}.py", frozen.ordinary(case["path"]).read_bytes())
        self.store.json("budget-contract.json", {
            "scanner_attempt_limit": 15, "deadline_seconds": 120,
            "per_call_seconds": 15, "cleanup_reserve_seconds": 1.1,
            "outer_retry": 0, "models": 0, "downloads": 0, "target_execution": 0,
            "control": "budget-control-incomplete",
        })
        self.observations, self.stop_reason = [], None

    def scan(self, label, query, manifest, split):
        if self.stop_reason is not None:
            return self.not_attempted(label, query, manifest, split, self.stop_reason)
        prefix = f"scans/{label}"
        query_path = self.store.root / f"{prefix}/query.yml"
        obs = {"label": label, "split": split, "query_sha256": frozen.sha(query),
               "manifest_sha256": frozen.sha(frozen.encoded(manifest)), "oracle_sha256": self.binding.oracle_sha256,
               "tool_binding_sha256": self.binding.binding_sha256, "raw_sha256": frozen.sha(b""),
               "scheduled": len(manifest), "attempted": 0, "complete": False, "reason": None,
               "cases": [{"id": case["id"], "source_sha256": case["sha256"], "status": "not_attempted",
                          "relation": None, "hit": None} for case in manifest]}
        try:
            self.binding.verify()
            self.store.put(f"{prefix}/query.yml", query)
            oracle_rows = [self.oracle.observe(frozen.ordinary(case["path"]).read_bytes())
                           for case in manifest]
            self.store.json(f"{prefix}/oracle.json", oracle_rows)
            for case, row in zip(obs["cases"], oracle_rows):
                case.update(relation=row.get("relation"),
                            oracle_trace_sha256=frozen.sha(frozen.encoded(row)), sinks=row.get("sinks", []))
            if frozen.ordinary(query_path).read_bytes() != query:
                raise ValueError("query-drift")
            if any(row.get("status") != "complete" or row.get("complete") is not True
                   or row.get("source_sha256") != case["sha256"] or row.get("contract") != frozen.CONTRACT
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
            command = [str(self.binding.sandbox), "-f", str(self.binding.policy), str(self.binding.launcher), "scan", "--json",
                       "--metrics=off", "--disable-version-check", "--config", str(query_path),
                       str(Path(manifest[0]["path"]).parent)]
            if any(Path(c["path"]).parent != Path(manifest[0]["path"]).parent for c in manifest):
                raise ValueError("mixed-source-directories")
            self.store.json(f"{prefix}/invocation.json", {"argv": command, "env": env,
                                                         "cwd": str(self.store.root), "admission": admission})
            run = self.adapter.invoke(command, self.store.root, env, admission["timeout"],
                                      stdout_cap=frozen.STDOUT_CAP, stderr_cap=frozen.STDERR_CAP)
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
            obs["raw_sha256"] = frozen.sha(raw["stdout"])
            self.binding.verify()
            if frozen.ordinary(query_path).read_bytes() != query:
                raise ValueError("query-drift")
            if not self.adapter.successful_run(run):
                raise ValueError("timeout" if run.get("timed_out") else "scanner_error")
            if len(raw["stdout"]) > frozen.STDOUT_CAP or len(raw["stderr"]) > frozen.STDERR_CAP:
                raise ValueError("capture-cap")
            if frozen.strict_json(raw["stdout"]).get("version") != "1.181.0":
                raise ValueError("scanner-version-mismatch")
            result = frozen.parse_scan(raw["stdout"], manifest, oracle_rows, scanner_cwd=self.store.root)
            for case in obs["cases"]:
                case.update(status="complete", hit=case["id"] in result["hits"])
            obs.update(complete=True, result_count=result["result_count"], reason="complete-finite-contract")
            if self.budget.clock() >= self.budget.deadline:
                raise ValueError("budget_stop")
        except Exception as error:
            obs["reason"] = failure_reason(error)
            obs["complete"] = False
            for case in obs["cases"]:
                case.update(status="unknown", hit=None)
            self.stop_reason = obs["reason"]
        self.observations.append(obs)
        try:
            self.store.json(f"{prefix}/observation.json", obs)
        except (ValueError, OSError) as error:
            # A missing receipt can never leave the controller open for another call.
            self.stop_reason = failure_reason(error)
            obs.update(complete=False, reason=self.stop_reason)
            for case in obs["cases"]:
                case.update(status="unknown", hit=None)
            raise
        return obs

    def run(self):
        full, baseline = frozen.extract_rules(frozen.ordinary(self.binding.rule_source).read_bytes())
        self.store.put("queries/bundled-six.yml", full)
        self.store.put("queries/baseline.yml", baseline)
        original = self.scan("dev-baseline", baseline, self.dev, "dev")
        selected, selected_obs, used, revisions = baseline, original, set(), []
        for index in range(2):
            if not selected_obs["complete"]:
                break
            candidate = frozen.revise_query(selected, selected_obs, used)
            if candidate is None:
                break
            used.add(candidate["opcode"])
            self.store.put(f"queries/revision-{index + 1}.yml", candidate["query"])
            self.store.put(f"queries/revision-{index + 1}.diff", candidate["diff"].encode())
            metadata = {key: value for key, value in candidate.items() if key not in ("query", "diff")}
            self.store.json(f"queries/revision-{index + 1}-lineage.json", metadata)
            observed = self.scan(f"dev-revision-{index + 1}", candidate["query"], self.dev, "dev")
            decision = frozen.accept_revision(selected_obs, observed)
            self.store.json(f"queries/revision-{index + 1}-decision.json", decision)
            revisions.append({**metadata, **decision})
            if not decision["accepted"]:
                break
            selected, selected_obs = candidate["query"], observed
        selection = {"split": "dev", "frozen": True, "query_sha256": frozen.sha(selected),
                     "baseline_sha256": frozen.sha(baseline), "dev_observation_sha256": frozen.sha(frozen.encoded(selected_obs)),
                     "selection_method": "strict-dev-contract-subset", "candidate_accepted": selected != baseline}
        self.store.put("queries/selected.yml", selected)
        holdout_result = {"status": "not_attempted", "reason": "no-accepted-complete-candidate"}
        if selected != baseline and self.stop_reason is None:
            self.gate.open(selection)
            holdout = frozen.checked_manifest(self.holdout_dir, self.gate.seal["cases"])
            if {c["sha256"] for c in holdout} & {c["sha256"] for c in self.dev}:
                raise ValueError("holdout-dev-byte-overlap")
            self.store.json("holdout-manifest-after-selection.json", holdout)
            for case in holdout:
                self.store.put(f"sources/holdout/{case['id']}.py", frozen.ordinary(case["path"]).read_bytes())
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
        self.binding.verify()
        batch_complete = self.stop_reason is None and original["complete"]
        query_evaluated = bool(revisions) and all(observation.get("complete") is True
            for observation in self.observations if observation["label"].startswith("dev-revision-"))
        validation_complete = (selected != baseline and holdout_result["status"] == "complete"
            and holdout_result.get("nonregression") is True
            and len(replay) == 2 and all(item["same"] for item in replay))
        summary = {"schema": 1, "status": "PARTIAL", "contract": frozen.CONTRACT,
                   "controller_contract": CONTROLLER_CONTRACT,
                   "runtime_binding_sha256": self.binding.binding_sha256,
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
                   "stage_denominators": frozen.stage_denominators(self.observations),
                   "adoption_eligible": False, "models": 0, "downloads": 0, "target_execution": 0,
                   "human_decision": None, "human_confirmed": 0, "unique_root_causes": None,
                   "cost_usd": None, "per_human_confirmed_cost": None,
                   "limitations": ["finite-synthetic-contract", "not-security-ground-truth",
                                   "same-family-holdout", "no-complete-R27-acceptance",
                                   "budget-control-incomplete", "no-product-rule-change"]}
        self.store.json("summary.json", summary)
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-dir", "profile", "approved-lock", "seal", "holdout-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--approved-lock-sha256", required=True)
    args = parser.parse_args(argv)
    budget, store, experiment, phase = frozen.Budget(), None, None, "output"
    try:
        if not args.run_dir.is_absolute():
            raise ValueError("run-dir-must-be-absolute")
        store = frozen.Store(args.run_dir)
        for name in ("profile", "approved_lock", "seal", "holdout_dir"):
            if not getattr(args, name).is_absolute():
                raise ValueError("input-path-must-be-absolute")
        phase = "profile"
        binding = runtime.load_binding(args.profile, args.profile_sha256,
                                       args.approved_lock, args.approved_lock_sha256,
                                       seal_path=args.seal)
        phase = "seal"
        seal = binding.read_seal()
        phase = "experiment"
        experiment = PublicExperiment(args.run_dir, binding, seal, args.holdout_dir,
                                      store=store, budget=budget)
        summary = experiment.run()
        print(json.dumps({"run_dir": str(store.root), "status": summary["status"],
                          "controller_contract": CONTROLLER_CONTRACT,
                          "stop_reason": summary["stop_reason"],
                          "attempted": summary["budget"]["attempted"],
                          "control": summary["budget"]["control"]}, sort_keys=True))
        return 0 if summary["experiment_complete"] else 2
    except Exception as error:
        reason = failure_reason(error)
        if phase in ("profile", "seal"):
            reason = phase + "-" + reason
        if store is not None:
            observations = experiment.observations if experiment is not None else []
            failure = {"schema": 2, "status": "incomplete", "reason": reason,
                       "controller_contract": CONTROLLER_CONTRACT,
                       "observations": observations, "budget": budget.status(),
                       "stage_denominators": frozen.stage_denominators(observations, reason),
                       "human_decision": None, "adoption_eligible": False,
                       "models": 0, "downloads": 0, "target_execution": 0}
            try:
                store.json("failed-run.json", failure)
            except (ValueError, OSError):
                # Failures to persist bounded evidence remain explicit on stderr.
                print(json.dumps({"status": "incomplete", "reason": "failure-receipt-unwritten"}),
                      file=sys.stderr)
        print(json.dumps({"status": "incomplete", "reason": reason,
                          "note": "preserve-existing-run; no-retry"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
