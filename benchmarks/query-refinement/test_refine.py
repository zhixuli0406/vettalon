"""Controller tests use self-authored observations; no scanner is invoked."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("query_refine", Path(__file__).with_name("refine.py"))
refine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refine)


def observation(relation="input_independent", hit=True, opcode="eval", literal=True):
    return {"split": "dev", "complete": True, "query_sha256": "a" * 64,
            "manifest_sha256": "b" * 64, "oracle_sha256": "c" * 64,
            "tool_binding_sha256": "d" * 64, "raw_sha256": "e" * 64,
            "cases": [{"id": "c01", "source_sha256": "f" * 64,
                       "status": "complete", "relation": relation, "hit": hit,
                       "oracle_trace_sha256": "1" * 64,
                       "sinks": [{"opcode": opcode, "operand_literal": literal}]}]}


class RefinementTests(unittest.TestCase):
    def setUp(self):
        self.source = Path(__file__).parents[2] / "crates/vettalon/src/audit/scanners/semgrep.rs"
        self.full, self.base = refine.extract_rules(self.source.read_bytes())

    def test_baseline_is_exact_existing_block_and_retains_six_rules(self):
        self.assertEqual(self.full.count(b"  - id:"), 6)
        self.assertIn(self.base[7:].rstrip(), self.full)
        self.assertEqual(self.base.count(b"  - id:"), 1)
        self.assertIn(b"- pattern: eval(...)", self.base)

    def test_no_mismatch_no_revision(self):
        for obs in (observation(hit=False), observation(relation="input_dependent"),
                    observation(literal=False), observation(relation="no_sink")):
            obs["query_sha256"] = refine.sha(self.base)
            self.assertIsNone(refine.revise_query(self.base, obs, set()))

    def test_true_feedback_changes_actual_yaml_with_bound_lineage(self):
        obs = observation(); obs["query_sha256"] = refine.sha(self.base)
        item = refine.revise_query(self.base, obs, set())
        self.assertNotEqual(item["query"], self.base)
        self.assertIn(b'pattern-not: eval("...")', item["query"])
        self.assertEqual(item["parent_sha256"], refine.sha(self.base))
        self.assertIn('+      - pattern-not:', item["diff"])
        self.assertEqual(item["trigger"]["id"], "c01")

    def test_holdout_and_predeclared_acceptance_are_rejected(self):
        for update in ({"split": "holdout"}, {"accepted": True}, {"complete": False},
                       {"holdout_path": "/sealed"}, {"holdout_sha256": "a" * 64}, {"unknown": 1}):
            obs = observation(); obs["query_sha256"] = refine.sha(self.base); obs.update(update)
            with self.assertRaisesRegex(ValueError, "^selector-requires-complete-dev-only$"):
                refine.revise_query(self.base, obs, set())
        obs = observation(); obs["query_sha256"] = refine.sha(self.base)
        obs["cases"][0]["holdout_path"] = "/sealed"
        with self.assertRaisesRegex(ValueError, "^invalid-case-observation$"):
            refine.revise_query(self.base, obs, set())

    def test_accept_requires_strict_gain_no_sensitive_loss_and_same_scope(self):
        parent = observation(); child = observation(hit=False)
        child["query_sha256"] = "2" * 64
        child["raw_sha256"] = "3" * 64
        self.assertTrue(refine.accept_revision(parent, child)["accepted"])
        self.assertFalse(refine.accept_revision(parent, parent)["accepted"])
        for key in ("manifest_sha256", "oracle_sha256", "tool_binding_sha256"):
            bad = json.loads(json.dumps(child)); bad[key] = "3" * 64
            self.assertFalse(refine.accept_revision(parent, bad)["accepted"])
        child["complete"] = False
        self.assertFalse(refine.accept_revision(parent, child)["accepted"])

    def test_sensitive_regression_and_new_mismatch_reject(self):
        parent = observation(relation="input_dependent")
        child = observation(relation="input_dependent", hit=False)
        self.assertFalse(refine.accept_revision(parent, child)["accepted"])
        self.assertFalse(refine.accept_revision(observation(hit=False), observation())["accepted"])

    def test_query_hash_and_second_opcode_are_bound(self):
        with self.assertRaises(ValueError): refine.revise_query(self.base, observation(), set())
        obs = observation(); obs["query_sha256"] = refine.sha(self.base)
        self.assertIsNone(refine.revise_query(self.base, obs, {"eval"}))
        obs["cases"].append(dict(obs["cases"][0], id="c02", sinks=[{"opcode": "exec", "operand_literal": True}]))
        first = refine.revise_query(self.base, obs, set())
        self.assertEqual(first["opcode"], "eval")
        obs["query_sha256"] = refine.sha(first["query"])
        second = refine.revise_query(first["query"], obs, {"eval"})
        self.assertEqual(second["opcode"], "exec")
        self.assertIn(b'pattern-not: eval("...")', second["query"])


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.path = self.root / "c01.py"; self.path.write_text("pass\n")
        self.manifest = [{"id": "c01", "path": str(self.path), "sha256": refine.sha(self.path.read_bytes())}]

    def payload(self):
        return {"results": [], "errors": [], "paths": {"scanned": [str(self.path)]}}

    def test_empty_results_only_complete_with_explicit_exact_scanned_scope(self):
        self.assertEqual(refine.parse_scan(json.dumps(self.payload()).encode(), self.manifest)["hits"], [])
        for paths in ([], [str(self.path), str(self.path)], [str(self.root / "other.py")]):
            raw = self.payload(); raw["paths"]["scanned"] = paths
            with self.assertRaises(ValueError): refine.parse_scan(json.dumps(raw).encode(), self.manifest)

    def test_duplicate_keys_nonfinite_errors_and_nonmanifest_hits_rejected(self):
        for raw in (b'{"results":[],"results":[],"errors":[],"paths":{"scanned":[]}}', b'{"x":NaN}', b''):
            with self.assertRaises(ValueError): refine.parse_scan(raw, self.manifest)
        for update in ({"errors": [{"message": "bad"}]},
                       {"results": [{"path": "/wrong.py", "check_id": refine.RULE_ID}]}):
            raw = self.payload(); raw.update(update)
            with self.assertRaises(ValueError): refine.parse_scan(json.dumps(raw).encode(), self.manifest)

    def test_wrong_source_hash_is_not_safe(self):
        self.path.write_text("different\n")
        with self.assertRaises(ValueError): refine.parse_scan(json.dumps(self.payload()).encode(), self.manifest)

    def test_relative_paths_bind_only_to_explicit_scanner_cwd(self):
        payload = self.payload(); payload["paths"]["scanned"] = ["c01.py"]
        self.assertEqual(refine.parse_scan(json.dumps(payload).encode(), self.manifest, scanner_cwd=self.root)["hits"], [])
        with self.assertRaises(ValueError):
            refine.parse_scan(json.dumps(payload).encode(), self.manifest, scanner_cwd=self.root / "different")
        payload["paths"]["scanned"] = ["../c01.py"]
        with self.assertRaises(ValueError):
            refine.parse_scan(json.dumps(payload).encode(), self.manifest, scanner_cwd=self.root / "different")

    def test_finding_must_bind_to_unique_oracle_sink_range(self):
        self.path.write_bytes(b"def subject(user_input):\n    eval(user_input)\n")
        self.manifest[0]["sha256"] = refine.sha(self.path.read_bytes())
        row = {"sinks": [{"byte_start": 29, "byte_end": 45}]}
        for start, end in ((0, 3), (True, 32), (29, 1000)):
            payload = self.payload(); payload["results"] = [{"check_id": refine.RULE_ID,
                "path": str(self.path), "start": {"offset": start}, "end": {"offset": end}}]
            with self.assertRaises(ValueError): refine.parse_scan(json.dumps(payload).encode(), self.manifest, [row])
        payload["results"][0].update(start={"offset": 29}, end={"offset": 45}, check_id="prefix." + refine.RULE_ID)
        self.assertEqual(refine.parse_scan(json.dumps(payload).encode(), self.manifest, [row])["hits"], ["c01"])

    def test_immutable_store_and_artifact_cap(self):
        store = refine.Store(self.root / "run", cap=8)
        store.put("raw", b"1234")
        with self.assertRaises(FileExistsError): store.put("raw", b"xx")
        with self.assertRaises(ValueError): store.put("../escape", b"xx")
        with self.assertRaises(ValueError): store.put("large", b"12345")
        self.assertEqual((self.root / "run/raw").read_bytes(), b"1234")

    def test_budget_debits_before_invocation_and_does_not_reset(self):
        now = [0.0]; budget = refine.Budget(clock=lambda: now[0], max_calls=2)
        self.assertEqual(budget.admit("first")["attempt"], 1)
        now[0] = 104.5
        self.assertLessEqual(budget.admit("second")["timeout"], 14.5)
        with self.assertRaises(ValueError): budget.admit("third")
        self.assertEqual(len(budget.attempts), 2)

    def test_budget_reserves_cleanup_and_records_hard_limit_unknown(self):
        now = [0.0]; budget = refine.Budget(clock=lambda: now[0])
        now[0] = 119.1
        with self.assertRaises(ValueError): budget.admit("too-late")
        self.assertEqual(budget.status()["control"], "budget-control-incomplete")

    def test_holdout_event_requires_selection_and_cannot_reopen(self):
        store = refine.Store(self.root / "run")
        seal = {"schema": 1, "created_by": "checker", "split": "holdout", "cases": [
            {"id": f"h{i}", "name": f"h{i}.py", "sha256": str(i) * 64} for i in range(4)]}
        gate = refine.HoldoutGate(store, seal)
        with self.assertRaises(ValueError): gate.open(None)
        selection = {"query_sha256": "a" * 64, "split": "dev", "frozen": True}
        gate.open(selection)
        with self.assertRaises(ValueError): gate.open(selection)


class InvocationContractTests(unittest.TestCase):
    """Self-authored fake invocation receipts only; zero subprocess/scanner calls."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        fixtures = self.root / "fixtures"; fixtures.mkdir()
        path = fixtures / "c01.py"; path.write_bytes(b'def subject(user_input):\n    return user_input\n')
        self.manifest = refine.checked_manifest(fixtures)
        self.adapter = refine.load_module("finite_test_adapter", refine.ADAPTER)
        self.experiment = refine.Experiment.__new__(refine.Experiment)
        self.experiment.budget = refine.Budget()
        self.experiment.store = refine.Store(self.root / "run")
        self.experiment.lock = {"files": {str(refine.HERE / "oracle.py"): "c" * 64}}
        self.experiment.binding = {"sha256": "d" * 64}
        self.experiment.stop_reason, self.experiment.observations = None, []
        self.invocations = []
        outer = self
        class Oracle:
            @staticmethod
            def observe(source):
                return {"contract": refine.CONTRACT, "source_sha256": refine.sha(source),
                        "status": "complete", "complete": True, "relation": "no_sink", "sinks": []}
        class Adapter:
            successful_run = staticmethod(outer.adapter.successful_run)
            @staticmethod
            def invoke(command, cwd, env, timeout, **caps):
                outer.invocations.append((command, cwd, env, timeout, caps))
                # Receipt must exist before attempting the fake invocation.
                outer.assertTrue((Path(cwd) / "attempts/01.json").is_file())
                return outer.receipt(command)
        self.experiment.oracle, self.experiment.adapter = Oracle(), Adapter()

    def receipt(self, command):
        stdout = json.dumps({"results": [], "errors": [], "paths": {"scanned": [self.manifest[0]["path"]]}})
        streams = {"stdout": stdout, "stderr": ""}
        return {"command": command, "returncode": 0, "error": None, "control_schema": 1,
                "control_complete": True, "timed_out": False, "cleanup_error": None, "seconds": .01,
                **streams, "captures": {name: {"cap_bytes": cap, "observed_bytes": len(streams[name].encode()),
                    "retained_bytes": len(streams[name].encode()), "sha256": refine.sha(streams[name].encode()),
                    "truncated": False, "decode_error": False}
                    for name, cap in (("stdout", refine.STDOUT_CAP), ("stderr", refine.STDERR_CAP))}}

    def scan(self):
        with patch.object(refine, "verify_lock", return_value={}):
            return self.experiment.scan("dev-baseline", b"rules: []\n", self.manifest, "dev")

    def test_controlled_invocation_uses_clean_env_caps_and_preserved_raw(self):
        result = self.scan()
        self.assertTrue(result["complete"])
        self.assertEqual(result["scheduled"], 1)
        command, cwd, env, timeout, caps = self.invocations[0]
        self.assertEqual(command[:3], ["/usr/bin/sandbox-exec", "-f", str(refine.POLICY)])
        self.assertNotIn("API_KEY", env)
        self.assertTrue(Path(env["HOME"]).is_relative_to(cwd))
        self.assertLessEqual(timeout, 15)
        self.assertEqual(caps, {"stdout_cap": 1048576, "stderr_cap": 262144})
        self.assertTrue((Path(cwd) / "scans/dev-baseline/stdout.raw").is_file())

    def test_nonzero_with_results_is_unknown_and_no_subsequent_retry(self):
        original = self.receipt
        def broken(command):
            value = original(command); value["returncode"] = 1
            return value
        self.receipt = broken
        result = self.scan()
        self.assertFalse(result["complete"])
        self.assertIsNone(result["cases"][0]["hit"])
        with patch.object(refine, "verify_lock", return_value={}):
            second = self.experiment.scan("replay-baseline", b"rules: []\n", self.manifest, "dev")
        self.assertEqual(second["attempted"], 0)
        self.assertEqual(len(self.invocations), 1)

    def test_invoked_query_file_drift_is_incomplete(self):
        original = self.receipt
        def changed(command):
            Path(command[command.index("--config") + 1]).write_bytes(b"altered-query\n")
            return original(command)
        self.receipt = changed
        result = self.scan()
        self.assertFalse(result["complete"])
        self.assertIsNone(result["cases"][0]["hit"])

    def test_cleanup_truncation_utf8_control_and_hash_failures_rejected(self):
        original = self.receipt
        changes = [("cleanup_error", "cleanup-deadline"), ("control_complete", False), ("returncode", True)]
        for index, (key, value) in enumerate(changes):
            with self.subTest(key=key):
                self.experiment.stop_reason = None
                def broken(command, key=key, value=value):
                    receipt = original(command); receipt[key] = value
                    return receipt
                self.receipt = broken
                with patch.object(refine, "verify_lock", return_value={}):
                    result = self.experiment.scan(f"bad-{index}", b"rules: []\n", self.manifest, "dev")
                self.assertFalse(result["complete"])
        for index, key in enumerate(("truncated", "decode_error", "sha256")):
            self.experiment.stop_reason = None
            def broken(command, key=key):
                receipt = original(command); receipt["captures"]["stdout"][key] = "0" * 64 if key == "sha256" else True
                return receipt
            self.receipt = broken
            with patch.object(refine, "verify_lock", return_value={}):
                result = self.experiment.scan(f"capture-{index}", b"rules: []\n", self.manifest, "dev")
            self.assertFalse(result["complete"])


class FakeClosedLoopTests(unittest.TestCase):
    """Control flow only: fake AST matcher is explicitly not Semgrep evidence."""
    def test_two_real_yaml_revisions_gate_replay_and_lineage_flow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            holdout = root / "self-authored-unit-holdout"; holdout.mkdir()
            forms = ['eval(user_input)', 'exec(user_input)', 'eval("unit-constant")', 'exec("unit-pass")']
            descriptors = []
            for index, form in enumerate(forms):
                name = f"h{index}.py"; raw = f"def subject(user_input):\n    {form}\n".encode()
                (holdout / name).write_bytes(raw)
                descriptors.append({"id": f"h{index}", "name": name, "sha256": refine.sha(raw)})
            seal = {"schema": 1, "created_by": "unit-test-self-authored-not-checker", "split": "holdout", "cases": descriptors}
            module_loader = refine.load_module
            oracle = module_loader("finite_unit_real_oracle", refine.HERE / "oracle.py")
            real_adapter = module_loader("finite_unit_capture_checker", refine.ADAPTER)
            calls = []
            class FakeMatcher:
                successful_run = staticmethod(real_adapter.successful_run)
                @staticmethod
                def invoke(command, cwd, env, timeout, **caps):
                    calls.append(command)
                    target = Path(command[-1]); query = Path(command[command.index("--config") + 1]).read_bytes()
                    if target == holdout:
                        # Selection must be durably present before holdout evaluation.
                        assert (Path(cwd) / "selection.json").is_file()
                        assert (Path(cwd) / "holdout-event.json").is_file()
                    paths, results = [], []
                    for path in sorted(target.glob("*.py")):
                        paths.append(str(path)); observation = oracle.observe(path.read_bytes())
                        for sink in observation["sinks"]:
                            excluded = sink["operand_literal"] and f'pattern-not: {sink["opcode"]}("...")'.encode() in query
                            if not excluded:
                                results.append({"check_id": refine.RULE_ID, "path": str(path),
                                    "start": {"offset": sink["byte_start"]}, "end": {"offset": sink["byte_end"]}})
                    stdout = json.dumps({"results": results, "errors": [], "paths": {"scanned": paths}})
                    streams = {"stdout": stdout, "stderr": ""}
                    return {"command": command, "returncode": 0, "error": None, "control_schema": 1,
                        "control_complete": True, "timed_out": False, "cleanup_error": None, "seconds": .001,
                        **streams, "captures": {name: {"cap_bytes": cap, "observed_bytes": len(streams[name].encode()),
                            "retained_bytes": len(streams[name].encode()), "sha256": refine.sha(streams[name].encode()),
                            "truncated": False, "decode_error": False}
                            for name, cap in (("stdout", refine.STDOUT_CAP), ("stderr", refine.STDERR_CAP))}}
            lock = {"schema": 1, "files": {str(refine.HERE / "oracle.py"): refine.sha((refine.HERE / "oracle.py").read_bytes())}}
            def modules(name, path):
                return FakeMatcher() if path == refine.ADAPTER else module_loader(name, path)
            with patch.object(refine, "verify_lock", return_value={"sha256": "d" * 64}), patch.object(refine, "load_module", side_effect=modules):
                experiment = refine.Experiment(root / "run", lock, seal, holdout)
                result = experiment.run()
            self.assertEqual(len(result["revisions"]), 2)
            self.assertTrue(all(item["accepted"] for item in result["revisions"]))
            self.assertEqual(result["holdout"]["status"], "complete")
            self.assertTrue(all(item["same"] for item in result["replay"]))
            self.assertGreaterEqual(result["minimize"]["attempts"], 1)
            self.assertTrue(result["minimize"]["steps"][0]["accepted"])
            self.assertEqual(result["budget"]["attempted"], len(calls))
            self.assertLessEqual(len(calls), 15)
            self.assertFalse(result["adoption_eligible"])
            self.assertEqual(result["budget"]["control"], "budget-control-incomplete")

    def test_failed_preflight_has_persistent_denominators_and_no_scanner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            code = refine.main(["--run-dir", str(root / "run"), "--approved-lock", str(root / "absent-lock.json"),
                                "--seal", str(root / "absent-seal.json"), "--holdout-dir", str(root / "absent")])
            self.assertEqual(code, 2)
            failure = json.loads((root / "run/failed-run.json").read_text())
            self.assertEqual(len(failure["stage_denominators"]), 15)
            self.assertEqual(failure["budget"]["attempted"], 0)


if __name__ == "__main__":
    unittest.main()
