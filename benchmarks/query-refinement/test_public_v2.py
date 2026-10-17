"""Public controller contracts; fixtures are self-authored, never real scanner evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import contextlib
import io
from unittest.mock import patch

import runtime_profile
from test_public_support import make_runtime_fixture, rewrite_fixture
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("public_v2_under_test", HERE / "refine_public_v2.py")
public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public)
frozen = public.frozen


class PublicPreflightTests(unittest.TestCase):
    def test_missing_profile_has_failed_receipt_zero_attempts_and_denominators(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            code = public.main([
                "--run-dir", str(root / "new-run"),
                "--profile", str(root / "absent-profile.json"),
                "--profile-sha256", "a" * 64,
                "--approved-lock", str(root / "absent-lock.json"),
                "--approved-lock-sha256", "b" * 64,
                "--seal", str(root / "absent-seal.json"),
                "--holdout-dir", str(root / "self-authored-holdout"),
            ])
            self.assertEqual(code, 2)
            result = json.loads((root / "new-run/failed-run.json").read_text())
            self.assertEqual(result["controller_contract"], public.CONTROLLER_CONTRACT)
            self.assertEqual(result["budget"]["attempted"], 0)
            self.assertEqual(len(result["stage_denominators"]), 15)
            self.assertFalse(result["adoption_eligible"])
            self.assertIn("profile", result["reason"])

    def test_invalid_binding_stops_constructor_before_adapter_load(self):
        class InvalidBinding:
            def verify(self):
                raise ValueError("runtime-binding-drift")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.assertRaisesRegex(ValueError, "runtime-binding-drift"):
                public.PublicExperiment(root / "new-run", InvalidBinding(), {}, root / "unopened-holdout")


FAKE_CLI = b"""import json, os, pathlib, sys
paths = [str(p) for p in sorted(pathlib.Path(sys.argv[-1]).glob('*.py'))]
sys.stderr.write(json.dumps({'self_authored_fake_cli': True, 'env': dict(os.environ)}, sort_keys=True))
print(json.dumps({'version': '1.181.0', 'results': [], 'errors': [], 'paths': {'scanned': paths}}))
"""


def replace_stdout(receipt, raw):
    receipt["stdout"] = raw.decode("utf-8")
    receipt["captures"]["stdout"].update(
        observed_bytes=len(raw), retained_bytes=len(raw), sha256=frozen.sha(raw))
    return receipt


class PublicControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.holdout = self.root / "self-authored-holdout"
        self.holdout.mkdir()
        cases = []
        forms = ['eval(user_input)', 'exec(user_input)', 'eval("fixture-x")', 'exec("fixture-y")']
        for index, form in enumerate(forms):
            name = f"new-h{index}.py"
            raw = f'# Self-authored test only.\ndef subject(user_input):\n    {form}\n'.encode()
            (self.holdout / name).write_bytes(raw)
            cases.append({"id": f"new-h{index}", "name": name, "sha256": frozen.sha(raw)})
        self.seal = {"schema": 1, "created_by": "public-v2-self-authored-unit-test",
                     "split": "holdout", "cases": cases}
        self.seal_path = self.root / "self-authored-seal.json"
        self.seal_path.write_bytes(frozen.encoded(self.seal))
        self.fixture = make_runtime_fixture(self.root / "runtime", self.seal_path,
                                            launcher_source=FAKE_CLI)
        self.calls = []

    def binding(self):
        f = self.fixture
        return runtime_profile.load_binding(f["profile_path"], f["profile_sha256"],
                                            f["lock_path"], f["lock_sha256"],
                                            seal_path=self.seal_path)

    def experiment(self, *, name="run"):
        return public.PublicExperiment(self.root / name, self.binding(), self.seal, self.holdout)

    def fake_adapter(self, experiment, *, change=None):
        outer = self
        real_success = experiment.adapter.successful_run
        class Adapter:
            successful_run = staticmethod(real_success)

            @staticmethod
            def invoke(command, cwd, env, timeout, **caps):
                outer.calls.append(command)
                outer.assertEqual(command[:5], [str(experiment.binding.sandbox), "-f",
                    str(experiment.binding.policy), str(experiment.binding.launcher), "scan"])
                debit = Path(cwd) / f"attempts/{len(outer.calls):02d}.json"
                outer.assertTrue(debit.is_file(), "attempt debit must precede invoke")
                outer.assertEqual(json.loads(debit.read_text())["attempt"], len(outer.calls))
                outer.assertLessEqual(timeout, 15)
                outer.assertGreater(timeout, 0)
                outer.assertEqual(caps, {"stdout_cap": frozen.STDOUT_CAP,
                                         "stderr_cap": frozen.STDERR_CAP})
                outer.assertEqual(set(env), {"PATH", "HOME", "LANG", "PYTHONDONTWRITEBYTECODE",
                                            "SEMGREP_SEND_METRICS", "SEMGREP_ENABLE_VERSION_CHECK"})
                outer.assertTrue(Path(env["HOME"]).is_relative_to(cwd))
                target = Path(command[-1])
                if target == outer.holdout:
                    outer.assertTrue((Path(cwd) / "selection.json").is_file())
                    outer.assertTrue((Path(cwd) / "holdout-event.json").is_file())
                query = Path(command[command.index("--config") + 1]).read_bytes()
                paths, findings = [], []
                for path in sorted(target.glob("*.py")):
                    paths.append(str(path))
                    for sink in experiment.oracle.observe(path.read_bytes())["sinks"]:
                        excluded = (sink["operand_literal"] and
                                    f'pattern-not: {sink["opcode"]}("...")'.encode() in query)
                        if not excluded:
                            findings.append({"check_id": frozen.RULE_ID, "path": str(path),
                                "start": {"offset": sink["byte_start"]},
                                "end": {"offset": sink["byte_end"]}})
                stdout = json.dumps({"version": "1.181.0", "results": findings,
                                     "errors": [], "paths": {"scanned": paths}})
                streams = {"stdout": stdout, "stderr": ""}
                receipt = {"command": command, "returncode": 0, "error": None, "control_schema": 1,
                    "control_complete": True, "timed_out": False, "cleanup_error": None, "seconds": .001,
                    **streams, "captures": {name: {"cap_bytes": cap,
                        "observed_bytes": len(streams[name].encode()), "retained_bytes": len(streams[name].encode()),
                        "sha256": frozen.sha(streams[name].encode()), "truncated": False, "decode_error": False}
                        for name, cap in (("stdout", frozen.STDOUT_CAP), ("stderr", frozen.STDERR_CAP))}}
                return change(receipt) if change else receipt
        return Adapter()

    def test_complete_fake_flow_keeps_two_revisions_holdout_replay_minimization_and_denominators(self):
        experiment = self.experiment()
        experiment.adapter = self.fake_adapter(experiment)
        original_globals = (frozen.LAUNCHER, frozen.CORE, frozen.POLICY, dict(frozen.PINS))
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "self-authored-dummy",
                                     "HTTPS_PROXY": "self-authored-dummy"}):
            result = experiment.run()
        self.assertEqual(original_globals, (frozen.LAUNCHER, frozen.CORE, frozen.POLICY, dict(frozen.PINS)))
        self.assertEqual(result["controller_contract"], public.CONTROLLER_CONTRACT)
        self.assertEqual(result["runtime_binding_sha256"], experiment.binding.binding_sha256)
        self.assertEqual(len(result["revisions"]), 2)
        self.assertTrue(all(item["accepted"] for item in result["revisions"]))
        self.assertTrue(result["experiment_complete"])
        self.assertEqual(result["holdout"]["status"], "complete")
        self.assertTrue(result["holdout"]["single_event"])
        self.assertTrue(all(item["same"] for item in result["replay"]))
        self.assertGreaterEqual(result["minimize"]["attempts"], 1)
        self.assertTrue(result["minimize"]["steps"][0]["accepted"])
        self.assertEqual(result["budget"]["attempted"], len(self.calls))
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(len(result["stage_denominators"]), 15)
        self.assertEqual(sum(row["attempted"] for row in result["stage_denominators"]), 39)
        self.assertEqual(result["budget"]["control"], "budget-control-incomplete")
        self.assertFalse(result["adoption_eligible"])
        self.assertEqual((experiment.store.root / "runtime-profile.json").read_bytes(), self.fixture["profile_path"].read_bytes())
        self.assertEqual((experiment.store.root / "approved-lock.json").read_bytes(), self.fixture["lock_path"].read_bytes())
        self.assertEqual(len(list(experiment.store.root.glob("holdout-event.json"))), 1)

    def test_runtime_drift_after_invoke_is_unknown_and_stops_next_arm(self):
        experiment = self.experiment()
        def changed(receipt):
            self.fixture["core"].write_bytes(b"changed-self-authored-fixture\n")
            return receipt
        experiment.adapter = self.fake_adapter(experiment, change=changed)
        result = experiment.scan("first", b"rules: []\n", experiment.dev, "dev")
        self.assertFalse(result["complete"])
        self.assertTrue(all(c["status"] == "unknown" and c["hit"] is None for c in result["cases"]))
        self.assertNotEqual(result["reason"], "complete-finite-contract")
        next_result = experiment.scan("next", b"rules: []\n", experiment.dev, "dev")
        self.assertEqual(next_result["attempted"], 0)
        self.assertEqual(len(self.calls), 1)

    def test_complete_holdout_sensitive_hit_loss_cannot_complete_experiment(self):
        experiment = self.experiment()
        def remove_selected_holdout_sensitive_hit(receipt):
            query_path = Path(receipt["command"][receipt["command"].index("--config") + 1])
            if query_path.parent.name == "holdout-selected":
                payload = json.loads(receipt["stdout"])
                sensitive = next(item for item in payload["results"]
                    if experiment.oracle.observe(Path(item["path"]).read_bytes())["relation"] == "input_dependent")
                payload["results"].remove(sensitive)
                receipt["stdout"] = json.dumps(payload)
                raw = receipt["stdout"].encode()
                receipt["captures"]["stdout"].update(
                    observed_bytes=len(raw), retained_bytes=len(raw), sha256=frozen.sha(raw))
            return receipt
        experiment.adapter = self.fake_adapter(experiment, change=remove_selected_holdout_sensitive_hit)
        result = experiment.run()
        self.assertEqual(result["holdout"]["status"], "complete")
        self.assertFalse(result["holdout"]["nonregression"])
        self.assertFalse(result["accepted_query_validation_complete"])
        self.assertFalse(result["experiment_complete"])
        f = self.fixture
        with patch.object(public.PublicExperiment, "run", return_value=result):
            code = public.main([
                "--run-dir", str(self.root / "main-exit-check"),
                "--profile", str(f["profile_path"]), "--profile-sha256", f["profile_sha256"],
                "--approved-lock", str(f["lock_path"]), "--approved-lock-sha256", f["lock_sha256"],
                "--seal", str(self.seal_path), "--holdout-dir", str(self.holdout),
            ])
        self.assertEqual(code, 2)

    def test_invalid_receipt_and_wrong_version_stop_without_retry(self):
        for index, kind in enumerate(("receipt", "version")):
            with self.subTest(kind=kind):
                self.calls.clear()
                experiment = self.experiment(name=f"run-{index}")
                def changed(receipt, kind=kind):
                    if kind == "receipt":
                        receipt["cleanup_error"] = "self-authored-unknown-cleanup"
                    else:
                        payload = json.loads(receipt["stdout"])
                        payload["version"] = "unapproved-version"
                        receipt["stdout"] = json.dumps(payload)
                        cap = receipt["captures"]["stdout"]
                        cap.update(observed_bytes=len(receipt["stdout"].encode()),
                                   retained_bytes=len(receipt["stdout"].encode()),
                                   sha256=frozen.sha(receipt["stdout"].encode()))
                    return receipt
                experiment.adapter = self.fake_adapter(experiment, change=changed)
                first = experiment.scan("first", b"rules: []\n", experiment.dev, "dev")
                self.assertFalse(first["complete"])
                self.assertEqual(first["reason"], "scanner_error" if kind == "receipt" else "scanner-version-mismatch")
                self.assertTrue(all(c["hit"] is None for c in first["cases"]))
                self.assertEqual(experiment.scan("next", b"rules: []\n", experiment.dev, "dev")["attempted"], 0)
                self.assertEqual(len(self.calls), 1)

    def test_binding_preinvoke_drift_debits_zero_and_holdout_is_unread(self):
        experiment = self.experiment()
        experiment.adapter = self.fake_adapter(experiment)
        self.fixture["policy"].write_bytes(b"invalid-self-authored-policy\n")
        first = experiment.scan("first", b"rules: []\n", experiment.dev, "dev")
        self.assertFalse(first["complete"])
        self.assertEqual(experiment.budget.status()["attempted"], 0)
        self.assertEqual(len(self.calls), 0)
        self.assertFalse((experiment.store.root / "holdout-event.json").exists())
        self.assertFalse((experiment.store.root / "sources/holdout").exists())

    def test_actual_self_authored_fake_cli_subprocess_uses_profile_and_clean_environment(self):
        experiment = self.experiment()
        target = self.root / "self-authored-no-sink"
        target.mkdir()
        (target / "case.py").write_bytes(b"def subject(user_input):\n    return user_input\n")
        manifest = frozen.checked_manifest(target)
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "self-authored-dummy",
                                     "HTTPS_PROXY": "self-authored-dummy"}):
            result = experiment.scan("actual-fake-only", b"rules: []\n", manifest, "dev")
        self.assertTrue(result["complete"], result)
        self.assertEqual(result["cases"][0]["relation"], "no_sink")
        self.assertFalse(result["cases"][0]["hit"])
        self.assertEqual(experiment.budget.status()["attempted"], 1)
        invocation = json.loads((experiment.store.root / "scans/actual-fake-only/invocation.json").read_text())
        self.assertEqual(invocation["argv"][3], str(self.fixture["launcher"]))
        stderr = json.loads((experiment.store.root / "scans/actual-fake-only/stderr.raw").read_text())
        self.assertTrue(stderr["self_authored_fake_cli"])
        self.assertNotIn("ANTHROPIC_API_KEY", stderr["env"])
        self.assertNotIn("HTTPS_PROXY", stderr["env"])
        receipt = json.loads((experiment.store.root / "scans/actual-fake-only/receipt.json").read_text())
        self.assertTrue(receipt["control_complete"])
        self.assertIsNone(receipt["cleanup_error"])

    def test_missing_approved_lock_has_zero_attempts_and_preserves_failure_class(self):
        self.fixture["lock_path"].unlink()
        f = self.fixture
        code = public.main([
            "--run-dir", str(self.root / "failed-run"), "--profile", str(f["profile_path"]),
            "--profile-sha256", f["profile_sha256"], "--approved-lock", str(f["lock_path"]),
            "--approved-lock-sha256", f["lock_sha256"], "--seal", str(self.seal_path),
            "--holdout-dir", str(self.holdout),
        ])
        self.assertEqual(code, 2)
        failure = json.loads((self.root / "failed-run/failed-run.json").read_text())
        self.assertEqual(failure["budget"]["attempted"], 0)
        self.assertIn("profile-", failure["reason"])
        self.assertFalse((self.root / "failed-run/holdout-event.json").exists())

    def test_constructor_rejects_unbound_seal_before_loading_adapter(self):
        binding = self.binding()
        for index, field in enumerate(("created_by", "cases")):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(self.seal))
                if field == "created_by":
                    changed[field] = "different-self-authored-descriptor"
                else:
                    changed[field][0]["sha256"] = "a" * 64
                with patch.object(public.frozen, "load_module", wraps=public.frozen.load_module) as loader:
                    with self.assertRaisesRegex(ValueError, "seal-binding-mismatch"):
                        public.PublicExperiment(self.root / f"seal-reject-{index}", binding,
                                                changed, self.holdout)
                    loader.assert_not_called()
                self.assertEqual(self.calls, [])
                self.assertFalse((self.root / f"seal-reject-{index}/attempts").exists())

    def test_constructor_accepts_equivalent_seal_key_order(self):
        reordered = dict(reversed(list(self.seal.items())))
        reordered["cases"] = [dict(reversed(list(case.items()))) for case in self.seal["cases"]]
        experiment = public.PublicExperiment(self.root / "equivalent-seal", self.binding(),
                                             reordered, self.holdout)
        self.assertEqual(experiment.gate.seal, self.seal)
        self.assertEqual(experiment.budget.status()["attempted"], 0)

    def test_main_rejects_correctly_pinned_seal_over_64k_before_adapter_import(self):
        self.seal_path.write_bytes(frozen.encoded(self.seal) + b" " * (64 * 1024))
        self.fixture["lock"]["files"][str(self.seal_path)] = frozen.sha(self.seal_path.read_bytes())
        rewrite_fixture(self.fixture)
        f = self.fixture
        with patch.object(public.frozen, "load_module",
                          side_effect=AssertionError("preflight-must-not-import-adapter")) as loader:
            code = public.main([
                "--run-dir", str(self.root / "oversize-seal-run"),
                "--profile", str(f["profile_path"]), "--profile-sha256", f["profile_sha256"],
                "--approved-lock", str(f["lock_path"]), "--approved-lock-sha256", f["lock_sha256"],
                "--seal", str(self.seal_path), "--holdout-dir", str(self.holdout),
            ])
            loader.assert_not_called()
        self.assertEqual(code, 2)
        result = json.loads((self.root / "oversize-seal-run/failed-run.json").read_text())
        self.assertIn("seal-bound", result["reason"])
        self.assertEqual(result["budget"]["attempted"], 0)
        self.assertEqual(self.calls, [])

    def test_managed_artifact_cap_failure_stops_without_admission(self):
        experiment = self.experiment()
        experiment.adapter = self.fake_adapter(experiment)
        experiment.store.cap = experiment.store.written
        with self.assertRaisesRegex(ValueError, "artifact-cap"):
            experiment.scan("first", b"rules: []\n", experiment.dev, "dev")
        self.assertEqual(experiment.stop_reason, "artifact-cap")
        self.assertEqual(experiment.budget.status()["attempted"], 0)
        with self.assertRaisesRegex(ValueError, "artifact-cap"):
            experiment.scan("next", b"rules: []\n", experiment.dev, "dev")
        self.assertEqual(self.calls, [])

    def test_run_end_verifies_real_binding_and_does_not_write_success_on_drift(self):
        binding = self.binding()
        checks = []
        class CountedBinding:
            def __getattr__(self, name):
                return getattr(binding, name)
            def verify(self):
                binding.verify()
                checks.append(True)
                if len(checks) == 18:
                    raise ValueError("runtime-binding-drift")
        experiment = public.PublicExperiment(self.root / "run", CountedBinding(), self.seal, self.holdout)
        experiment.adapter = self.fake_adapter(experiment)
        with self.assertRaisesRegex(ValueError, "runtime-binding-drift"):
            experiment.run()
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(len(checks), 18)
        self.assertFalse((experiment.store.root / "summary.json").exists())

    def test_dev_without_mismatch_does_not_select_or_read_holdout_sources(self):
        experiment = self.experiment()
        def only_dependent_hits(receipt):
            payload = json.loads(receipt["stdout"])
            payload["results"] = [item for item in payload["results"]
                if experiment.oracle.observe(Path(item["path"]).read_bytes())["relation"] == "input_dependent"]
            return replace_stdout(receipt, json.dumps(payload).encode())
        experiment.adapter = self.fake_adapter(experiment, change=only_dependent_hits)
        read_bytes = Path.read_bytes
        def guarded_read(path):
            if path.parent == self.holdout:
                raise AssertionError("holdout-source-read-without-selection")
            return read_bytes(path)
        with patch.object(Path, "read_bytes", new=guarded_read):
            result = experiment.run()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(result["selection"]["candidate_accepted"])
        self.assertEqual(result["holdout"]["status"], "not_attempted")
        self.assertFalse((experiment.store.root / "holdout-event.json").exists())
        self.assertEqual(result["revisions"], [])

    def test_revision_sensitive_loss_is_rejected_without_unsealing_holdout(self):
        experiment = self.experiment()
        def lose_revision_sensitive_hit(receipt):
            query = Path(receipt["command"][receipt["command"].index("--config") + 1])
            if query.parent.name == "dev-revision-1":
                payload = json.loads(receipt["stdout"])
                sensitive = next(item for item in payload["results"]
                    if experiment.oracle.observe(Path(item["path"]).read_bytes())["relation"] == "input_dependent")
                payload["results"].remove(sensitive)
                return replace_stdout(receipt, json.dumps(payload).encode())
            return receipt
        experiment.adapter = self.fake_adapter(experiment, change=lose_revision_sensitive_hit)
        result = experiment.run()
        self.assertEqual(len(result["revisions"]), 1)
        self.assertFalse(result["revisions"][0]["accepted"])
        self.assertEqual(result["revisions"][0]["reason"], "sensitive-hit-loss")
        self.assertFalse(result["selection"]["candidate_accepted"])
        self.assertEqual(result["holdout"]["status"], "not_attempted")
        self.assertFalse((experiment.store.root / "holdout-event.json").exists())

    def test_timeout_preserves_partial_raw_and_stops_next_invocation(self):
        experiment = self.experiment()
        partial = b'{"version":"1.181.0","results":['
        def timeout(receipt):
            replace_stdout(receipt, partial)
            receipt.update(timed_out=True, returncode=-15, error="timeout")
            return receipt
        experiment.adapter = self.fake_adapter(experiment, change=timeout)
        result = experiment.scan("timed-out", b"rules: []\n", experiment.dev, "dev")
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"], "timeout")
        self.assertTrue(all(c["status"] == "unknown" and c["hit"] is None for c in result["cases"]))
        self.assertEqual((experiment.store.root / "scans/timed-out/stdout.raw").read_bytes(), partial)
        self.assertEqual(experiment.scan("next", b"rules: []\n", experiment.dev, "dev")["attempted"], 0)
        self.assertEqual(len(self.calls), 1)

    def test_invoked_query_drift_is_unknown_and_stops_next_invocation(self):
        experiment = self.experiment()
        def alter_query(receipt):
            path = Path(receipt["command"][receipt["command"].index("--config") + 1])
            path.write_bytes(b"changed-self-authored-query\n")
            return receipt
        experiment.adapter = self.fake_adapter(experiment, change=alter_query)
        result = experiment.scan("changed-query", b"rules: []\n", experiment.dev, "dev")
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"], "query-drift")
        self.assertTrue(all(c["hit"] is None for c in result["cases"]))
        self.assertEqual(experiment.scan("next", b"rules: []\n", experiment.dev, "dev")["attempted"], 0)
        self.assertEqual(len(self.calls), 1)

    def test_expired_budget_admits_no_attempt_and_invokes_nothing(self):
        experiment = self.experiment()
        experiment.adapter = self.fake_adapter(experiment)
        experiment.budget.deadline = experiment.budget.clock() - 1
        result = experiment.scan("expired", b"rules: []\n", experiment.dev, "dev")
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"], "budget_stop")
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(experiment.budget.status()["attempted"], 0)
        self.assertEqual(self.calls, [])

    def test_observation_write_failure_preserves_raw_marks_unknown_and_stops_calls(self):
        experiment = self.experiment()
        experiment.adapter = self.fake_adapter(experiment)
        write_json = experiment.store.json
        def fail_observation(relative, value):
            if relative.endswith("/observation.json"):
                raise OSError("self-authored-observation-write-failure")
            return write_json(relative, value)
        with patch.object(experiment.store, "json", side_effect=fail_observation):
            with self.assertRaises(OSError):
                experiment.scan("unwritten-observation", b"rules: []\n", experiment.dev, "dev")
            result = experiment.observations[-1]
            self.assertFalse(result["complete"])
            self.assertTrue(all(c["status"] == "unknown" and c["hit"] is None for c in result["cases"]))
            self.assertIsNotNone(experiment.stop_reason)
            self.assertTrue((experiment.store.root / "scans/unwritten-observation/stdout.raw").is_file())
            self.assertTrue((experiment.store.root / "scans/unwritten-observation/receipt.json").is_file())
            with self.assertRaises(OSError):
                experiment.scan("next", b"rules: []\n", experiment.dev, "dev")
        self.assertEqual(len(self.calls), 1)

    def test_cli_rejects_relative_paths_and_preserves_existing_output_without_invocation(self):
        f = self.fixture
        original = {
            "run-dir": str(self.root / "cli-new-run"),
            "profile": str(f["profile_path"]), "profile-sha256": f["profile_sha256"],
            "approved-lock": str(f["lock_path"]), "approved-lock-sha256": f["lock_sha256"],
            "seal": str(self.seal_path), "holdout-dir": str(self.holdout),
        }
        sentinel_dir = self.root / "existing-output"
        sentinel_dir.mkdir()
        sentinel = sentinel_dir / "keep.txt"
        sentinel_bytes = b"self-authored-existing-output-must-remain\n"
        sentinel.write_bytes(sentinel_bytes)
        for index, field in enumerate(("run-dir", "profile", "approved-lock", "seal", "holdout-dir", "existing-output")):
            with self.subTest(field=field):
                options = dict(original)
                output = self.root / f"cli-reject-{index}"
                options["run-dir"] = str(output)
                if field == "existing-output":
                    options["run-dir"] = str(sentinel_dir)
                elif field == "run-dir":
                    options[field] = os.path.relpath(output, Path.cwd())
                else:
                    options[field] = os.path.relpath(options[field], Path.cwd())
                arguments = [part for key, value in options.items() for part in ("--" + key, value)]
                budget = frozen.Budget()
                stderr = io.StringIO()
                with patch.object(public.frozen, "Budget", return_value=budget), \
                     patch.object(public.frozen, "load_module", side_effect=AssertionError("no-adapter-import")) as loader, \
                     contextlib.redirect_stderr(stderr):
                    code = public.main(arguments)
                self.assertEqual(code, 2)
                self.assertEqual(budget.status()["attempted"], 0)
                loader.assert_not_called()
                self.assertEqual(sentinel.read_bytes(), sentinel_bytes)
                self.assertEqual(set(sentinel_dir.iterdir()), {sentinel})
                if field in ("run-dir", "existing-output"):
                    self.assertFalse((output / "attempts").exists())
                    self.assertFalse((output / "failed-run.json").exists())
                else:
                    failure = json.loads((output / "failed-run.json").read_text())
                    self.assertEqual(failure["reason"], "input-path-must-be-absolute")
                    self.assertEqual(failure["budget"]["attempted"], 0)
                self.assertIn('"status": "incomplete"', stderr.getvalue())

    def test_unsupported_oracle_source_is_unknown_without_admission_or_next_invocation(self):
        experiment = self.experiment()
        experiment.adapter = self.fake_adapter(experiment)
        directory = self.root / "self-authored-unsupported-source"
        directory.mkdir()
        (directory / "case.py").write_bytes(b"def subject(user_input):\n    eval(user_input.attr)\n")
        manifest = frozen.checked_manifest(directory)
        result = experiment.scan("unsupported", b"rules: []\n", manifest, "dev")
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"], "oracle_unsupported")
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["scheduled"], 1)
        self.assertEqual(result["cases"][0]["status"], "unknown")
        self.assertIsNone(result["cases"][0]["hit"])
        self.assertEqual(experiment.budget.status()["attempted"], 0)
        self.assertFalse((experiment.store.root / "holdout-event.json").exists())
        later = experiment.scan("next", b"rules: []\n", experiment.dev, "dev")
        self.assertEqual(later["attempted"], 0)
        self.assertTrue(all(c["status"] == "not_attempted" for c in later["cases"]))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
