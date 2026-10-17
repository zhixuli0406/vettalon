import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import adapter
from test_process_supervisor import observed_run

TARGET = {"id": "GO-2021-0113", "purl": "pkg:golang/golang.org/x/text@v0.3.5", "module": "golang.org/x/text", "version": "v0.3.5"}


def stream(symbol=False, level="symbol"):
    frame = {"module": TARGET["module"], "version": TARGET["version"], "package": "golang.org/x/text/language"}
    if symbol:
        frame["function"] = "Parse"
    messages = [
        {"config": {"protocol_version": "v1.0.0", "scan_level": level, "scan_mode": "source", "scanner_version": "v1.4.0"}},
        {"SBOM": {"modules": [{"path": TARGET["module"], "version": TARGET["version"]}]}},
        {"osv": {"id": TARGET["id"], "affected": [{"package": {"name": TARGET["module"]}, "ecosystem_specific": {"imports": [{"path": "golang.org/x/text/language", "symbols": ["Parse"]}]}}]}},
        {"finding": {"osv": TARGET["id"], "trace": [frame]}}]
    return "\n".join(json.dumps(m) for m in messages)


class AdapterTests(unittest.TestCase):
    def test_reachable(self):
        self.assertEqual(adapter.classify(stream(True), 0, TARGET)["status"], "reachable")

    def test_not_observed_is_not_safe(self):
        result = adapter.classify(stream(), 0, TARGET)
        self.assertEqual(result["status"], "not-observed")
        self.assertEqual(result["vex"]["status"], "under_investigation")
        self.assertFalse(result["suppress_alert"])

    def test_failure_is_unknown_even_with_trace(self):
        self.assertEqual(adapter.classify(stream(True), 1, TARGET)["status"], "unknown")

    def test_invalid_incomplete_and_wrong_level_are_unknown(self):
        for raw in ["", "{", "[]", "{}", stream(level="module"), stream().replace("v1.0.0", "v9"), stream().replace("v1.4.0", "v9")]:
            with self.subTest(raw=raw):
                self.assertEqual(adapter.classify(raw, 0, TARGET)["status"], "unknown")

    def test_no_target_finding_or_module_is_unknown(self):
        lines = stream().splitlines()
        for raw in ["\n".join(lines[:-1]), "\n".join(lines[:1] + lines[2:]), stream().replace('"v0.3.5"', '"v9"')]:
            self.assertEqual(adapter.classify(raw, 0, TARGET)["status"], "unknown")

    def test_unrecognised_symbol_is_unknown(self):
        self.assertEqual(adapter.classify(stream(True).replace('"function": "Parse"', '"function": "Mystery"'), 0, TARGET)["status"], "unknown")

    def test_each_cache_dimension_invalidates(self):
        base = {name: "value" for name in adapter.CACHE_FIELDS}
        original = adapter.cache_key(base)
        for field in adapter.CACHE_FIELDS:
            changed = copy.deepcopy(base)
            changed[field] = "changed"
            self.assertNotEqual(original, adapter.cache_key(changed), field)
        with self.assertRaises(ValueError):
            adapter.cache_key({})

    def test_source_hash_content_path_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.go").write_text("a")
            first = adapter.tree_hash(root)
            (root / "main.go").write_text("b")
            self.assertNotEqual(first, adapter.tree_hash(root))
            (root / "link").symlink_to(root / "main.go")
            with self.assertRaises(ValueError):
                adapter.tree_hash(root)

    def test_cli_missing_tool_and_unsupported_preserve_unknown(self):
        for language, reason in [("rust", "unsupported"), ("go", "missing-tool")]:
            with tempfile.TemporaryDirectory() as temp:
                result = adapter.scan(Path(__file__).parent / "fixtures/called", Path(temp) / "result", Path("/missing/tool"), language=language)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reason"], reason)

    def test_process_timeout_and_error(self):
        import os
        import sys
        result = adapter.invoke([sys.executable, "-c", "import time; time.sleep(2)"], Path.cwd(), dict(os.environ), 0.02)
        self.assertEqual(result["error"], "timeout")
        result = adapter.invoke(["/missing/reachability-tool"], Path.cwd(), {}, 1)
        self.assertEqual(result["error"], "process-error")
        result = adapter.invoke([sys.executable, "-c", "print('static')"], Path.cwd(), dict(os.environ), 1)
        self.assertEqual(result["stdout"].strip(), "static")



if __name__ == "__main__":
    unittest.main()

class ScanIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.host = self.root / "host"
        self.dep = self.root / "dep"
        self.db = self.root / "db"
        for path in [self.host, self.dep, self.db]:
            path.mkdir()
        (self.host / "go.mod").write_text("module host\nrequire golang.org/x/text v0.3.5\n")
        (self.dep / "go.mod").write_text("module golang.org/x/text\n")
        (self.db / "advisory.json").write_text("{}")
        self.tool = self.root / "govulncheck"
        self.tool.write_text("tool fixture")
        self.cache = self.root / "cache"

    def tearDown(self):
        self.temp.cleanup()

    def fake_run(self, command, cwd, env, timeout):
        raw = (json.dumps({"Path": adapter.TARGET["module"], "Version": adapter.TARGET["version"], "Dir": str(self.dep.resolve())}) if "list" in command else "go version go1.27.0 darwin/arm64\n" if command[-1] == "version" else "darwin\narm64\n\n" if "env" in command else stream(True))
        return observed_run(command, raw)

    def run_scan(self, **kwargs):
        options = {"dependency": self.dep, "db": self.db, "cache": self.cache}
        options.update(kwargs)
        output = self.root / ("output-" + str(len(list(self.root.glob("output-*")))))
        return adapter.scan(self.host, output, self.tool, **options)

    def test_complete_cache_hit_and_corrupt_cache_recompute(self):
        with patch("adapter.invoke", side_effect=self.fake_run) as call:
            first = self.run_scan()
            self.assertEqual(first["status"], "reachable")
            self.assertFalse(first["cache"]["hit"])
            second = self.run_scan()
            self.assertTrue(second["cache"]["hit"])
            self.assertEqual(call.call_count, 7)
            (self.cache / (first["cache_key"] + ".json")).write_text("broken")
            third = self.run_scan()
            self.assertFalse(third["cache"]["hit"])
            self.assertEqual(third["status"], "reachable")
            entry = self.cache / (third["cache_key"] + ".json")
            data = json.loads(entry.read_text())
            data["run"]["stdout"] = stream()
            entry.write_text(json.dumps(data))
            self.assertFalse(self.run_scan()["cache"]["hit"])

    def test_db_source_target_and_tags_change_invalidate(self):
        with patch("adapter.invoke", side_effect=self.fake_run):
            baseline = self.run_scan()
            for target, tags in [("linux/amd64", ""), ("darwin/arm64", "custom")]:
                changed = self.run_scan(target=target, tags=tags)
                self.assertNotEqual(baseline["cache_key"], changed["cache_key"])
            (self.db / "advisory.json").write_text('{"changed":true}')
            self.assertNotEqual(baseline["cache_key"], self.run_scan()["cache_key"])

    def test_validation_and_toolchain_fail_closed(self):
        self.assertEqual(self.run_scan(dependency=None)["status"], "unknown")
        (self.host / "go.mod").write_text("replace anything\n")
        self.assertEqual(self.run_scan()["status"], "unknown")
        (self.host / "go.mod").write_text("module host\nrequire golang.org/x/text v0.3.5\n")
        with patch("adapter.shutil.which", return_value=None):
            self.assertEqual(self.run_scan()["reason"], "missing-go")
        with patch("adapter.invoke", return_value={"returncode": 1}):
            self.assertEqual(self.run_scan()["reason"], "toolchain-error")
        with patch("adapter.invoke", side_effect=self.fake_run):
            self.assertEqual(self.run_scan(target="invalid")["status"], "unknown")
        (self.dep / "go.mod").write_text("module wrong\n")
        self.assertEqual(self.run_scan()["status"], "unknown")

    def test_timeout_and_mutation_never_cached(self):
        def timeout_run(command, cwd, env, timeout):
            if command[0] == str(self.tool.resolve()):
                return {"command": command, "returncode": -1, "stdout": stream(True), "stderr": "", "seconds": 120, "error": "timeout"}
            return self.fake_run(command, cwd, env, timeout)
        with patch("adapter.invoke", side_effect=timeout_run):
            self.assertEqual(self.run_scan()["reason"], "timeout")
            self.assertFalse(self.cache.exists())
        def mutation(command, cwd, env, timeout):
            result = self.fake_run(command, cwd, env, timeout)
            if command[0] == str(self.tool.resolve()):
                (self.host / "main.go").write_text("mutated")
            return result
        with patch("adapter.invoke", side_effect=mutation):
            self.assertEqual(self.run_scan()["reason"], "source-changed-during-scan")
            self.assertFalse(self.cache.exists())

    def test_lock_busy_is_unknown(self):
        with patch("adapter.invoke", side_effect=self.fake_run), patch("adapter.fcntl.flock", side_effect=BlockingIOError):
            self.assertEqual(self.run_scan()["reason"], "busy-one-inflight")

    def test_input_output_overlap(self):
        result = adapter.scan(self.host, self.host / "output", self.tool, dependency=self.dep, db=self.db)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse((self.host / "output").exists())

    def test_resolved_dependency_mismatch_unknown(self):
        def wrong_source(command, cwd, env, timeout):
            result = self.fake_run(command, cwd, env, timeout)
            if "list" in command:
                result["stdout"] = json.dumps({"Path": adapter.TARGET["module"], "Version": adapter.TARGET["version"], "Dir": "/wrong/source"})
            return result
        with patch("adapter.invoke", side_effect=wrong_source):
            self.assertEqual(self.run_scan()["status"], "unknown")

    def test_zero_exit_with_timeout_is_unknown_and_not_cached(self):
        def timed_out(command, cwd, env, timeout):
            result = self.fake_run(command, cwd, env, timeout)
            if command[0] == str(self.tool.resolve()):
                result["error"] = "timeout"
            return result
        with patch("adapter.invoke", side_effect=timed_out):
            result = self.run_scan()
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], "timeout")
            self.assertFalse(self.cache.exists())
            self.assertIn("run", result)
            self.assertTrue(list(self.root.glob("output-*/raw.jsons")))

    def test_postscan_symlink_or_read_error_is_unknown_preserving_raw(self):
        for mode in ("symlink", "read-error"):
            with self.subTest(mode=mode):
                finished = [False]
                original_hash = adapter.tree_hash
                def changing_tool(command, cwd, env, timeout):
                    result = self.fake_run(command, cwd, env, timeout)
                    if command[0] == str(self.tool.resolve()):
                        finished[0] = True
                        if mode == "symlink":
                            (self.host / "changed-link").symlink_to(self.dep / "go.mod")
                    return result
                def hash_source(path):
                    if mode == "read-error" and finished[0]:
                        raise OSError("source cannot be reread")
                    return original_hash(path)
                with patch("adapter.invoke", side_effect=changing_tool), patch("adapter.tree_hash", side_effect=hash_source):
                    result = self.run_scan()
                if (self.host / "changed-link").is_symlink():
                    (self.host / "changed-link").unlink()
                self.assertEqual(result["status"], "unknown")
                self.assertFalse(self.cache.exists())
                self.assertIn("run", result)
                self.assertTrue(list(self.root.glob("output-*/raw.jsons")))

    def test_corrupt_cache_missing_metadata_falls_back(self):
        with patch("adapter.invoke", side_effect=self.fake_run):
            first = self.run_scan()
            path = self.cache / (first["cache_key"] + ".json")
            for field in ("seconds", "command", "stderr", "error", "returncode"):
                data = json.loads(path.read_text())
                del data["run"][field]
                path.write_text(json.dumps(data))
                result = self.run_scan()
                self.assertEqual(result["status"], "reachable")
                self.assertFalse(result["cache"]["hit"])


    def test_valid_cached_observation_cannot_override_postscan_failure(self):
        with patch("adapter.invoke", side_effect=self.fake_run):
            first = self.run_scan()
            cachefile = self.cache / (first["cache_key"] + ".json")
            original_cache = cachefile.read_bytes()
            count = [0]
            original_hash = adapter.tree_hash
            def failed_revalidation(path):
                count[0] += 1
                if count[0] == 4:
                    raise OSError("postscan read failure")
                return original_hash(path)
            with patch("adapter.tree_hash", side_effect=failed_revalidation):
                result = self.run_scan()
            self.assertEqual(result["status"], "unknown")
            self.assertTrue(result["cache"]["hit"])
            self.assertFalse(result["cache"]["accepted"])
            self.assertEqual(original_cache, cachefile.read_bytes())
            self.assertIn("run", result)


class RunnerTests(unittest.TestCase):
    def test_runner_success_and_setup_failures(self):
        import run_experiment
        for fail in [False, True]:
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "new-run"
                db = Path(temp) / "db"
                db.mkdir()
                (db / "GO-2021-0113.json").write_text("{}")
                def fake(command, cwd, env, timeout):
                    run = observed_run(command, json.dumps({"Dir": temp}))
                    if fail:
                        run.update(returncode=1, error="nonzero-exit")
                    return run
                with patch("sys.argv", ["runner", "--tool", "/tmp/tool", "--db", str(db), "--output", str(output)]), patch("run_experiment.DB_SHA256", adapter.digest(b"{}")), patch("adapter.invoke", side_effect=fake), patch("adapter.scan", return_value={"status": "reachable", "reason": "test", "traces": [[]]}):
                    self.assertEqual(run_experiment.main(), 2 if fail else 0)

    def test_cli_main(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("sys.argv", ["adapter", "--project", temp, "--output", str(Path(temp)/"out"), "--tool", "/missing", "--language", "rust"]), patch("builtins.print"):
                self.assertEqual(adapter.main(), 2)

class OutputSafetyTests(unittest.TestCase):
    def test_adapter_never_overwrites_existing_result(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "run"
            output.mkdir()
            marker = output / "result.json"
            marker.write_text("preserve")
            result = adapter.scan(Path(__file__).parent / "fixtures/called", output, Path("/missing/tool"))
            self.assertEqual(result["reason"], "output-exists")
            self.assertEqual(marker.read_text(), "preserve")

    def test_runner_required_db_and_output(self):
        import run_experiment
        with patch("sys.argv", ["runner", "--tool", "/tmp/tool"]), patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                run_experiment.main()

    def test_runner_rejects_existing_output_without_mutation(self):
        import run_experiment
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            marker = output / "summary.json"
            marker.write_text("preserve")
            with patch("sys.argv", ["runner", "--tool", "/tmp/tool", "--db", temp, "--output", temp]), patch("builtins.print"):
                self.assertEqual(run_experiment.main(), 2)
            self.assertEqual(marker.read_text(), "preserve")

    def test_runner_db_checksum_and_input_overlap(self):
        import run_experiment
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db = root / "db"
            db.mkdir()
            (db / "GO-2021-0113.json").write_text("wrong")
            output = root / "new"
            with patch("sys.argv", ["runner", "--tool", "/tmp/tool", "--db", str(db), "--output", str(output)]), patch("builtins.print"):
                self.assertEqual(run_experiment.main(), 2)
                self.assertFalse(output.exists())
            with patch("sys.argv", ["runner", "--tool", "/tmp/tool", "--db", str(db), "--output", str(db / "new")]), patch("builtins.print"):
                self.assertEqual(run_experiment.main(), 2)
                self.assertFalse((db / "new").exists())
