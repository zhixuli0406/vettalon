"""Bounded offline diagnostic contracts; these tests never call a real model."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "offline_probe", Path(__file__).parents[1] / "offline-probe.py"
)
offline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(offline)


class OfflineProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def payload(self):
        return {
            "model": offline.MODEL,
            "messages": [{"role": "user", "content": offline.MARKER}],
            "max_tokens": 256,
            "stream": False,
            "temperature": 0.0,
        }

    def test_clean_env_drops_proxy_credentials_and_separates_home(self):
        with patch.dict(
            offline.os.environ,
            {
                "HTTP_PROXY": "http://proxy.invalid",
                "OPENAI_API_KEY": "dummy-never-copy",
                "HOME": "/original/home",
            },
            clear=False,
        ):
            env = offline.clean_environment(self.root / "home", self.root / "tmp")
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertEqual(env["HOME"], str(self.root / "home"))
        self.assertEqual(env["OLLAMA_CONTEXT_LENGTH"], "4096")
        self.assertEqual(env["OLLAMA_KEEP_ALIVE"], "0")
        self.assertEqual(env["OLLAMA_NOPRUNE"], "true")

    def test_policy_allows_loopback_and_denies_models_writes(self):
        policy = offline.policy_text(self.root / "models", self.root / "readonly")
        self.assertIn("(deny network*)", policy)
        self.assertIn("localhost:*", policy)
        self.assertIn("(deny file-write*", policy)
        self.assertIn(str(self.root / "models"), policy)
        self.assertNotIn("(allow network*)", policy)

    def test_manifest_digest_layers_and_sizes(self):
        models = self.root / "models"
        manifest = models / "manifests/registry.ollama.ai/library/qwen2.5-coder/7b"
        manifest.parent.mkdir(parents=True)
        blob = b"dummy model bytes"
        digest = hashlib.sha256(blob).hexdigest()
        (models / "blobs").mkdir()
        (models / "blobs" / ("sha256-" + digest)).write_bytes(blob)
        raw = json.dumps(
            {"layers": [{"digest": "sha256:" + digest, "size": len(blob)}]}
        ).encode()
        manifest.write_bytes(raw)
        info = offline.inspect_model(models, hashlib.sha256(raw).hexdigest())
        self.assertEqual(info["layer_bytes"], len(blob))
        self.assertEqual(info["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):
            offline.inspect_model(models, "f" * 64)
        (models / "blobs" / ("sha256-" + digest)).write_bytes(b"wrong")
        with self.assertRaises(ValueError):
            offline.inspect_model(models, hashlib.sha256(raw).hexdigest())

    def test_one_completion_reserved_even_when_upstream_fails(self):
        gate = offline.CompletionGate(self.root, offline.MODEL)
        native = gate.reserve("/v1/chat/completions", self.payload())
        self.assertEqual(
            native["options"], {"num_ctx": 4096, "num_predict": 256, "temperature": 0.0}
        )
        self.assertEqual(native["keep_alive"], 0)
        with self.assertRaises(ValueError):
            gate.reserve("/v1/chat/completions", self.payload())
        state = json.loads((self.root / "completion-state.json").read_text())
        self.assertEqual(state["reserved"], 1)
        self.assertEqual(state["attempts"], 2)
        self.assertEqual(state["rejected"], 1)
        self.assertTrue((self.root / "completion-1-openai-request.json").exists())
        self.assertTrue((self.root / "completion-1-native-request.json").exists())

    def test_wrong_tokens_model_stream_or_missing_marker_never_forward(self):
        cases = [
            {"max_tokens": 257},
            {"model": "other"},
            {"stream": True},
            {"messages": [{"role": "user", "content": "not fixture"}]},
        ]
        for index, change in enumerate(cases):
            folder = self.root / str(index)
            folder.mkdir()
            gate = offline.CompletionGate(folder, offline.MODEL)
            payload = self.payload()
            payload.update(change)
            with self.assertRaises(ValueError):
                gate.reserve("/v1/chat/completions", payload)
            self.assertEqual(gate.reserved, 0)

    def test_envelope_preserves_content_and_raw_digest(self):
        gate = offline.CompletionGate(self.root, offline.MODEL)
        gate.reserve("/v1/chat/completions", self.payload())
        gate.mark_upstream_attempt()
        raw = json.dumps(
            {
                "model": offline.MODEL,
                "message": {"content": " []\n"},
                "done": True,
                "done_reason": "stop",
            }
        ).encode()
        reply = gate.record_response(raw)
        self.assertEqual(reply["choices"][0]["message"]["content"], " []\n")
        self.assertEqual(
            (self.root / "completion-1-model-content.txt").read_text(), " []\n"
        )
        state = json.loads((self.root / "completion-state.json").read_text())
        self.assertEqual(state["response_sha256"], hashlib.sha256(raw).hexdigest())

    def test_policy_success_requires_real_eperm_in_both_processes(self):
        good = {
            "supervisor": {"external": {"errno": 1}, "loopback": True},
            "child": {"external": {"errno": 1}, "loopback": True},
            "readonly": {"errno": 1, "unchanged": True},
        }
        self.assertTrue(offline.policy_passed(good))
        good["child"]["external"]["errno"] = 60
        self.assertFalse(offline.policy_passed(good))

    def test_diagnostic_never_complete_after_parse_retry_or_cleanup_failure(self):
        summary = {
            "reserved": 1,
            "upstream_attempts": 1,
            "response_validated": True,
            "attempts": 1,
            "response_received": True,
            "source_marker_observed": True,
            "rejected": 0,
        }
        report = {"run_status": "complete"}
        self.assertEqual(offline.final_status(summary, 0, report, True), "complete")
        self.assertEqual(
            offline.final_status(
                {**summary, "attempts": 2, "rejected": 1}, 0, report, True
            ),
            "incomplete",
        )
        self.assertEqual(offline.final_status(summary, 0, report, False), "incomplete")
        self.assertEqual(
            offline.final_status(summary, 0, {"run_status": "incomplete"}, True),
            "incomplete",
        )

    def test_existing_or_model_overlapping_outputs_refused_before_write(self):
        models = self.root / "models"
        models.mkdir()
        for output in (models, models / "new-probe"):
            argv = [
                "offline-probe",
                "--diagnose-policy",
                "--models",
                str(models),
                "--output",
                str(output),
            ]
            with (
                patch.object(offline.sys, "argv", argv),
                patch.object(offline.subprocess, "Popen") as spawn,
                self.assertRaises(SystemExit),
            ):
                offline.main()
            spawn.assert_not_called()
        self.assertEqual(list(models.iterdir()), [])

    def test_native_incomplete_length_or_over_cap_keeps_raw_and_fails(self):
        for index, change in enumerate(
            (
                {"done": False},
                {"done_reason": "length"},
                {"eval_count": 257},
                {"eval_count": True},
            )
        ):
            output = self.root / str(index)
            output.mkdir()
            gate = offline.CompletionGate(output, offline.MODEL)
            gate.reserve("/v1/chat/completions", self.payload())
            gate.mark_upstream_attempt()
            value = {
                "model": offline.MODEL,
                "message": {"content": "[]"},
                "done": True,
                "done_reason": "stop",
                "eval_count": 2,
            }
            value.update(change)
            raw = json.dumps(value).encode()
            with self.assertRaises(ValueError):
                gate.record_response(raw)
            self.assertEqual(
                (output / "completion-1-native-response.raw").read_bytes(), raw
            )
            self.assertEqual(
                (output / "completion-1-model-content.txt").read_text(), "[]"
            )
            self.assertFalse(gate.snapshot()["response_validated"])

    def test_reservation_is_not_an_upstream_attempt(self):
        gate = offline.CompletionGate(self.root, offline.MODEL)
        gate.reserve("/v1/chat/completions", self.payload())
        self.assertEqual(gate.snapshot()["reserved"], 1)
        self.assertEqual(gate.snapshot()["upstream_attempts"], 0)
        gate.mark_upstream_attempt()
        self.assertEqual(gate.snapshot()["upstream_attempts"], 1)
        with self.assertRaises(ValueError):
            gate.mark_upstream_attempt()

    def test_counting_proxy_forwards_only_one_real_http_fixture(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading, urllib.request, urllib.error

        hits = []

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(
                    json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                )
                raw = json.dumps(
                    {
                        "model": offline.MODEL,
                        "message": {"content": "[]"},
                        "done": True,
                        "done_reason": "stop",
                        "eval_count": 2,
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        t = threading.Thread(target=upstream.serve_forever, daemon=True)
        t.start()
        gate = offline.CompletionGate(self.root, offline.MODEL)
        proxy, thread = offline.proxy_server(self.root, upstream.server_port, gate)
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{proxy.server_port}/v1/chat/completions",
                data=json.dumps(self.payload()).encode(),
                headers={"Content-Type": "application/json"},
            )
            with offline.opener().open(request, timeout=3) as response:
                reply = json.loads(response.read())
            self.assertEqual(reply["choices"][0]["message"]["content"], "[]")
            with self.assertRaises(urllib.error.HTTPError) as error:
                offline.opener().open(request, timeout=3)
            self.assertEqual(error.exception.code, 429)
            self.assertEqual(len(hits), 1)
            self.assertEqual(gate.snapshot()["upstream_attempts"], 1)
            self.assertTrue(gate.snapshot()["response_validated"])
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join()
            upstream.shutdown()
            upstream.server_close()
            t.join()

    def test_supervisor_policy_failure_never_starts_daemon_and_persists(self):
        from types import SimpleNamespace

        args = SimpleNamespace(
            output=self.root,
            diagnose_policy=False,
            models=self.root / "models",
            expected_digest=offline.EXPECTED_DIGEST,
            ollama=self.root / "ollama",
            binary=self.root / "binary",
        )
        with (
            patch.object(offline, "diagnose_policy", return_value={"passed": False}),
            patch.object(offline.subprocess, "Popen") as spawn,
        ):
            self.assertEqual(offline.supervisor(args), 1)
        spawn.assert_not_called()
        record = json.loads((self.root / "supervisor-result.json").read_text())
        self.assertEqual(record["status"], "incomplete")
        self.assertTrue(record["errors"])

    def test_group_cleanup_failure_is_not_success(self):
        with patch.object(
            offline, "group_members", side_effect=OSError("fixture ps failure")
        ):
            self.assertFalse(offline.cleanup_group(12345)["ok"])

    def test_model_response_identity_must_match_selected_model(self):
        gate = offline.CompletionGate(self.root, offline.MODEL)
        gate.reserve("/v1/chat/completions", self.payload())
        gate.mark_upstream_attempt()
        raw = json.dumps(
            {
                "model": "other-model",
                "message": {"content": "[]"},
                "done": True,
                "done_reason": "stop",
                "eval_count": 2,
            }
        ).encode()
        with self.assertRaises(ValueError):
            gate.record_response(raw)
        self.assertEqual(
            (self.root / "completion-1-native-response.raw").read_bytes(), raw
        )

    def test_oversize_upstream_response_keeps_only_bounded_partial(self):
        import io, threading, urllib.request, urllib.error

        class FakeOpener:
            def open(self, *args, **kwargs):
                return io.BytesIO(b"x" * (2 * 1024 * 1024 + 1))

        gate = offline.CompletionGate(self.root, offline.MODEL)
        server, thread = offline.proxy_server(self.root, 12345, gate)
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                data=json.dumps(self.payload()).encode(),
                headers={"Content-Type": "application/json"},
            )
            with (
                patch.object(offline, "opener", return_value=FakeOpener()),
                self.assertRaises(urllib.error.HTTPError),
            ):
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    request, timeout=3
                )
            self.assertEqual(
                (self.root / "completion-1-response.partial").stat().st_size,
                2 * 1024 * 1024,
            )
            note = json.loads((self.root / "response-truncation.json").read_text())
            self.assertTrue(note["truncated"])
            self.assertFalse(gate.snapshot()["response_validated"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def good_policy(self):
        return {
            "supervisor": {"external": {"errno": 1}, "loopback": True},
            "child": {"external": {"errno": 1}, "loopback": True},
            "readonly": {"errno": 1, "unchanged": True},
        }

    def test_cli_timeout_retains_incomplete_and_stops_own_children(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        args = SimpleNamespace(
            output=self.root,
            diagnose_policy=False,
            models=self.root / "models",
            expected_digest=offline.EXPECTED_DIGEST,
            ollama=self.root / "ollama",
            binary=self.root / "binary",
        )
        daemon = Mock(pid=100)
        daemon.poll.return_value = None
        daemon.wait.return_value = 0
        cli = Mock(pid=101)
        cli.wait.side_effect = [
            offline.subprocess.TimeoutExpired("fixture-cli", 125),
            0,
        ]
        proxy = Mock(server_port=12345)
        thread = Mock()
        tags = {"models": [{"name": offline.MODEL, "digest": offline.EXPECTED_DIGEST}]}
        with (
            patch.object(offline, "diagnose_policy", return_value=self.good_policy()),
            patch.object(
                offline, "inspect_model", return_value={"fixture": "modelmetadata"}
            ),
            patch.object(offline, "free_port", return_value=12344),
            patch.object(offline, "get_json", side_effect=[tags, {"models": []}]),
            patch.object(offline, "proxy_server", return_value=(proxy, thread)),
            patch.object(
                offline.subprocess, "Popen", side_effect=[daemon, cli]
            ) as spawn,
        ):
            self.assertEqual(offline.supervisor(args), 1)
        self.assertEqual(spawn.call_count, 2)
        cli.terminate.assert_called_once()
        daemon.terminate.assert_called_once()
        result = json.loads((self.root / "supervisor-result.json").read_text())
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["completion"]["upstream_attempts"], 0)
        self.assertTrue(any(x["kind"] == "TimeoutError" for x in result["errors"]))

    def test_daemon_start_failure_never_launches_cli(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        args = SimpleNamespace(
            output=self.root,
            diagnose_policy=False,
            models=self.root / "models",
            expected_digest=offline.EXPECTED_DIGEST,
            ollama=self.root / "ollama",
            binary=self.root / "binary",
        )
        daemon = Mock(pid=100)
        daemon.poll.return_value = 1
        daemon.wait.return_value = 1
        with (
            patch.object(offline, "diagnose_policy", return_value=self.good_policy()),
            patch.object(offline, "inspect_model", return_value={}),
            patch.object(offline, "free_port", return_value=12344),
            patch.object(offline.subprocess, "Popen", return_value=daemon) as spawn,
        ):
            self.assertEqual(offline.supervisor(args), 1)
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(
            json.loads((self.root / "supervisor-result.json").read_text())["status"],
            "incomplete",
        )

    def test_outer_timeout_cleanup_is_persisted_without_inference(self):
        from unittest.mock import Mock
        import io

        actual_is_file = offline.Path.is_file
        output = self.root / "timeout"
        process = Mock(pid=1234)
        process.wait.side_effect = offline.subprocess.TimeoutExpired(
            "fixture-supervisor", 160
        )
        process.poll.return_value = 0
        with (
            patch.object(
                offline.sys,
                "argv",
                ["offline-probe", "--diagnose-policy", "--output", str(output)],
            ),
            patch.object(offline.sys, "platform", "darwin"),
            patch.object(
                offline.Path,
                "is_file",
                autospec=True,
                side_effect=lambda path: path == Path("/usr/bin/sandbox-exec")
                or actual_is_file(path),
            ),
            patch.object(offline.subprocess, "Popen", return_value=process),
            patch.object(
                offline,
                "cleanup_group",
                return_value={"ok": False, "remaining": [{"pid": 1234}]},
            ),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(offline.main(), 1)
        result = json.loads((output / "result.json").read_text())
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["status"], "incomplete")

    def test_no_action_does_not_start_any_process(self):
        with (
            patch.object(offline.subprocess, "Popen") as spawn,
            patch.object(offline.sys, "argv", ["offline-probe"]),
        ):
            with self.assertRaises(SystemExit):
                offline.main()
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
