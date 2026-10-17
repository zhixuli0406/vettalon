"""Bounds use only self-authored processes and normal loopback fixture data."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("bounded_dataflow_probe", Path(__file__).parents[1] / "dataflow-probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
NORMAL_CLI = """import json,pathlib,sys,tomllib,urllib.request
args=sys.argv
config=tomllib.loads(pathlib.Path(args[args.index('--config')+1]).read_text())
body=json.dumps({'content':pathlib.Path(args[2]+'/app.py').read_text()}).encode()
with urllib.request.urlopen(urllib.request.Request(config['model'][0]['base_url']+'/chat/completions',data=body)) as response: response.read()
sys.exit(1)
"""


class HTTPBoundsTests(unittest.TestCase):
    def server(self, seconds=.35, **limits):
        server = probe.FixtureHTTP(time.monotonic() + seconds, **limits)
        server.start()
        self.addCleanup(lambda: server.stop(time.monotonic() + .5))
        return server

    def send(self, server, raw):
        with socket.create_connection(("127.0.0.1", server.port), timeout=.5) as connection:
            connection.sendall(raw)
            try: return connection.recv(4096)
            except ConnectionResetError: return b""

    def test_valid_marker_only_complete_json_records_capture(self):
        server = self.server()
        body = json.dumps({"content": probe.MARKER}).encode()
        self.assertIn(b"200", self.send(server, b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body))
        cleanup = server.stop(time.monotonic() + .5)
        self.assertTrue(cleanup["cleanup_complete"])
        snapshot = server.snapshot()
        self.assertEqual(len(snapshot["captures"]), 1)
        self.assertEqual(snapshot["errors"], [])

    def test_invalid_framing_never_captured(self):
        for header in (b"", b"Content-Length: -1\r\n", b"Content-Length: x\r\n",
                       b"Content-Length: 2\r\nContent-Length: 2\r\n",
                       b"Content-Length: 9999999\r\n", b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n"):
            with self.subTest(header=header):
                server = self.server()
                self.send(server, b"POST /x HTTP/1.1\r\n" + header + b"\r\n{}")
                self.assertTrue(server.stop(time.monotonic() + .5)["cleanup_complete"])
                self.assertEqual(server.snapshot()["captures"], [])
                self.assertTrue(server.snapshot()["errors"])

    def test_idle_partial_header_and_slow_body_share_absolute_deadline(self):
        for initial in (b"", b"POST / HTTP/1.1\r\n", b"POST / HTTP/1.1\r\nContent-Length: 30\r\n\r\n{"):
            server = self.server(seconds=.2)
            connection = socket.create_connection(("127.0.0.1", server.port), timeout=.5)
            connection.sendall(initial)
            started = time.monotonic()
            for _ in range(8):
                time.sleep(.04)
                try: connection.sendall(b" ")
                except OSError: break
            connection.close()
            cleanup = server.stop(time.monotonic() + .5)
            self.assertLess(time.monotonic() - started, .8)
            self.assertTrue(cleanup["cleanup_complete"])
            self.assertTrue(server.snapshot()["errors"])
            self.assertEqual(server.snapshot()["captures"], [])

    def test_body_header_and_total_caps_are_distinct(self):
        server = self.server(body_cap=8, total_body_cap=10, header_cap=128, total_header_cap=256, request_limit=2)
        for raw in (b"{}", b"{}"):
            self.send(server, b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n" + raw)
        server.stop(time.monotonic() + .5)
        snapshot = server.snapshot()
        self.assertLessEqual(snapshot["admitted_connections"], 2)
        self.assertLessEqual(snapshot["body_retained_bytes"], 10)

    def test_connection_deadline_does_not_extend_to_longer_global_budget(self):
        server = self.server(seconds=1, connection_seconds=.12)
        with socket.create_connection(("127.0.0.1", server.port), timeout=.5) as connection:
            connection.sendall(b"POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n{")
            time.sleep(.2)
            self.assertEqual(connection.recv(1), b"")
        server.stop(time.monotonic() + .5)
        self.assertIn("http-total-deadline", server.snapshot()["errors"])

    def test_cumulative_body_cap_and_partial_raw_retention(self):
        server = self.server(body_cap=8, total_body_cap=3)
        self.send(server, b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
        self.send(server, b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
        server.stop(time.monotonic() + .5)
        snapshot = server.snapshot()
        self.assertEqual(len(snapshot["captures"]), 1)
        self.assertTrue(snapshot["errors"])
        self.assertLessEqual(snapshot["body_retained_bytes"], 3)

    def test_invalid_json_utf8_and_oversized_header_preserve_raw_unknown(self):
        for body in (b"{", b"\xff", b'{"a":1,"a":2}', b'{"a":NaN}',
                     ('{"content":"'+probe.MARKER+'","number":1e999}').encode()):
            server = self.server()
            self.send(server, b"POST / HTTP/1.1\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            self.assertTrue(server.stop(time.monotonic() + .5)["cleanup_complete"])
            snapshot = server.snapshot()
            self.assertEqual(snapshot["captures"], [])
            self.assertTrue(snapshot["errors"])
            self.assertTrue(snapshot["events"][0]["body_base64"])
        server = self.server(header_cap=64, total_header_cap=128)
        self.send(server, b"POST / HTTP/1.1\r\nX-Test: " + b"x" * 100)
        server.stop(time.monotonic() + .5)
        self.assertLessEqual(server.snapshot()["header_retained_bytes"], 64)
        self.assertTrue(server.snapshot()["errors"])


class ProcessBoundsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def executable(self, source):
        path = self.root / "self-authored-cli"
        path.write_text("#!" + sys.executable + "\n" + source)
        path.chmod(0o755)
        return path

    def run_probe(self, source, **limits):
        return probe.run_probe(self.executable(source), self.root / "output", timeout_seconds=2.5, **limits)

    def test_large_output_is_capped_and_incomplete(self):
        record = self.run_probe("import os\nos.write(1,b'x'*20000)\n", stdout_cap=1024)
        self.assertEqual(record["status"], "incomplete")
        self.assertLessEqual((self.root / "output/stdout.txt").stat().st_size, 1024)
        self.assertTrue(record["cli"]["captures"]["stdout"]["truncated"])
        self.assertFalse(record["cleanup_complete"])
        self.assertIsNone(record["cli_cleanup_complete"])

    def test_timeout_and_child_inherited_pipe_exit_are_owned(self):
        source = "import os,time\nif os.fork()==0:\n time.sleep(20)\nelse:\n os._exit(0)\n"
        record = self.run_probe(source)
        self.assertEqual(record["status"], "incomplete")
        self.assertTrue(record["cleanup_complete"])
        self.assertFalse(record["source_marker_observed"])
        self.assertLess(record["wall_seconds"], 3)

    def test_timeout_retains_partial_stdout_and_stderr(self):
        record = self.run_probe("import os,time\nos.write(1,b'partial stdout');os.write(2,b'partial stderr');time.sleep(20)\n")
        self.assertTrue(record["timed_out"])
        self.assertEqual((self.root / "output/stdout.txt").read_bytes(), b"partial stdout")
        self.assertEqual((self.root / "output/stderr.txt").read_bytes(), b"partial stderr")

    def test_stderr_cap_and_invalid_utf8_are_not_clean(self):
        record = self.run_probe("import os\nos.write(2,b'\\xff'*12000)\n", stderr_cap=512)
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual((self.root / "output/stderr.txt").stat().st_size, 512)
        self.assertTrue(record["cli"]["captures"]["stderr"]["decode_error"])

    def test_marker_then_timeout_preserves_observation_and_clean_environment(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "disposable-test-sentinel"}):
            record = self.run_probe("""import json,os,pathlib,sys,time,tomllib,urllib.request
args=sys.argv
config=tomllib.loads(pathlib.Path(args[args.index('--config')+1]).read_text())
body=json.dumps({'content':pathlib.Path(args[2]+'/app.py').read_text()}).encode()
url=config['model'][0]['base_url']+'/chat/completions'
with urllib.request.urlopen(urllib.request.Request(url,data=body)) as response: response.read()
assert 'ANTHROPIC_API_KEY' not in os.environ
os.write(1,b'partial marker');time.sleep(20)
""")
        self.assertTrue(record["source_marker_observed"])
        self.assertTrue(record["timed_out"])
        self.assertEqual(record["requests"], 1)
        self.assertEqual(record["status"], "incomplete")

    def test_normal_transport_and_findings_exit_one_are_complete(self):
        record = self.run_probe(NORMAL_CLI)
        self.assertEqual(record["status"], "complete")
        self.assertEqual(record["exit_code"], 1)
        self.assertTrue(record["cleanup_complete"])

    def test_real_missing_binary_retains_failure_and_denominator(self):
        record = probe.run_probe(self.root / "absent", self.root / "output", timeout_seconds=2.5)
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["error"]["kind"], "cli_start_error")
        self.assertEqual(record["requests"], 0)
        self.assertEqual(record["limits"]["cli_attempts"], 1)

    def test_credentials_are_not_forwarded_to_cli(self):
        source = "import os\nassert 'ANTHROPIC_API_KEY' not in os.environ\nassert 'HTTPS_PROXY' not in os.environ\n" + NORMAL_CLI
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "self-authored-dummy", "HTTPS_PROXY": "self-authored-dummy"}):
            record = self.run_probe(source)
        self.assertEqual(record["status"], "complete")

    def test_invocation_oserror_is_debited_before_call_without_retry(self):
        output = self.root / "output"
        def failure(*args, **kwargs):
            self.assertTrue((output / "cli-attempt.json").is_file())
            raise OSError("self-authored-start-failure")
        with patch.object(probe, "invoke", side_effect=failure) as invoke:
            record = probe.run_probe(self.root / "absent", output, timeout_seconds=2.5)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["limits"]["cli_attempts"], 1)
        self.assertIsNone(record["cli_cleanup_complete"])

    def test_fixture_thread_start_failure_retains_evidence_without_cli_attempt(self):
        output = self.root / "output"
        stopped_servers = []
        original_stop = probe.FixtureHTTP.stop
        def record_stop(server, deadline):
            stopped_servers.append(server)
            return original_stop(server, deadline)
        with patch.object(probe.FixtureHTTP, "start", side_effect=RuntimeError("self-authored-thread-start-failure")), \
                patch.object(probe.FixtureHTTP, "stop", record_stop), \
                patch.object(probe, "invoke") as invoke:
            record = probe.run_probe(self.root / "absent", output, timeout_seconds=2.5)
        invoke.assert_not_called()
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["error"]["kind"], "fixture_start_error")
        self.assertEqual(record["limits"]["cli_attempts"], 0)
        self.assertIsNone(record["cli_cleanup_complete"])
        self.assertEqual(record["requests"], 0)
        self.assertFalse(record["source_marker_observed"])
        self.assertTrue(record["fixture_cleanup"]["cleanup_complete"])
        self.assertFalse(record["fixture_cleanup"]["thread_alive"])
        self.assertTrue(record["fixture_cleanup"]["owned_connections_closed"])
        self.assertEqual(len(stopped_servers), 1)
        self.assertEqual(stopped_servers[0].listener.fileno(), -1)
        self.assertFalse(stopped_servers[0].thread.is_alive())
        self.assertFalse((output / "cli-attempt.json").exists())
        self.assertEqual((output / "stdout.txt").read_bytes(), b"")
        self.assertEqual((output / "stderr.txt").read_bytes(), b"")
        self.assertEqual(json.loads((output / "requests.json").read_text()), [])
        self.assertEqual(json.loads((output / "http-events.json").read_text()), [])
        self.assertEqual(json.loads((output / "result.json").read_text()), record)

    def test_output_symlinks_are_rejected_before_write(self):
        real = self.root / "real"; real.mkdir()
        link = self.root / "parent-link"; link.symlink_to(real, target_is_directory=True)
        dangling = self.root / "dangling"; dangling.symlink_to(self.root / "absent-target")
        for output in (link, dangling):
            with self.assertRaisesRegex(ValueError, "^output-symlink$"):
                probe.run_probe(self.root / "absent", output)
        self.assertFalse((real / "new-output").exists())
        self.assertFalse((self.root / "absent-target").exists())
        self.assertEqual(list(real.iterdir()), [])

    def test_only_tighter_finite_limits_are_allowed(self):
        for kwargs in ({"timeout_seconds": float("nan")}, {"timeout_seconds": True},
                       {"timeout_seconds": 91}, {"stdout_cap": True}, {"stderr_cap": 262145}):
            with self.assertRaises(ValueError):
                probe.run_probe(self.root / "absent", self.root / "output", **kwargs)
        self.assertFalse((self.root / "output").exists())

    def test_unproved_http_cleanup_cannot_be_complete(self):
        original = probe.FixtureHTTP.stop
        def incomplete(server, deadline):
            result = original(server, deadline); result["cleanup_complete"] = False
            return result
        with patch.object(probe.FixtureHTTP, "stop", incomplete):
            record = self.run_probe(NORMAL_CLI)
        self.assertTrue(record["source_marker_observed"])
        self.assertEqual(record["exit_code"], 1)
        self.assertTrue(record["cli_cleanup_complete"])
        self.assertEqual(record["fixture"]["errors"], [])
        self.assertTrue(record["global_deadline_met"])
        self.assertFalse(record["cleanup_complete"])
        self.assertEqual(record["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
