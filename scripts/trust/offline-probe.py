#!/usr/bin/env python3
"""Opt-in, one-call macOS local-model diagnostic. Never a benchmark or general firewall."""

import argparse
import errno
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

MODEL = "qwen2.5-coder:7b"
EXPECTED_DIGEST = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
MARKER = "VETTALON_OFFLINE_LOCAL_MODEL_SOURCE_MARKER"
LIMITS = {
    "outer_wall_seconds": 180,
    "supervisor_wait_seconds": 160,
    "completion_timeout_seconds": 120,
    "cli_wall_seconds": 125,
    "model_calls": 1,
    "automatic_model_retries": 0,
    "max_tokens": 256,
    "context_length": 4096,
    "parallel": 1,
    "max_loaded_models": 1,
    "keep_alive": 0,
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.replace(path)


def clean_environment(home, temp):
    # Do not copy credentials, proxies, model providers, DYLD overrides or real HOME.
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "TMPDIR": str(temp),
        "LANG": "en_US.UTF-8",
        "NO_PROXY": "127.0.0.1,localhost",
        "OLLAMA_CONTEXT_LENGTH": "4096",
        "OLLAMA_NUM_PARALLEL": "1",
        "OLLAMA_MAX_LOADED_MODELS": "1",
        "OLLAMA_KEEP_ALIVE": "0",
        "OLLAMA_NOPRUNE": "true",
        "OLLAMA_NO_CLOUD": "true",
    }


def policy_text(models, readonly):
    return "\n".join(
        [
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            '(allow network-inbound (local ip "localhost:*"))',
            '(allow network-outbound (remote ip "localhost:*"))',
            "(deny file-write* (subpath "
            + json.dumps(str(Path(models).resolve()))
            + "))",
            "(deny file-write* (subpath "
            + json.dumps(str(Path(readonly).resolve()))
            + "))",
            "",
        ]
    )


def inspect_model(models, expected):
    models = Path(models).resolve()
    manifest = models / "manifests/registry.ollama.ai/library/qwen2.5-coder/7b"
    raw = manifest.read_bytes()
    if digest(raw) != expected:
        raise ValueError("existing model manifest digest mismatch")
    value = json.loads(raw)
    layers = []
    for layer in value.get("layers", []):
        identity = layer["digest"]
        if not identity.startswith("sha256:") or len(identity) != 71:
            raise ValueError("invalid model layer digest")
        blob = models / "blobs" / identity.replace(":", "-")
        if (
            not blob.resolve().is_relative_to(models)
            or blob.stat().st_size != layer["size"]
        ):
            raise ValueError("model layer missing, escaped source or size mismatch")
        layers.append(
            {
                "digest": identity,
                "size": layer["size"],
                "mtime_ns": blob.stat().st_mtime_ns,
            }
        )
    if not layers:
        raise ValueError("model layers missing")
    return {
        "model": MODEL,
        "manifest_sha256": expected,
        "layer_bytes": sum(x["size"] for x in layers),
        "layers": layers,
        "blob_integrity": "existence and size only; full model blobs are not rehashed",
        "models_read_only_policy": True,
    }


class CompletionGate:
    def __init__(self, output, model):
        self.output = Path(output)
        self.model = model
        self.lock = threading.Lock()
        self.attempts = 0
        self.reserved = 0
        self.upstream_attempts = 0
        self.response_validated = False
        self.rejected = 0
        self.response_received = False
        self.source_marker_observed = False
        self.response_sha256 = None

    def snapshot(self):
        return {
            "attempts": self.attempts,
            "reserved": self.reserved,
            "upstream_attempts": self.upstream_attempts,
            "response_validated": self.response_validated,
            "rejected": self.rejected,
            "response_received": self.response_received,
            "source_marker_observed": self.source_marker_observed,
            "response_sha256": self.response_sha256,
        }

    def save(self):
        write_json(self.output / "completion-state.json", self.snapshot())

    def reserve(self, path, payload):
        with self.lock:
            self.attempts += 1
            write_json(
                self.output / f"attempt-{self.attempts}.json",
                {"path": path, "payload": payload},
            )
            valid = (
                path == "/v1/chat/completions"
                and payload.get("model") == self.model
                and payload.get("max_tokens") == 256
                and payload.get("stream") is False
                and MARKER in json.dumps(payload.get("messages", []))
            )
            if self.reserved != 0 or not valid:
                self.rejected += 1
                self.save()
                raise ValueError(
                    "request rejected: one-completion budget or fixture/payload contract"
                )
            self.reserved = (
                1  # Reserve before I/O; an upstream failure never restores budget.
            )
            self.source_marker_observed = True
            native = {
                "model": self.model,
                "messages": payload["messages"],
                "stream": False,
                "keep_alive": 0,
                "options": {"num_ctx": 4096, "num_predict": 256, "temperature": 0.0},
            }
            write_json(self.output / "completion-1-openai-request.json", payload)
            write_json(self.output / "completion-1-native-request.json", native)
            write_json(
                self.output / "request-hashes.json",
                {
                    "openai_sha256": digest(
                        json.dumps(payload, sort_keys=True).encode()
                    ),
                    "native_sha256": digest(
                        json.dumps(native, sort_keys=True).encode()
                    ),
                    "interpretation": "OpenAI envelope adapted to native /api/chat; not native /v1 behavior acceptance",
                },
            )
            self.save()
            return native

    def mark_upstream_attempt(self):
        with self.lock:
            if self.reserved != 1 or self.upstream_attempts != 0:
                raise ValueError("upstream attempt exceeds the one-call reservation")
            self.upstream_attempts = 1
            self.save()

    def record_response(self, raw):
        with self.lock:
            (self.output / "completion-1-native-response.raw").write_bytes(raw)
            self.response_sha256 = digest(raw)
            self.response_received = True
            self.save()
            value = json.loads(raw)
            content = value["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("model content must be text")
            (self.output / "completion-1-model-content.txt").write_text(content)
            write_json(
                self.output / "response-hashes.json",
                {
                    "native_sha256": self.response_sha256,
                    "content_sha256": digest(content.encode()),
                },
            )
            if value.get("model") != self.model:
                raise ValueError(
                    "native response model identity mismatch; raw evidence retained"
                )
            if value.get("done") is not True or value.get("done_reason") != "stop":
                raise ValueError(
                    "native generation incomplete or length-limited; raw evidence retained"
                )
            count = value.get("eval_count")
            if count is not None and (type(count) is not int or not 0 <= count <= 256):
                raise ValueError(
                    "native eval_count invalid or exceeds the 256-token cap"
                )
            reply = {
                "choices": [{"message": {"content": content}, "finish_reason": "stop"}]
            }
            write_json(self.output / "completion-1-openai-response.json", reply)
            write_json(
                self.output / "response-hashes.json",
                {
                    "native_sha256": self.response_sha256,
                    "content_sha256": digest(content.encode()),
                    "openai_sha256": digest(json.dumps(reply, sort_keys=True).encode()),
                    "eval_count": count,
                },
            )
            self.response_validated = True
            self.save()
            return reply


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get_json(url, timeout=2):
    with opener().open(url, timeout=timeout) as response:
        return json.loads(response.read(2 * 1024 * 1024))


def external_probe():
    try:
        with socket.create_connection(("203.0.113.1", 443), timeout=1):
            pass
        return {"errno": None, "unexpected_connect": True}
    except OSError as error:
        return {
            "errno": error.errno,
            "error": type(error).__name__,
            "message": str(error),
        }


def network_child(port):
    local = False
    try:
        local = (
            get_json(f"http://127.0.0.1:{port}/probe").get("fixture") == "local-only"
        )
    except (OSError, ValueError):
        pass
    return {"external": external_probe(), "loopback": local}


def policy_passed(record):
    try:
        return all(
            record[key]["external"]["errno"] == errno.EPERM
            and record[key]["loopback"] is True
            for key in ("supervisor", "child")
        ) and record["readonly"] == {"errno": errno.EPERM, "unchanged": True}
    except (KeyError, TypeError):
        return False


def diagnose_policy(output, env):
    class Probe(BaseHTTPRequestHandler):
        def do_GET(self):
            raw = b'{"fixture":"local-only"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Probe)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    record = {}
    try:
        record["supervisor"] = network_child(server.server_port)
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--_network-child",
            str(server.server_port),
        ]
        result = subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=5
        )
        record["child_process"] = {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        record["child"] = json.loads(result.stdout) if result.returncode == 0 else {}
        sentinel = output / "readonly-probe/sentinel.txt"
        denied = None
        try:
            sentinel.write_text("unexpected permitted write")
        except OSError as error:
            denied = error.errno
        record["readonly"] = {
            "errno": denied,
            "unchanged": sentinel.read_text() == "original dummy bytes",
        }
        record["passed"] = policy_passed(record)
        write_json(output / "policy-diagnostic.json", record)
        return record
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def proxy_server(output, daemon_port, gate):
    class Forward(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024 * 1024:
                    raise ValueError("request size outside fixture cap")
                payload = json.loads(self.rfile.read(length))
                native = gate.reserve(self.path, payload)
            except (ValueError, TypeError, AttributeError) as error:
                self.respond(429, {"error": str(error)})
                return
            try:
                raw_request = json.dumps(native).encode()
                request = urllib.request.Request(
                    f"http://127.0.0.1:{daemon_port}/api/chat",
                    data=raw_request,
                    headers={"Content-Type": "application/json"},
                )
                gate.mark_upstream_attempt()
                with opener().open(request, timeout=120) as response:
                    raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    partial = raw[: 2 * 1024 * 1024]
                    (output / "completion-1-response.partial").write_bytes(partial)
                    write_json(
                        output / "response-truncation.json",
                        {
                            "truncated": True,
                            "observed_at_least_bytes": len(raw),
                            "saved_bytes": len(partial),
                            "partial_sha256": digest(partial),
                        },
                    )
                    raise ValueError(
                        "response exceeded 2 MiB cap; bounded partial saved"
                    )
                reply = gate.record_response(raw)
                self.respond(200, reply)
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                http.client.HTTPException,
            ) as error:
                partial = getattr(error, "partial", b"")
                if isinstance(error, urllib.error.HTTPError):
                    try:
                        partial = error.read(2 * 1024 * 1024)
                    except (OSError, http.client.HTTPException):
                        pass
                if isinstance(partial, bytes) and partial:
                    (output / "completion-1-upstream-error.partial").write_bytes(
                        partial[: 2 * 1024 * 1024]
                    )
                write_json(
                    output / "completion-error.json",
                    {"kind": type(error).__name__, "message": str(error)},
                )
                self.respond(
                    502, {"error": "one model call failed; budget is not restored"}
                )

        def respond(self, status, value):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except OSError:
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Forward)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def final_status(completion, cli_exit, report, cleanup_ok):
    return (
        "complete"
        if (
            cleanup_ok
            and cli_exit in (0, 1)
            and report.get("run_status") == "complete"
            and completion.get("reserved") == 1
            and completion.get("upstream_attempts") == 1
            and completion.get("response_validated") is True
            and completion.get("attempts") == 1
            and completion.get("rejected") == 0
            and completion.get("response_received") is True
            and completion.get("source_marker_observed") is True
        )
        else "incomplete"
    )


def supervisor(args):
    output = args.output.resolve()
    env = clean_environment(output / "home", output / "tmp")
    record = {
        "status": "incomplete",
        "limits": LIMITS,
        "diagnostic_only": args.diagnose_policy,
        "errors": [],
    }
    daemon = None
    server = None
    thread = None
    cli_exit = None
    report = {}
    gate = CompletionGate(output, MODEL)
    cleanup_ok = True
    started = time.monotonic()
    try:
        policy = diagnose_policy(output, env)
        if not policy_passed(policy):
            raise ValueError("OS policy diagnostic failed; no Ollama process started")
        if args.diagnose_policy:
            record["status"] = "policy-diagnostic-complete"
            return 0
        before = inspect_model(args.models, args.expected_digest)
        write_json(output / "model-before.json", before)
        daemon_port = free_port()
        env.update(
            {
                "OLLAMA_HOST": f"127.0.0.1:{daemon_port}",
                "OLLAMA_MODELS": str(args.models.resolve()),
            }
        )
        write_json(output / "daemon-environment.json", env)
        # No new session: daemon and every runner inherit sandbox + supervisor process group.
        with (
            (output / "ollama.stdout.txt").open("w") as stdout,
            (output / "ollama.stderr.txt").open("w") as stderr,
        ):
            daemon = subprocess.Popen(
                [str(args.ollama), "serve"],
                env=env,
                cwd=output,
                stdout=stdout,
                stderr=stderr,
            )
        record["daemon_pid"] = daemon.pid
        record["daemon_port"] = daemon_port
        ready = time.monotonic() + 15
        while True:
            if daemon.poll() is not None:
                raise ValueError("isolated Ollama daemon exited during startup")
            try:
                metadata = get_json(f"http://127.0.0.1:{daemon_port}/api/tags")
                if any(
                    item.get("name") == MODEL
                    and item.get("digest", "").removeprefix("sha256:")
                    == args.expected_digest
                    for item in metadata["models"]
                ):
                    break
                raise ValueError(
                    "isolated daemon metadata does not match expected model digest"
                )
            except (OSError, urllib.error.URLError):
                if time.monotonic() > ready:
                    raise TimeoutError("isolated Ollama metadata readiness timeout")
                time.sleep(0.2)
        write_json(output / "daemon-model-metadata.json", metadata)
        initial_ps = get_json(f"http://127.0.0.1:{daemon_port}/api/ps")
        write_json(output / "daemon-initial-ps.json", initial_ps)
        if initial_ps.get("models") != []:
            raise ValueError("isolated daemon unexpectedly already has a model loaded")
        server, thread = proxy_server(output, daemon_port, gate)
        fixture = output / "fixture"
        fixture.mkdir()
        (fixture / "app.py").write_text(
            f'def fixture_constant():\n    return "{MARKER}"\n'
        )
        roster = output / "roster.toml"
        roster.write_text(
            f'[[model]]\nid="offline-local"\nbackend="openai"\nfamily="qwen"\nmodel="{MODEL}"\nbase_url="http://127.0.0.1:{server.server_port}/v1"\nroles=["finder"]\nmax_tokens=256\ntimeout_secs=120\ntemperature=0.0\n'
        )
        command = [
            str(args.binary),
            "scan",
            str(fixture),
            "--profile",
            "deep",
            "--config",
            str(roster),
            "--finders",
            "offline-local",
            "--max-modules",
            "1",
            "--no-prior",
            "--rank",
            "heuristic",
            "--time-budget",
            "120",
            "--report",
            str(output / "scan.json"),
            "--trace",
            str(output / "trace.jsonl"),
        ]
        record["cli_command"] = command
        record["proxy_port"] = server.server_port
        write_json(output / "supervisor-result.json", record)
        with (
            (output / "cli.stdout.txt").open("w") as stdout,
            (output / "cli.stderr.txt").open("w") as stderr,
        ):
            cli = subprocess.Popen(
                command, env=env, cwd=output, stdout=stdout, stderr=stderr
            )
            try:
                cli_exit = cli.wait(
                    timeout=min(125, max(1, 160 - (time.monotonic() - started)))
                )
            except subprocess.TimeoutExpired:
                cli.terminate()
                try:
                    cli.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    cli.kill()
                    cli.wait(timeout=2)
                raise TimeoutError("CLI wall budget exceeded; no retry")
        if (output / "scan.json").exists():
            report = json.loads((output / "scan.json").read_text())
        after = inspect_model(args.models, args.expected_digest)
        write_json(output / "model-after.json", after)
        if before != after:
            raise ValueError("selected model metadata changed during diagnostic")
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
    ) as error:
        record["errors"].append({"kind": type(error).__name__, "message": str(error)})
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        if daemon is not None:
            try:
                daemon.terminate()
                daemon.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_ok = False
                record["errors"].append(
                    {"kind": "daemon_cleanup", "message": str(error)}
                )
                try:
                    daemon.kill()
                    daemon.wait(timeout=2)
                except (OSError, subprocess.SubprocessError):
                    pass
        record.update(
            cli_exit_code=cli_exit,
            completion=gate.snapshot(),
            daemon_cleanup_ok=cleanup_ok,
            wall_seconds=time.monotonic() - started,
        )
        if not args.diagnose_policy:
            record["status"] = final_status(
                gate.snapshot(), cli_exit, report, cleanup_ok and not record["errors"]
            )
        write_json(output / "supervisor-result.json", record)
    return 0 if record["status"] in ("complete", "policy-diagnostic-complete") else 1


def group_members(group):
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,stat="],
        capture_output=True,
        text=True,
        timeout=2,
        check=True,
    )
    return [
        {"pid": int(p), "state": state}
        for line in result.stdout.splitlines()
        for p, g, state in [line.split()]
        if int(g) == group
    ]


def cleanup_group(group):
    record = {"group": group, "signals": [], "remaining": [], "ok": True}
    try:
        for sig, wait in ((signal.SIGTERM, 1), (signal.SIGKILL, 1)):
            if not group_members(group):
                break
            os.killpg(group, sig)
            record["signals"].append(int(sig))
            time.sleep(wait)
        record["remaining"] = group_members(group)
        record["ok"] = not record["remaining"]
    except ProcessLookupError:
        pass
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record.update(ok=False, error=str(error))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-one-model-call",
        action="store_true",
        help="Explicitly permit one existing local 7B completion; no paid/cloud calls",
    )
    parser.add_argument(
        "--diagnose-policy",
        action="store_true",
        help="Run OS policy probes only; never start Ollama",
    )
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--models", type=Path, default=Path.home() / ".ollama/models")
    parser.add_argument("--ollama", type=Path, default=Path("/usr/local/bin/ollama"))
    parser.add_argument("--expected-digest", default=EXPECTED_DIGEST)
    parser.add_argument("--_supervisor", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--_network-child", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args._network_child is not None:
        print(json.dumps(network_child(args._network_child)))
        return 0
    if not args.allow_one_model_call and not args.diagnose_policy:
        parser.error(
            "choose --diagnose-policy or explicitly opt in with --allow-one-model-call; no process started"
        )
    if args.allow_one_model_call and args.diagnose_policy:
        parser.error("choose exactly one action")
    if args.output is None or (args.allow_one_model_call and args.binary is None):
        parser.error("--output and a binary for the one-call action are required")
    args.output = args.output.resolve()
    args.models = args.models.resolve()
    args.ollama = args.ollama.resolve()
    if args.binary is not None:
        args.binary = args.binary.resolve()
    # Never create diagnostics inside model input or another supplied input path.
    protected = [args.models]
    if args.binary is not None:
        protected.append(args.binary)
    protected.append(args.ollama)
    if any(
        args.output == source or source in args.output.parents for source in protected
    ):
        parser.error(
            "output overlaps a protected model/executable input; no files written"
        )
    if args._supervisor:
        return supervisor(args)
    if args.output.exists():
        parser.error("output must not exist; preserving previous evidence")
    started = time.monotonic()
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ("home", "tmp", "readonly-probe"):
        (args.output / name).mkdir()
    (args.output / "readonly-probe/sentinel.txt").write_text("original dummy bytes")
    policy = args.output / "policy.sb"
    policy.write_text(policy_text(args.models, args.output / "readonly-probe"))
    record = {
        "status": "incomplete",
        "limits": LIMITS,
        "source_sha256": file_digest(__file__),
        "policy_sha256": file_digest(policy),
        "model": MODEL,
        "expected_digest": args.expected_digest,
        "action": "policy-only" if args.diagnose_policy else "one-local-call",
        "boundary": "Allows all localhost loopback ports for Ollama runner IPC. Not an airgap or localhost-relay defense. Does not touch existing daemon on 11434.",
        "adapter": "OpenAI request -> native /api/chat with explicit generation limits; original /v1 semantics not verified",
    }
    process = None
    try:
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
            raise ValueError("macOS sandbox-exec is required; no fallback policy")
        if args.allow_one_model_call:
            if not args.binary.is_file() or not args.ollama.is_file():
                raise ValueError("existing executable missing")
            record.update(
                binary_sha256=file_digest(args.binary),
                ollama_sha256=file_digest(args.ollama),
                model=inspect_model(args.models, args.expected_digest),
            )
        env = clean_environment(args.output / "home", args.output / "tmp")
        command = [
            "/usr/bin/sandbox-exec",
            "-f",
            str(policy),
            sys.executable,
            str(Path(__file__).resolve()),
            "--_supervisor",
            "--output",
            str(args.output),
            "--models",
            str(args.models),
            "--ollama",
            str(args.ollama),
            "--expected-digest",
            args.expected_digest,
        ]
        command += (
            ["--diagnose-policy"]
            if args.diagnose_policy
            else ["--allow-one-model-call", "--binary", str(args.binary)]
        )
        record["supervisor_command"] = command
        write_json(args.output / "result.json", record)
        with (
            (args.output / "supervisor.stdout.txt").open("w") as stdout,
            (args.output / "supervisor.stderr.txt").open("w") as stderr,
        ):
            process = subprocess.Popen(
                command,
                env=env,
                cwd=args.output,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                record["supervisor_exit_code"] = process.wait(
                    timeout=max(
                        1,
                        LIMITS["supervisor_wait_seconds"]
                        - (time.monotonic() - started),
                    )
                )
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record["error"] = {"kind": type(error).__name__, "message": str(error)}
    finally:
        if process is not None:
            record["process_group_cleanup"] = cleanup_group(process.pid)
            if process.poll() is None:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    record["process_group_cleanup"]["ok"] = False
        result_path = args.output / "supervisor-result.json"
        if result_path.exists():
            record["supervisor"] = json.loads(result_path.read_text())
        ok = (
            record.get("supervisor_exit_code") == 0
            and record.get("process_group_cleanup", {}).get("ok") is True
            and not record.get("error")
            and not record.get("timed_out")
        )
        record["status"] = (
            record.get("supervisor", {}).get("status", "incomplete")
            if ok
            else "incomplete"
        )
        record["wall_seconds"] = time.monotonic() - started
        write_json(args.output / "result.json", record)
    print(
        json.dumps(
            {
                "status": record["status"],
                "output": str(args.output),
                "upstream_attempts": record.get("supervisor", {})
                .get("completion", {})
                .get("upstream_attempts", 0),
                "model_response_received": record.get("supervisor", {})
                .get("completion", {})
                .get("response_received", False),
                "wall_seconds": record["wall_seconds"],
            }
        )
    )
    return 0 if record["status"] in ("complete", "policy-diagnostic-complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
