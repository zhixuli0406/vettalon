#!/usr/bin/env python3
"""Capture disposable fixture HTTP prompts with bounded pipes and owned sockets."""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import sys
import tempfile
import threading
import time

MARKER = "VETTALON_PUBLIC_FIXTURE_SOURCE_MARKER"
STDOUT_CAP, STDERR_CAP = 1024 * 1024, 256 * 1024
MAX_SECONDS = 90.0
HELPER = Path(__file__).resolve().parents[2] / "benchmarks/reachability/adapter.py"


def process_adapter():
    spec = importlib.util.spec_from_file_location("dataflow_process_capture", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def invoke(*args, **kwargs):
    return process_adapter().invoke(*args, **kwargs)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("invalid-json-number")
    def finite_float(raw_number):
        value = float(raw_number)
        if not math.isfinite(value):
            raise ValueError("invalid-json-number")
        return value
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=invalid, parse_float=finite_float)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid-json") from error


class FixtureStartError(OSError):
    """Thread startup failed before any CLI attempt was admitted."""


class FixtureHTTP:
    """Single-use HTTP/1 fixture framing, not a general purpose HTTP server."""
    def __init__(self, deadline, *, request_limit=8, body_cap=2_000_000,
                 total_body_cap=2_000_000, header_cap=16_384, total_header_cap=65_536,
                 connection_seconds=15.0):
        limits = ((request_limit, 8), (body_cap, 2_000_000), (total_body_cap, 2_000_000),
                  (header_cap, 16_384), (total_header_cap, 65_536))
        if (any(type(value) is not int or not 0 < value <= maximum for value, maximum in limits)
                or type(connection_seconds) not in (float, int) or not math.isfinite(connection_seconds)
                or not 0 < connection_seconds <= 15 or not math.isfinite(deadline)):
            raise ValueError("invalid-fixture-limits")
        self.deadline, self.connection_seconds = deadline, connection_seconds
        self.request_limit, self.body_cap, self.total_body_cap = request_limit, body_cap, total_body_cap
        self.header_cap, self.total_header_cap = header_cap, total_header_cap
        self.captures, self.events, self.errors = [], [], []
        self.admitted, self.headers, self.bodies = 0, 0, 0
        self.stop_event, self.lock = threading.Event(), threading.Lock()
        self.connection = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(4); self.listener.setblocking(False)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def start(self):
        self.thread.start()

    def ready(self, connection, deadline, write=False):
        while not self.stop_event.is_set():
            remaining = min(self.deadline, deadline) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("http-total-deadline")
            readable, writable, _ = select.select([] if write else [connection],
                                                 [connection] if write else [], [], min(.02, remaining))
            if readable or writable:
                return
        raise OSError("fixture-stopping")

    def receive(self, connection, maximum, deadline):
        self.ready(connection, deadline)
        raw = connection.recv(maximum)
        if not raw:
            raise ValueError("incomplete-http")
        return raw

    def request(self, connection, deadline, event):
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            remaining = min(self.header_cap, self.total_header_cap - self.headers) - len(raw)
            if remaining <= 0:
                raise ValueError("header-cap")
            raw.extend(self.receive(connection, min(4096, remaining), deadline))
            event["header"] = bytes(raw)
        boundary = raw.index(b"\r\n\r\n") + 4
        header, body = bytes(raw[:boundary]), bytearray(raw[boundary:])
        event["header"], event["body"] = header, bytes(body)
        self.headers += len(header)
        lines = header[:-4].decode("ascii", "strict").split("\r\n")
        if not re.fullmatch(r"POST /[^\x00-\x20]* HTTP/1\.[01]", lines[0]):
            raise ValueError("unsupported-http-request")
        values = {}
        for line in lines[1:]:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line):
                raise ValueError("invalid-http-header")
            name, value = line.split(":", 1)
            name = name.lower()
            if name in values:
                raise ValueError("duplicate-http-header")
            values[name] = value.strip()
        length = values.get("content-length")
        if "transfer-encoding" in values or length is None or not re.fullmatch(r"[0-9]{1,10}", length):
            raise ValueError("invalid-content-length")
        size = int(length)
        if not 0 < size <= self.body_cap or size > self.total_body_cap - self.bodies:
            raise ValueError("body-cap")
        if len(body) > size:
            raise ValueError("extra-http-body")
        while len(body) < size:
            body.extend(self.receive(connection, min(4096, size - len(body)), deadline))
            event["body"] = bytes(body)
        event["body"] = bytes(body)
        self.bodies += len(body)
        payload = strict_json(body)
        if not isinstance(payload, dict):
            raise ValueError("json-body-must-be-object")
        self.captures.append({"path": lines[0].split(" ")[1], "body": payload})
        response = json.dumps({"choices": [{"message": {"content": "[]"}, "finish_reason": "stop"}]}).encode()
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                    + str(len(response)).encode() + b"\r\n\r\n" + response)
        sent = 0
        while sent < len(response):
            self.ready(connection, deadline, write=True)
            count = connection.send(response[sent:])
            if not count:
                raise ValueError("http-response-incomplete")
            sent += count
        event["complete"] = True

    def serve(self):
        try:
            while not self.stop_event.is_set() and self.admitted < self.request_limit:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([self.listener], [], [], min(.02, remaining))
                if not ready:
                    continue
                connection, _ = self.listener.accept(); connection.setblocking(False)
                with self.lock:
                    self.connection = connection
                self.admitted += 1
                event = {"header": b"", "body": b"", "complete": False, "error": None}
                header_before, body_before = self.headers, self.bodies
                try:
                    self.request(connection, min(self.deadline, time.monotonic() + self.connection_seconds), event)
                except (OSError, ValueError, UnicodeError) as error:
                    event["error"] = "http-total-deadline" if isinstance(error, TimeoutError) else "http-incomplete-or-invalid"
                    self.errors.append(event["error"])
                finally:
                    # Charge incomplete framing too; cap retained raw across all connections.
                    if self.headers == header_before:
                        event["header"] = event["header"][:max(0, self.total_header_cap - self.headers)]
                        self.headers += len(event["header"])
                    if self.bodies == body_before:
                        event["body"] = event["body"][:max(0, min(self.body_cap, self.total_body_cap - self.bodies))]
                        self.bodies += len(event["body"])
                    self.events.append({"complete": event["complete"], "error": event["error"],
                        "header_base64": base64.b64encode(event["header"]).decode(),
                        "body_base64": base64.b64encode(event["body"]).decode(),
                        "header_sha256": hashlib.sha256(event["header"]).hexdigest(),
                        "body_sha256": hashlib.sha256(event["body"]).hexdigest()})
                    connection.close()
                    with self.lock:
                        self.connection = None
        except (OSError, ValueError):
            if not self.stop_event.is_set():
                self.errors.append("fixture-server-error")
        finally:
            self.listener.close()

    def stop(self, deadline):
        self.stop_event.set()
        with self.lock:
            active = self.connection
            if active is not None:
                try: active.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                active.close()
        self.listener.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=max(0.0, min(.5, deadline - time.monotonic())))
        alive = self.thread.is_alive()
        return {"cleanup_complete": not alive and self.listener.fileno() == -1
                and (active is None or active.fileno() == -1), "thread_alive": alive,
                "owned_connections_closed": active is None or active.fileno() == -1,
                "bounded_join_seconds": .5}

    def snapshot(self):
        return {"captures": list(self.captures), "events": list(self.events), "errors": list(self.errors),
                "admitted_connections": self.admitted, "complete_requests": sum(e["complete"] for e in self.events),
                "incomplete_requests": sum(not e["complete"] for e in self.events),
                "inflight_requests": self.admitted - len(self.events),
                "header_retained_bytes": self.headers, "body_retained_bytes": self.bodies,
                "limits": {"admitted_connections": self.request_limit, "body_bytes_each": self.body_cap,
                    "body_bytes_total": self.total_body_cap, "header_bytes_each": self.header_cap,
                    "header_bytes_total": self.total_header_cap, "connection_seconds": self.connection_seconds}}


def raw_capture(run, name):
    capture = run.get("captures", {}).get(name, {})
    if "raw_base64" in capture:
        return base64.b64decode(capture["raw_base64"], validate=True)
    return run.get(name, "").encode("utf-8", "strict")


def run_probe(binary, output, *, timeout_seconds=MAX_SECONDS, stdout_cap=STDOUT_CAP, stderr_cap=STDERR_CAP):
    started = time.monotonic()
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= MAX_SECONDS
            or any(type(value) is not int or not 0 < value <= maximum
                   for value, maximum in ((stdout_cap, STDOUT_CAP), (stderr_cap, STDERR_CAP)))):
        raise ValueError("limits-can-only-tighten")
    deadline = started + timeout_seconds
    supplied_output = Path(output).absolute()
    if supplied_output.is_symlink():
        raise ValueError("output-symlink")
    output = supplied_output.resolve(); binary = Path(binary).resolve()
    output.mkdir(parents=True, exist_ok=False)
    server, cleanup, run, error, cli_valid = None, {"cleanup_complete": False}, {}, None, False
    attempted = 0
    try:
        server = FixtureHTTP(deadline)
        try:
            server.start()
        except RuntimeError as failure:
            raise FixtureStartError("fixture-thread-start-failed") from failure
        with tempfile.TemporaryDirectory(prefix="vettalon-dataflow-") as temporary:
            root = Path(temporary); fixture = root / "fixture"; fixture.mkdir()
            (fixture / "app.py").write_text(f'def echo(value):\n    return "{MARKER}" + value\n')
            home = root / "home"; home.mkdir()
            config = root / "roster.toml"
            config.write_text(f'[[model]]\nid="local-probe"\nbackend="openai"\nfamily="fixture"\nbase_url="http://127.0.0.1:{server.port}/v1"\nmodel="fixture"\nroles=["finder","verifier"]\ntimeout_secs=15\n')
            command = [str(binary), "scan", str(fixture), "--profile", "deep", "--config", str(config),
                       "--max-modules", "1", "--report", str(output / "report.json")]
            remaining = deadline - time.monotonic() - 1.5  # helper cleanup (1s), HTTP join and recording reserve
            if remaining <= 0:
                raise TimeoutError("probe-budget-exhausted-before-launch")
            env = {"PATH": os.defpath, "HOME": str(home), "TMPDIR": str(root), "LANG": "C.UTF-8",
                   "NO_PROXY": "127.0.0.1,localhost", "PYTHONDONTWRITEBYTECODE": "1"}
            attempted = 1
            with (output / "cli-attempt.json").open("x") as receipt:
                json.dump({"attempt": attempted, "maximum": 1, "phase": "debited-before-invoke",
                           "not_actual_spawn_proof": True, "command": command,
                           "elapsed_before": time.monotonic() - started,
                           "timeout_seconds": remaining}, receipt, indent=2)
                receipt.write("\n")
            remaining = min(remaining, deadline - time.monotonic() - 1.5)
            if remaining <= 0:
                raise TimeoutError("probe-budget-exhausted-before-launch")
            run = invoke(command, root, env, remaining, stdout_cap=stdout_cap, stderr_cap=stderr_cap)
            valid = dict(run)
            # Exit 1 is the established CLI findings exit, not a harness failure.
            if type(valid.get("returncode")) is int and valid["returncode"] == 1 and valid.get("error") == "nonzero-exit":
                valid.update(returncode=0, error=None)
            cli_valid = process_adapter().successful_run(valid)
            if not cli_valid:
                error = {"kind": "timeout" if run.get("timed_out") else
                         ("cli_start_error" if run.get("error") == "process-error" else "cli_control_error"),
                         "message": "CLI incomplete; bounded partial evidence retained; no retry"}
    except (OSError, ValueError, TimeoutError) as failure:
        error = {"kind": "fixture_start_error" if isinstance(failure, FixtureStartError) else
                 ("timeout" if isinstance(failure, TimeoutError) else "harness_error"),
                 "message": type(failure).__name__}
    finally:
        if server is not None:
            cleanup = server.stop(min(deadline, time.monotonic() + .5))
    snapshot = server.snapshot() if server is not None else {"captures": [], "events": [], "errors": ["server-not-started"]}
    observed = any(MARKER in json.dumps(capture["body"]) for capture in snapshot["captures"])
    for name in ("stdout", "stderr"):
        (output / (name + ".txt")).write_bytes(raw_capture(run, name))
    (output / "requests.json").write_text(json.dumps(snapshot["captures"], indent=2) + "\n")
    raw_events = (json.dumps(snapshot["events"], indent=2) + "\n").encode()
    (output / "http-events.json").write_bytes(raw_events)
    # Missing exit/control metadata cannot establish cleanup from absence of an error.
    cli_cleanup = True if cli_valid else (False if run.get("cleanup_error") else None)
    cleanup_complete = cleanup["cleanup_complete"] and cli_cleanup is True
    in_deadline = time.monotonic() < deadline
    if error is None and snapshot["errors"]:
        error = {"kind": "fixture_http_error", "message": "HTTP framing, bytes or deadline incomplete"}
    if error is None and not cleanup_complete:
        error = {"kind": "cleanup_incomplete", "message": "Required cleanup evidence unavailable"}
    if error is None and not in_deadline:
        error = {"kind": "timeout", "message": "Global admission deadline exhausted; no retry"}
    complete = (error is None and observed and type(run.get("returncode")) is int and run["returncode"] in (0, 1)
                and not snapshot["errors"] and cleanup_complete and in_deadline)
    record = {"resolved_output": str(output),
        "command": [str(binary), "scan", "<disposable fixture>", "--profile", "deep", "--config", "<loopback roster>", "--max-modules", "1"],
        "status": "complete" if complete else "incomplete", "exit_code": run.get("returncode"),
        "timed_out": run.get("timed_out", False) or bool(error and error["kind"] == "timeout"), "error": error,
        "requests": len(snapshot["captures"]), "source_marker_observed": observed,
        "cleanup_complete": cleanup_complete, "fixture_cleanup": cleanup,
        "cli_cleanup_complete": cli_cleanup, "global_deadline_met": in_deadline,
        "deadline_observation_scope": "after-capture-artifact-writes-before-final-receipt-write",
        "cli_cleanup_status": "complete-with-valid-control" if cli_cleanup is True else
            ("cleanup-error" if cli_cleanup is False else "no-cleanup-error-observed-or-not-started"),
        "wall_seconds": time.monotonic() - started,
        "limits": {"global_seconds": timeout_seconds, "stdout_bytes": stdout_cap, "stderr_bytes": stderr_cap,
                   "cli_attempts": attempted, "outer_retries": 0},
        "cli": {key: value for key, value in run.items() if key not in ("stdout", "stderr")},
        "fixture": {key: value for key, value in snapshot.items() if key not in ("captures", "events")},
        "http_events": {"file": "http-events.json", "sha256": hashlib.sha256(raw_events).hexdigest(),
                        "bytes": len(raw_events)},
        "boundary": "loopback fixture HTTP source transmission only; not scan coverage or cloud retention proof",
        "limitations": ["no-hard-blocking-spawn-or-OS-deadline-guarantee", "setsid-escape-not-covered",
                        "CPU-and-RSS-unknown", "not-a-general-HTTP-server", "no-filesystem-isolation",
                        "report-HOME-and-other-CLI-disk-writes-not-size-capped",
                        "final-receipt-serialization-and-recording-IO-not-hard-wall-bounded"]}
    # Raw bytes live in the retained capped stream files, not duplicated in the final receipt.
    for capture in record["cli"].get("captures", {}).values():
        capture.pop("raw_base64", None)
    (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=MAX_SECONDS)
    parser.add_argument("--stdout-cap-bytes", type=int, default=STDOUT_CAP)
    parser.add_argument("--stderr-cap-bytes", type=int, default=STDERR_CAP)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    try:
        record = run_probe(args.binary, args.output, timeout_seconds=args.timeout_seconds,
                           stdout_cap=args.stdout_cap_bytes, stderr_cap=args.stderr_cap_bytes)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(record))
    if record["status"] != "complete":
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
