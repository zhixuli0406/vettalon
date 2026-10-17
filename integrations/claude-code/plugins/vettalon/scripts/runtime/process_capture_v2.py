#!/usr/bin/env python3
"""Versioned POSIX process capture; frozen legacy ownership and strict result contract.

Default execution ceiling is 120 seconds; explicit callers may opt in up to 600.
Cleanup remains at most one additional shared second. This is not OS containment.
"""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import selectors
import sys
import subprocess
import time

CONTROL_SCHEMA = 1
STDOUT_CAP = 4 * 1024 * 1024
STDERR_CAP = 1024 * 1024
CONFIG_LIMIT = 65536
STATUS_LIMIT = 1024
CLEANUP_SECONDS = 1.0
SUPERVISOR = Path(__file__).with_name("process_supervisor.py")

def digest(data):
    return hashlib.sha256(data).hexdigest()

def decode_status(raw):
    if (not raw or len(raw) > STATUS_LIMIT or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1):
        raise ValueError("missing, truncated, repeated or oversized status frame")
    try:
        def unique_keys(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate status key")
                value[key] = item
            return value
        frame = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid status encoding") from error
    if (not isinstance(frame, dict) or set(frame) != {"schema", "exit_code", "error"}
            or type(frame["schema"]) is not int or frame["schema"] != CONTROL_SCHEMA):
        raise ValueError("invalid status schema")
    code, error = frame["exit_code"], frame["error"]
    if error is None:
        if type(code) is not int or not -255 <= code <= 255:
            raise ValueError("invalid target exit code")
    elif error not in ("process-error", "supervisor-error") or code is not None:
        raise ValueError("invalid supervisor error")
    return frame

def invoke(command, cwd, env, timeout, *, stdout_cap=STDOUT_CAP, stderr_cap=STDERR_CAP, timeout_ceiling_seconds=120):
    """Own an unreaped supervisor group; bounded pipes, one deadline and cleanup.

    POSIX only. SIGCHLD auto-reaping/custom handlers are rejected. External
    waitpid reapers and setsid escapes are outside this ownership contract.
    Cap overrides only tighten bounds (used by self-authored process tests).
    """
    started = time.monotonic()
    result = {"command": command, "returncode": None, "stdout": "", "stderr": "",
              "seconds": 0.0, "error": None, "control_schema": CONTROL_SCHEMA,
              "control_complete": False, "timed_out": False, "cleanup_error": None,
              "captures": {}}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {"stdout": 0, "stderr": 0}
    truncated = {"stdout": False, "stderr": False}
    caps = {"stdout": stdout_cap, "stderr": stderr_cap}
    proc = None
    selector = None
    open_fds = set()
    stream_fds = {}
    packet_fd = None
    status_fd = None
    status_bytes = bytearray()

    def close_fd(fd):
        if fd is None or fd not in open_fds:
            return
        if selector is not None:
            try:
                selector.unregister(fd)
            except (KeyError, ValueError, OSError):
                pass
        try:
            os.close(fd)
        except OSError:
            pass
        open_fds.discard(fd)

    def capture(fd, name):
        data = os.read(fd, 65536)
        if not data:
            close_fd(fd)
            stream_fds.pop(fd, None)
            return
        observed[name] += len(data)
        remaining = caps[name] - len(buffers[name])
        buffers[name].extend(data[:max(0, remaining)])
        if len(data) > remaining:
            truncated[name] = True
            if result["error"] is None:
                result["error"] = "output-limit"

    try:
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
                or timeout > 600
                or type(timeout_ceiling_seconds) is not int or not 0 < timeout_ceiling_seconds <= 600
                or any(type(caps[n]) is not int or not 0 < caps[n] <= limit
                       for n, limit in (("stdout", STDOUT_CAP), ("stderr", STDERR_CAP)))):
            result["error"] = "invalid-limits"
            return result
        deadline = started + min(timeout, timeout_ceiling_seconds)
        if os.name != "posix":
            result["error"] = "unsupported-platform"
            return result
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            result["error"] = "unsupported-sigchld"
            return result
        # Bound serialization before allocating a packet or starting a process.
        if (not isinstance(command, (list, tuple)) or not command or len(command) > 256
                or not all(isinstance(v, str) and "\0" not in v for v in command)
                or not isinstance(env, dict) or len(env) > 256
                or not all(isinstance(k, str) and isinstance(v, str) and "\0" not in k + v
                           for k, v in env.items())):
            result["error"] = "invalid-config"
            return result
        if sum(len(v) for v in command) + sum(len(k) + len(v) for k, v in env.items()) + len(str(cwd)) > CONFIG_LIMIT:
            result["error"] = "config-limit"
            return result
        packet = json.dumps({"argv": list(command), "cwd": str(cwd), "env": env}, ensure_ascii=True).encode()
        if len(packet) > CONFIG_LIMIT:
            result["error"] = "config-limit"
            return result
        if time.monotonic() >= deadline:
            result.update(error="timeout", timed_out=True)
            return result
        config_read, packet_fd = os.pipe()
        open_fds.update((config_read, packet_fd))
        status_fd, status_write = os.pipe()
        open_fds.update((status_fd, status_write))
        proc = subprocess.Popen([sys.executable, "-I", "-S", str(SUPERVISOR), str(config_read), str(status_write)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={"PATH": os.defpath, "LANG": "C"}, close_fds=True,
                                pass_fds=(config_read, status_write), start_new_session=True)
        close_fd(config_read)
        close_fd(status_write)
        selector = selectors.DefaultSelector()
        # Detach pipe FDs from file objects so each descriptor has one owner.
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            fd = os.dup(pipe.fileno())
            pipe.close()
            open_fds.add(fd)
            stream_fds[fd] = name
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, name)
        for fd, event, name in ((packet_fd, selectors.EVENT_WRITE, "config"), (status_fd, selectors.EVENT_READ, "status")):
            os.set_blocking(fd, False)
            selector.register(fd, event, name)
        sent = 0
        while result["error"] is None and not result["control_complete"]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result.update(error="timeout", timed_out=True)
                break
            for key, _ in selector.select(min(.05, remaining)):
                fd, name = key.fd, key.data
                if name == "config":
                    sent += os.write(fd, packet[sent:sent + 4096])
                    if sent == len(packet):
                        close_fd(fd)
                        packet_fd = None
                elif name == "status":
                    data = os.read(fd, STATUS_LIMIT + 1 - len(status_bytes))
                    if data:
                        status_bytes.extend(data)
                        if len(status_bytes) > STATUS_LIMIT:
                            result["error"] = "invalid-status"
                    else:
                        close_fd(fd)
                        try:
                            status = decode_status(bytes(status_bytes))
                            if packet_fd is not None:
                                raise ValueError("status before complete config")
                            result["returncode"] = status["exit_code"]
                            result["control_complete"] = True
                            result["error"] = status["error"] or ("nonzero-exit" if status["exit_code"] else None)
                        except ValueError:
                            result["error"] = "invalid-status"
                else:
                    capture(fd, name)
                if result["error"] is not None:
                    break
    except KeyboardInterrupt:
        result["error"] = "cancelled"
    except Exception:
        result["error"] = "process-error"
    finally:
        if proc is not None:
            cleanup_end = time.monotonic() + min(1.0, CLEANUP_SECONDS)
            close_fd(packet_fd)
            # This supervisor has not been polled/reaped. Its PID still reserves
            # our group ID even if it died unexpectedly. Never signal after reap.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, KeyboardInterrupt):
                result["cleanup_error"] = "group-termination-failed"
            reaped = False
            cleanup_selector_failed = False
            while time.monotonic() < cleanup_end:
                if not reaped:
                    try:
                        pid, status = os.waitpid(proc.pid, os.WNOHANG)
                        if pid == proc.pid:
                            proc.returncode = os.waitstatus_to_exitcode(status)
                            reaped = True
                    except InterruptedError:
                        continue
                    except ChildProcessError:
                        proc.returncode = 0  # Disarm Popen finalizer after lost ownership.
                        reaped = True
                        result["cleanup_error"] = "wait-ownership-lost"
                    except (OSError, KeyboardInterrupt):
                        result["cleanup_error"] = "leader-wait-failed"
                        break
                if not stream_fds and reaped:
                    break
                if selector is not None and not cleanup_selector_failed:
                    try:
                        events = selector.select(min(.01, max(0, cleanup_end - time.monotonic())))
                    except (Exception, KeyboardInterrupt):
                        result["cleanup_error"] = "cleanup-selector-failed"
                        cleanup_selector_failed = True
                        for fd in list(stream_fds):
                            close_fd(fd)
                        stream_fds.clear()
                        continue
                    for key, _ in events:
                        if key.fd in stream_fds:
                            try:
                                capture(key.fd, stream_fds[key.fd])
                            except OSError:
                                result["cleanup_error"] = "pipe-read-failed"
                                stream_fds.pop(key.fd, None)
                                close_fd(key.fd)
                        else:
                            close_fd(key.fd)
                else:
                    time.sleep(min(.01, max(0, cleanup_end - time.monotonic())))
            if stream_fds or not reaped:
                result["cleanup_error"] = result["cleanup_error"] or "cleanup-deadline"
        for fd in list(open_fds):
            close_fd(fd)
        if proc is not None:
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        result["cleanup_error"] = "pipe-close-failed"
        if selector is not None:
            try:
                selector.close()
            except (OSError, KeyboardInterrupt):
                result["cleanup_error"] = "selector-close-failed"
        for name, raw in buffers.items():
            try:
                text = raw.decode("utf-8", "strict")
                decode_error = False
            except UnicodeError:
                text = raw.decode("utf-8", "replace")
                decode_error = True
                result["error"] = result["error"] or "invalid-utf8"
            result[name] = text
            result["captures"][name] = {"cap_bytes": caps[name], "observed_bytes": observed[name],
                                        "retained_bytes": len(raw), "sha256": digest(raw),
                                        "truncated": truncated[name], "decode_error": decode_error}
            if decode_error:
                result["captures"][name]["raw_base64"] = base64.b64encode(raw).decode("ascii")
        if result["cleanup_error"]:
            result["error"] = result["error"] or "cleanup-error"
        result["seconds"] = time.monotonic() - started
    return result

def successful_run(run):
    if not (isinstance(run, dict) and type(run.get("returncode")) is int and run["returncode"] == 0
            and run.get("error", "missing") is None and type(run.get("control_schema")) is int
            and run["control_schema"] == CONTROL_SCHEMA and run.get("control_complete") is True
            and run.get("timed_out") is False and "cleanup_error" in run and run["cleanup_error"] is None
            and isinstance(run.get("command"), list) and bool(run["command"])
            and all(isinstance(v, str) for v in run["command"])
            and type(run.get("seconds")) in (int, float) and math.isfinite(run["seconds"]) and run["seconds"] >= 0
            and isinstance(run.get("captures"), dict) and set(run["captures"]) == {"stdout", "stderr"}):
        return False
    for name, maximum in (("stdout", STDOUT_CAP), ("stderr", STDERR_CAP)):
        text, capture = run.get(name), run["captures"][name]
        if not isinstance(text, str) or not isinstance(capture, dict):
            return False
        try:
            raw = text.encode("utf-8", "strict")
        except UnicodeError:
            return False
        if not (type(capture.get("cap_bytes")) is int and 0 < capture["cap_bytes"] <= maximum
                and type(capture.get("observed_bytes")) is int
                and type(capture.get("retained_bytes")) is int
                and 0 <= capture["observed_bytes"] == capture["retained_bytes"] == len(raw) <= capture["cap_bytes"]
                and capture.get("truncated") is False and capture.get("decode_error") is False
                and capture.get("sha256") == digest(raw) and "raw_base64" not in capture):
            return False
    return True
