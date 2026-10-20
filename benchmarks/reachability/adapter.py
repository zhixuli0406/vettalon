#!/usr/bin/env python3
"""Bounded, opt-in govulncheck adapter. It never suppresses an alert."""
import argparse
import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import selectors
import sys
import subprocess
import tempfile
import time

ADAPTER_VERSION = "0.3.0"
TOOL_VERSION = "v1.4.0"
TARGET = {"id": "GO-2021-0113", "purl": "pkg:golang/golang.org/x/text@v0.3.5", "module": "golang.org/x/text", "version": "v0.3.5"}
# Source-mode call graphs do not follow reflection, unsafe pointer laundering
# or go:linkname (govulncheck documents reflect/unsafe as false-negative
# sources). A host that uses them never gets not-observed, only unknown.
BLIND_SPOT_IMPORTS = ("reflect", "unsafe")
BLIND_SPOT_FILE_LIMIT = 4096
BLIND_SPOT_BYTE_LIMIT = 32 * 1024 * 1024
CACHE_FIELDS = ("purl", "advisory", "dependency_source_sha256", "host_source_sha256", "toolchain", "tool_binary_sha256", "tool_version", "adapter_version", "adapter_source_sha256", "features", "tags", "target", "db_snapshot_sha256", "scan_options")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tree_hash(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("source is not an ordinary directory")
    hasher = hashlib.sha256()
    size = 0
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            raise ValueError("symlink in source snapshot")
        if path.is_file():
            content = path.read_bytes()
            size += len(content)
            if size > 128 * 1024 * 1024:
                raise ValueError("source snapshot exceeds 128 MiB")
            hasher.update(path.relative_to(root).as_posix().encode() + b"\0")
            hasher.update(len(content).to_bytes(8, "big") + content)
    return hasher.hexdigest()


def blind_spot_signals(root):
    """Conservatively list host-authored reflection/unsafe/linkname use.

    Scans every non-test .go file outside vendor/testdata/./_ directories for
    any "reflect"/"unsafe" string literal or //go:linkname line. It does not
    parse, strip comments or evaluate build tags, so it can only over-report. Third-party
    dependency code is out of scope (documented residual blind spot).
    """
    root = Path(root)
    signals = set()
    files = 0
    size = 0
    for path in sorted(root.rglob("*.go")):
        parts = path.relative_to(root).parts
        if (path.name.endswith("_test.go") or any(part in ("vendor", "testdata") or part.startswith((".", "_")) for part in parts[:-1])):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("unsupported host source entry")
        files += 1
        content = path.read_bytes()
        size += len(content)
        if files > BLIND_SPOT_FILE_LIMIT or size > BLIND_SPOT_BYTE_LIMIT:
            raise ValueError("host source exceeds blind-spot scan limit")
        text = content.decode("utf-8", "replace")
        if re.search(r"(?m)^\s*//go:linkname\s", text):
            signals.add("linkname")
        # Any interpreted or raw string literal naming the package counts;
        # a non-import literal only adds a false unknown, never a miss.
        for name in BLIND_SPOT_IMPORTS:
            if re.search(r'["`]' + name + r'["`]', text):
                signals.add(name)
    return sorted(signals)


def cache_key(material):
    if set(material) != set(CACHE_FIELDS) or any(v is None for v in material.values()):
        raise ValueError("all cache dimensions are required")
    return digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())


def unknown(reason):
    return {"status": "unknown", "reason": reason, "traces": [], "suppress_alert": False,
            "vex": {"status": "under_investigation", "policy": "reachability-v1; no not_affected authorization"}}


def classify(raw, returncode, target):
    result = unknown("tool-error" if returncode else "parse-or-incomplete")
    if returncode:
        return result
    try:
        decoder = json.JSONDecoder()
        rest = raw.strip()
        messages = []
        while rest:
            message, end = decoder.raw_decode(rest)
            if not isinstance(message, dict) or len(message) != 1:
                raise ValueError("invalid stream message")
            messages.append(message)
            rest = rest[end:].lstrip()
        config = messages[0]["config"]
        if (config["protocol_version"] != "v1.0.0" or config.get("scan_level") != "symbol"
                or config.get("scan_mode") != "source" or config.get("scanner_version") != TOOL_VERSION):
            raise ValueError("unsupported protocol/tool/mode/level")
        sboms = [m["SBOM"] for m in messages if "SBOM" in m]
        if not any(any(mod.get("path") == target["module"] and mod.get("version") == target["version"]
                       for mod in sbom["modules"]) for sbom in sboms):
            raise ValueError("target module absent")
        advisories = [m["osv"] for m in messages if "osv" in m and m["osv"].get("id") == target["id"]]
        symbols = set()
        for entry in advisories:
            for affected in entry["affected"]:
                if affected["package"]["name"] == target["module"]:
                    for imp in affected.get("ecosystem_specific", {}).get("imports", []):
                        symbols.update((imp["path"], symbol) for symbol in imp.get("symbols", []))
        if not symbols:
            raise ValueError("no target advisory symbols")
        findings = [m["finding"] for m in messages if "finding" in m and m["finding"].get("osv") == target["id"]]
        if not findings:
            raise ValueError("no version-affected finding; no inference from absence")
        traces = []
        for finding in findings:
            trace = finding["trace"]
            frame = trace[0]
            if frame.get("module") != target["module"] or frame.get("version") != target["version"]:
                raise ValueError("target frame mismatch")
            if frame.get("function"):
                # govulncheck reports pointer receivers as "*T"; advisories list "T.Method".
                receiver = frame.get("receiver", "").lstrip("*").split("[", 1)[0]
                symbol = (receiver + "." if receiver else "") + frame["function"]
                if (frame.get("package"), symbol) not in symbols:
                    raise ValueError("unrecognised symbol")
                traces.append(trace)
        result = {"status": "reachable" if traces else "not-observed", "reason": "symbol-path-observed" if traces else "module-or-package-only",
                  "traces": traces, "suppress_alert": False,
                  "vex": {"status": "under_investigation", "policy": "reachability-v1; static path is not exploit proof; absence is not not_affected"}}
        result["config"] = config
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        pass
    return result


CONTROL_SCHEMA = 1
STDOUT_CAP = 4 * 1024 * 1024
STDERR_CAP = 1024 * 1024
CONFIG_LIMIT = 65536
STATUS_LIMIT = 1024
CLEANUP_SECONDS = 1.0
SUPERVISOR = Path(__file__).with_name("process_supervisor.py")


def supervisor_source_hash():
    return digest(SUPERVISOR.read_bytes())


def implementation_fingerprint():
    return digest(Path(__file__).read_bytes()) + ":" + supervisor_source_hash()


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


def invoke(command, cwd, env, timeout, *, stdout_cap=STDOUT_CAP, stderr_cap=STDERR_CAP):
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
                or any(type(caps[n]) is not int or not 0 < caps[n] <= limit
                       for n, limit in (("stdout", STDOUT_CAP), ("stderr", STDERR_CAP)))):
            result["error"] = "invalid-limits"
            return result
        deadline = started + min(timeout, 120)
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


def valid_cached_run(run):
    return successful_run(run)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def scan(project, output, tool, *, language="go", dependency=None, db=None, tags="", target=None, cache=None, timeout=120,
         candidate=None, goflags=""):
    project, output, tool = Path(project).resolve(), Path(output).resolve(), Path(tool).resolve()
    protected = [project] + [Path(path).resolve() for path in (dependency, db) if path is not None]
    destinations = [output] + ([Path(cache).resolve()] if cache else [])
    if any(destination == source or source in destination.parents for source in protected for destination in destinations):
        return unknown("output-overlaps-source")
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        return unknown("output-exists")
    result = unknown("unsupported" if language != "go" else "missing-tool")
    candidate = dict(candidate or TARGET)
    result.update({"adapter_version": ADAPTER_VERSION, "candidate": candidate, "cache": {"hit": False}, "scope": "single-advisory Go source symbol analysis"})
    try:
        if language != "go" or not tool.is_file():
            return result
        if dependency is None or db is None:
            raise ValueError("dependency source and local DB snapshot are required")
        dependency, db = Path(dependency).resolve(), Path(db).resolve()
        module = (project / "go.mod").read_text()
        if set(candidate) != {"id", "purl", "module", "version"} or not all(isinstance(v, str) and v for v in candidate.values()):
            raise ValueError("candidate needs id, purl, module and version")
        if goflags not in ("", "-mod=mod"):
            raise ValueError("only empty GOFLAGS or -mod=mod are supported")
        if candidate["purl"] != "pkg:golang/%s@%s" % (candidate["module"], candidate["version"]):
            raise ValueError("candidate purl must name the same module and version")
        pinned = re.search(r"(?m)^\s*(?:require\s+)?" + re.escape(candidate["module"]) + r"\s+" + re.escape(candidate["version"]) + r"(?:\s|$)", module)
        if "replace" in module or "toolchain" in module or pinned is None:
            raise ValueError("fixture must pin target without replace/toolchain")
        dependency_mod = dependency / "go.mod"
        if dependency_mod.exists() or dependency_mod.is_symlink():
            declared = re.search(r'(?m)^module\s+"?([^"\s]+)"?\s*$', dependency_mod.read_text())
            if declared is None or declared.group(1) != candidate["module"]:
                raise ValueError("dependency source module mismatch")
        elif not dependency.is_dir():
            raise ValueError("dependency source directory missing")
        # Pre-module sources (no go.mod) are bound only by the go list Dir check below.
        go = shutil.which("go")
        if not go:
            result["reason"] = "missing-go"
            return result
        with tempfile.TemporaryDirectory(prefix="vettalon-reachability-") as home:
            env = {"PATH": str(Path(go).parent) + os.pathsep + os.defpath, "HOME": home, "TMPDIR": tempfile.gettempdir(),
                   "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": goflags, "CGO_ENABLED": "0", "GOTELEMETRY": "off",
                   "GOPROXY": "off", "GOSUMDB": "off", "GOMODCACHE": str(dependency.parents[2]),
                   "GOCACHE": str(Path(tempfile.gettempdir()) / "vettalon-reachability-go-build")}
            # GOMODCACHE is the explicit preloaded cache root, not a dependency-relative guess.
            for ancestor in dependency.parents:
                if ancestor.name == "mod" and ancestor.parent.name == "pkg":
                    env["GOMODCACHE"] = str(ancestor)
                    break
            version_run = invoke([go, "version"], project, env, 20)
            env_run = invoke([go, "env", "GOOS", "GOARCH", "GOEXPERIMENT"], project, env, 20)
            result["preflight"] = {"version": version_run, "environment": env_run}
            if not successful_run(version_run) or not successful_run(env_run):
                result["reason"] = "toolchain-error"
                return result
            resolution = invoke([go, "list", "-m", "-json", candidate["module"]], project, env, 20)
            result["preflight"]["module_resolution"] = resolution
            write_json(output / "module-resolution.json", resolution)
            try:
                resolved = json.loads(resolution["stdout"])
                if (not successful_run(resolution) or resolved.get("Path") != candidate["module"]
                        or resolved.get("Version") != candidate["version"] or "Replace" in resolved
                        or Path(resolved["Dir"]).resolve() != dependency):
                    raise ValueError("resolved dependency source mismatch")
            except (ValueError, KeyError, TypeError):
                result["reason"] = "dependency-source-mismatch"
                return result
            defaults = env_run["stdout"].splitlines()
            selected = target or "/".join(defaults[:2])
            if len(selected.split("/")) != 2:
                raise ValueError("target must be GOOS/GOARCH")
            env["GOOS"], env["GOARCH"] = selected.split("/")
            material = {"purl": candidate["purl"], "advisory": candidate["id"], "dependency_source_sha256": tree_hash(dependency),
                        "host_source_sha256": tree_hash(project), "toolchain": version_run["stdout"].strip(),
                        "tool_binary_sha256": digest(tool.read_bytes()), "tool_version": TOOL_VERSION,
                        "adapter_version": ADAPTER_VERSION, "adapter_source_sha256": digest(implementation_fingerprint().encode()),
                        "features": {"cgo": False, "goexperiment": "", "test": False}, "tags": tags,
                        "target": selected, "db_snapshot_sha256": tree_hash(db),
                        "scan_options": ["source", "symbol", "./..."] + (["GOFLAGS=" + goflags] if goflags else [])}
            key = cache_key(material)
            result.update({"cache_key": key, "cache_material": material, "data_flow": "preloaded dependency and local advisory subset; GOPROXY=off; no credentials inherited; no host execution"})
            lockroot = Path(tempfile.gettempdir()) / "vettalon-reachability.lock"
            with lockroot.open("a") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    result["reason"] = "busy-one-inflight"
                    return result
                cachefile = Path(cache) / (key + ".json") if cache else None
                cached = None
                if cachefile and cachefile.exists():
                    try:
                        entry = json.loads(cachefile.read_text())
                        if entry["key"] == key and valid_cached_run(entry.get("run")) and entry["raw_sha256"] == digest(entry["run"]["stdout"].encode()):
                            cached = entry["run"]
                    except (ValueError, KeyError, TypeError):
                        pass
                if cached:
                    run = cached
                    result["cache"] = {"hit": True, "source": str(cachefile), "original_seconds": run["seconds"]}
                else:
                    command = [str(tool), "-json", "-mode=source", "-scan=symbol", "-db=" + db.as_uri()]
                    if tags:
                        command += ["-tags=" + tags]
                    run = invoke(command + ["./..."], project, env, timeout)
                result.update(classify(run["stdout"], run["returncode"], candidate))
                if result["status"] == "not-observed":
                    signals = blind_spot_signals(project)
                    if signals:
                        result.update(unknown("blind-spot-" + "+".join(signals)))
                        result["blind_spot_signals"] = signals
                if not successful_run(run):
                    result.update(unknown(run.get("error") or "incomplete-process-observation"))
                result["run"] = {k: v for k, v in run.items() if k not in ("stdout", "stderr")}
                result["raw_sha256"] = digest(run["stdout"].encode())
                (output / "raw.jsons").write_text(run["stdout"])
                (output / "stderr.txt").write_text(run["stderr"])
                # Detect source mutation while analyzing; do not cache such a run.
                if tree_hash(project) != material["host_source_sha256"] or tree_hash(dependency) != material["dependency_source_sha256"] or tree_hash(db) != material["db_snapshot_sha256"]:
                    result.update(unknown("source-changed-during-scan"))
                if cachefile and not cached and result["status"] != "unknown":
                    cachefile.parent.mkdir(parents=True, exist_ok=True)
                    write_json(cachefile, {"key": key, "raw_sha256": result["raw_sha256"], "run": run})
    except (ValueError, OSError, KeyError, TypeError) as error:
        result.update(unknown("input-or-source-error"))
        result["error"] = str(error)
    finally:
        result["cache"]["accepted"] = result["status"] != "unknown" and result["cache"]["hit"]
        write_json(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tool", required=True, type=Path)
    parser.add_argument("--dependency-source", type=Path)
    parser.add_argument("--db", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--tags", default="")
    parser.add_argument("--target")
    parser.add_argument("--language", choices=["go", "rust"], default="go")
    args = parser.parse_args()
    result = scan(args.project, args.output, args.tool, language=args.language, dependency=args.dependency_source, db=args.db, cache=args.cache, tags=args.tags, target=args.target)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result["status"] == "unknown" else 0


if __name__ == "__main__":
    raise SystemExit(main())
