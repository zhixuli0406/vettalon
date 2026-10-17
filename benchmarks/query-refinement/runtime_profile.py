"""Opt-in, file-only bindings for the public finite query experiment."""
from dataclasses import dataclass
import configparser
from email.parser import Parser
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from typing import Mapping

PROFILE_KIND = "public-query-runtime-v2"
LOCK_KIND = "public-query-lock-v2"
SCHEMA = 2
SCANNER_VERSION = "1.181.0"
POLICY_BYTES = b"(version 1)\n(allow default)\n(deny network*)\n"
PROFILE_CAP = 64 * 1024
LOCK_CAP = 256 * 1024
SEAL_CAP = 64 * 1024
MAX_FILES = 256
FILE_CAP = 256 * 1024 * 1024
TOTAL_CAP = 512 * 1024 * 1024
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BINDING_ROLES = frozenset({"launcher", "core", "policy", "sandbox", "launcher_python", "controller_python"})
RUNTIME_RELATIVE = (
    "semgrep/__init__.py", "semgrep/console_scripts/entrypoint.py", "semgrep/semgrep_core.py",
    "semgrep-1.181.0.dist-info/METADATA", "semgrep-1.181.0.dist-info/entry_points.txt",
)


def required_paths():
    """Return repository files that every v2 lock must bind explicitly."""
    paths = {
        "research_controller": HERE / "refine.py", "oracle": HERE / "oracle.py",
        "public_controller": HERE / "refine_public_v2.py", "profile_parser": HERE / "runtime_profile.py",
        "adapter": ROOT / "benchmarks/reachability/adapter.py",
        "supervisor": ROOT / "benchmarks/reachability/process_supervisor.py",
        "rule_source": ROOT / "crates/vettalon/src/audit/scanners/semgrep.rs",
    }
    for name in ("a73c", "b84d", "c95e", "d06f", "e17a", "f28b"):
        paths[f"dev_{name}"] = HERE / "fixtures/dev" / f"{name}.py"
    return paths


@dataclass(frozen=True)
class Binding:
    launcher: Path
    core: Path
    policy: Path
    sandbox: Path
    oracle: Path
    rule_source: Path
    files: Mapping[str, str]
    oracle_sha256: str
    binding_sha256: str
    profile_bytes: bytes
    lock_bytes: bytes
    controller_python_version: str
    launcher_python: Path
    controller_python: Path
    _profile_path: Path
    _profile_sha256: str
    _lock_path: Path
    _lock_sha256: str
    _seal_path: Path

    def verify(self):
        current = load_binding(self._profile_path, self._profile_sha256,
                               self._lock_path, self._lock_sha256, seal_path=self._seal_path)
        if current != self:
            raise ValueError("binding-drift")

    def read_seal(self):
        """Read the currently bound descriptor with a separate byte cap."""
        if not isinstance(self.files, Mapping):
            raise ValueError("binding-drift")
        expected = self.files.get(str(self._seal_path))
        if not _valid_hash(expected):
            raise ValueError("binding-drift")
        try:
            raw = _checked_bytes(self._seal_path, expected, cap=SEAL_CAP)
        except ValueError as error:
            reason = "seal-bound" if str(error) == "file-bound" else "seal-drift"
            raise ValueError(reason) from error
        except OSError as error:
            raise ValueError("seal-drift") from error
        # Validate effective fields before returning parsed data. Generic verification
        # also streams locked files; this is not a whole-run filesystem byte cap.
        self.verify()
        try:
            value = _json(raw)
        except ValueError as error:
            raise ValueError("seal-schema") from error
        if type(value) is not dict:
            raise ValueError("seal-schema")
        return value


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _valid_hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _path(value, *, allow_leaf_symlink=False):
    if not isinstance(value, (str, Path)):
        raise ValueError("unsafe-path")
    text = str(value)
    path = Path(text)
    if not path.is_absolute() or os.path.normpath(text) != text or str(path) != text:
        raise ValueError("unsafe-path")
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("unsafe-path")
    if not allow_leaf_symlink and path.is_symlink():
        raise ValueError("unsafe-path")
    if not allow_leaf_symlink and path.resolve(strict=True) != path:
        raise ValueError("unsafe-path")
    return path


def _read(path, cap, *, collect=False):
    """Hash in bounded chunks; reject non-regular files before reading."""
    path = _path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not-regular-file")
        if before.st_size > cap:
            raise ValueError("file-bound")
        value, pieces, count = hashlib.sha256(), [], 0
        while True:
            raw = os.read(fd, min(1024 * 1024, cap - count + 1))
            if not raw:
                break
            count += len(raw)
            if count > cap:
                raise ValueError("file-bound")
            value.update(raw)
            if collect:
                pieces.append(raw)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("file-drift")
        return value.hexdigest(), count, b"".join(pieces) if collect else None
    finally:
        os.close(fd)


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate-json-key")
            value[key] = item
        return value
    def finite(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("nonfinite-json")
        return value
    def invalid(_):
        raise ValueError("nonfinite-json")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_float=finite, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as error:
        raise ValueError("invalid-json") from error


def _exact(value, keys, reason):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(reason)


def _version(value, *, minor=False):
    pattern = r"3\.[0-9]+" if minor else r"3\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?"
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _checked_bytes(path, expected, cap=PROFILE_CAP):
    observed, _, raw = _read(path, cap, collect=True)
    if observed != expected:
        raise ValueError("file-drift")
    return raw


def _load(profile_path, profile_sha256, lock_path, lock_sha256, *, seal_path):
    if sys.platform != "darwin":
        raise ValueError("unsupported-platform")
    if not _valid_hash(profile_sha256) or not _valid_hash(lock_sha256):
        raise ValueError("invalid-expected-hash")
    profile_path, lock_path, seal_path = (_path(path) for path in (profile_path, lock_path, seal_path))
    if len({profile_path, lock_path, seal_path}) != 3:
        raise ValueError("binding-path-overlap")
    observed, _, profile_raw = _read(profile_path, PROFILE_CAP, collect=True)
    if observed != profile_sha256:
        raise ValueError("profile-drift")
    observed, lock_size, lock_raw = _read(lock_path, LOCK_CAP, collect=True)
    if observed != lock_sha256:
        raise ValueError("lock-drift")
    value, lock = _json(profile_raw), _json(lock_raw)
    _exact(value, {"schema", "kind", "platform", "scanner_version", "python_minor",
                   "controller_python_version", "venv_root", "bindings", "runtime_files"}, "profile-schema")
    _exact(lock, {"schema", "kind", "files"}, "lock-schema")
    if (type(value["schema"]) is not int or value["schema"] != SCHEMA
            or value["kind"] != PROFILE_KIND or value["platform"] != "darwin"
            or value["scanner_version"] != SCANNER_VERSION
            or not _version(value["python_minor"], minor=True)
            or not _version(value["controller_python_version"])):
        raise ValueError("profile-schema")
    if type(lock["schema"]) is not int or lock["schema"] != SCHEMA or lock["kind"] != LOCK_KIND:
        raise ValueError("lock-schema")
    venv = _path(value["venv_root"])
    if not venv.is_dir():
        raise ValueError("runtime-layout")
    _exact(value["bindings"], BINDING_ROLES, "binding-schema")
    bindings = {}
    for role, row in value["bindings"].items():
        _exact(row, {"path", "sha256"}, "binding-schema")
        if not _valid_hash(row["sha256"]):
            raise ValueError("binding-schema")
        bindings[role] = _path(row["path"])
    if (bindings["controller_python"] != Path(sys.executable).resolve(strict=True)
            or value["controller_python_version"] != sys.version.split()[0]):
        raise ValueError("controller-python-identity")
    package = venv / f"lib/python{value['python_minor']}/site-packages"
    if (bindings["launcher"] != venv / "bin/semgrep"
            or bindings["core"] != package / "semgrep/bin/semgrep-core"
            or bindings["sandbox"] != Path("/usr/bin/sandbox-exec")):
        raise ValueError("runtime-layout")
    runtime, files = value["runtime_files"], lock["files"]
    if type(runtime) is not dict or type(files) is not dict:
        raise ValueError("files-schema")
    if len(files) > MAX_FILES or len(runtime) > MAX_FILES:
        raise ValueError("files-bound")
    venv_config = venv / "pyvenv.cfg"
    if str(venv_config) not in runtime or str(venv_config) not in files:
        raise ValueError("venv-config")
    try:
        if not _path(venv_config).is_file():
            raise ValueError("venv-config")
    except OSError as error:
        raise ValueError("venv-config") from error
    for name, expected in runtime.items():
        path = _path(name)
        if not path.is_relative_to(venv) or not _valid_hash(expected):
            raise ValueError("runtime-files")
        if files.get(name) != expected:
            raise ValueError("missing-required-file")
    if not {str(package / relative) for relative in RUNTIME_RELATIVE} <= set(runtime):
        raise ValueError("missing-runtime-file")
    required = dict(required_paths())
    required.update(bindings)
    required.update(profile=profile_path, seal=seal_path)
    for path in required.values():
        if str(path) not in files:
            raise ValueError("missing-required-file")
    for role, row in value["bindings"].items():
        if files[str(bindings[role])] != row["sha256"]:
            raise ValueError("binding-hash-mismatch")
    if files[str(profile_path)] != profile_sha256 or str(lock_path) in files:
        raise ValueError("lock-profile-binding")
    total = lock_size
    for name, expected in files.items():
        if not _valid_hash(expected):
            raise ValueError("files-schema")
        observed, count, _ = _read(_path(name), FILE_CAP)
        total += count
        if total > TOTAL_CAP:
            raise ValueError("total-bound")
        if observed != expected:
            raise ValueError("file-drift")
    if _checked_bytes(bindings["policy"], files[str(bindings["policy"])]) != POLICY_BYTES:
        raise ValueError("network-policy")
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    try:
        config_raw = _checked_bytes(venv_config, files[str(venv_config)])
        config.read_string("[venv]\n" + config_raw.decode("utf-8", "strict"))
        declared_version = config.get("venv", "version", raw=True)
        if (config.sections() != ["venv"] or config.defaults()
                or config.get("venv", "include-system-site-packages", raw=True) != "false"
                or not _version(declared_version)
                or ".".join(declared_version.split(".")[:2]) != value["python_minor"]):
            raise ValueError("venv-config")
    except (configparser.Error, UnicodeError) as error:
        raise ValueError("venv-config") from error
    launcher_raw = _checked_bytes(bindings["launcher"], files[str(bindings["launcher"])])
    try:
        launcher_text = launcher_raw.decode("utf-8", "strict")
        header = launcher_text.splitlines()[0]
        if not header.startswith("#!/") or len(header[2:].split()) != 1:
            raise ValueError("launcher-shebang")
        interpreter_path = _path(header[2:], allow_leaf_symlink=True)
        allowed_python_paths = {venv / "bin" / name for name in (
            "python", "python3", "python" + value["python_minor"])}
        if interpreter_path not in allowed_python_paths:
            raise ValueError("launcher-shebang")
        interpreter = interpreter_path.resolve(strict=True)
        if interpreter != bindings["launcher_python"]:
            raise ValueError("launcher-shebang")
        if not re.search(r"(?m)^from semgrep\.console_scripts\.entrypoint import main$", launcher_text):
            raise ValueError("launcher-entrypoint")
    except (UnicodeError, IndexError) as error:
        raise ValueError("launcher-shebang") from error
    metadata_path = package / RUNTIME_RELATIVE[3]
    metadata_raw = _checked_bytes(metadata_path, files[str(metadata_path)])
    metadata = Parser().parsestr(metadata_raw.decode("utf-8", "strict"))
    if metadata.get_all("Name") != ["semgrep"] or metadata.get_all("Version") != [SCANNER_VERSION]:
        raise ValueError("package-metadata")
    entry_path = package / RUNTIME_RELATIVE[4]
    entry = configparser.ConfigParser(interpolation=None, strict=True)
    entry.optionxform = str
    try:
        entry.read_string(_checked_bytes(entry_path, files[str(entry_path)]).decode("utf-8", "strict"))
        if entry.get("console_scripts", "semgrep", raw=True) != "semgrep.console_scripts.entrypoint:main":
            raise ValueError("package-entrypoint")
    except configparser.Error as error:
        raise ValueError("package-entrypoint") from error
    binding_sha256 = _hash((profile_sha256 + ":" + lock_sha256).encode("ascii"))
    return Binding(bindings["launcher"], bindings["core"], bindings["policy"], bindings["sandbox"],
                   required["oracle"], required["rule_source"], MappingProxyType(dict(files)),
                   files[str(required["oracle"])], binding_sha256, profile_raw, lock_raw,
                   value["controller_python_version"], bindings["launcher_python"],
                   bindings["controller_python"], profile_path, profile_sha256,
                   lock_path, lock_sha256, seal_path)


def load_binding(profile_path, profile_sha256, lock_path, lock_sha256, *, seal_path):
    """Validate explicit raw digests and an immutable, bounded local runtime."""
    try:
        return _load(profile_path, profile_sha256, lock_path, lock_sha256, seal_path=seal_path)
    except OSError as error:
        raise ValueError("runtime-file-error") from error
