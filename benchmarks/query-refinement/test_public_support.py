"""Self-authored file fixtures; no scanner, target, model, or subprocess runs."""
import hashlib
import json
from pathlib import Path
import sys

import runtime_profile as profile


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def make_runtime_fixture(root, seal_path, *, launcher_source=None):
    """Build local fake package bytes, binding the actual interpreter/sandbox."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    seal_path = Path(seal_path)
    venv = root / "venv"
    minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    package = venv / f"lib/python{minor}/site-packages"
    interpreter = Path(sys.executable).resolve()
    python_link = venv / "bin/python"
    python_link.parent.mkdir(parents=True)
    python_link.symlink_to(interpreter)
    launcher = venv / "bin/semgrep"
    launcher_body = b"raise SystemExit(main())\n" if launcher_source is None else launcher_source
    launcher.write_bytes((f"#!{python_link}\nimport sys\nsys.path.insert(0, {str(package)!r})\n"
                          "from semgrep.console_scripts.entrypoint import main\n").encode() + launcher_body)
    launcher.chmod(0o755)
    core = package / "semgrep/bin/semgrep-core"
    core.parent.mkdir(parents=True)
    core.write_bytes(b"self-authored-inert-core-fixture\n")
    core.chmod(0o755)
    contents = {
        "semgrep/__init__.py": b"# Self-authored package fixture.\n",
        "semgrep/console_scripts/entrypoint.py": b"def main():\n    return 0\n",
        "semgrep/semgrep_core.py": b"# Self-authored module fixture.\n",
        "semgrep-1.181.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: semgrep\nVersion: 1.181.0\n\n",
        "semgrep-1.181.0.dist-info/entry_points.txt": b"[console_scripts]\nsemgrep = semgrep.console_scripts.entrypoint:main\n",
    }
    runtime = {}
    for relative, raw in contents.items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        runtime[str(path)] = digest(path)
    venv_config = venv / "pyvenv.cfg"
    venv_config.write_text(f"home = {interpreter.parent}\ninclude-system-site-packages = false\nversion = {sys.version.split()[0]}\n")
    runtime[str(venv_config)] = digest(venv_config)
    policy = root / "deny-network.sb"
    policy.write_bytes(profile.POLICY_BYTES)
    sandbox = Path("/usr/bin/sandbox-exec")
    bindings = {name: {"path": str(path), "sha256": digest(path)} for name, path in {
        "launcher": launcher, "core": core, "policy": policy, "sandbox": sandbox,
        "launcher_python": interpreter, "controller_python": interpreter,
    }.items()}
    value = {
        "schema": profile.SCHEMA, "kind": profile.PROFILE_KIND, "platform": "darwin",
        "scanner_version": profile.SCANNER_VERSION, "python_minor": minor,
        "controller_python_version": sys.version.split()[0], "venv_root": str(venv),
        "bindings": bindings, "runtime_files": runtime,
    }
    profile_path, lock_path = root / "runtime.json", root / "lock.json"
    profile_path.write_bytes(encoded(value))
    files = {str(path): digest(path) for path in profile.required_paths().values()}
    files.update(runtime)
    files.update({row["path"]: row["sha256"] for row in bindings.values()})
    files[str(profile_path)] = digest(profile_path)
    files[str(seal_path)] = digest(seal_path)
    lock = {"schema": profile.SCHEMA, "kind": profile.LOCK_KIND, "files": files}
    lock_path.write_bytes(encoded(lock))
    return {"root": root, "venv": venv, "venv_root": venv, "package": package,
            "launcher": launcher, "core": core, "policy": policy, "sandbox": sandbox,
            "profile_path": profile_path, "profile_sha256": digest(profile_path),
            "lock_path": lock_path, "lock_sha256": digest(lock_path),
            "seal_path": seal_path, "profile": value, "lock": lock}


def rewrite_fixture(fixture):
    """Rebind intentional test edits without hiding invalid parser inputs."""
    fixture["profile_path"].write_bytes(encoded(fixture["profile"]))
    fixture["profile_sha256"] = digest(fixture["profile_path"])
    if type(fixture["lock"].get("files")) is dict:
        fixture["lock"]["files"][str(fixture["profile_path"])] = fixture["profile_sha256"]
    fixture["lock_path"].write_bytes(encoded(fixture["lock"]))
    fixture["lock_sha256"] = digest(fixture["lock_path"])
