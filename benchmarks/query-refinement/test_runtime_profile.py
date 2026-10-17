"""File-only acceptance of explicit public runtime profiles."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import runtime_profile as profile
from test_public_support import digest, make_runtime_fixture, rewrite_fixture


class RuntimeProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        seal = self.root / "seal.json"
        seal.write_bytes(b'{"self_authored":"seal-only-no-source"}\n')
        self.fixture = make_runtime_fixture(self.root / "runtime", seal)

    def load(self, **changes):
        value = {key: self.fixture[key] for key in (
            "profile_path", "profile_sha256", "lock_path", "lock_sha256", "seal_path")}
        value.update(changes)
        return profile.load_binding(**value)

    def rebind(self):
        rewrite_fixture(self.fixture)

    def test_valid_binding_is_immutable_and_does_not_execute_tools(self):
        with patch("subprocess.Popen", side_effect=AssertionError("external-execution")):
            binding = self.load()
            binding.verify()
        self.assertEqual(binding.launcher, self.fixture["venv"] / "bin/semgrep")
        self.assertEqual(binding.oracle, profile.required_paths()["oracle"])
        self.assertEqual(binding.oracle_sha256, digest(binding.oracle))
        self.assertEqual(binding.profile_bytes, self.fixture["profile_path"].read_bytes())
        self.assertEqual(binding.lock_bytes, self.fixture["lock_path"].read_bytes())
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            binding.launcher = Path("/unapproved")
        with self.assertRaises(TypeError):
            binding.files["/unapproved"] = "0" * 64

    def test_verify_rejects_replaced_effective_binding_fields(self):
        binding = self.load()
        changed = {field: Path("/arbitrary") for field in (
            "launcher", "core", "policy", "sandbox", "oracle", "rule_source",
            "launcher_python", "controller_python")}
        changed.update(files={"/arbitrary": "0" * 64}, oracle_sha256="0" * 64,
                       controller_python_version="3.0.0", profile_bytes=b"{}", lock_bytes=b"{}")
        for field, value in changed.items():
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "binding-drift"):
                replace(binding, **{field: value}).verify()

    def test_expected_raw_digests_are_required_and_strict(self):
        for field in ("profile_sha256", "lock_sha256"):
            for value in (None, True, "", "A" * 64, "0" * 63, "0" * 64):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.load(**{field: value})

    def test_profile_duplicate_utf8_nonfinite_and_unknown_fields_rejected(self):
        invalid = [b'{"schema":2,"schema":2}', b"\xff", b'{"schema":NaN}', b'{"schema":1e999}']
        for raw in invalid:
            self.fixture["profile_path"].write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.load(profile_sha256=digest(self.fixture["profile_path"]))
        for key in ("argv", "env", "hooks", "download", "fallback"):
            self.fixture["profile"][key] = {}
            self.rebind()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load()
            del self.fixture["profile"][key]

    def test_profile_fixed_fields_and_exact_primitive_types(self):
        changes = {"schema": [True, 1, "2"], "kind": ["other"], "platform": ["linux"],
                   "scanner_version": ["1.180.0"], "python_minor": [True, "3", "3.12/../"],
                   "controller_python_version": [True, "unknown"]}
        for key, values in changes.items():
            before = self.fixture["profile"][key]
            for value in values:
                self.fixture["profile"][key] = value
                self.rebind()
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.load()
            self.fixture["profile"][key] = before

    def test_lock_duplicate_extra_wrong_type_and_nonfinite_rejected(self):
        invalid = [b'{"schema":2,"schema":2}', b"\xff", b'{"files":NaN}', b'{"files":1e999}']
        for raw in invalid:
            self.fixture["lock_path"].write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.load(lock_sha256=digest(self.fixture["lock_path"]))
        for key, value in (("schema", True), ("kind", "other"), ("files", []), ("hooks", [])):
            before = self.fixture["lock"].copy()
            self.fixture["lock"][key] = value
            self.rebind()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load()
            self.fixture["lock"] = before

    def test_missing_required_repository_runtime_and_seal_files_rejected(self):
        for path in list(profile.required_paths().values()) + [self.fixture["seal_path"], self.fixture["profile_path"]]:
            name = str(path)
            before = self.fixture["lock"]["files"].pop(name)
            self.rebind()
            # rewrite_fixture restores the profile binding by design.
            if path == self.fixture["profile_path"]:
                del self.fixture["lock"]["files"][name]
                self.fixture["lock_path"].write_text(json.dumps(self.fixture["lock"]))
                self.fixture["lock_sha256"] = digest(self.fixture["lock_path"])
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.load()
            self.fixture["lock"]["files"][name] = before

    def test_runtime_files_cannot_omit_package_identity(self):
        for name in list(self.fixture["profile"]["runtime_files"]):
            before = self.fixture["profile"]["runtime_files"].pop(name)
            self.rebind()
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.load()
            self.fixture["profile"]["runtime_files"][name] = before

    def test_profile_and_locked_files_detect_drift_after_load(self):
        binding = self.load()
        for path in (self.fixture["profile_path"], self.fixture["lock_path"],
                     self.fixture["seal_path"], self.fixture["venv"] / "bin/semgrep"):
            raw = path.read_bytes()
            path.write_bytes(raw + b"\n")
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                binding.verify()
            path.write_bytes(raw)
        binding.verify()

    def test_profile_lock_and_seal_must_be_absolute_canonical_regular_files(self):
        for name in ("profile_path", "lock_path", "seal_path"):
            path = self.fixture[name]
            link = self.root / (name + ".link")
            link.symlink_to(path)
            for invalid in (link, Path(os.path.relpath(path)), path.parent / ".." / path.parent.name / path.name):
                with self.subTest(name=name, path=str(invalid)), self.assertRaises(ValueError):
                    self.load(**{name: invalid})

    def test_symlink_ancestor_and_directory_entries_are_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.fixture["root"], target_is_directory=True)
        with self.assertRaises(ValueError):
            self.load(profile_path=alias / self.fixture["profile_path"].name)
        self.fixture["lock"]["files"][str(self.root)] = "0" * 64
        self.rebind()
        with self.assertRaises(ValueError):
            self.load()

    def test_runtime_paths_must_belong_to_declared_venv(self):
        outsider = self.root / "unrelated.py"
        outsider.write_bytes(b"# unrelated package\n")
        self.fixture["profile"]["runtime_files"][str(outsider)] = digest(outsider)
        self.fixture["lock"]["files"][str(outsider)] = digest(outsider)
        self.rebind()
        with self.assertRaises(ValueError):
            self.load()

    def test_binding_roles_are_exact_and_cannot_override_required_source(self):
        for role in list(profile.BINDING_ROLES):
            before = self.fixture["profile"]["bindings"].pop(role)
            self.rebind()
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.load()
            self.fixture["profile"]["bindings"][role] = before
        self.fixture["profile"]["bindings"]["oracle"] = self.fixture["profile"]["bindings"]["core"]
        self.rebind()
        with self.assertRaises(ValueError):
            self.load()

    def test_binding_paths_hashes_and_layout_are_enforced(self):
        for role in ("launcher", "core", "sandbox", "controller_python"):
            row = self.fixture["profile"]["bindings"][role]
            before = row.copy()
            for key, value in (("path", "relative"), ("sha256", True), ("extra", "unsupported")):
                row[key] = value
                self.rebind()
                with self.subTest(role=role, key=key), self.assertRaises(ValueError):
                    self.load()
                row.clear()
                row.update(before)

    def test_package_metadata_name_version_and_console_entrypoint_are_exact(self):
        for relative, invalids in {
            "semgrep-1.181.0.dist-info/METADATA": [b"Name: other\nVersion: 1.181.0\n", b"Name: semgrep\nVersion: 1.180.0\n", b"Name: semgrep\nName: semgrep\nVersion: 1.181.0\n"],
            "semgrep-1.181.0.dist-info/entry_points.txt": [b"[console_scripts]\nsemgrep = other:main\n", b"[console_scripts]\nsemgrep = semgrep.console_scripts.entrypoint:main\nsemgrep = other:main\n"],
        }.items():
            path = self.fixture["package"] / relative
            before = path.read_bytes()
            for invalid in invalids:
                path.write_bytes(invalid)
                self.fixture["profile"]["runtime_files"][str(path)] = digest(path)
                self.fixture["lock"]["files"][str(path)] = digest(path)
                self.rebind()
                with self.subTest(relative=relative, invalid=invalid), self.assertRaises(ValueError):
                    self.load()
            path.write_bytes(before)
            self.fixture["profile"]["runtime_files"][str(path)] = digest(path)
            self.fixture["lock"]["files"][str(path)] = digest(path)

    def test_launcher_shebang_requires_bound_absolute_python_without_arguments(self):
        launcher = self.fixture["venv"] / "bin/semgrep"
        python = self.fixture["profile"]["bindings"]["launcher_python"]["path"]
        for header in ("#!/usr/bin/env python3", "#!python3", f"#!{python} -I", "#!/bin/sh"):
            launcher.write_text(header + "\nfrom semgrep.console_scripts.entrypoint import main\n")
            value = digest(launcher)
            self.fixture["profile"]["bindings"]["launcher"]["sha256"] = value
            self.fixture["lock"]["files"][str(launcher)] = value
            self.rebind()
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.load()

    def test_launcher_shebang_must_lexically_use_the_declared_venv(self):
        launcher = self.fixture["launcher"]
        base_python = Path(self.fixture["profile"]["bindings"]["launcher_python"]["path"])
        other_python = self.root / "other-venv/bin/python"
        other_python.parent.mkdir(parents=True)
        other_python.symlink_to(base_python)
        for python in (base_python, other_python):
            launcher.write_text(f"#!{python}\nfrom semgrep.console_scripts.entrypoint import main\n")
            value = digest(launcher)
            self.fixture["profile"]["bindings"]["launcher"]["sha256"] = value
            self.fixture["lock"]["files"][str(launcher)] = value
            self.rebind()
            with self.subTest(python=str(python)), self.assertRaisesRegex(ValueError, "launcher-shebang"):
                self.load()

    def test_venv_config_requires_locked_unique_false_system_site_and_layout_version(self):
        path = self.fixture["venv"] / "pyvenv.cfg"
        before = path.read_bytes()
        invalid = (
            b"include-system-site-packages = true\nversion = 3.0.0\n",
            before + b"include-system-site-packages = false\n",
            b"include-system-site-packages = false\nversion = 3.0.0\n",
            b"version = 3.0.0\n",
        )
        for raw in invalid:
            path.write_bytes(raw)
            self.fixture["profile"]["runtime_files"][str(path)] = digest(path)
            self.fixture["lock"]["files"][str(path)] = digest(path)
            self.rebind()
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "venv-config"):
                self.load()
        path.write_bytes(before)
        del self.fixture["profile"]["runtime_files"][str(path)]
        del self.fixture["lock"]["files"][str(path)]
        path.unlink()
        self.rebind()
        with self.subTest(missing=True), self.assertRaisesRegex(ValueError, "venv-config"):
            self.load()

    def test_network_policy_cannot_be_relaxed_even_with_matching_hash(self):
        path = Path(self.fixture["profile"]["bindings"]["policy"]["path"])
        path.write_bytes(profile.POLICY_BYTES + b"(allow network*)\n")
        self.fixture["profile"]["bindings"]["policy"]["sha256"] = digest(path)
        self.fixture["lock"]["files"][str(path)] = digest(path)
        self.rebind()
        with self.assertRaises(ValueError):
            self.load()

    def test_profile_lock_file_and_total_byte_caps(self):
        for name, cap in (("profile_path", profile.PROFILE_CAP), ("lock_path", profile.LOCK_CAP)):
            path = self.fixture[name]
            raw = path.read_bytes()
            path.write_bytes(b" " * (cap + 1))
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.load(**{name.replace("path", "sha256"): digest(path)})
            path.write_bytes(raw)
        with patch.object(profile, "FILE_CAP", 8), self.assertRaises(ValueError):
            self.load()
        with patch.object(profile, "TOTAL_CAP", 8), self.assertRaises(ValueError):
            self.load()
        with patch.object(profile, "MAX_FILES", 1), self.assertRaises(ValueError):
            self.load()

    def test_seal_bytes_are_hashed_without_parsing_or_loading_holdout(self):
        seal = self.fixture["seal_path"]
        seal.write_bytes(b"opaque seal payload; deliberately invalid JSON\n")
        self.fixture["lock"]["files"][str(seal)] = digest(seal)
        self.rebind()
        self.load().verify()

    def test_platform_must_be_macos(self):
        with patch.object(profile.sys, "platform", "linux"), self.assertRaises(ValueError):
            self.load()

    def test_current_controller_interpreter_path_and_exact_version_are_bound(self):
        before = self.fixture["profile"]["controller_python_version"]
        self.fixture["profile"]["controller_python_version"] = "3.0.0"
        self.rebind()
        with self.assertRaisesRegex(ValueError, "controller-python-identity"):
            self.load()
        self.fixture["profile"]["controller_python_version"] = before
        outsider = self.root / "other-python"
        outsider.write_bytes(b"self-authored-not-running-python\n")
        self.fixture["profile"]["bindings"]["controller_python"] = {"path": str(outsider), "sha256": digest(outsider)}
        self.fixture["lock"]["files"][str(outsider)] = digest(outsider)
        self.rebind()
        with self.assertRaisesRegex(ValueError, "controller-python-identity"):
            self.load()

    def set_seal_bytes(self, raw):
        path = self.fixture["seal_path"]
        path.write_bytes(raw)
        self.fixture["lock"]["files"][str(path)] = digest(path)
        self.rebind()

    def test_read_seal_uses_bounded_actual_bytes_and_preserves_json_semantics(self):
        holdout = self.root / "unread-holdout.py"
        holdout.write_bytes(b"must-not-read-holdout-source\n")
        original_open = os.open
        def checked_open(path, *args, **kwargs):
            if Path(path) == holdout:
                raise AssertionError("holdout-source-read")
            return original_open(path, *args, **kwargs)
        for raw in (b'{"first":1,"second":{"x":true}}', b'{\n "second": {"x": true}, "first": 1\n}\n'):
            self.set_seal_bytes(raw)
            binding = self.load()
            with patch("subprocess.Popen", side_effect=AssertionError("external-execution")), patch.object(os, "open", checked_open):
                self.assertEqual(binding.read_seal(), {"first": 1, "second": {"x": True}})

    def test_read_seal_rejects_oversize_even_when_lock_is_resigned(self):
        self.set_seal_bytes(b" " * (profile.SEAL_CAP + 1))
        binding = self.load()
        with self.assertRaisesRegex(ValueError, "seal-bound"):
            binding.read_seal()

    def test_read_seal_rejects_bytes_changed_after_binding(self):
        binding = self.load()
        self.fixture["seal_path"].write_bytes(b'{"changed":"after-binding"}\n')
        with self.assertRaisesRegex(ValueError, "seal-drift"):
            binding.read_seal()

    def test_read_seal_rejects_invalid_or_nonobject_json(self):
        invalid = (b'{"same":1,"same":2}', b'{"x":NaN}', b'{"x":1e999}', b"\xff",
                   b"[]", b'"text"', b"null", b"true", b"1")
        for raw in invalid:
            self.set_seal_bytes(raw)
            binding = self.load()
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "seal-schema"):
                binding.read_seal()
if __name__ == "__main__":
    unittest.main()
