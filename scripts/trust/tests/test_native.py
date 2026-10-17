import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "native", Path(__file__).parents[1] / "native.py"
)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


def marker_environment():
    return {
        "implementation_name": "cpython",
        "implementation_version": "3.12.0",
        "os_name": "nt",
        "platform_machine": "AMD64",
        "platform_release": "10",
        "platform_system": "Windows",
        "platform_version": "10.0",
        "python_full_version": "3.12.0",
        "platform_python_implementation": "CPython",
        "python_version": "3.12",
        "sys_platform": "win32",
    }


def pip_snapshot(requirements):
    return {
        "environment": marker_environment(),
        "installed": [
            {
                "metadata": {
                    "name": "app",
                    "version": "1",
                    "requires_dist": requirements,
                },
                "requested": True,
            },
            {"metadata": {"name": "dep", "version": "2"}, "requested": False},
        ],
    }


class NativeGraphTests(unittest.TestCase):
    def test_npm_lock_nested_graph(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1", "dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1", "dependencies": {"b": "2"}},
                "node_modules/b": {"version": "2"},
            },
        }
        nodes, edges, direct = native.npm_graph(lock)
        self.assertIn(("a", "1"), direct)
        self.assertIn((("a", "1"), ("b", "2")), edges)

    def test_npm_missing_resolved_node_fails(self):
        with self.assertRaises(ValueError):
            native.npm_graph(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "app",
                            "version": "1",
                            "dependencies": {"missing": "1"},
                        }
                    },
                }
            )

    def test_pip_metadata_marker_and_requested(self):
        inspect = {
            "environment": marker_environment(),
            "installed": [
                {
                    "metadata": {
                        "name": "requests",
                        "version": "1",
                        "requires_dist": ["idna>=2", 'extra-only; extra == "x"'],
                    },
                    "requested": True,
                },
                {"metadata": {"name": "idna", "version": "3"}, "requested": False},
            ],
        }
        nodes, edges, direct = native.pip_graph(inspect)
        self.assertEqual(direct, {("requests", "1")})
        self.assertEqual(edges, {(("requests", "1"), ("idna", "3"))})

    def test_pip_missing_dependency_fails(self):
        with self.assertRaises(ValueError):
            native.pip_graph(
                {
                    "environment": marker_environment(),
                    "installed": [
                        {
                            "metadata": {
                                "name": "a",
                                "version": "1",
                                "requires_dist": ["absent"],
                            }
                        }
                    ]
                }
            )

    def test_go_native_missing_node_gets_explicit_native_provenance(self):
        bom = {"components": []}
        result = native.enrich(
            bom,
            {("example.com/a", "v1")},
            set(),
            {("example.com/a", "v1")},
            "go-native",
            "a" * 64,
        )
        self.assertEqual(result["components"][0]["purl"], "pkg:golang/example.com/a@v1")
        self.assertIn(
            {
                "name": "vettalon:license:status",
                "value": "unknown; native module metadata lacks license evidence",
            },
            result["components"][0]["properties"],
        )

    def test_npm_missing_inventory_still_fails(self):
        with self.assertRaises(ValueError):
            native.enrich(
                {"components": []}, {("a", "1")}, set(), set(), "npm-lock-v3", "b" * 64
            )

    def test_go_graph_ignores_unselected_source_edges(self):
        _, edges, _ = native.go_graph(
            {"Require": []}, "a@v1 b@v1\n", {"a": "v2", "b": "v1"}
        )
        self.assertEqual(edges, set())

    def test_go_graph_uses_selected_versions(self):
        nodes, edges, direct = native.go_graph(
            {
                "Module": {"Path": "app"},
                "Require": [
                    {"Path": "a", "Version": "v2"},
                    {"Path": "b", "Version": "v3", "Indirect": True},
                ],
            },
            "app a@v2\na@v2 b@v1\n",
            {"app": None, "a": "v2", "b": "v3"},
        )
        self.assertEqual(direct, {("a", "v2")})
        self.assertIn((("a", "v2"), ("b", "v3")), edges)


class PipMarkerSnapshotTests(unittest.TestCase):
    def test_marker_missing_environment_fails_instead_of_using_host(self):
        snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
        del snapshot["environment"]
        with self.assertRaises(ValueError):
            native.pip_graph(snapshot)

    def test_partial_malformed_and_empty_environment_fail(self):
        for value in (None, {}, [], {"sys_platform": "win32"}):
            with self.subTest(environment=value):
                snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
                snapshot["environment"] = value
                with self.assertRaises(ValueError):
                    native.pip_graph(snapshot)
        for key in marker_environment():
            for value in (None, True, 7, "", " \t"):
                with self.subTest(key=key, value=value):
                    snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
                    snapshot["environment"][key] = value
                    with self.assertRaises(ValueError):
                        native.pip_graph(snapshot)
        for key in ("implementation_version", "python_full_version", "python_version"):
            with self.subTest(version_key=key):
                snapshot = pip_snapshot(['dep; python_version >= "3"'])
                snapshot["environment"][key] = "not-a-version"
                with self.assertRaises(ValueError):
                    native.pip_graph(snapshot)

    def test_true_and_false_markers_use_snapshot_and_keep_exclusions(self):
        snapshot = pip_snapshot(['dep>=2; sys_platform == "win32"'])
        exclusions = []
        nodes, edges, direct = native.pip_graph(snapshot, exclusions=exclusions)
        self.assertEqual(nodes, {("app", "1"), ("dep", "2")})
        self.assertEqual(direct, {("app", "1")})
        self.assertEqual(edges, {(("app", "1"), ("dep", "2"))})
        self.assertEqual(exclusions, [])
        snapshot["environment"]["sys_platform"] = "linux"
        nodes, edges, direct = native.pip_graph(snapshot, exclusions=exclusions)
        self.assertEqual(edges, set())
        self.assertEqual(
            exclusions,
            [{
                "source_name": "app",
                "source_version": "1",
                "requirement": 'dep>=2; sys_platform == "win32"',
                "marker": 'sys_platform == "win32"',
                "outcome": "not-applicable",
            }],
        )

    def test_host_defaults_cannot_change_graph_or_leak_to_exclusions(self):
        snapshot = pip_snapshot(['dep; sys_platform == "win32"'])
        original = copy.deepcopy(snapshot)
        results = []
        for platform in ("linux", "darwin"):
            host = {key: "HOST_PRIVATE_CANARY" for key in marker_environment()}
            host["sys_platform"] = platform
            exclusions = []
            with patch("packaging.markers.default_environment", return_value=host):
                results.append(native.pip_graph(snapshot, exclusions=exclusions))
            self.assertNotIn("HOST_PRIVATE_CANARY", json.dumps(exclusions))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0][1], {(("app", "1"), ("dep", "2"))})
        self.assertEqual(snapshot, original)

    def test_base_extra_scope_is_explicit_and_requested_extras_still_fail(self):
        snapshot = pip_snapshot(['absent; extra == "speedups"'])
        snapshot["environment"]["extra"] = "speedups"
        exclusions = []
        _, edges, _ = native.pip_graph(snapshot, exclusions=exclusions)
        self.assertEqual(edges, set())
        self.assertEqual(exclusions[0]["marker"], 'extra == "speedups"')
        for requirement in ("dep[fast]", "dep @ https://example.invalid/dep.whl"):
            with self.subTest(requirement=requirement):
                with self.assertRaises(ValueError):
                    native.pip_graph(pip_snapshot([requirement]))

    def test_unsupported_marker_context_does_not_become_false(self):
        with self.assertRaises(ValueError):
            native.pip_graph(pip_snapshot(['dep; "fast" in extras']))

    def test_true_missing_or_unsatisfied_dependency_still_fails(self):
        for requirement in (
            'missing; sys_platform == "win32"',
            'dep>=3; sys_platform == "win32"',
        ):
            with self.subTest(requirement=requirement):
                with self.assertRaises(ValueError):
                    native.pip_graph(pip_snapshot([requirement]))

    def test_cli_persists_snapshot_environment_and_marker_exclusions(self):
        snapshot = pip_snapshot(['absent; sys_platform == "linux"'])
        bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "name": name, "version": version,
                 "purl": f"pkg:pypi/{name}@{version}", "bom-ref": name}
                for name, version in (("app", "1"), ("dep", "2"))
            ],
        }
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "inspect.json"
            source.write_text(json.dumps(snapshot))
            input_bom = directory / "input.json"
            input_bom.write_text(json.dumps(bom))
            output = directory / "output.json"
            command = [sys.executable, "-B", str(SPEC.origin), "pip-inspect",
                       "--bom", str(input_bom), "--source", str(source),
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(len(summary["excluded_marker_requirements"]), 1)
            saved = json.loads(output.read_text())
            properties = {p["name"]: p["value"] for p in saved["metadata"]["properties"]}
            expected_environment = {**marker_environment(), "extra": ""}
            self.assertEqual(json.loads(properties["vettalon:graph:marker-environment"]), expected_environment)
            self.assertEqual(json.loads(properties["vettalon:graph:marker-exclusions"]), summary["excluded_marker_requirements"])
            self.assertEqual(len(saved["components"]), 2)
            self.assertEqual(summary["direct"], 1)


if __name__ == "__main__":
    unittest.main()
