import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mizan.dependency_scanner import scan_dependencies


def _offline_env(testcase):
    """Hermetic OSV: the RW-204 batch check resolves offline (deterministic
    offline-miss) instead of hitting the network inside unit tests."""
    old = os.environ.get("MIZAN_OFFLINE")
    os.environ["MIZAN_OFFLINE"] = "1"
    testcase.addCleanup(
        lambda: os.environ.pop("MIZAN_OFFLINE", None) if old is None
        else os.environ.__setitem__("MIZAN_OFFLINE", old)
    )


class DependencyScannerTests(unittest.TestCase):

    def setUp(self):
        _offline_env(self)

    def test_detects_requirements(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "requirements.txt").write_text(
                "requests>=2.0\nPyYAML==6.0\n",
                encoding="utf-8"
            )

            result = scan_dependencies(root)

            self.assertEqual(result["dependencies_count"], 2)

    def test_detects_package_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "package.json").write_text(
                json.dumps({
                    "dependencies": {"react": "^18.0.0"}
                }),
                encoding="utf-8"
            )

            result = scan_dependencies(root)

            self.assertEqual(result["dependencies_count"], 1)

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "package.json").write_text(
                "{invalid json",
                encoding="utf-8"
            )

            result = scan_dependencies(root)

            self.assertEqual(result["findings_count"], 1)

    def test_read_only_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            result = scan_dependencies(temp)

            self.assertEqual(result["mode"], "read-only")
            self.assertFalse(result["execution_performed"])

    def test_invalid_directory(self):
        with self.assertRaises(ValueError):
            scan_dependencies("/invalid/mizan/path")


class PyprojectSectionCoverageTests(unittest.TestCase):
    """E-03 (2026-11-17 review): the pyproject.toml parser previously read
    ONLY ``project.dependencies``, silently skipping PEP 621 extras, PEP
    735 dependency groups and both Poetry forms — a coverage gap that
    made a vulnerable optional dependency invisible to the OSV check.
    Each documented section now has a deterministic parse + scope rule,
    and each rule below is the regression test for it."""

    def setUp(self):
        _offline_env(self)

    def _write(self, root, content):
        root = Path(root)
        (root / "pyproject.toml").write_text(content, encoding="utf-8")
        return scan_dependencies(root)

    def test_pep621_optional_dependencies_are_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, (
                "[project]\n"
                'name = "demo"\n'
                'dependencies = ["requests>=2.0"]\n'
                "\n"
                "[project.optional-dependencies]\n"
                'socks = ["urllib3[socks]>=1.26"]\n'
            ))
            self.assertEqual(result["dependencies_count"], 2)
            socks = [d for d in result["dependencies"]
                     if d.get("section") == "project.optional-dependencies.socks"]
            self.assertEqual(len(socks), 1)
            self.assertEqual(socks[0]["name"], "urllib3")
            self.assertEqual(socks[0]["scope"], "runtime")

    def test_pep735_dependency_groups_are_scanned_as_dev(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, (
                "[project]\n"
                'name = "demo"\n'
                "\n"
                "[dependency-groups]\n"
                'test = ["mypy>=1.0"]\n'
            ))
            self.assertEqual(result["dependencies_count"], 1)
            self.assertEqual(result["dependencies"][0]["name"], "mypy")
            self.assertEqual(result["dependencies"][0]["scope"], "dev")

    def test_poetry_classic_dependencies_are_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, (
                "[tool.poetry.dependencies]\n"
                'python = "^3.10"\n'
                'requests = "2.28.0"\n'
                "\n"
                "[tool.poetry.dev-dependencies]\n"
                'black = "23.1.0"\n'
            ))
            self.assertEqual(result["dependencies_count"], 2)
            names = {d["name"]: d for d in result["dependencies"]}
            self.assertNotIn("python", names,
                             "language constraint is not a package")
            self.assertEqual(names["requests"]["scope"], "runtime")
            self.assertEqual(names["black"]["scope"], "dev")

    def test_poetry_table_constraint_folds_extras_into_name(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, (
                "[tool.poetry.dependencies]\n"
                'requests = {version = "2.28.0", extras = ["socks"]}\n'
            ))
            dep = result["dependencies"][0]
            self.assertEqual(dep["name"], "requests[socks]")
            self.assertEqual(dep["constraint"], "2.28.0")

    def test_poetry_group_form_dev_and_runtime_scopes(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, (
                "[tool.poetry.group.test.dependencies]\n"
                'pytest = ">=7"\n'
                "\n"
                "[tool.poetry.group.deploy.dependencies]\n"
                'ansible = "8.0"\n'
            ))
            names = {d["name"]: d for d in result["dependencies"]}
            self.assertEqual(names["pytest"]["scope"], "dev")
            self.assertEqual(names["ansible"]["scope"], "runtime")

    def test_broken_pyproject_is_a_loud_finding_not_a_clean_empty(self):
        """E-03: a parse failure must surface as invalid-dependency-manifest
        — never silently degrade to a clean zero-dependency report."""
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, "[project]\ndependencies = [unclosed\n")
            self.assertEqual(result["dependencies_count"], 0)
            rules = [f["rule"] for f in result.get("findings", [])]
            self.assertIn("invalid-dependency-manifest", rules)

    def test_pyproject_without_any_dependency_section_is_valid_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._write(temp, (
                "[project]\n"
                'name = "demo"\n'
            ))
            self.assertEqual(result["dependencies_count"], 0)
            self.assertEqual(result.get("findings", []), [])


if __name__ == "__main__":
    unittest.main()
