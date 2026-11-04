import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mizan.detector import _read_package_lock, _read_poetry_lock
from mizan.sarif import build_sarif
from mizan.scan import scan_repository
from mizan.vulnerabilities import OsvScanError, check_vulnerabilities, parse_requirements_txt


class LockFileTests(unittest.TestCase):
    def test_reads_package_lock_v3(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "package-lock.json"
            path.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/express": {"version": "4.17.0"},
                    "node_modules/@scope/pkg": {"version": "1.0.0"},
                },
            }), encoding="utf-8")
            deps = {(d["name"], d["version"]) for d in _read_package_lock(path)}
            self.assertIn(("express", "4.17.0"), deps)
            self.assertIn(("@scope/pkg", "1.0.0"), deps)

    def test_reads_poetry_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "poetry.lock"
            path.write_text(
                '[[package]]\nname = "requests"\nversion = "2.0.0"\n\n'
                '[[package]]\nname = "flask"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
            deps = {(d["name"], d["version"]) for d in _read_poetry_lock(path)}
            self.assertEqual(deps, {("requests", "2.0.0"), ("flask", "1.0.0")})


class PyprojectOptionalTests(unittest.TestCase):
    def test_reads_optional_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pyproject.toml"
            content = """[project]
name = "demo"
dependencies = ["flask>=2.0"]

[project.optional-dependencies]
legacy = ["requests==2.0.0"]
"""
            path.write_text(content, encoding="utf-8")
            from mizan.detector import _read_pyproject_dependencies
            deps = {(d["name"], d["version"]) for d in _read_pyproject_dependencies(path)}
            self.assertIn(("requests", "2.0.0"), deps)

    def test_reads_poetry_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pyproject.toml"
            path.write_text(
                "[tool.poetry.dependencies]\n"
                "python = '^3.12'\n"
                "requests = '2.0.0'\n",
                encoding="utf-8",
            )
            from mizan.detector import _read_pyproject_dependencies
            deps = {(d["name"], d["version"]) for d in _read_pyproject_dependencies(path)}
            self.assertIn(("requests", "2.0.0"), deps)
            self.assertNotIn("python", {d["name"] for d in _read_pyproject_dependencies(path)})


class PyprojectTests(unittest.TestCase):
    def test_reads_exact_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pyproject.toml"
            path.write_text(
                '[project]\n'
                'name = "demo"\n'
                'dependencies = ["requests==2.0.0", "flask>=2.0"]\n',
                encoding="utf-8",
            )
            from mizan.detector import _read_pyproject_dependencies
            deps = {d["name"]: d["version"] for d in _read_pyproject_dependencies(path)}
            self.assertEqual(deps.get("requests"), "2.0.0")


class RequirementsTxtTests(unittest.TestCase):
    def test_extracts_exact_pins_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text(
                "requests==2.0.0\n"
                "flask>=1.0.0\n"
                "# comment\n"
                "-r base.txt\n"
                "django==3.2.0  # pinned\n",
                encoding="utf-8",
            )
            deps = {(d["name"], d["version"]) for d in parse_requirements_txt(path)}
            self.assertEqual(deps, {("requests", "2.0.0"), ("django", "3.2.0")})


class OsvClientTests(unittest.TestCase):
    @patch.dict(os.environ, {"MIZAN_DISABLE_OSV": "1"})
    def test_disabled_raises_scan_error(self):
        with self.assertRaises(OsvScanError):
            check_vulnerabilities("requests", "2.0.0", "PyPI")

    @patch("mizan.vulnerabilities.urllib.request.urlopen")
    def test_returns_vulns_on_success(self, mock_urlopen):
        os.environ.pop("MIZAN_DISABLE_OSV", None)
        resp = MagicMock()
        resp.read.return_value = json.dumps({
            "vulns": [{"id": "GHSA-xxxx", "summary": "Test"}],
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = resp
        result = check_vulnerabilities("requests", "2.0.0", "PyPI")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "GHSA-xxxx")


class SarifTests(unittest.TestCase):
    def test_build_sarif_high_severity_is_error(self):
        scan_result = {
            "root": "/tmp/x", "files_scanned": 1, "truncated": False,
            "dependencies_checked": 1,
            "findings": [{
                "dependency": {
                    "name": "requests", "version": "2.0.0",
                    "ecosystem": "PyPI", "manifest": "requirements.txt",
                },
                "vuln": {
                    "id": "GHSA-xxxx", "summary": "Test vuln",
                    "database_specific": {"severity": "HIGH"},
                },
            }],
        }
        sarif = json.loads(build_sarif(scan_result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
        self.assertEqual(
            sarif["runs"][0]["results"][0]["ruleId"],
            "MIZAN-PyPI-GHSA-xxxx",
        )


class BackupIgnoredTests(unittest.TestCase):
    def test_ignores_mizan_backup_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text("requests==2.33.0\n")
            backup = root / ".mizan" / "backup" / "20260101"
            backup.mkdir(parents=True)
            (backup / "requirements.txt").write_text("requests==2.0.0\n")

            from mizan.detector import collect_files
            files, _ = collect_files(root)
            names = {f.name for f in files}
            self.assertIn("requirements.txt", names)
            self.assertFalse(
                any(".mizan" in str(f) for f in files),
                "Backup files must be excluded from scan"
            )


class ScanEndToEndTests(unittest.TestCase):
    @patch.dict(os.environ, {"MIZAN_DISABLE_OSV": "1"})
    def test_empty_project_returns_zero_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            result = scan_repository(Path(temp))
            self.assertEqual(result["dependencies_checked"], 0)
            self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
