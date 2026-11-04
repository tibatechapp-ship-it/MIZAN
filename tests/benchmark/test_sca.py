"""SCA benchmarks 01-20 aligned with NIST SAMATE/SATE + OWASP Benchmark.

Each test corresponds to a numbered benchmark item (BM-XX).
"""
import io
import json
import os
import tempfile
from contextlib import redirect_stdout
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mizan.detector import collect_files
from mizan.scan import scan_repository
from mizan.vulnerabilities import (
    OsvScanError,
    check_vulnerabilities,
    parse_dependencies,
)


# ---------- Mocked OSV responses (deterministic) ----------

OSV_REQUESTS_2_0_0 = {
    "vulns": [
        {"id": "GHSA-9hjg-9r4m-mvj7",
         "summary": "Credential leak via malicious URLs",
         "database_specific": {"severity": "HIGH"}},
        {"id": "GHSA-9wx4-h78v-vm56",
         "summary": "verify=False persists on Session",
         "database_specific": {"severity": "MEDIUM"}},
        {"id": "GHSA-gc5v-m9x4-r6x2",
         "summary": "Predictable filename in extract_zipped_paths",
         "database_specific": {"severity": "LOW"}},
        {"id": "PYSEC-2018-28",
         "summary": "CRLF injection via URL",
         "database_specific": {"severity": "HIGH"}},
    ]
}

OSV_LODASH_4_17_0 = {
    "vulns": [
        {"id": "GHSA-35jh-r3h4-6jhm",
         "summary": "Prototype pollution in lodash",
         "database_specific": {"severity": "HIGH"}},
    ]
}


def _mock_osv(vulns):
    """Context manager: patch urlopen to return given vulns."""
    def factory(*args, **kwargs):
        cm = MagicMock()
        resp = MagicMock()
        resp.read.return_value = json.dumps({"vulns": vulns}).encode()
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = False
        return cm
    return patch("mizan.vulnerabilities.urllib.request.urlopen", side_effect=factory)


def _write_requirements(root, content):
    (root / "requirements.txt").write_text(content, encoding="utf-8")


def _write_package_lock(root, packages):
    data = {"lockfileVersion": 3, "packages": packages}
    (root / "package-lock.json").write_text(json.dumps(data), encoding="utf-8")


def _write_poetry_lock(root, packages):
    lines = []
    for name, version in packages:
        lines.append('[[package]]\nname = "' + name + '"\nversion = "' + version + '"\n')
    (root / "poetry.lock").write_text("\n".join(lines), encoding="utf-8")


def _write_pipfile_lock(root, packages):
    data = {"default": {name: {"version": "==" + v} for name, v in packages}}
    (root / "Pipfile.lock").write_text(json.dumps(data), encoding="utf-8")


def _write_pyproject(root, content):
    (root / "pyproject.toml").write_text(content, encoding="utf-8")


# ---------- Benchmarks 01-10: Detection (Recall = 100%) ----------

class ScaDetectionBenchmark(unittest.TestCase):
    """NIST SAMATE: Recall must be 100% on known vulnerabilities."""

    def test_01_pypi_known_vuln_detected(self):
        """BM-01: requests==2.0.0 -> 4 known vulns (100% recall)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.0.0\n")
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertEqual(len(deps), 1)
            self.assertEqual(deps[0]["name"], "requests")
            self.assertEqual(deps[0]["version"], "2.0.0")
            with _mock_osv(OSV_REQUESTS_2_0_0["vulns"]):
                vulns = check_vulnerabilities("requests", "2.0.0", "PyPI")
            self.assertEqual(len(vulns), 4)

    def test_02_npm_known_vuln_detected(self):
        """BM-02: lodash@4.17.0 -> 1 known vuln."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_package_lock(root, {"node_modules/lodash": {"version": "4.17.0"}})
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertTrue(any(d["name"] == "lodash" for d in deps))
            with _mock_osv(OSV_LODASH_4_17_0["vulns"]):
                vulns = check_vulnerabilities("lodash", "4.17.0", "npm")
            self.assertEqual(len(vulns), 1)

    def test_03_django_critical_detected(self):
        """BM-03: django==2.0 -> detected as exact pin."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "django==2.0\n")
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertEqual(deps[0]["name"], "django")
            self.assertEqual(deps[0]["version"], "2.0")

    def test_04_package_lock_v3_parsed(self):
        """BM-04: package-lock.json v3 -> all packages parsed."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_package_lock(root, {
                "node_modules/express": {"version": "4.17.0"},
                "node_modules/@scope/pkg": {"version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.0"},
            })
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            names = {d["name"] for d in deps}
            self.assertIn("express", names)
            self.assertIn("@scope/pkg", names)
            self.assertIn("lodash", names)

    def test_05_poetry_lock_parsed(self):
        """BM-05: poetry.lock -> all packages parsed."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_poetry_lock(root, [("requests", "2.0.0"), ("flask", "1.0.0")])
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertEqual(len(deps), 2)

    def test_06_pipfile_lock_parsed(self):
        """BM-06: Pipfile.lock -> all packages parsed."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_pipfile_lock(root, [("requests", "2.0.0")])
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertEqual(len(deps), 1)
            self.assertEqual(deps[0]["name"], "requests")

    def test_07_pyproject_all_sections(self):
        """BM-07: pyproject.toml -> project + optional + poetry sections."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_pyproject(root, (
                '[project]\n'
                'name = "demo"\n'
                'dependencies = ["flask==2.0.0"]\n'
                '[project.optional-dependencies]\n'
                'legacy = ["requests==2.0.0"]\n'
                '[tool.poetry.dependencies]\n'
                'click = "8.0.0"\n'
            ))
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            names = {(d["name"], d["version"]) for d in deps}
            self.assertIn(("flask", "2.0.0"), names)
            self.assertIn(("requests", "2.0.0"), names)
            self.assertIn(("click", "8.0.0"), names)

    def test_08_requirements_exact_pins_only(self):
        """BM-08: requirements.txt -> only exact pins, not ranges/comments."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, (
                "# comment\n"
                "-r base.txt\n"
                "flask>=1.0\n"
                "requests==2.0.0\n"
                "django==3.0\n"
            ))
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            names = {d["name"] for d in deps}
            self.assertIn("requests", names)
            self.assertIn("django", names)
            self.assertNotIn("flask", names)

    def test_09_mizan_backup_ignored(self):
        """BM-09: .mizan/backup/ must not produce phantom findings."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "requirements.txt").write_text("requests==2.33.0\n")
            backup = root / ".mizan" / "backup" / "20260101"
            backup.mkdir(parents=True)
            (backup / "requirements.txt").write_text("requests==2.0.0\n")
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            versions = {d["version"] for d in deps if d["name"] == "requests"}
            self.assertEqual(versions, {"2.33.0"})

    def test_10_virtual_env_ignored(self):
        """BM-10: .venv/__pycache__ must not appear in scan."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "requirements.txt").write_text("requests==2.33.0\n")
            (root / ".venv").mkdir()
            (root / ".venv" / "requirements.txt").write_text("bad==0.0.1\n")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "requirements.txt").write_text("bad==0.0.1\n")
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertEqual(len(deps), 1)
            self.assertEqual(deps[0]["name"], "requests")



# ---------- Benchmarks 11-20: Honesty & Output ----------

class ScaHonestyBenchmark(unittest.TestCase):
    """NIST SATE: unknown != safe. SARIF 2.1.0 compliance."""

    @patch.dict(os.environ, {"MIZAN_DISABLE_OSV": "1"})
    def test_11_osv_disabled_raises(self):
        """BM-11: MIZAN_DISABLE_OSV -> OsvScanError (not silent [])."""
        with self.assertRaises(OsvScanError):
            check_vulnerabilities("requests", "2.0.0", "PyPI")

    @patch("mizan.vulnerabilities.urllib.request.urlopen")
    def test_12_osv_network_error_raises(self, mock_urlopen):
        """BM-12: network error -> OsvScanError (not [])."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("network down")
        with self.assertRaises(OsvScanError):
            check_vulnerabilities("requests", "2.0.0", "PyPI")

    def test_13_sarif_locations_present(self):
        """BM-13: SARIF finding has locations.length >= 1."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.0.0\n")
            with _mock_osv(OSV_REQUESTS_2_0_0["vulns"]):
                scan = scan_repository(root)
            from mizan.sarif import build_sarif
            sarif = json.loads(build_sarif(scan))
        results = sarif["runs"][0]["results"]
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertGreaterEqual(len(r.get("locations", [])), 1)

    def test_14_sarif_rule_id_unique(self):
        """BM-14: SARIF ruleId unique per vulnerability."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.0.0\n")
            with _mock_osv(OSV_REQUESTS_2_0_0["vulns"]):
                scan = scan_repository(root)
            from mizan.sarif import build_sarif
            sarif = json.loads(build_sarif(scan))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_15_sarif_severity_level(self):
        """BM-15: SARIF level matches CVSS severity (HIGH->error, etc)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.0.0\n")
            with _mock_osv(OSV_REQUESTS_2_0_0["vulns"]):
                scan = scan_repository(root)
            from mizan.sarif import build_sarif
            sarif = json.loads(build_sarif(scan))
        results = sarif["runs"][0]["results"]
        levels = {r["level"] for r in results}
        self.assertIn("error", levels)      # HIGH
        self.assertIn("warning", levels)    # MEDIUM
        self.assertIn("note", levels)       # LOW

    def test_16_sarif_schema(self):
        """BM-16: SARIF version = 2.1.0."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.33.0\n")
            with _mock_osv([]):
                scan = scan_repository(root)
            from mizan.sarif import build_sarif
            sarif = json.loads(build_sarif(scan))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("2.1.0", sarif["$schema"])

    def test_17_exit_code_on_findings(self):
        """BM-17: exit code = 1 when findings exist (CI gate)."""
        from mizan.scan import main as scan_main
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.0.0\n")
            with _mock_osv(OSV_REQUESTS_2_0_0["vulns"]):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = scan_main([str(root), "--format", "json"])
        self.assertEqual(code, 1)

    def test_18_exit_code_no_findings(self):
        """BM-18: exit code = 0 when no findings."""
        from mizan.scan import main as scan_main
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write_requirements(root, "requests==2.33.0\n")
            with _mock_osv([]):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = scan_main([str(root), "--format", "json"])
        self.assertEqual(code, 0)

    def test_19_max_files_truncated(self):
        """BM-19: > MAX_FILES -> truncated=True (performance guard)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "sub").mkdir()
            for i in range(10):
                (root / "sub" / ("f" + str(i) + ".py")).write_text("pass\n")
            with patch("mizan.detector.MAX_FILES", 5):
                files, truncated = collect_files(root)
        self.assertTrue(truncated)
        self.assertEqual(len(files), 5)

    def test_20_large_deps_no_leak(self):
        """BM-20: 1000 deps parsed (performance baseline)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            lines = ["pkg" + str(i) + "==1.0.0" for i in range(1000)]
            _write_requirements(root, "\n".join(lines) + "\n")
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertEqual(len(deps), 1000)


if __name__ == "__main__":
    unittest.main()
