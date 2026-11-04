"""Remediation benchmarks 21-40 aligned with SWE-bench + Snyk Agent Fix."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mizan.fix import (
    FixPlan,
    _apply_to_pyproject_toml,
    _apply_to_requirements_txt,
    _min_fixed_for_vuln,
    apply_fixes,
    detect_test_command,
    plan_fixes,
    run_tests,
)


def _write(root, name, content):
    (root / name).write_text(content, encoding="utf-8")


def _make_scan(pkg, version, vulns_by_id, manifest="requirements.txt"):
    findings = []
    for vid, fixed in vulns_by_id:
        affected = {"ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": fixed}]}]}
        findings.append({
            "dependency": {"name": pkg, "version": version,
                          "ecosystem": "PyPI", "manifest": manifest},
            "vuln": {"id": vid, "affected": [affected]},
        })
    return {"findings": findings}


def _fix_plan(pkg="requests", current="2.0.0", target="2.33.0",
              manifest="requirements.txt"):
    return FixPlan(
        manifest=manifest, package=pkg, ecosystem="PyPI",
        current_version=current, target_version=target, vuln_ids=["X"],
    )


# ---------- BM-21 to BM-23: Planning (SWE-bench) ----------

class PlanBenchmark(unittest.TestCase):
    """SWE-bench: correct target version selection."""

    def test_21_picks_max_fixed_across_vulns(self):
        """BM-21: fix --plan picks max(fixed) across multiple vulns."""
        scan = _make_scan("requests", "2.0.0", [
            ("A", "2.20.0"), ("B", "2.32.4"), ("C", "2.33.0"),
        ])
        plans = plan_fixes(scan)
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].target_version, "2.33.0")

    def test_22_returns_max_fixed_within_vuln(self):
        """BM-22: within a single vuln, returns highest fixed point (past all)."""
        vuln = {"id": "X", "affected": [
            {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]},
            {"ranges": [{"events": [{"introduced": "2.5.0"}, {"fixed": "2.32.0"}]}]},
        ]}
        self.assertEqual(_min_fixed_for_vuln(vuln), "2.32.0")

    def test_23_no_fix_available_marks_none(self):
        """BM-23: vuln without fix -> target_version=None, reason='no_fix_available'."""
        scan = _make_scan("badpkg", "1.0", [("Y", "1.0.1")])
        scan["findings"][0]["vuln"]["affected"][0]["ranges"][0]["events"] = [
            {"introduced": "0"}
        ]
        plans = plan_fixes(scan)
        self.assertEqual(len(plans), 1)
        self.assertIsNone(plans[0].target_version)


# ---------- BM-24 to BM-29: Apply correctness ----------

class ApplyBenchmark(unittest.TestCase):
    """Exact in-place rewrite with formatting preservation."""

    def test_24_requirements_txt_exact_pin(self):
        """BM-24: _apply_to_requirements_txt rewrites name==old to name==new."""
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "requirements.txt"
            path.write_text("requests==2.0.0\n", encoding="utf-8")
            changed = _apply_to_requirements_txt(path, _fix_plan())
            self.assertTrue(changed)
            self.assertEqual(path.read_text(encoding="utf-8").strip(),
                             "requests==2.33.0")

    def test_25_pyproject_pep621_array(self):
        """BM-25: _apply_to_pyproject_toml rewrites PEP 621 array entry."""
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "pyproject.toml"
            path.write_text(
                '[project]\n'
                'dependencies = ["requests==2.0.0"]\n',
                encoding="utf-8",
            )
            changed = _apply_to_pyproject_toml(path, _fix_plan(manifest="pyproject.toml"))
            self.assertTrue(changed)
            content = path.read_text(encoding="utf-8")
            self.assertIn('"requests==2.33.0"', content)
            self.assertNotIn('"requests==2.0.0"', content)

    def test_26_pyproject_poetry_exact(self):
        """BM-26: _apply_to_pyproject_toml rewrites Poetry exact string."""
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "pyproject.toml"
            path.write_text(
                '[tool.poetry.dependencies]\n'
                'requests = "2.0.0"\n',
                encoding="utf-8",
            )
            changed = _apply_to_pyproject_toml(path, _fix_plan(manifest="pyproject.toml"))
            self.assertTrue(changed)
            content = path.read_text(encoding="utf-8")
            self.assertIn('requests = "2.33.0"', content)

    def test_27_pyproject_poetry_caret(self):
        """BM-27: _apply_to_pyproject_toml rewrites Poetry caret pin."""
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "pyproject.toml"
            path.write_text(
                '[tool.poetry.dependencies]\n'
                'requests = "^2.0.0"\n',
                encoding="utf-8",
            )
            changed = _apply_to_pyproject_toml(path, _fix_plan(manifest="pyproject.toml"))
            self.assertTrue(changed)
            content = path.read_text(encoding="utf-8")
            self.assertIn('"^2.33.0"', content)

    def test_28_preserves_comments(self):
        """BM-28: comments and other lines preserved."""
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "requirements.txt"
            path.write_text(
                "# main deps\n"
                "requests==2.0.0\n"
                "# dev deps\n"
                "flask==1.0.0\n",
                encoding="utf-8",
            )
            _apply_to_requirements_txt(path, _fix_plan())
            content = path.read_text(encoding="utf-8")
            self.assertIn("# main deps", content)
            self.assertIn("# dev deps", content)
            self.assertIn("flask==1.0.0", content)
            self.assertIn("requests==2.33.0", content)

    def test_29_only_target_package_changed(self):
        """BM-29: only the target package is modified."""
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "requirements.txt"
            path.write_text(
                "requests==2.0.0\n"
                "flask==2.0.0\n"
                "django==3.0.0\n",
                encoding="utf-8",
            )
            _apply_to_requirements_txt(path, _fix_plan(pkg="requests"))
            content = path.read_text(encoding="utf-8")
            self.assertIn("requests==2.33.0", content)
            self.assertIn("flask==2.0.0", content)
            self.assertIn("django==3.0.0", content)


# ---------- BM-30 to BM-35: FixValidator safety ----------

class ValidationBenchmark(unittest.TestCase):
    """Snyk Agent Fix: change kept on tests pass, rolled back on fail."""

    def test_30_keeps_on_test_pass(self):
        """BM-30: tests pass -> change kept."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "requirements.txt", "requests==2.0.0\n")
            plans = [_fix_plan()]
            with patch("mizan.fix.run_tests", return_value=(True, "OK")):
                result = apply_fixes(root, plans, validate=True)
            self.assertTrue(result.tests_passed)
            self.assertFalse(result.rolled_back)
            self.assertEqual(len(result.applied), 1)


    def test_31_rolls_back_on_test_fail(self):
        """BM-31: tests fail -> rollback, no change kept."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "requirements.txt", "requests==2.0.0\n")
            plans = [_fix_plan()]
            with patch("mizan.fix.run_tests", return_value=(False, "FAIL")):
                result = apply_fixes(root, plans, validate=True)
            self.assertFalse(result.tests_passed)
            self.assertTrue(result.rolled_back)
            self.assertEqual(result.applied, [])

    def test_32_rollback_restores_content(self):
        """BM-32: rollback restores byte-for-byte."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            original = "requests==2.0.0\nflask==1.0.0\n"
            _write(root, "requirements.txt", original)
            plans = [_fix_plan()]
            with patch("mizan.fix.run_tests", return_value=(False, "FAIL")):
                apply_fixes(root, plans, validate=True)
            self.assertEqual(
                (root / "requirements.txt").read_text(encoding="utf-8"),
                original,
            )

    def test_33_backup_created(self):
        """BM-33: backup file created under .mizan/backup/<timestamp>/."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "requirements.txt", "requests==2.0.0\n")
            plans = [_fix_plan()]
            with patch("mizan.fix.run_tests", return_value=(True, "OK")):
                apply_fixes(root, plans, validate=True)
            backup_dir = root / ".mizan" / "backup"
            self.assertTrue(backup_dir.exists())
            backups = list(backup_dir.rglob("requirements.txt"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8").strip(),
                             "requests==2.0.0")

    def test_34_no_validate_skips_tests(self):
        """BM-34: --no-validate -> tests_passed=None, change kept."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "requirements.txt", "requests==2.0.0\n")
            plans = [_fix_plan()]
            result = apply_fixes(root, plans, validate=False)
            self.assertIsNone(result.tests_passed)
            self.assertFalse(result.rolled_back)
            self.assertEqual(len(result.applied), 1)

    def test_35_fix_validator_timeout(self):
        """BM-35: timeout returns (False, 'test runner error: ...')."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "tests").mkdir()
            with patch("mizan.fix.subprocess.run",
                       side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)):
                passed, output = run_tests(root, timeout=1)
            self.assertFalse(passed)
            self.assertIn("test runner error", output)


# ---------- BM-36 to BM-38: Test command detection ----------

class DetectTestCommandBenchmark(unittest.TestCase):
    """SWE-bench: correct test runner detection."""

    def test_36_detects_unittest_when_tests_dir(self):
        """BM-36: tests/ -> unittest discover."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "tests").mkdir()
            with patch("mizan.fix._pytest_available", return_value=False):
                cmd = detect_test_command(root)
            self.assertIn("unittest", " ".join(cmd))

    def test_37_detects_pytest_when_available(self):
        """BM-37: pyproject + pytest installed -> pytest -q."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "pyproject.toml", "[project]\nname='x'\n")
            (root / "conftest.py").write_text("", encoding="utf-8")
            with patch("mizan.fix._pytest_available", return_value=True):
                cmd = detect_test_command(root)
            self.assertIn("pytest", " ".join(cmd))

    def test_38_detects_npm_when_package_json(self):
        """BM-38: package.json -> npm test --silent."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "package.json", "{}")
            cmd = detect_test_command(root)
            self.assertIsNotNone(cmd)
            self.assertIn("npm", cmd)


# ---------- BM-39 to BM-40: End-to-end (SWE-bench) ----------

class EndToEndBenchmark(unittest.TestCase):
    """SWE-bench end-to-end: full flow from plan to applied change."""

    def test_39_e2e_requirements_txt(self):
        """BM-39: full flow on requirements.txt (plan -> apply -> verify)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "requirements.txt", "requests==2.0.0\n")
            scan = _make_scan("requests", "2.0.0", [
                ("A", "2.32.4"), ("B", "2.33.0"),
            ])
            plans = plan_fixes(scan)
            self.assertEqual(plans[0].target_version, "2.33.0")
            with patch("mizan.fix.run_tests", return_value=(True, "OK")):
                result = apply_fixes(root, plans, validate=True)
            self.assertEqual(len(result.applied), 1)
            content = (root / "requirements.txt").read_text(encoding="utf-8")
            self.assertIn("requests==2.33.0", content)

    def test_40_e2e_pyproject_dogfooding(self):
        """BM-40: full flow on pyproject.toml (MIZAN self-fix scenario)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _write(root, "pyproject.toml",
                   '[project]\n'
                   'name = "dogfood-demo"\n'
                   '\n'
                   '[project.optional-dependencies]\n'
                   'self-test = ["requests==2.0.0"]\n')
            scan = _make_scan("requests", "2.0.0", [
                ("PYSEC-2018-28", "2.20.0"),
                ("GHSA-9hjg-9r4m-mvj7", "2.32.4"),
                ("GHSA-gc5v-m9x4-r6x2", "2.33.0"),
            ], manifest="pyproject.toml")
            plans = plan_fixes(scan)
            self.assertEqual(plans[0].target_version, "2.33.0")
            with patch("mizan.fix.run_tests", return_value=(True, "OK")):
                result = apply_fixes(root, plans, validate=True)
            self.assertEqual(len(result.applied), 1)
            content = (root / "pyproject.toml").read_text(encoding="utf-8")
            self.assertIn('"requests==2.33.0"', content)
            self.assertNotIn('"requests==2.0.0"', content)


if __name__ == "__main__":
    unittest.main()
