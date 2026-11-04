import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mizan.fix import (
    FixPlan,
    _apply_to_requirements_txt,
    _min_fixed_for_vuln,
    _parse_version,
    apply_fixes,
    detect_test_command,
    plan_fixes,
    run_tests,
)


def _vuln(vid, fixed):
    """Build a minimal OSV record with a single range."""
    return {
        "id": vid,
        "affected": [{
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": fixed}],
            }]
        }],
    }


class VersionTests(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertLess(_parse_version("2.0.0"), _parse_version("2.32.5"))
        self.assertLess(_parse_version("2.9.0"), _parse_version("2.10.0"))


class MinFixedTests(unittest.TestCase):
    def test_single_vuln(self):
        self.assertEqual(_min_fixed_for_vuln(_vuln("X", "2.32.4")), "2.32.4")

    def test_no_fix(self):
        self.assertIsNone(_min_fixed_for_vuln({"id": "X", "affected": []}))


class PlanTests(unittest.TestCase):
    def test_picks_max_of_minimums(self):
        scan_result = {
            "findings": [
                {"dependency": {"name": "requests", "version": "2.0.0",
                                 "ecosystem": "PyPI", "manifest": "requirements.txt"},
                 "vuln": _vuln("A", "2.20.0")},
                {"dependency": {"name": "requests", "version": "2.0.0",
                                 "ecosystem": "PyPI", "manifest": "requirements.txt"},
                 "vuln": _vuln("B", "2.32.4")},
                {"dependency": {"name": "requests", "version": "2.0.0",
                                 "ecosystem": "PyPI", "manifest": "requirements.txt"},
                 "vuln": _vuln("C", "2.33.0")},
            ]
        }
        plans = plan_fixes(scan_result)
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].target_version, "2.33.0")
        self.assertEqual(sorted(plans[0].vuln_ids), ["A", "B", "C"])

    def test_unfixed_vuln_marks_no_fix(self):
        scan_result = {
            "findings": [{
                "dependency": {"name": "badpkg", "version": "1.0",
                                "ecosystem": "PyPI", "manifest": "requirements.txt"},
                "vuln": {"id": "Y", "affected": []},
            }]
        }
        plans = plan_fixes(scan_result)
        self.assertEqual(len(plans), 1)
        self.assertIsNone(plans[0].target_version)
        self.assertEqual(plans[0].reason, "no_fix_available")


class ApplyTests(unittest.TestCase):
    def test_rewrites_exact_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text(
                "# deps\nrequests==2.0.0\nflask==1.0.0\n",
                encoding="utf-8",
            )
            plan = FixPlan(
                manifest="requirements.txt", package="requests",
                ecosystem="PyPI", current_version="2.0.0",
                target_version="2.32.5", vuln_ids=["X"],
            )
            changed = _apply_to_requirements_txt(path, plan)
            self.assertTrue(changed)
            content = path.read_text(encoding="utf-8")
            self.assertIn("requests==2.32.5", content)
            self.assertIn("flask==1.0.0", content)
            self.assertIn("# deps", content)


class TestRunnerTests(unittest.TestCase):
    def test_detects_unittest_when_tests_dir_present(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tests").mkdir()
            cmd = detect_test_command(root)
            self.assertIsNotNone(cmd)
            self.assertIn("unittest", " ".join(cmd))

    def test_returns_none_for_empty_project(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertIsNone(detect_test_command(root))


class DetectTestCommandRobustTests(unittest.TestCase):
    def test_falls_back_to_unittest_when_pytest_missing(self):
        """When pyproject exists but pytest isn't installed, use unittest."""
        import unittest.mock as mock
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pyproject.toml").write_text("[project]\nname='x'\n")
            (root / "tests").mkdir()
            with mock.patch("mizan.fix._pytest_available", return_value=False):
                cmd = detect_test_command(root)
            self.assertIsNotNone(cmd)
            self.assertIn("unittest", " ".join(cmd))

    def test_uses_pytest_when_available_and_configured(self):
        import unittest.mock as mock
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pyproject.toml").write_text("[project]\nname='x'\n")
            (root / "conftest.py").write_text("")
            with mock.patch("mizan.fix._pytest_available", return_value=True):
                cmd = detect_test_command(root)
            self.assertIn("pytest", " ".join(cmd))


class ApplyFixesTests(unittest.TestCase):
    def test_rolls_back_on_test_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text(
                "requests==2.0.0\n", encoding="utf-8"
            )
            (root / "tests").mkdir()
            (root / "tests" / "test_fake.py").write_text(
                "import unittest\n"
                "class T(unittest.TestCase):\n"
                "    def test_fail(self):\n"
                "        self.fail('intentional')\n",
                encoding="utf-8",
            )
            plans = [FixPlan(
                manifest="requirements.txt", package="requests",
                ecosystem="PyPI", current_version="2.0.0",
                target_version="2.32.5", vuln_ids=["X"],
            )]
            result = apply_fixes(root, plans, validate=True)
            self.assertTrue(result.rolled_back)
            self.assertEqual(result.applied, [])
            self.assertFalse(result.tests_passed)
            content = (root / "requirements.txt").read_text(encoding="utf-8")
            self.assertIn("requests==2.0.0", content)

    def test_keeps_change_on_test_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text(
                "requests==2.0.0\n", encoding="utf-8"
            )
            (root / "tests").mkdir()
            (root / "tests" / "test_ok.py").write_text(
                "import unittest\n"
                "class T(unittest.TestCase):\n"
                "    def test_ok(self):\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            plans = [FixPlan(
                manifest="requirements.txt", package="requests",
                ecosystem="PyPI", current_version="2.0.0",
                target_version="2.32.5", vuln_ids=["X"],
            )]
            result = apply_fixes(root, plans, validate=True)
            self.assertFalse(result.rolled_back)
            self.assertEqual(len(result.applied), 1)
            self.assertTrue(result.tests_passed)
            content = (root / "requirements.txt").read_text(encoding="utf-8")
            self.assertIn("requests==2.32.5", content)


if __name__ == "__main__":
    unittest.main()
