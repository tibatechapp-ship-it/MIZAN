"""CI/CD benchmarks 56-70 aligned with SARIF 2.1.0 + SLSA v1.1."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from mizan.sarif import build_sarif
from mizan.scan import scan_repository


ROOT = Path(__file__).resolve().parents[2]


def _run_mock(vulns):
    def factory(*args, **kwargs):
        cm = MagicMock()
        resp = MagicMock()
        resp.read.return_value = json.dumps({"vulns": vulns}).encode()
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = False
        return cm
    return patch("mizan.vulnerabilities.urllib.request.urlopen", side_effect=factory)


VULNS = [
    {"id": "GHSA-test-1", "summary": "Critical issue",
     "database_specific": {"severity": "CRITICAL"}},
]


class ActionYamlBenchmark(unittest.TestCase):
    def test_56_action_yml_valid_yaml(self):
        """BM-56: action/action.yml parses as YAML."""
        path = ROOT / "action" / "action.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        self.assertIsInstance(data, dict)

    def test_57_action_yml_has_required_keys(self):
        """BM-57: action.yml has name, description, runs."""
        with open(ROOT / "action" / "action.yml") as f:
            data = yaml.safe_load(f)
        for key in ("name", "description", "runs"):
            self.assertIn(key, data)

    def test_58_action_yml_is_composite(self):
        """BM-58: runs.using == 'composite'."""
        with open(ROOT / "action" / "action.yml") as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["runs"]["using"], "composite")
        self.assertGreater(len(data["runs"]["steps"]), 0)

    def test_59_workflow_yml_valid(self):
        """BM-59: .github/workflows/mizan.yml parses as YAML."""
        path = ROOT / ".github" / "workflows" / "mizan.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        self.assertIsInstance(data, dict)

    def test_60_workflow_triggers_complete(self):
        """BM-60: workflow has push, pull_request, schedule, workflow_dispatch."""
        with open(ROOT / ".github" / "workflows" / "mizan.yml") as f:
            data = yaml.safe_load(f)
        triggers = data.get("on") or data.get(True) or {}
        for key in ("push", "pull_request", "schedule", "workflow_dispatch"):
            self.assertIn(key, triggers, f"missing trigger: {key}")


class PermissionsBenchmark(unittest.TestCase):
    def _perms(self):
        with open(ROOT / ".github" / "workflows" / "mizan.yml") as f:
            data = yaml.safe_load(f)
        return data.get("permissions", {})

    def test_61_security_events_write(self):
        """BM-61: permissions.security-events == write."""
        self.assertEqual(self._perms().get("security-events"), "write")

    def test_62_pull_requests_write(self):
        """BM-62: permissions.pull-requests == write."""
        self.assertEqual(self._perms().get("pull-requests"), "write")

    def test_63_contents_write(self):
        """BM-63: permissions.contents == write."""
        self.assertEqual(self._perms().get("contents"), "write")

    def test_64_no_admin_permission(self):
        """BM-64: workflow must not request admin permission."""
        perms = self._perms()
        self.assertNotIn("admin", perms)
        self.assertNotIn("administration", perms)

    def test_65_all_uses_pinned(self):
        """BM-65: every external action pinned with @ref (no bare uses)."""
        with open(ROOT / ".github" / "workflows" / "mizan.yml") as f:
            content = f.read()
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("- uses:") or s.startswith("uses:"):
                target = s.split("uses:")[1].strip()
                if target.startswith("./"):
                    continue
                self.assertIn("@", target, f"unpinned action: {target}")


class SarifCIBenchmark(unittest.TestCase):
    def _build(self, vulns):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "requirements.txt").write_text("requests==2.0.0\n")
            with _run_mock(vulns):
                scan = scan_repository(root)
        return json.loads(build_sarif(scan))

    def test_66_sarif_valid_json(self):
        """BM-66: SARIF output is valid JSON."""
        sarif = self._build(VULNS)
        self.assertIsInstance(sarif, dict)

    def test_67_sarif_has_runs(self):
        """BM-67: SARIF has runs[0] with tool + results."""
        sarif = self._build(VULNS)
        self.assertIn("runs", sarif)
        self.assertGreater(len(sarif["runs"]), 0)
        self.assertIn("tool", sarif["runs"][0])
        self.assertIn("results", sarif["runs"][0])

    def test_68_sarif_tool_name_mizan(self):
        """BM-68: SARIF tool name = MIZAN."""
        sarif = self._build(VULNS)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "MIZAN")

    def test_69_sarif_level_from_cvss(self):
        """BM-69: CRITICAL -> error, MEDIUM -> warning, LOW -> note."""
        sarif = self._build([
            {"id": "A", "summary": "x", "database_specific": {"severity": "CRITICAL"}},
            {"id": "B", "summary": "y", "database_specific": {"severity": "MEDIUM"}},
            {"id": "C", "summary": "z", "database_specific": {"severity": "LOW"}},
        ])
        results = sarif["runs"][0]["results"]
        levels = {r["level"] for r in results}
        self.assertIn("error", levels)
        self.assertIn("warning", levels)
        self.assertIn("note", levels)

    def test_70_sarif_empty_clean(self):
        """BM-70: SARIF for clean scan has empty results + valid structure."""
        sarif = self._build([])
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)
        self.assertEqual(sarif["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
