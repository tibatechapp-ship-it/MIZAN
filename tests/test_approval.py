import unittest
from unittest.mock import patch

from mizan.approval import _path_is_excluded, is_pr_eligible


class PathExcludedTests(unittest.TestCase):
    def test_github_dir(self):
        self.assertTrue(_path_is_excluded(".github/workflows/x.yml", (".github/",)))

    def test_dockerfile(self):
        self.assertTrue(_path_is_excluded("Dockerfile", ("Dockerfile",)))

    def test_env(self):
        self.assertTrue(_path_is_excluded(".env", (".env",)))

    def test_safe_file(self):
        self.assertFalse(_path_is_excluded("src/main.py", (".github/", "Dockerfile")))

    def test_wildcard(self):
        self.assertTrue(_path_is_excluded("Dockerfile.prod", ("Dockerfile.",)))


class EligibilityTests(unittest.TestCase):
    def _pr_json(self, **overrides):
        base = {
            "author": {"login": "dependabot[bot]"},
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "files": [{"path": "requirements.txt"}],
            "reviews": [],
            "headRefName": "dependabot/foo",
        }
        base.update(overrides)
        import json
        return json.dumps(base)

    @patch("mizan.approval._run")
    def test_eligible(self, mock_run):
        mock_run.return_value = (0, self._pr_json(), "")
        ok, reason = is_pr_eligible(123, findings_count=0)
        self.assertTrue(ok)
        self.assertEqual(reason, "eligible")

    @patch("mizan.approval._run")
    def test_blocked_on_findings(self, mock_run):
        mock_run.return_value = (0, self._pr_json(), "")
        ok, reason = is_pr_eligible(123, findings_count=5)
        self.assertFalse(ok)
        self.assertIn("vulnerabilities", reason)

    @patch("mizan.approval._run")
    def test_blocked_on_excluded_path(self, mock_run):
        mock_run.return_value = (0, self._pr_json(
            files=[{"path": ".github/workflows/ci.yml"}]
        ), "")
        ok, reason = is_pr_eligible(123, findings_count=0)
        self.assertFalse(ok)
        self.assertIn(".github", reason)

    @patch("mizan.approval._run")
    def test_blocked_on_draft(self, mock_run):
        mock_run.return_value = (0, self._pr_json(isDraft=True), "")
        ok, reason = is_pr_eligible(123)
        self.assertFalse(ok)
        self.assertIn("draft", reason)

    @patch("mizan.approval._run")
    def test_blocked_on_untrusted_author(self, mock_run):
        mock_run.return_value = (0, self._pr_json(
            author={"login": "randomuser"}
        ), "")
        ok, reason = is_pr_eligible(123)
        self.assertFalse(ok)
        self.assertIn("author", reason)

    @patch("mizan.approval._run")
    def test_blocked_on_already_approved(self, mock_run):
        mock_run.return_value = (0, self._pr_json(
            reviews=[{"state": "APPROVED"}]
        ), "")
        ok, reason = is_pr_eligible(123)
        self.assertFalse(ok)
        self.assertIn("already approved", reason)


if __name__ == "__main__":
    unittest.main()
