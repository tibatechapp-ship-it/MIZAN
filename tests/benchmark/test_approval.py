"""Approval benchmarks 41-55 aligned with GitHub Actions Security Hardening.

Standards:
- Least Privilege (only trusted bots)
- Defense in Depth (7 independent gates)
- Opt-in only (disabled by default)

F-01/F-02 (2026-11-26 live audit): the executive approve/merge helpers
are deleted — the module is report-only. BM-56+ below benchmark the
replacement contract: findings are MEASURED from a report file, and a
report that cannot be measured is never "0 findings".
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mizan.approval import (
    DEFAULT_ALLOWED_AUTHORS,
    DEFAULT_EXCLUDE_PATHS,
    _path_is_excluded,
    is_pr_eligible,
    measure_report_findings,
)


def _pr_json(**overrides):
    base = {
        "author": {"login": "dependabot[bot]"},
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "files": [{"path": "requirements.txt"}],
        "reviews": [],
        "headRefName": "dependabot/pip/requests-2.33.0",
    }
    base.update(overrides)
    return json.dumps(base)


# ---------- BM-41 to BM-45: Trusted author gate ----------

class TrustedAuthorBenchmark(unittest.TestCase):
    """Least Privilege: only allow known bots."""

    @patch("mizan.approval._run")
    def test_41_blocks_untrusted_author(self, mock_run):
        """BM-41: randomuser -> BLOCKED."""
        mock_run.return_value = (0, _pr_json(author={"login": "randomuser"}), "")
        ok, reason = is_pr_eligible(1)
        self.assertFalse(ok)
        self.assertIn("author", reason)

    @patch("mizan.approval._run")
    def test_42_allows_dependabot(self, mock_run):
        """BM-42: dependabot[bot] -> ELIGIBLE."""
        mock_run.return_value = (0, _pr_json(), "")
        ok, _ = is_pr_eligible(1)
        self.assertTrue(ok)

    @patch("mizan.approval._run")
    def test_43_allows_renovate(self, mock_run):
        """BM-43: renovate[bot] -> ELIGIBLE."""
        mock_run.return_value = (0, _pr_json(author={"login": "renovate[bot]"}), "")
        ok, _ = is_pr_eligible(1)
        self.assertTrue(ok)

    @patch("mizan.approval._run")
    def test_44_allows_github_actions(self, mock_run):
        """BM-44: github-actions[bot] -> ELIGIBLE."""
        mock_run.return_value = (0, _pr_json(author={"login": "github-actions[bot]"}), "")
        ok, _ = is_pr_eligible(1)
        self.assertTrue(ok)

    def test_45_default_allowed_authors_exact(self):
        """BM-45: DEFAULT_ALLOWED_AUTHORS = exactly 3 trusted bots."""
        self.assertEqual(set(DEFAULT_ALLOWED_AUTHORS), {
            "dependabot[bot]", "renovate[bot]", "github-actions[bot]",
        })


# ---------- BM-46 to BM-50: Path exclusion gate ----------

class PathExclusionBenchmark(unittest.TestCase):
    """Defense in Depth: block sensitive paths."""

    def test_46_github_dir_blocked(self):
        """BM-46: .github/workflows/ci.yml -> excluded."""
        self.assertTrue(_path_is_excluded(".github/workflows/ci.yml",
                                          DEFAULT_EXCLUDE_PATHS))

    def test_47_dockerfile_blocked(self):
        """BM-47: Dockerfile -> excluded."""
        self.assertTrue(_path_is_excluded("Dockerfile", DEFAULT_EXCLUDE_PATHS))

    def test_48_env_blocked(self):
        """BM-48: .env -> excluded."""
        self.assertTrue(_path_is_excluded(".env", DEFAULT_EXCLUDE_PATHS))

    def test_49_secrets_k8s_terraform_blocked(self):
        """BM-49: secrets/, k8s/, terraform/, helm/ -> excluded."""
        for path in ("secrets/key.pem", "k8s/deploy.yaml",
                     "terraform/main.tf", "helm/values.yaml"):
            self.assertTrue(_path_is_excluded(path, DEFAULT_EXCLUDE_PATHS),
                            "not excluded: " + path)

    def test_50_safe_file_allowed(self):
        """BM-50: src/main.py and requirements.txt -> not excluded."""
        for path in ("src/main.py", "requirements.txt", "README.md"):
            self.assertFalse(_path_is_excluded(path, DEFAULT_EXCLUDE_PATHS))


# ---------- BM-51 to BM-55: Other gates ----------

class OtherGatesBenchmark(unittest.TestCase):
    """Defense in Depth: findings, checks, reviews, draft, mergeable."""

    @patch("mizan.approval._run")
    def test_51_blocks_on_findings(self, mock_run):
        """BM-51: findings > 0 -> BLOCKED."""
        mock_run.return_value = (0, _pr_json(), "")
        ok, reason = is_pr_eligible(1, findings_count=5)
        self.assertFalse(ok)
        self.assertIn("vulnerabilities", reason)

    @patch("mizan.approval._run")
    def test_52_blocks_on_draft(self, mock_run):
        """BM-52: isDraft=True -> BLOCKED."""
        mock_run.return_value = (0, _pr_json(isDraft=True), "")
        ok, reason = is_pr_eligible(1)
        self.assertFalse(ok)
        self.assertIn("draft", reason)

    @patch("mizan.approval._run")
    def test_53_blocks_on_not_mergeable(self, mock_run):
        """BM-53: mergeable=CONFLICTING -> BLOCKED."""
        mock_run.return_value = (0, _pr_json(mergeable="CONFLICTING"), "")
        ok, reason = is_pr_eligible(1)
        self.assertFalse(ok)
        self.assertIn("mergeable", reason)

    @patch("mizan.approval._run")
    def test_54_blocks_on_changes_requested(self, mock_run):
        """BM-54: CHANGES_REQUESTED review -> BLOCKED."""
        mock_run.return_value = (0, _pr_json(reviews=[{"state": "CHANGES_REQUESTED"}]), "")
        ok, reason = is_pr_eligible(1)
        self.assertFalse(ok)
        self.assertIn("changes requested", reason)

    @patch("mizan.approval._run")
    def test_55_blocks_on_failing_checks(self, mock_run):
        """BM-55: gh pr checks fails -> BLOCKED."""
        def side_effect(cmd, *args, **kwargs):
            if cmd[:3] == ["gh", "pr", "checks"]:
                return (1, "", "some checks failed")
            return (0, _pr_json(), "")
        mock_run.side_effect = side_effect
        ok, reason = is_pr_eligible(1)
        self.assertFalse(ok)
        self.assertIn("checks", reason)

# ---------- BM-56+: F-01/F-02 measured-report contract ----------

class MeasuredReportBenchmark(unittest.TestCase):
    """F-02: eligibility is measured from a report file, never trusted
    from a flag; an unmeasurable report refuses (exit-2 semantics)."""

    def _write(self, name, content):
        d = tempfile.mkdtemp()
        p = Path(d) / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_56_sarif_count_is_measured(self):
        """BM-56: SARIF results[] length is the measured count."""
        sarif = self._write("r.sarif", json.dumps({
            "runs": [{"results": [{"ruleId": "x"}, {"ruleId": "y"}]}],
        }))
        count, meta = measure_report_findings(sarif)
        self.assertEqual(count, 2)
        self.assertEqual(meta["format"], "sarif")

    def test_57_mizan_json_count_is_measured(self):
        """BM-57: len(findings[]) is the measured count."""
        doc = self._write("r.json", json.dumps({
            "findings": [{"rule": "a"}, {"rule": "b"}, {"rule": "c"}],
            "findings_count": 99,  # stale declared counter
        }))
        count, meta = measure_report_findings(doc)
        self.assertEqual(count, 3)
        self.assertEqual(meta["declared_findings_count_mismatch"], 99)

    def test_58_missing_report_is_refused(self):
        """BM-58: a missing report is NEVER "0 findings"."""
        with self.assertRaises(ValueError) as ctx:
            measure_report_findings(Path("/nonexistent/report.sarif"))
        self.assertIn("not found", str(ctx.exception))

    def test_59_malformed_report_is_refused(self):
        """BM-59: malformed JSON refuses with the path named."""
        bad = self._write("bad.sarif", "{not json")
        with self.assertRaises(ValueError) as ctx:
            measure_report_findings(bad)
        self.assertIn("bad.sarif", str(ctx.exception))

    def test_60_empty_sarif_runs_is_refused(self):
        """BM-60: SARIF with empty runs[] refuses — not counted as clean."""
        empty = self._write("empty.sarif", json.dumps({"runs": []}))
        with self.assertRaises(ValueError) as ctx:
            measure_report_findings(empty)
        self.assertIn("empty", str(ctx.exception))

    def test_61_unrecognized_format_is_refused(self):
        """BM-61: a random JSON object refuses instead of guessing."""
        junk = self._write("junk.json", json.dumps({"hello": "world"}))
        with self.assertRaises(ValueError) as ctx:
            measure_report_findings(junk)
        self.assertIn("not a recognized format", str(ctx.exception))

    def test_62_executive_helpers_are_deleted(self):
        """BM-62 (F-01): approve_pr / merge_pr no longer exist — the
        module cannot approve or merge, by absence of the capability."""
        import mizan.approval as approval_module
        self.assertFalse(hasattr(approval_module, "approve_pr"))
        self.assertFalse(hasattr(approval_module, "merge_pr"))


if __name__ == "__main__":
    unittest.main()
