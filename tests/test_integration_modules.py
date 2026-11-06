"""Coverage uplift tests: email_reporter, semgrep_scanner, code_quality, cli.

External processes (bandit/semgrep/eslint/smtp) are mocked — no network,
no tools required.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mizan import email_reporter  # noqa: E402
from mizan.code_quality import CodeQualityScanner  # noqa: E402
from mizan.semgrep_scanner import SemgrepScanner  # noqa: E402


def _sarif(results):
    return {"version": "2.1.0", "runs": [{"results": results}]}


class _CwdTestCase(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmp.cleanup()


class EmailReporterTests(_CwdTestCase):
    def test_skips_without_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(email_reporter.send_email_report())

    def test_sends_report_content(self):
        Path("mizan_report.md").write_text("## report body", encoding="utf-8")
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, context=None):
                sent["host"], sent["port"] = host, port

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def login(self, user, pwd):
                sent["user"], sent["pwd"] = user, pwd

            def send_message(self, msg):
                sent["msg"] = msg

        env = {"GMAIL_USERNAME": "m@example.com",
               "GMAIL_APP_PASSWORD": "app-pass"}
        with patch.dict(os.environ, env, clear=True):
            with patch("smtplib.SMTP_SSL", FakeSMTP):
                email_reporter.send_email_report()

        self.assertEqual(sent["user"], "m@example.com")
        self.assertEqual(sent["pwd"], "app-pass")
        self.assertEqual(sent["msg"]["Subject"], "⚖️ تقرير MIZAN الآلي")
        self.assertEqual(sent["msg"]["From"], "m@example.com")
        self.assertEqual(sent["msg"]["To"], "m@example.com")
        self.assertIn("report body", sent["msg"].get_content())

    def test_smtp_failure_is_caught(self):
        Path("mizan_report.md").write_text("x", encoding="utf-8")

        class BoomSMTP:
            def __init__(self, *a, **k):
                raise OSError("no network")

        env = {"GMAIL_USERNAME": "m@example.com",
               "GMAIL_APP_PASSWORD": "p"}
        with patch.dict(os.environ, env, clear=True):
            with patch("smtplib.SMTP_SSL", BoomSMTP):
                # must not raise
                email_reporter.send_email_report()


class SemgrepScannerTests(_CwdTestCase):
    def test_bandit_findings_detected(self):
        Path("bandit.sarif").write_text(
            json.dumps(_sarif([{"ruleId": "B307", "level": "error"}])))
        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            ok, results = scanner._run_bandit()
        self.assertFalse(ok)
        self.assertEqual(len(results), 1)

    def test_bandit_clean(self):
        Path("bandit.sarif").write_text(json.dumps(_sarif([])))
        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            ok, results = scanner._run_bandit()
        self.assertTrue(ok)
        self.assertEqual(results, [])

    def test_bandit_missing_report(self):
        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            ok, results = scanner._run_bandit()
        self.assertTrue(ok)

    def test_bandit_crash_is_tolerated(self):
        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", side_effect=OSError("boom")):
            ok, results = scanner._run_bandit()
        self.assertTrue(ok)
        self.assertEqual(results, [])

    def test_semgrep_skipped_when_not_installed(self):
        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            ok, results = scanner._run_semgrep_tool()
        self.assertTrue(ok)
        self.assertEqual(results, [])

    def test_semgrep_findings_detected(self):
        Path("semgrep.sarif").write_text(
            json.dumps(_sarif([{"check_id": "x"}])))

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["semgrep", "--version"]:
                return MagicMock(returncode=0)
            return MagicMock(returncode=0)

        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", side_effect=fake_run):
            ok, results = scanner._run_semgrep_tool()
        self.assertFalse(ok)
        self.assertEqual(len(results), 1)

    def test_run_semgrep_combines_both(self):
        Path("bandit.sarif").write_text(json.dumps(_sarif([])))
        Path("semgrep.sarif").write_text(json.dumps(_sarif([])))

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["semgrep", "--version"]:
                return MagicMock(returncode=0)
            return MagicMock(returncode=0)

        scanner = SemgrepScanner(target_dir=".")
        with patch("subprocess.run", side_effect=fake_run):
            ok, results = scanner.run_semgrep()
        self.assertTrue(ok)
        self.assertEqual(results, [])


class CodeQualityTests(_CwdTestCase):
    def test_no_config_is_skipped_not_created(self):
        """Read-only policy (v0.8.2): missing config => skip cleanly,
        NEVER write eslint.config.js into the scanned repository."""
        scanner = CodeQualityScanner(target_dir=".")
        ok, results = scanner.run_eslint()
        self.assertTrue(ok)  # skipped, not failed
        self.assertEqual(results, [])
        self.assertFalse(Path("eslint.config.js").exists())

    def test_clean_code(self):
        Path("eslint.config.js").write_text("export default [];\n")
        scanner = CodeQualityScanner(target_dir=".")
        with patch("subprocess.run", return_value=MagicMock(
                stdout="[]", stderr="", returncode=0)):
            ok, issues = scanner.run_eslint()
        self.assertTrue(ok)
        self.assertEqual(issues, [])

    def test_issues_detected(self):
        Path("eslint.config.js").write_text("export default [];\n")
        out = json.dumps([
            {"errorCount": 2, "warningCount": 1},
            {"errorCount": 0, "warningCount": 0},
        ])
        scanner = CodeQualityScanner(target_dir=".")
        with patch("subprocess.run", return_value=MagicMock(
                stdout=out, stderr="", returncode=1)):
            ok, issues = scanner.run_eslint()
        self.assertFalse(ok)
        self.assertEqual(len(issues), 2)

    def test_eslint_technical_error(self):
        Path("eslint.config.js").write_text("export default [];\n")
        scanner = CodeQualityScanner(target_dir=".")
        with patch("subprocess.run", return_value=MagicMock(
                stdout="", stderr="config broken", returncode=1)):
            ok, issues = scanner.run_eslint()
        self.assertFalse(ok)
        self.assertEqual(issues, [])

    def test_npx_missing(self):
        Path("eslint.config.js").write_text("export default [];\n")
        scanner = CodeQualityScanner(target_dir=".")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            ok, issues = scanner.run_eslint()
        self.assertFalse(ok)
        self.assertEqual(issues, [])


class CliDispatchTests(_CwdTestCase):
    def _run_cli(self, *argv):
        from mizan import cli
        with patch.object(sys, "argv", ["mizan", *argv]):
            cli.main()

    def test_inspect_outputs_json(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run_cli("inspect", ".")
        out = buf.getvalue()
        self.assertIn("{", out)

    def test_plugins_list(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run_cli("plugins", "list")
        self.assertTrue(buf.getvalue().strip())

    def test_ledger_add_entry(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run_cli("ledger", "test entry", "--actor", "human")
        self.assertTrue(Path(".mizan/ledger.jsonl").exists())
        self.assertIn("test entry",
                      Path(".mizan/ledger.jsonl").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
