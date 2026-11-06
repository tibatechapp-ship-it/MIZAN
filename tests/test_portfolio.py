"""Portfolio aggregation (v0.12.0) — acceptance contract.

Doctrine: the report's numbers must be EXACTLY the gate's numbers
(same fingerprint dedup), the HTML must be self-contained and
injection-proof, the scan must be read-only, and the exit contract
must be honest (0 with a report, 2 only when nothing could be scanned).
"""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from mizan.cli import main as cli_main
from mizan.portfolio import (
    aggregate_one,
    aggregate_portfolio,
    build_portfolio,
    render_portfolio_html,
)


def _code_finding(rule, file_, line, severity, message):
    return {
        "rule": rule, "file": file_, "line": line,
        "severity": severity, "message": message,
    }


def _fake_scan(path, findings, wall=1.23, files=7, failed=None):
    return {
        "engine": "MIZAN Security Master Engine",
        "version": "test",
        "repository": path,
        "execution": {"jobs": 4, "wall_seconds": wall},
        "scanners_failed": failed or [],
        "analysis": {
            "files_scanned": files,
            "findings": list(findings),
        },
        # The scanner section MIRRORS analysis in the real full-scan —
        # portfolio MUST deduplicate it via the gate fingerprint.
        "scanner": {
            "files_scanned": files,
            "findings": list(findings),
        },
        "ci": {"findings": []},
        "dependencies": {"findings": []},
    }


def _mk_repo(root, with_finding=True):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    code = "eval('1+1')\n" if with_finding else "print('ok')\n"
    (root / "app.py").write_text(code, encoding="utf-8")


class AggregateOneTests(unittest.TestCase):
    def test_mirror_sections_deduplicated(self):
        f = _code_finding("dynamic-execution", "a.py", 3, "high", "eval")
        repo = aggregate_one(_fake_scan("/r/demo", [f]))
        self.assertEqual(repo["total"], 1, "mirror section must not double-count")
        self.assertEqual(repo["findings_by_severity"], {"high": 1})

    def test_osv_shaped_finding_counted(self):
        osv_finding = {
            "dependency": {"name": "left-pad", "version": "1.0.0",
                           "ecosystem": "npm"},
            "vuln": {"id": "GHSA-xxx", "severity": "HIGH",
                     "summary": "bad package"},
        }
        repo = aggregate_one(_fake_scan("/r/demo", [osv_finding]))
        self.assertEqual(repo["findings_by_severity"].get("high"), 1)
        self.assertEqual(repo["top_findings"][0]["rule"], "GHSA-xxx")

    def test_top_findings_only_critical_high(self):
        f_high = _code_finding("r1", "a.py", 1, "high", "m1")
        f_info = _code_finding("todo", "a.py", 2, "info", "m2")
        f_med = _code_finding("r2", "b.py", 5, "medium", "m3")
        repo = aggregate_one(_fake_scan("/r/demo", [f_high, f_info, f_med]))
        rules = {f["rule"] for f in repo["top_findings"]}
        self.assertEqual(rules, {"r1"}, "only critical/high enter top findings")
        self.assertEqual(repo["total"], 3)

    def test_error_entry_shape(self):
        repo = aggregate_one({"path": "/nope", "error": "invalid directory"})
        self.assertEqual(repo["error"], "invalid directory")
        self.assertEqual(repo["total"], 0)


class AggregatePortfolioTests(unittest.TestCase):
    def test_totals_ranking_and_errored(self):
        high1 = _code_finding("dynamic-execution", "a.py", 1, "high", "m")
        high2 = _code_finding("shell-true", "b.py", 9, "high", "m")
        med = _code_finding("process-execution", "b.py", 2, "medium", "m")
        r_clean = _fake_scan("/r/clean", [])
        r_risky = _fake_scan("/r/risky", [high1, high2, med])
        r_broken = {"path": "/r/broken", "error": "boom"}
        p = aggregate_portfolio([r_clean, r_risky, r_broken])

        self.assertEqual(p["repos_count"], 3)
        self.assertEqual(p["scanned_ok"], 2)
        self.assertEqual(p["errored"], 1)
        self.assertEqual(p["totals"]["total"], 3)
        self.assertEqual(p["totals"]["findings_by_severity"]["high"], 2)
        self.assertEqual(p["ranking"], ["risky", "clean"])
        self.assertEqual(p["top_rules"][0]["rule"], "dynamic-execution")

    def test_ranking_is_stable_and_documented(self):
        p = aggregate_portfolio([_fake_scan("/r/x", [])])
        self.assertIn("display heuristic", p["score_note"])
        self.assertIn("--gate", p["score_note"])


class RenderHtmlTests(unittest.TestCase):
    def setUp(self):
        evil = _code_finding(
            "xss-rule", '<script>alert(1)</script>.py', 1, "high",
            '<img src=x onerror=alert(2)>',
        )
        self.portfolio = aggregate_portfolio([
            _fake_scan("/r/<b>repo&name</b>", [evil]),
        ])
        self.html = render_portfolio_html(self.portfolio)

    def test_user_strings_escaped(self):
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertNotIn("<img src=x", self.html)
        self.assertIn("&lt;script&gt;", self.html)

    def test_self_contained_no_external_resources(self):
        self.assertNotIn('src="http', self.html)
        self.assertNotIn('href="http', self.html)
        self.assertNotIn("@import", self.html)
        self.assertNotIn("<script", self.html)

    def test_contains_counts_and_note(self):
        self.assertIn("MIZAN Portfolio", self.html)
        self.assertIn("display heuristic", self.html)
        # severity count appears in the totals chips
        self.assertIn("high: 1", self.html)


class CliIntegrationTests(unittest.TestCase):
    def _mk_repo(self, root, with_finding=True):
        _mk_repo(root, with_finding=with_finding)

    def test_portfolio_writes_html_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            r1 = Path(tmp) / "alpha"
            r2 = Path(tmp) / "beta"
            self._mk_repo(r1, with_finding=True)
            self._mk_repo(r2, with_finding=False)
            out = Path(tmp) / "report.html"

            rc = cli_main([
                "portfolio", str(r1), str(r2),
                "--output", str(out), "--jobs", "1",
            ])

            self.assertEqual(rc, 0)
            html = out.read_text(encoding="utf-8")
            self.assertIn("alpha", html)
            self.assertIn("beta", html)
            self.assertIn("dynamic-execution", html)

    def test_portfolio_json_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            r1 = Path(tmp) / "gamma"
            self._mk_repo(r1, with_finding=True)
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["portfolio", str(r1), "--json", "--jobs", "1"])
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["repos_count"], 1)
            self.assertEqual(data["scanned_ok"], 1)
            self.assertEqual(data["engine"], "MIZAN Portfolio")

    def test_all_invalid_paths_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "does-not-exist")
            rc = cli_main(["portfolio", missing, "--json"])
            self.assertEqual(rc, 2, "a report nobody can trust is not a report")

    def test_mixed_valid_invalid_still_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good"
            self._mk_repo(good, with_finding=False)
            out = Path(tmp) / "mixed.html"
            rc = cli_main([
                "portfolio", str(good), str(Path(tmp) / "ghost"),
                "--output", str(out), "--json", "--jobs", "1",
            ])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8")) \
                if out.exists() else None
            # --json prints; the file path was for HTML mode — re-run HTML
            rc2 = cli_main([
                "portfolio", str(good), str(Path(tmp) / "ghost"),
                "--output", str(out), "--jobs", "1",
            ])
            self.assertEqual(rc2, 0)
            html = out.read_text(encoding="utf-8")
            self.assertIn("good", html)
            self.assertIn("scan error", html)

    def test_read_only_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "frozen"
            self._mk_repo(repo, with_finding=True)
            extra = repo / "notes.txt"
            extra.write_text("hello", encoding="utf-8")

            def snapshot():
                state = {}
                for path in sorted(repo.rglob("*")):
                    if path.is_file():
                        state[str(path)] = hashlib.sha256(
                            path.read_bytes()
                        ).hexdigest()
                return state

            before = snapshot()
            out = Path(tmp) / "ro.html"
            rc = cli_main([
                "portfolio", str(repo), "--output", str(out), "--jobs", "1",
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(snapshot(), before,
                             "portfolio must not modify scanned repositories")
            self.assertTrue(out.exists())


class BuildPortfolioDirectTests(unittest.TestCase):
    def test_wall_seconds_and_files_flow_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            r1 = Path(tmp) / "proj"
            _mk_repo(r1, with_finding=True)
            p = build_portfolio([str(r1)], jobs=1)
            self.assertEqual(p["scanned_ok"], 1)
            repo = p["repos"][0]
            self.assertGreaterEqual(repo["files_scanned"], 1)
            self.assertIsNotNone(repo["wall_seconds"])
            # A plain temp dir is not a git repository — the git-dependent
            # scanners record isolated errors; everything else must pass.
            self.assertLessEqual(set(repo["scanners_failed"]),
                                 {"git", "change_risk"})
            self.assertGreaterEqual(repo["total"], 1)


if __name__ == "__main__":
    unittest.main()
