"""Review wave tests (v0.8.2): closing the confirmed audit findings.

RW-101..RW-114 — scanner isolation, full-scan gate/baseline, fail-closed
gate validation, plugin registry sync, CLI --version, engine version
unity, and the literal read-only policy.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mizan import __version__  # noqa: E402
from mizan.analyzer import analyze_repository  # noqa: E402
from mizan.cli import full_scan_repository, main as cli_main  # noqa: E402
from mizan.code_quality import CodeQualityScanner  # noqa: E402
from mizan.detector import detect_project  # noqa: E402
from mizan.ci_scanner import scan_ci_repository  # noqa: E402
from mizan.git_scanner import scan_git_repository  # noqa: E402
from mizan.risk_scanner import scan_change_risk  # noqa: E402
from mizan.dependency_scanner import scan_dependencies  # noqa: E402
from mizan.gate import (  # noqa: E402
    apply_gate,
    collect_findings,
    dedupe_findings,
    save_baseline,
    validate_blocking,
)


def _make_git_project():
    """Create a real git repo with one high-severity code finding."""
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as fh:
        fh.write('def f():\n    return eval("1+1")\n')
    subprocess.run(["git", "init", "-q", root], check=True)
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "t")
    env.setdefault("GIT_AUTHOR_EMAIL", "t@t")
    env.setdefault("GIT_COMMITTER_NAME", "t")
    env.setdefault("GIT_COMMITTER_EMAIL", "t@t")
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=env)
    subprocess.run(
        ["git", "-C", root, "commit", "-qm", "init"], check=True, env=env
    )
    return root


class TestScannerIsolation(unittest.TestCase):
    """RW-101..RW-103: one failing scanner must not kill the full-scan."""

    def test_rw_101_full_scan_survives_non_git_directory(self):
        """RW-101: full-scan on a non-git dir keeps the 5 non-git sections
        and records the 2 git-bound scanners as visible errors."""
        root = tempfile.mkdtemp()  # deliberately NOT a git repo
        result = full_scan_repository(root)

        failed = result["scanners_failed"]
        self.assertEqual(sorted(failed), ["change_risk", "git"])

        for section in ("analysis", "detection", "scanner", "ci",
                        "dependencies"):
            self.assertIn(section, result)
            self.assertNotIn("error", result[section])

        for section in ("git", "change_risk"):
            self.assertIn("error", result[section])
            self.assertIn("Git repository", result[section]["error"])

    def test_rw_102_git_project_has_no_failed_scanners(self):
        """RW-102: a real git repo runs all 7 scanners cleanly."""
        result = full_scan_repository(_make_git_project())
        self.assertEqual(result["scanners_failed"], [])
        self.assertNotIn("error", result["git"])
        self.assertNotIn("error", result["change_risk"])

    def test_rw_103_invalid_directory_still_raises(self):
        """RW-103: an invalid directory keeps raising ValueError."""
        with self.assertRaises(ValueError):
            full_scan_repository("/nonexistent/mizan-rw-103")


class TestGateValidation(unittest.TestCase):
    """RW-104..RW-107: fail-closed gate inputs + full-scan gating."""

    def test_rw_104_validate_blocking_accepts_any_case(self):
        """RW-104: CRITICAL/high normalizes; empty falls to default."""
        self.assertEqual(
            validate_blocking(["CRITICAL", "High"]), ("critical", "high")
        )
        self.assertEqual(validate_blocking([]), ("critical", "high"))

    def test_rw_105_typoed_gate_severity_fails_loudly(self):
        """RW-105: 'critial' must raise ValueError, never silently pass."""
        with self.assertRaises(ValueError) as ctx:
            validate_blocking(["critial"])
        self.assertIn("critial", str(ctx.exception))
        self.assertIn("valid", str(ctx.exception))

    def test_rw_106_cli_rejects_unknown_gate_severity_with_exit_2(self):
        """RW-106: `mizan scan --gate banana` exits 2 with a clear error."""
        clean = tempfile.mkdtemp()
        with open(os.path.join(clean, "ok.py"), "w", encoding="utf-8") as fh:
            fh.write("def f():\n    return 1 + 1\n")

        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "scan", clean, "--gate", "banana"]
            err = io.StringIO()
            with self.assertRaises(SystemExit) as ctx:
                with contextlib.redirect_stderr(err):
                    cli_main()
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("banana", err.getvalue())
        finally:
            sys.argv = old_argv

    def test_rw_107_uppercase_gate_is_accepted(self):
        """RW-107: `--gate CRITICAL,HIGH` works (case-normalized)."""
        dirty = _make_git_project()
        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "scan", dirty, "--gate", "CRITICAL,HIGH"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "fail")
        finally:
            sys.argv = old_argv


class TestFullScanGate(unittest.TestCase):
    """RW-108..RW-110: one gate across EVERY scanner's findings."""

    def test_rw_108_full_scan_gate_fails_on_high_finding(self):
        """RW-108: `full-scan --gate` sees code findings and exits 1."""
        root = _make_git_project()
        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "full-scan", root, "--gate", "critical,high"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "fail")
            rules = {f["rule"] for f in payload["gate"]["blocking_findings"]}
            self.assertIn("dynamic-execution", rules)
        finally:
            sys.argv = old_argv

    def test_rw_109_full_scan_baseline_absorbs_known_findings(self):
        """RW-109: baseline saved from full-scan gates only NEW findings —
        the Q2 asymmetry (fingerprints collected but never evaluated)."""
        root = _make_git_project()
        baseline_path = os.path.join(root, ".mizan", "baseline.json")

        full = full_scan_repository(root)
        save_baseline(collect_findings(full), path=baseline_path)

        old_argv = sys.argv
        try:
            sys.argv = [
                "mizan", "full-scan", root,
                "--gate", "critical,high",
                "--baseline", baseline_path,
            ]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "pass")
            self.assertGreater(payload["gate"]["known_suppressed"], 0)
            self.assertEqual(payload["gate"]["evaluated"], 0)
        finally:
            sys.argv = old_argv

    def test_rw_110_apply_gate_dedupes_and_gates_osv_findings(self):
        """RW-110: duplicated section findings count once; OSV-shaped
        findings (dependency+vuln) gate on their normalized severity."""
        finding = {
            "rule": "dynamic-execution", "file": "a.py", "line": 1,
            "severity": "high", "message": "Dynamic code execution detected.",
        }
        deduped = dedupe_findings([finding, dict(finding)])
        self.assertEqual(len(deduped), 1)

        decision = apply_gate(
            [finding, dict(finding)], blocking=("high",)
        )
        self.assertEqual(decision["blocking_count"], 1)

        osv_finding = {
            "dependency": {"name": "requests", "version": "2.19.0",
                           "ecosystem": "PyPI"},
            "vuln": {"id": "GHSA-xxxx"},
            "severity": "HIGH",
        }
        decision = apply_gate([osv_finding], blocking=("high",))
        self.assertEqual(decision["decision"], "fail")
        self.assertEqual(decision["blocking_count"], 1)


class TestPluginRegistrySync(unittest.TestCase):
    """RW-111: analyzer rules must not silently vanish from `scan`."""

    def test_rw_111_scan_surfaces_process_execution_and_syntax_errors(self):
        """RW-111: os.system (medium) and a syntax error now appear in
        `mizan scan` — previously visible in `analyze` only."""
        root = tempfile.mkdtemp()
        with open(os.path.join(root, "proc.py"), "w", encoding="utf-8") as fh:
            fh.write("import os\nos.system('ls')\n")
        with open(os.path.join(root, "broken.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("def broken(:\n    pass\n")

        analysis = analyze_repository(root)
        analysis_rules = {f["rule"] for f in analysis["findings"]}
        self.assertIn("process-execution", analysis_rules)
        self.assertIn("python-syntax-error", analysis_rules)

        from mizan.scanner import scan_repository
        scanned = scan_repository(root)
        scanned_rules = {f["rule"] for f in scanned["findings"]}
        self.assertIn("process-execution", scanned_rules)
        self.assertIn("python-syntax-error", scanned_rules)

        # and the gate can now act on the medium-severity finding
        decision = apply_gate(
            [f for f in scanned["findings"]
             if f["rule"] == "process-execution"],
            blocking=("medium",),
        )
        self.assertEqual(decision["decision"], "fail")


class TestCliSurface(unittest.TestCase):
    """RW-112..RW-113: standard CLI expectations."""

    def test_rw_112_cli_version_flag(self):
        """RW-112: `mizan --version` prints the release version, exit 0."""
        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "--version"]
            out = io.StringIO()
            with self.assertRaises(SystemExit) as ctx:
                with contextlib.redirect_stdout(out):
                    cli_main()
            self.assertEqual(ctx.exception.code, 0)
            self.assertIn(f"MIZAN Security {__version__}", out.getvalue())
        finally:
            sys.argv = old_argv

    def test_rw_113_every_engine_reports_the_release_version(self):
        """RW-113: no engine keeps a hardcoded stale version."""
        git_root = _make_git_project()
        engines = {
            "analyzer": analyze_repository(git_root),
            "detector": detect_project(git_root),
            "ci": scan_ci_repository(git_root),
            "git": scan_git_repository(git_root),
            "risk": scan_change_risk(git_root),
            "dependencies": scan_dependencies(git_root),
            "full": full_scan_repository(git_root),
        }
        for name, report in engines.items():
            with self.subTest(engine=name):
                self.assertEqual(report.get("version"), __version__)


class TestReadOnlyPolicy(unittest.TestCase):
    """RW-114: MIZAN must never write into the scanned repository."""

    def test_rw_114_eslint_runner_never_creates_config_files(self):
        """RW-114: no eslint.config.js is generated in the target dir —
        the scan is skipped with a warning instead (read-only policy)."""
        root = tempfile.mkdtemp()  # no eslint.config.js on purpose
        scanner = CodeQualityScanner(target_dir=root)
        success, results = scanner.run_eslint()

        self.assertFalse(
            os.path.exists(os.path.join(root, "eslint.config.js")),
            "read-only policy violated: config file was written",
        )
        self.assertTrue(success)  # skipped, not failed
        self.assertEqual(results, [])

    def test_rw_114b_run_mizan_imports_installed_package(self):
        """RW-114b: run_mizan.py uses the installed `mizan` package,
        not the fragile `src.mizan` namespace path."""
        repo_root = Path(__file__).resolve().parents[1]
        source = (repo_root / "run_mizan.py").read_text(encoding="utf-8")
        self.assertIn("from mizan.code_quality import", source)
        self.assertIn("from mizan.semgrep_scanner import", source)
        self.assertNotIn("from src.mizan", source)


if __name__ == "__main__":
    unittest.main()
