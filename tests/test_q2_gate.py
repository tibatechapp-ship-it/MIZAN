"""Q2 wave tests (v0.8.0): severity gate + baseline delta scanning.

BM-101..BM-113 — MIZAN Security unified gate module (src/mizan/gate.py).
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mizan.gate import (  # noqa: E402
    apply_gate,
    collect_findings,
    fingerprint,
    filter_baseline,
    gate_findings,
    load_baseline,
    normalize_severity,
    save_baseline,
)


class TestSeverityNormalization(unittest.TestCase):
    """BM-101..BM-103: one canonical severity ladder for all scanners."""

    def test_bm_101_uppercase_and_lowercase_agree(self):
        """BM-101: HIGH/high/High all normalize to the same rung."""
        for raw in ("HIGH", "high", "High", " high "):
            self.assertEqual(normalize_severity(raw), "high")

    def test_bm_102_osv_ecosystem_aliases(self):
        """BM-102: OSV/GH aliases map onto the ladder (MODERATE→medium,
        IMPORTANT→high, TRIVIAL→low, CRITICAL→critical)."""
        self.assertEqual(normalize_severity("MODERATE"), "medium")
        self.assertEqual(normalize_severity("IMPORTANT"), "high")
        self.assertEqual(normalize_severity("TRIVIAL"), "low")
        self.assertEqual(normalize_severity("CRITICAL"), "critical")

    def test_bm_103_unknown_and_none_never_invent_evidence(self):
        """BM-103: unknown spellings/None → 'unknown' (surfaced, never gated)."""
        self.assertEqual(normalize_severity(None), "unknown")
        self.assertEqual(normalize_severity("bogus"), "unknown")
        self.assertEqual(normalize_severity(""), "unknown")
        self.assertEqual(normalize_severity(123), "unknown")


class TestFingerprints(unittest.TestCase):
    """BM-104..BM-106: stable finding identity for delta scanning."""

    def test_bm_104_code_finding_fingerprint_is_stable(self):
        """BM-104: same rule|file|line|message → same fingerprint."""
        finding = {"rule": "eval", "file": "a.py", "line": 10,
                   "message": "Dynamic code execution detected."}
        self.assertEqual(fingerprint(finding), fingerprint(dict(finding)))

    def test_bm_105_fingerprint_changes_with_location_or_text(self):
        """BM-105: line/message/rule changes produce different fingerprints."""
        base = {"rule": "eval", "file": "a.py", "line": 10, "message": "m1"}
        moved = dict(base, line=11)
        reworded = dict(base, message="m2")
        other_rule = dict(base, rule="exec")
        self.assertNotEqual(fingerprint(base), fingerprint(moved))
        self.assertNotEqual(fingerprint(base), fingerprint(reworded))
        self.assertNotEqual(fingerprint(base), fingerprint(other_rule))

    def test_bm_106_osv_finding_fingerprint_ignores_line_noise(self):
        """BM-106: OSV findings fingerprint as name@version|vuln-id."""
        finding = {"dependency": {"name": "requests", "version": "2.0.0"},
                   "vuln": {"id": "GHSA-xxxx"}}
        self.assertEqual(fingerprint(finding), fingerprint(dict(finding)))
        moved = dict(finding, dependency={"name": "requests", "version": "2.33.0"})
        self.assertNotEqual(fingerprint(finding), fingerprint(moved))


class TestCollectFindings(unittest.TestCase):
    """BM-107: recursive gathering across full-scan result shapes."""

    def test_bm_107_collects_findings_lists_at_any_depth(self):
        """BM-107: findings lists nested at any depth are all collected."""
        tree = {
            "analysis": {"findings": [{"rule": "r1", "file": "f", "line": 1,
                                        "message": "m"}]},
            "scanner": {"plugins": [
                {"name": "security", "findings": [
                    {"rule": "r2", "file": "f", "line": 2, "message": "m"}]},
                {"name": "quality", "findings": []},
            ]},
            "dependencies": {"findings": [
                {"dependency": {"name": "requests", "version": "2.0.0"},
                 "vuln": {"id": "GHSA-1"}}]},
            "unrelated": {"findings": "not-a-list"},
        }
        collected = collect_findings(tree)
        self.assertEqual(len(collected), 3)


class TestGateAndBaseline(unittest.TestCase):
    """BM-108..BM-112: threshold gate + baseline suppression logic."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.high = {"rule": "dynamic-execution", "file": "app.py",
                     "line": 2, "severity": "high",
                     "message": "Dynamic code execution detected."}
        self.warning = {"rule": "todo-comment", "file": "app.py",
                        "line": 9, "severity": "warning",
                        "message": "TODO found."}
        self.critical = {"rule": "hardcoded-secret", "file": "cfg.py",
                         "line": 5, "severity": "CRITICAL",
                         "message": "secret literal"}

    def test_bm_108_gate_splits_by_normalized_severity(self):
        """BM-108: gate_findings routes blocking vs allowed; custom sets work."""
        blocking, allowed = gate_findings(
            [self.high, self.warning, self.critical],
            blocking=("critical", "high"),
        )
        self.assertEqual(len(blocking), 2)
        self.assertEqual([f["rule"] for f in allowed], ["todo-comment"])

        strict, _ = gate_findings([self.warning], blocking=("warning",))
        self.assertEqual(len(strict), 1)

    def test_bm_109_baseline_roundtrip_and_schema_guard(self):
        """BM-109: save/load roundtrip; wrong schema is rejected loudly."""
        path = os.path.join(self.tmp, "bl", "baseline.json")
        save_baseline([self.high, self.warning], path=path, note="hello")
        doc = load_baseline(path)
        self.assertEqual(doc["schema"], "mizan-baseline/1")
        self.assertEqual(doc["count"], 2)
        self.assertEqual(doc["note"], "hello")

        bad = dict(doc, schema="other-tool/9")
        bad_path = os.path.join(self.tmp, "bad.json")
        with open(bad_path, "w", encoding="utf-8") as fh:
            json.dump(bad, fh)
        with self.assertRaises(ValueError):
            load_baseline(bad_path)

    def test_bm_110_filter_baseline_returns_new_and_known(self):
        """BM-110: known findings are absorbed; unseen ones come back."""
        path = os.path.join(self.tmp, "bl2.json")
        save_baseline([self.high, self.warning], path=path)
        doc = load_baseline(path)
        new = dict(self.high, line=3)  # same rule/file/message, moved line
        new_findings, known = filter_baseline(
            [self.high, self.warning, new], doc
        )
        self.assertEqual(known, 2)
        self.assertEqual([f["line"] for f in new_findings], [3])

    def test_bm_111_apply_gate_fails_on_high_by_default(self):
        """BM-111: apply_gate → decision=fail with high findings, no baseline."""
        report = apply_gate([self.high, self.warning])
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["blocking_count"], 1)
        self.assertEqual(report["blocking_severities"], ["critical", "high"])
        self.assertEqual(report["known_suppressed"], 0)

    def test_bm_112_apply_gate_with_baseline_passes_on_known_only(self):
        """BM-112: delta scanning — known highs suppressed, verdict=pass."""
        path = os.path.join(self.tmp, "bl3.json")
        save_baseline([self.high], path=path)
        report = apply_gate([self.high, self.warning], baseline_path=path)
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["known_suppressed"], 1)
        self.assertEqual(report["evaluated"], 1)

        # a NEW high finding still fails even with a baseline in place
        report2 = apply_gate([self.high, dict(self.high, line=77), self.warning],
                             baseline_path=path)
        self.assertEqual(report2["decision"], "fail")
        self.assertEqual(report2["blocking_count"], 1)


class TestGateCLI(unittest.TestCase):
    """BM-113: end-to-end `mizan scan --gate` exit codes in-process."""

    def test_bm_113_scan_gate_exit_codes(self):
        """BM-113: --gate exits 1 on a high finding and 0 on a clean tree."""
        from mizan.cli import main as cli_main

        dirty = tempfile.mkdtemp()
        with open(os.path.join(dirty, "app.py"), "w", encoding="utf-8") as fh:
            fh.write('def f():\n    return eval("1+1")\n')
        clean = tempfile.mkdtemp()
        with open(os.path.join(clean, "ok.py"), "w", encoding="utf-8") as fh:
            fh.write("def f():\n    return 1 + 1\n")

        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "scan", dirty, "--gate", "critical,high",
                        "--format", "json"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "fail")

            sys.argv = ["mizan", "scan", clean, "--gate", "critical,high",
                        "--format", "json"]
            out2 = io.StringIO()
            with contextlib.redirect_stdout(out2):
                code2 = cli_main()
            self.assertIn(code2, (0, None))
            payload2 = json.loads(out2.getvalue())
            self.assertEqual(payload2["gate"]["decision"], "pass")
        finally:
            sys.argv = old_argv

    def test_bm_119_bare_gate_flag_defaults_to_critical_high(self):
        """BM-119: bare `--gate` (no value) works and defaults to
        critical,high — the documented README usage must not crash."""
        from mizan.cli import main as cli_main

        dirty = tempfile.mkdtemp()
        with open(os.path.join(dirty, "app.py"), "w", encoding="utf-8") as fh:
            fh.write('def f():\n    return eval("1+1")\n')

        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "scan", dirty, "--gate", "--format", "json"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertEqual(
                payload["gate"]["blocking_severities"], ["critical", "high"]
            )
            self.assertEqual(payload["gate"]["decision"], "fail")
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
