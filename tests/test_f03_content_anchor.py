"""F-03 content-anchored fingerprints — the REFUTED gate.

The 2026-11-26 live audit (F-03) proved FOUR times in one day that the
line-anchored fingerprint (rule|file|line|message) breaks on any line
shift: inserting lines above a known finding re-fired the suppressed
finding as "new" and burned the strict self-scan gate on unchanged
content. The reproductions:

1. the audit's own insert-shifting repro on the CHANGELOG FP;
2. the wave-3 CHANGELOG insert re-firing it (blocking=1, decision=fail);
3. the wave-3 baseline regen recording an off-by-one line anchor;
4. the wave-4 CHANGELOG insert re-firing it again (157 -> 165).

The REFUTED gate below replays reproduction 2 exactly, at unit scale:
save a baseline over a finding, INSERT lines above it, re-scan — under
the line-anchored /1 scheme the finding re-fires (the measured bug),
under the content-anchored /2 scheme it stays suppressed (the fix).
Everything else here pins the honest edges: /2 without a root refuses
loudly, /1 keeps its historical semantics unchanged, line-0 findings
and unreadable files degrade to the line formula instead of inventing
identity, a changed offending line re-fires honestly, and identical
content+message findings deliberately share one fingerprint.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mizan.gate import (
    apply_gate,
    fingerprint,
    filter_baseline,
    load_baseline,
    save_baseline,
)

FINDING_LINE = '    return eval(expr)\n'


def _make_repo(root: Path, extra_lines_before: int = 0) -> Path:
    """One vulnerable app.py; extra comment lines shift the finding."""
    root.mkdir(parents=True, exist_ok=True)
    head = "".join(f"# padding line {i}\n" for i in range(extra_lines_before))
    (root / "app.py").write_text(
        "def handle(expr):\n" + head + FINDING_LINE, encoding="utf-8"
    )
    subprocess.run(
        ["git", "init", "-q"], cwd=str(root), check=True,
        capture_output=True,
    )
    return root


def _shift_lines_above_finding(root: Path, count=3):
    """The exact live-audit reproduction: pure insert, content untouched."""
    app = root / "app.py"
    text = app.read_text(encoding="utf-8")
    inserted = "".join(f"# inserted line {i}\n" for i in range(count))
    app.write_text(text.replace("def handle(expr):\n",
                                "def handle(expr):\n" + inserted),
                   encoding="utf-8")


def _finding(root: Path) -> dict:
    from mizan.analyzer import analyze_repository

    findings = [
        f for f in analyze_repository(str(root))["findings"]
        if f["rule"] == "dynamic-execution"
    ]
    assert findings, "the fixture must carry a dynamic-execution finding"
    return findings[0]


class ContentAnchorRefutationTests(unittest.TestCase):
    """The four-times-reproduced scenario, replayed and REFUTED."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.repo = _make_repo(self.work / "repo")
        self.baseline_path = self.work / "baseline.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_wave4_reproduction_refuted_under_v2(self):
        """Insert-above + v2 baseline: the FP stays suppressed (the fix)."""
        finding = _finding(self.repo)
        doc = save_baseline([finding], path=self.baseline_path,
                            note="v2 accepted set", root=self.repo)
        self.assertEqual(doc["schema"], "mizan-baseline/2")
        self.assertEqual(doc["fingerprint_scheme"], "content-anchored")

        _shift_lines_above_finding(self.repo, 3)
        shifted = _finding(self.repo)
        self.assertEqual(
            shifted["line"], finding["line"] + 3,
            "the reproduction requires the line to have shifted"
        )

        new_findings, known = filter_baseline(
            [shifted], load_baseline(self.baseline_path), root=self.repo
        )
        self.assertEqual(
            known, 1,
            "F-03 REFUTED: a pure line shift must NOT re-fire the "
            "suppressed finding under the content-anchored scheme"
        )
        self.assertEqual(new_findings, [])

        report = apply_gate([shifted], baseline_path=self.baseline_path,
                            root=self.repo)
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["known_suppressed"], 1)
        self.assertEqual(report["baseline_schema"], "mizan-baseline/2")
        self.assertEqual(report["fingerprint_scheme"], "content-anchored")

    def test_wave4_reproduction_replays_under_v1(self):
        """Insert-above + /1 baseline: the measured bug replays (contrast)."""
        finding = _finding(self.repo)
        doc = save_baseline([finding], path=self.baseline_path,
                            note="v1 accepted set")
        self.assertEqual(doc["schema"], "mizan-baseline/1")
        self.assertEqual(doc["fingerprint_scheme"], "line-anchored")

        _shift_lines_above_finding(self.repo, 3)
        shifted = _finding(self.repo)
        new_findings, known = filter_baseline(
            [shifted], load_baseline(self.baseline_path)
        )
        self.assertEqual(
            known, 0,
            "the historical line-anchored behaviour: the shifted finding "
            "re-fires — preserved verbatim for /1 baselines"
        )
        self.assertEqual(len(new_findings), 1)


class ContentAnchorContractTests(unittest.TestCase):
    """The honest edges of the content-anchored scheme."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.repo = _make_repo(self.work / "repo")
        self.baseline_path = self.work / "baseline.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_v2_without_root_refuses_loudly(self):
        """A /2 baseline without the scan root must not mis-compare."""
        finding = _finding(self.repo)
        save_baseline([finding], path=self.baseline_path, root=self.repo)
        with self.assertRaises(ValueError) as ctx:
            filter_baseline([finding], load_baseline(self.baseline_path))
        self.assertIn("requires the scan root", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            apply_gate([finding], baseline_path=self.baseline_path)
        self.assertIn("requires the scan root", str(ctx.exception))

    def test_changed_content_refires_honestly(self):
        """The offending TEXT changing means a different finding."""
        finding = _finding(self.repo)
        save_baseline([finding], path=self.baseline_path, root=self.repo)
        app = self.repo / "app.py"
        app.write_text(
            "def handle(expr):\n    return eval(expr, {}, {})\n",
            encoding="utf-8",
        )
        changed = _finding(self.repo)
        new_findings, known = filter_baseline(
            [changed], load_baseline(self.baseline_path), root=self.repo
        )
        self.assertEqual(
            known, 0,
            "the offending line's content changed — the fingerprint must "
            "change with it (a re-firing here is honest, not F-03)"
        )
        self.assertEqual(len(new_findings), 1)

    def test_line_zero_findings_use_the_line_formula(self):
        """A line-0 finding has no anchor — /2 falls back, stays stable."""
        orphan = {"rule": "doc-orphan-code", "file": "eslint.config.js",
                  "line": 0, "severity": "info", "message": "orphan module"}
        doc = save_baseline([orphan], path=self.baseline_path, root=self.repo)
        self.assertEqual(doc["schema"], "mizan-baseline/2")
        fp_anchored = fingerprint(orphan, root=self.repo)
        fp_plain = fingerprint(orphan)
        self.assertEqual(
            fp_anchored, fp_plain,
            "line-0 findings cannot anchor on content — the /2 entry "
            "must equal the historical line-anchored fingerprint"
        )
        new_findings, known = filter_baseline(
            [orphan], load_baseline(self.baseline_path), root=self.repo
        )
        self.assertEqual(known, 1)
        self.assertEqual(new_findings, [])

    def test_unreadable_file_degrades_to_line_formula(self):
        """A missing file degrades the anchor — never an invented identity."""
        finding = {"rule": "r", "file": "gone.py", "line": 7,
                   "severity": "low", "message": "m"}
        fp_with_root = fingerprint(finding, root=self.repo)
        fp_without_root = fingerprint(finding)
        self.assertEqual(
            fp_with_root, fp_without_root,
            "an unreadable file cannot anchor — the fingerprint must "
            "degrade to the historical formula"
        )

    def test_identical_content_and_message_share_one_fingerprint(self):
        """Two same-text findings are indistinguishable to suppression."""
        twin_repo = self.work / "twins"
        twin_repo.mkdir(parents=True)
        # two occurrences of the IDENTICAL line: same variable name, same
        # string literal — the collision case the trade-off describes.
        (twin_repo / "dup.py").write_text(
            "a = 1\np = '/tmp/cache'\nc = 2\np = '/tmp/cache'\n",
            encoding="utf-8",
        )
        from mizan.analyzer import analyze_repository

        fired = [
            f for f in analyze_repository(str(twin_repo))["findings"]
            if f["rule"] == "hardcoded-tmp-path"
            and f["file"] == "dup.py"
        ]
        self.assertEqual(len(fired), 2, "the twins must both fire")
        # synthetic twins with IDENTICAL rule+file+content+message: the
        # analyzer's own message is identical here anyway, so this is the
        # exact collision case against the same file.
        twin_a = dict(fired[0], line=2, message="m")
        twin_b = dict(fired[1], line=4, message="m")
        fps = {
            fingerprint(twin_a, root=twin_repo),
            fingerprint(twin_b, root=twin_repo),
        }
        self.assertEqual(
            len(fps), 1,
            "identical rule+file+content+message shares one fingerprint "
            "(measured trade-off: accepting one accepts both)"
        )

    def test_unknown_baseline_schema_refused_loudly(self):
        path = self.work / "bad.json"
        path.write_text(json.dumps({"schema": "mizan-baseline/3"}),
                        encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            load_baseline(path)
        self.assertIn("Unsupported baseline schema", str(ctx.exception))

    def test_v1_baseline_still_loads_and_compares(self):
        """A /1 baseline keeps working on a /2-capable binary."""
        finding = _finding(self.repo)
        doc = save_baseline([finding], path=self.baseline_path)
        self.assertEqual(doc["schema"], "mizan-baseline/1")
        new_findings, known = filter_baseline(
            [finding], load_baseline(self.baseline_path)
        )
        self.assertEqual(known, 1)
        self.assertEqual(new_findings, [])
        report = apply_gate([finding], baseline_path=self.baseline_path)
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["baseline_schema"], "mizan-baseline/1")
        self.assertEqual(report["fingerprint_scheme"], "line-anchored")

    def test_lru_cache_reflects_file_changes_within_a_run(self):
        """The per-file cache must not serve stale lines across edits."""
        finding = _finding(self.repo)
        first = fingerprint(finding, root=self.repo)
        _shift_lines_above_finding(self.repo, 2)
        shifted = _finding(self.repo)
        second = fingerprint(shifted, root=self.repo)
        self.assertEqual(
            first, second,
            "the same content at a moved line keeps its fingerprint "
            "even after the file changed on disk mid-run"
        )


if __name__ == "__main__":
    unittest.main()
