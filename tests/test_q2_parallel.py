"""Q2 wave tests (v0.8.0): parallel full-scan + baseline CLI command.

BM-114..BM-118 — MIZAN Security speed wave (deterministic parallelism).
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_project(root):
    """Small deterministic tree inside a real git repo (git/ci scanners
    require one) with mixed languages and a manifest."""
    os.makedirs(os.path.join(root, "pkg"), exist_ok=True)
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as fh:
        fh.write('import os\n\n\ndef run(cmd):\n    return eval(cmd)\n')
    with open(os.path.join(root, "pkg", "util.py"), "w",
              encoding="utf-8") as fh:
        fh.write('def add(a, b):\n    return a + b\n')
    with open(os.path.join(root, "requirements.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("requests==2.0.0\n")
    with open(os.path.join(root, "TODO.md"), "w", encoding="utf-8") as fh:
        fh.write("# TODO: harden\n")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, env=env)
    subprocess.run(
        ["git", "commit", "-q", "--allow-empty", "-m", "init"],
        cwd=root, check=True, env=env,
    )
    return root


class TestParallelFullScan(unittest.TestCase):
    """BM-114..BM-117: thread-parallel scanners stay deterministic."""

    def setUp(self):
        self.tmp = _make_project(tempfile.mkdtemp())
        from mizan.cli import full_scan_repository
        self._full_scan = full_scan_repository

    def test_bm_114_jobs1_and_jobs4_produce_identical_results(self):
        """BM-114: parallel (jobs=4) ≡ sequential (jobs=1) result payload."""
        seq = self._full_scan(self.tmp, jobs=1)
        par = self._full_scan(self.tmp, jobs=4)
        seq.pop("execution"), par.pop("execution")
        self.assertEqual(seq, par)

    def test_bm_115_execution_block_records_jobs_and_wall_time(self):
        """BM-115: report embeds execution {jobs, wall_seconds>=0}."""
        seq = self._full_scan(self.tmp, jobs=1)
        par = self._full_scan(self.tmp, jobs=4)
        self.assertEqual(seq["execution"]["jobs"], 1)
        self.assertEqual(par["execution"]["jobs"], 4)
        for doc in (seq, par):
            wall = doc["execution"]["wall_seconds"]
            self.assertIsInstance(wall, float)
            self.assertGreaterEqual(wall, 0.0)

    def test_bm_116_all_seven_sections_present_when_parallel(self):
        """BM-116: parallel run still returns every scanner section."""
        doc = self._full_scan(self.tmp, jobs=4)
        for section in ("analysis", "detection", "scanner", "git", "ci",
                        "dependencies", "change_risk"):
            self.assertIn(section, doc)

    def test_bm_117_high_findings_survive_parallel_aggregation(self):
        """BM-117: the eval() high finding is found identically in both modes."""
        seq = self._full_scan(self.tmp, jobs=1)
        par = self._full_scan(self.tmp, jobs=4)
        for doc in (seq, par):
            rules = {f["rule"] for f in doc["analysis"]["findings"]}
            self.assertIn("dynamic-execution", rules)


class TestBaselineCLI(unittest.TestCase):
    """BM-118: `mizan baseline` command persists a usable baseline file."""

    def test_bm_118_baseline_command_saves_fingerprints(self):
        """BM-118: CLI baseline --save writes mizan-baseline/1 doc."""
        from mizan.cli import main as cli_main
        from mizan.gate import load_baseline
        root = _make_project(tempfile.mkdtemp())
        target = os.path.join(root, ".mizan", "baseline.json")

        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "baseline", root, "--save", target,
                        "--note", "q2 dogfood"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli_main()
        finally:
            sys.argv = old_argv

        doc = load_baseline(target)
        self.assertEqual(doc["schema"], "mizan-baseline/1")
        self.assertEqual(doc["note"], "q2 dogfood")
        self.assertGreater(doc["count"], 0)

        summary = json.loads(out.getvalue())
        self.assertEqual(summary["tool"], "MIZAN Security")
        self.assertEqual(summary["fingerprints"], doc["count"])


if __name__ == "__main__":
    unittest.main()
