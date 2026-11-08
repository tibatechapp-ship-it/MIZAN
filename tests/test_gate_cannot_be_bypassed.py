"""The triage gate must be UNBYPASSABLE — no flag, no env var, no escape.

docs/REPORT_SECURITY.md hole #1: an auto-report path around the manual
triage gate is a false-positive spam machine. These tests hold the CLI
boundary, not just triage.check():

  1. generate() without a matching --confirm never writes a file;
  2. no --skip/--force/--bypass/no-triage/override flag exists on any
     `mizan report` subcommand (help-text scan + exact option allowlist);
  3. no such flag exists in the report source itself (static scan);
  4. hostile environment variables cannot lower the gate;
  5. a malformed / empty triage file is blocked, loud (exit 2).

show() staying ungated is a DOCUMENTED decision (viewing is not
disclosure) — it is not a bypass and is not asserted here.
"""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REPORT_SRC = REPO / "src" / "mizan" / "report"

BANNED_FLAG = re.compile(
    r"--[A-Za-z0-9_-]*(skip|force|bypass|no[-_]triage|override|emergency)"
    r"[A-Za-z0-9_-]*\b",
    re.IGNORECASE,
)

GENERATE_ALLOWLIST = {
    "--help", "--finding-id", "--confirm", "--triage", "--output",
    "--repo-root", "--repo", "--include-snippet",
}

HIGH_CODE = '''import pickle

def load_state(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
'''


def _mizan(*args, env=None):
    merged = dict(__import__("os").environ)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "mizan.cli", *args],
        capture_output=True, text=True, env=merged,
    )


class GateBypassTests(unittest.TestCase):
    """Every path around the gate must dead-end at exit 2, file-free."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app").mkdir()
        (self.root / "app" / "state.py").write_text(HIGH_CODE,
                                                    encoding="utf-8")
        scan = _mizan("scan", str(self.root), "--format", "json",
                      "--output", str(self.root / "scan.json"))
        assert scan.returncode == 0, scan.stderr
        self.scan_json = self.root / "scan.json"
        data = json.loads(self.scan_json.read_text(encoding="utf-8"))
        high = [f for f in data["findings"]
                if f["rule"] == "unsafe-deserialization"]
        assert high, data["findings"]
        from mizan.report.ids import fingerprint
        self.fid = fingerprint(high[0])
        self.triage = self.root / "triage.json"
        self.triage.write_text(json.dumps({
            "finding_id": self.fid,
            "answers": {
                "exploitable_path": True,
                "default_env_safe": True,
                "nosec_justified": False,
                "test_or_example_only": False,
                "reachable_in_prod": True,
                "external_mitigation": False,
                "affected_version_confirmed": True,
                "local_poc_reproduced": True,
                "authorized_to_disclose": True,
                "contact_verified": True,
            },
        }), encoding="utf-8")
        self.outdir = self.root / "out"
        self.db = self.root / "disclosures.db"

    def tearDown(self):
        self.tmp.cleanup()

    def _generate(self, *extra, env=None):
        return _mizan(
            "report", "generate", str(self.scan_json),
            "--finding-id", self.fid,
            "--confirm", self.fid,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
            env={"MIZAN_REPORT_DB": str(self.db), **(env or {})},
            *extra,
        )

    def _no_files(self):
        written = (list(self.outdir.glob("*")) if self.outdir.exists()
                   else [])
        self.assertEqual(written, [],
                         f"gate bypass wrote files: {written}")

    # -- 1. confirm is mandatory and must match -------------------------

    def test_missing_confirm_argparse_rejects(self):
        result = _mizan(
            "report", "generate", str(self.scan_json),
            "--finding-id", self.fid,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
        )
        self.assertNotEqual(result.returncode, 0)
        self._no_files()

    def test_wrong_confirm_blocked_with_files_clean(self):
        result = _mizan(
            "report", "generate", str(self.scan_json),
            "--finding-id", self.fid,
            "--confirm", "deadbeef" + "0" * 8,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
            env={"MIZAN_REPORT_DB": str(self.db)},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not match", result.stderr)
        self._no_files()

    def test_empty_triage_blocked(self):
        empty = self.root / "empty_triage.json"
        empty.write_text("{}", encoding="utf-8")
        result = _mizan(
            "report", "generate", str(self.scan_json),
            "--finding-id", self.fid,
            "--confirm", self.fid,
            "--triage", str(empty),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
            env={"MIZAN_REPORT_DB": str(self.db)},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("BLOCKED", result.stderr)
        self._no_files()

    def test_valid_gate_passes_control(self):
        """Control: the same harness through the gate DOES produce files.

        Without this control the three negative tests above would be
        vacuous (a broken CLI always exits non-zero).
        """
        result = self._generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        for suffix in ("md", "html", "sarif", "json"):
            self.assertTrue(
                (self.outdir / f"report-{self.fid}.{suffix}").exists(),
                f"missing report-{self.fid}.{suffix}")

    # -- 2. no bypass flag exists on any report subcommand --------------

    def _help_flags(self, *args):
        result = _mizan("report", *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return set(re.findall(r"--[A-Za-z0-9_-]+", result.stdout))

    def test_no_bypass_flag_in_generate_help(self):
        flags = self._help_flags("generate", "--help")
        for flag in flags:
            self.assertIsNone(
                BANNED_FLAG.search(flag),
                f"bypass-shaped flag {flag!r} exists on generate")

    def test_generate_options_are_exactly_the_allowlist(self):
        flags = self._help_flags("generate", "--help")
        self.assertEqual(
            flags, GENERATE_ALLOWLIST,
            "generate gained/lost flags — the allowlist in "
            "tests/test_gate_cannot_be_bypassed.py must be updated "
            "consciously, never silently")

    def test_no_bypass_flag_anywhere_in_report_help(self):
        for sub in ([], ["generate"], ["show"], ["overdue"], ["export"]):
            result = _mizan("report", *sub, "--help")
            self.assertIsNone(
                BANNED_FLAG.search(result.stdout),
                f"bypass-shaped flag in report {' '.join(sub) or '(root)'} "
                f"help:\n{result.stdout}")
            self.assertIsNone(
                BANNED_FLAG.search(result.stderr),
                f"bypass-shaped flag in report {' '.join(sub) or '(root)'} "
                f"stderr")

    # -- 3. no bypass symbol in the report source ------------------------

    def test_no_bypass_argument_in_report_source(self):
        offenders = []
        for path in REPORT_SRC.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if "add_argument" in line and BANNED_FLAG.search(line):
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
                if re.search(
                        r"\b(skip_triage|no_triage|force_generate|"
                        r"bypass_gate)\b", line):
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(offenders, [],
                         "bypass-shaped symbols in report source:\n"
                         + "\n".join(offenders))

    # -- 4. hostile environment cannot lower the gate --------------------

    def test_hostile_env_cannot_skip_gate(self):
        for hostile in ({"MIZAN_SKIP_TRIAGE": "1"},
                        {"MIZAN_FORCE": "1"},
                        {"MIZAN_BYPASS_GATE": "yes"},
                        {"MIZAN_REPORT_NO_GATE": "1"},
                        {"MIZAN_EMERGENCY": "1"}):
            result = _mizan(
                "report", "generate", str(self.scan_json),
                "--finding-id", self.fid,
                "--confirm", "not-the-id",
                "--triage", str(self.triage),
                "--output", str(self.outdir),
                "--repo-root", str(self.root),
                env={"MIZAN_REPORT_DB": str(self.db), **hostile},
            )
            self.assertEqual(
                result.returncode, 2,
                f"env {hostile} lowered the gate")
            self.assertIn("does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
