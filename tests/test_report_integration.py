"""P1 gap #3 — FULL workflow integration: scan -> generate -> show -> overdue.

`mizan report` was shipped with 34 unit tests, but `mizan scan` itself
was never exercised by a report test: nothing proved the two commands
snap together on real artifacts. This suite runs the REAL CLI (subprocess)
end to end against a fixture repository:

    1. mizan scan  -> findings.json (real analyzer output)
    2. generate on the LOW finding  -> exit 2 (gate holds end to end)
    3. generate on the HIGH finding -> exit 0, four files, real contact
    4. show  -> redacted JSON, snippet-free, exit 0
    5. overdue -> empty now; deadline rolled back 91 days -> reported
    6. export -> SARIF carrying the tracked draft

Everything runs under MIZAN_REPORT_DB pointing INTO the temp dir — the
developer's real ~/.mizan/disclosures.db is never touched.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mizan.report.ids import fingerprint

HIGH_CODE = '''import pickle

def load_state(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
'''

LOW_CODE = '''import requests

def ping(url):
    return requests.get(url)
'''


class ReportIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app").mkdir()
        (self.root / "SECURITY.md").write_text(
            "Report to acme-security@example.com\n", encoding="utf-8")
        (self.root / "app" / "state.py").write_text(HIGH_CODE,
                                                    encoding="utf-8")
        (self.root / "app" / "ping.py").write_text(LOW_CODE,
                                                   encoding="utf-8")
        self.db = self.root / "disclosures.db"
        self.env = {**os.environ, "MIZAN_REPORT_DB": str(self.db)}

        scan = subprocess.run(
            [sys.executable, "-m", "mizan.cli", "scan", str(self.root),
             "--format", "json", "--output", str(self.root / "scan.json")],
            capture_output=True, text=True, env=self.env,
        )
        self.assertEqual(scan.returncode, 0, scan.stderr)
        self.scan_json = self.root / "scan.json"

        data = json.loads(self.scan_json.read_text(encoding="utf-8"))
        self.high = next(f for f in data["findings"]
                         if f["rule"] == "unsafe-deserialization")
        self.low = next(f for f in data["findings"]
                        if f["rule"] == "request-without-timeout")
        self.high_id = fingerprint(self.high)
        self.low_id = fingerprint(self.low)

        self.triage = self.root / "triage.json"
        self.triage.write_text(json.dumps({
            "finding_id": self.high_id,
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

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "mizan.cli", "report", *args],
            capture_output=True, text=True, env=self.env,
        )

    # -- 1. scan ---------------------------------------------------------

    def test_step1_scan_json_feeds_report_loader(self):
        """The real `mizan scan` shape loads through report/_load_findings."""
        from mizan.report.cli import _load_findings
        loaded = _load_findings(str(self.scan_json))
        rules = {f["rule"] for f in loaded}
        self.assertIn("unsafe-deserialization", rules)
        self.assertIn("request-without-timeout", rules)

    # -- 2. gate holds end to end ---------------------------------------

    def test_step2_gate_blocks_low_finding_via_cli(self):
        result = self._report(
            "generate", str(self.scan_json),
            "--finding-id", self.low_id,
            "--confirm", self.low_id,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("not report-eligible", result.stderr)
        self.assertFalse(self.outdir.exists()
                         and list(self.outdir.glob("*")))

    def test_step2b_wrong_confirm_still_blocked_via_cli(self):
        result = self._report(
            "generate", str(self.scan_json),
            "--finding-id", self.high_id,
            "--confirm", "0" * 16,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
        )
        self.assertEqual(result.returncode, 2)

    # -- 3. generate ------------------------------------------------------

    def test_step3_generate_writes_four_files_with_real_contact(self):
        result = self._report(
            "generate", str(self.scan_json),
            "--finding-id", self.high_id,
            "--confirm", self.high_id,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for suffix in ("md", "html", "sarif", "json"):
            path = self.outdir / f"report-{self.high_id}.{suffix}"
            self.assertTrue(path.exists(), f"missing {path.name}")
            self.assertGreater(path.stat().st_size, 0, f"empty {path.name}")
        md = (self.outdir / f"report-{self.high_id}.md").read_text(
            encoding="utf-8")
        self.assertIn("acme-security@example.com", md)   # real SECURITY.md
        self.assertIn("unsafe-deserialization", md)
        self.assertIn("DRAFT", md)

    # -- 4. show ----------------------------------------------------------

    def test_step4_show_is_snippet_free_and_redacted(self):
        result = self._report("show", str(self.scan_json),
                              "--finding-id", self.high_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        shown = json.loads(result.stdout)
        self.assertNotIn("snippet", shown)
        self.assertEqual(shown["rule"], "unsafe-deserialization")

    # -- 5. overdue --------------------------------------------------------

    def test_step5_overdue_empty_then_reported_after_91_days(self):
        fresh = self._report("overdue")
        self.assertEqual(fresh.returncode, 0)
        self.assertIn("no overdue", fresh.stdout)

        # a draft must EXIST first — the clock starts at generation
        gen = self._report(
            "generate", str(self.scan_json),
            "--finding-id", self.high_id,
            "--confirm", self.high_id,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
        )
        self.assertEqual(gen.returncode, 0, gen.stderr)

        still = self._report("overdue")
        self.assertIn("no overdue", still.stdout)

        # simulate 91 days: roll the deadline back
        past = (datetime.now(timezone.utc)
                - timedelta(days=91)).isoformat()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE disclosures SET deadline = ?", (past,))

        late = self._report("overdue")
        self.assertEqual(late.returncode, 0)
        self.assertNotIn("no overdue", late.stdout)
        self.assertIn(self.high_id, late.stdout)
        self.assertIn(self.root.name, late.stdout)

    # -- 6. export ----------------------------------------------------------

    def test_step6_export_emits_sarif_after_generate(self):
        gen = self._report(
            "generate", str(self.scan_json),
            "--finding-id", self.high_id,
            "--confirm", self.high_id,
            "--triage", str(self.triage),
            "--output", str(self.outdir),
            "--repo-root", str(self.root),
        )
        self.assertEqual(gen.returncode, 0, gen.stderr)
        sarif_path = self.root / "tracked.sarif"
        result = self._report("export", "--output", str(sarif_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        self.assertIn("unsafe-deserialization", rule_ids)


if __name__ == "__main__":
    unittest.main()
