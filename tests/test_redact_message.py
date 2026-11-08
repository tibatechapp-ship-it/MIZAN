"""P1 gap #2 — redact() must hit EVERY text field, message included.

`report show` and `report generate` previously could carry a raw token
inside a finding's `message` (e.g. a hardcoded-secret-candidate message
quoting the value). redact_finding() already walks every string field;
these tests pin the PIPELINE guarantee the requirement asks for:

  * message bearing a GitHub token / AWS key / generic assignment is
    [REDACTED] in every output form (markdown, html, sarif, json) and
    on disk after the CLI's post-write re-verification;
  * the file field is redacted too (paths can leak material);
  * rule is a stable constant — never mangled by redaction;
  * layer 3 (scan_text_for_secrets on the written file) accepts the
    redacted output — redaction succeeded, no fail-loud deletion.

Secret literals here are assembled at RUNTIME (project convention,
docs/REPORT_SECURITY.md #5): no secret-shaped literal ships in source.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mizan.report.generator import generate
from mizan.report.ids import fingerprint
from mizan.report.redact import redact_finding

GHP = "ghp_" + "aB3" * 12              # 36 token chars, never a real one
AKIA = "AKIA" + "Q2W8E5R9" * 2         # AWS-access-key shaped


def _secret_message_finding():
    return {
        "file": "app/client.py",
        "line": 12,
        "rule": "hardcoded-secret-candidate",
        "severity": "high",
        "message": (f"Possible hardcoded credential: token {GHP} "
                    f"and access key {AKIA} in source."),
    }


class MessageRedactionPipelineTests(unittest.TestCase):

    def setUp(self):
        self.raw = _secret_message_finding()

    def _payload(self, finding):
        return generate(finding, repo="demo", contact={})

    def test_message_tokens_survive_nowhere_in_payload(self):
        payload = self._payload(self.raw)
        dumped = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(GHP, dumped)
        self.assertNotIn(AKIA, dumped)

    def test_message_redacted_in_every_form(self):
        payload = self._payload(self.raw)
        self.assertIn("[REDACTED-GITHUB-TOKEN]", payload["markdown"])
        self.assertIn("[REDACTED-AWS-ACCESS-KEY]", payload["markdown"])
        self.assertIn("[REDACTED-GITHUB-TOKEN]", payload["html"])
        sarif_text = json.dumps(payload["sarif"], ensure_ascii=False)
        self.assertNotIn(GHP, sarif_text)
        self.assertIn("[REDACTED", sarif_text)

    def test_file_field_is_redacted_too(self):
        finding = dict(self.raw)
        finding["file"] = 'logs/token="s3cr3t_value9"/client.py'
        payload = self._payload(finding)
        dumped = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("s3cr3t_value9", dumped)
        self.assertIn("[REDACTED]", payload["markdown"])

    def test_rule_field_never_mangled(self):
        payload = self._payload(self.raw)
        self.assertEqual(payload["finding"]["rule"],
                         "hardcoded-secret-candidate")

    def test_show_cli_redacts_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan = root / "scan.json"
            scan.write_text(json.dumps({"findings": [self.raw]}),
                            encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "mizan.cli", "report", "show",
                 str(scan), "--finding-id", fingerprint(self.raw)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(GHP, result.stdout)
            self.assertNotIn(AKIA, result.stdout)
            shown = json.loads(result.stdout)
            self.assertIn("[REDACTED", shown["message"])

    def test_cli_write_survives_layer3_when_redaction_succeeded(self):
        """End-to-end: secret-bearing message -> generate -> 4 files kept.

        Layer 3 re-reads every written file; if redaction missed, it
        deletes and exits 2. Green here means the on-disk bytes are
        secret-free — the whole three-layer chain held.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan = root / "scan.json"
            scan.write_text(json.dumps({"findings": [self.raw]}),
                            encoding="utf-8")
            fid = fingerprint(self.raw)
            triage = root / "triage.json"
            triage.write_text(json.dumps({
                "finding_id": fid,
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
            outdir = root / "out"
            result = subprocess.run(
                [sys.executable, "-m", "mizan.cli", "report", "generate",
                 str(scan), "--finding-id", fid, "--confirm", fid,
                 "--triage", str(triage), "--output", str(outdir),
                 "--repo-root", str(root)],
                capture_output=True, text=True,
                env={**os.environ, "MIZAN_REPORT_DB": str(root / "db.sqlite")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            md = (outdir / f"report-{fid}.md").read_text(encoding="utf-8")
            self.assertNotIn(GHP, md)
            self.assertIn("[REDACTED-GITHUB-TOKEN]", md)


class GenericAssignmentMessageTests(unittest.TestCase):

    def test_password_assignment_in_message_redacted(self):
        finding = {
            "file": "a.py", "line": 1, "rule": "quality",
            "severity": "low",
            "message": 'leaked line: password = "hunter2hunter2"',
        }
        out = redact_finding(finding)
        self.assertNotIn("hunter2hunter2", out["message"])
        self.assertIn("[REDACTED]", out["message"])

    def test_env_var_names_untouched(self):
        finding = {
            "file": "a.py", "line": 1, "rule": "quality",
            "severity": "low",
            "message": "read DB_PASSWORD from os.environ",
        }
        out = redact_finding(finding)
        self.assertEqual(out["message"],
                         "read DB_PASSWORD from os.environ")


if __name__ == "__main__":
    unittest.main()
