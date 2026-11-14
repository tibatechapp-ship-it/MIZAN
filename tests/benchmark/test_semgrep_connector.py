"""Contract tests for the optional Semgrep run connector (Wave 2).

The measured contracts, straight from the plan (v0.15.0, rules 2 & 4):

* a missing tool is INCOMPLETE, never a silent clean;
* a crashing / hanging / lying tool is INCOMPLETE with the reason and
  the path — the flaw #1 (`except Exception → return True, []`) stays
  dead;
* a produced SARIF passes through the Wave-0 import contract with the
  source preserved verbatim (`source.tool`, `tool_level` unmapped);
* a version mismatch is recorded, not normalized away;
* the connector never writes inside the scanned target.

Every external interaction here uses throwaway fake binaries — no
network, no installed Semgrep, fully deterministic.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mizan.integrations.semgrep_connector import (
    SEMGREP_REFERENCE_VERSION,
    run_semgrep,
)

CANNED_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep OSS",
                    "semanticVersion": "1.185.0",
                }
            },
            "results": [
                {
                    "ruleId": "local-eval-call",
                    "level": "warning",
                    "message": {"text": "measured canned finding"},
                    "properties": {"severity": "NOTE"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "sample_eval.py"
                                },
                                "region": {"startLine": 3},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


class _FakeTool:
    """Build a fake `semgrep` binary with scripted behaviors."""

    def __init__(self, directory: Path, version: str = "1.185.0"):
        self.directory = directory
        self.version = version
        self.path = directory / "fakesemgrep"

    def write(
        self,
        *,
        exit_code: int = 0,
        version_stdout: str | None = None,
        report: dict | None = None,
        report_bytes: bytes | None = None,
        sleep: int = 0,
        stderr: str = "",
    ) -> str:
        version_line = (
            version_stdout
            if version_stdout is not None
            else f"{self.version}\n"
        )
        body = f"cat <<'FV'\n{version_line}FV\n"
        if sleep:
            # exec: the kill at the connector's timeout must reach the
            # sleeping process itself, or the inherited pipe keeps the
            # run hanging for the full sleep duration. Gated on scan so
            # the version probe still returns fast.
            body += f"if [ \"$1\" = scan ]; then exec sleep {sleep}; fi\n"
        wants_report = report is not None or report_bytes is not None
        if wants_report:
            # argv layout: $0=binary $1=scan $2=--config $3=CFG
            #              $4=--sarif $5=--output $6=OUT $7=TARGET
            body += "OUT=\"$6\"\n"
            if report_bytes is not None:
                script = (
                    "printf '%s' \""
                    + report_bytes.decode("utf-8", "replace")
                    + "\" > \"$OUT\"\n"
                )
            elif report is not None:
                script = (
                    "cat > \"$OUT\" <<'SAR'\n"
                    + json.dumps(report)
                    + "\nSAR\n"
                )
            else:
                script = ":"
            body += f"if [ \"$1\" = scan ]; then\n{script}\nfi\n"
        if stderr:
            body += f"cat <<'SE' >&2\n{stderr}\nSE\n"
        body += f"exit {exit_code}\n"
        self.path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        self.path.chmod(0o755)
        return str(self.path)


class SemgrepConnectorContractTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.target = self.work / "target"
        self.target.mkdir()
        (self.target / "sample_eval.py").write_text(
            "user_input = input()\neval(user_input)\n", encoding="utf-8"
        )
        self.config = self.work / "local_rules.yaml"
        self.config.write_text("rules: []\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, binary=None, **kwargs):
        return run_semgrep(
            self.target, self.config, binary=binary, **kwargs
        )

    def test_missing_tool_is_incomplete_never_clean(self):
        with mock.patch(
            "mizan.integrations.semgrep_connector.shutil.which",
            return_value=None,
        ):
            run = self._run()
        self.assertEqual(run["status"], "incomplete")
        self.assertEqual(run["reason"], "tool-missing")
        self.assertIn("never installs", run["detail"])
        self.assertNotIn("import", run)

    def test_success_path_passes_through_wave0_contract(self):
        fake = _FakeTool(self.work / "bin_ok")
        (self.work / "bin_ok").mkdir()
        binary = fake.write(report=CANNED_SARIF)
        run = self._run(binary=binary)
        self.assertEqual(run["status"], "complete", run)
        self.assertEqual(run["tool"], "semgrep")
        self.assertEqual(run["tool_version"], SEMGREP_REFERENCE_VERSION)
        self.assertTrue(run["version_match"])
        imported = run["import"]
        self.assertEqual(imported["schema"], "mizan.import.v1")
        self.assertEqual(imported["count"], 1)
        self.assertIn("Semgrep OSS", imported["tools"])
        finding = imported["findings"][0]
        self.assertEqual(finding["schema"], "mizan.finding.v1")
        # Source preserved verbatim; SARIF level NOT mapped silently.
        self.assertEqual(finding["source"]["tool"], "Semgrep OSS")
        self.assertEqual(finding["source"]["rule_id"], "local-eval-call")
        self.assertEqual(finding["tool_level"], "warning")
        self.assertEqual(finding["severity"], "NOTE")
        self.assertEqual(finding["location"]["file"], "sample_eval.py")
        self.assertEqual(finding["location"]["line"], 3)
        self.assertEqual(finding["triage"], "unreviewed")

    def test_crashing_tool_is_incomplete_with_reason(self):
        fake = _FakeTool(self.work / "bin_crash")
        (self.work / "bin_crash").mkdir()
        binary = fake.write(exit_code=3, stderr="boom: rule engine died")
        run = self._run(binary=binary)
        self.assertEqual(run["status"], "incomplete")
        self.assertEqual(run["reason"], "tool-exit-3")
        self.assertIn(str(self.target), run["detail"])
        self.assertIn("boom", run["detail"])

    def test_hanging_tool_times_out_to_incomplete(self):
        fake = _FakeTool(self.work / "bin_hang")
        (self.work / "bin_hang").mkdir()
        binary = fake.write(sleep=30)
        run = self._run(binary=binary, timeout=2)
        self.assertEqual(run["status"], "incomplete")
        self.assertEqual(run["reason"], "tool-timeout")
        self.assertIn("2s", run["detail"])

    def test_garbage_report_is_incomplete_not_clean(self):
        fake = _FakeTool(self.work / "bin_garbage")
        (self.work / "bin_garbage").mkdir()
        binary = fake.write(
            report_bytes=b"{ not json at all",
            version_stdout="1.185.0\n",
        )
        run = self._run(binary=binary)
        self.assertEqual(run["status"], "incomplete")
        self.assertEqual(run["reason"], "report-invalid")
        self.assertIn("rejected by the import contract", run["detail"])

    def test_zero_exit_without_report_is_incomplete(self):
        fake = _FakeTool(self.work / "bin_silent")
        (self.work / "bin_silent").mkdir()
        binary = fake.write()
        run = self._run(binary=binary)
        self.assertEqual(run["status"], "incomplete")
        self.assertEqual(run["reason"], "report-missing")
        self.assertIn("no SARIF report", run["detail"])

    def test_version_mismatch_is_recorded_not_normalized(self):
        fake = _FakeTool(self.work / "bin_newver")
        (self.work / "bin_newver").mkdir()
        binary = fake.write(version_stdout="9.9.9\n", report=CANNED_SARIF)
        run = self._run(binary=binary)
        self.assertEqual(run["status"], "complete")
        self.assertEqual(run["tool_version"], "9.9.9")
        self.assertFalse(run["version_match"])
        self.assertEqual(
            run["reference_version"], SEMGREP_REFERENCE_VERSION
        )

    def test_version_probe_failure_is_incomplete(self):
        fake = _FakeTool(self.work / "bin_nover")
        (self.work / "bin_nover").mkdir()
        binary = fake.write(version_stdout="", report=CANNED_SARIF)
        run = self._run(binary=binary)
        self.assertEqual(run["status"], "incomplete")
        self.assertEqual(run["reason"], "version-check-failed")

    def test_connector_never_writes_inside_target(self):
        fake = _FakeTool(self.work / "bin_ok2")
        (self.work / "bin_ok2").mkdir()
        binary = fake.write(report=CANNED_SARIF)
        run = self._run(binary=binary)  # output_path=None → connector owns it
        self.assertEqual(run["status"], "complete", run)
        self.assertNotIn(
            str(self.target), run["sarif_path"],
            "connector must not write reports into the scanned tree",
        )

    def test_explicit_output_path_is_respected(self):
        fake = _FakeTool(self.work / "bin_ok3")
        (self.work / "bin_ok3").mkdir()
        binary = fake.write(report=CANNED_SARIF)
        out = self.work / "reports" / "run.sarif"
        run = self._run(binary=binary, output_path=out)
        self.assertEqual(run["status"], "complete", run)
        self.assertEqual(Path(run["sarif_path"]), out)
        self.assertTrue(out.is_file())


if __name__ == "__main__":
    unittest.main()
