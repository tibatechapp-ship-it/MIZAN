"""Wave-0 SARIF import contract — docs/DEV_PLAN_V0150.md.

Positive tests pin provenance preservation (tool, rule, location, level,
fingerprint, triage). Negative tests pin the no-silent-clean guarantee:
a missing/invalid report raises with the path in the message instead of
returning an empty result set, and the CLI exits 2 (incomplete) rather
than certifying a clean import.
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mizan.cli import main
from mizan.integrations.sarif_import import (
    FINDING_SCHEMA,
    SarifImportError,
    import_sarif_report,
    normalize_sarif,
)


def valid_report(tool="Semgrep", rule="python.lang.security", **overrides):
    result = {
        "ruleId": rule,
        "level": "error",
        "message": {"text": "example finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 12},
                }
            }
        ],
        "properties": {"severity": "high"},
    }
    result.update(overrides.get("result", {}))
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "rules": [{"id": rule}]}},
                "results": [result],
            }
        ],
    }
    doc.update(overrides.get("doc", {}))
    return doc


class SarifImportProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, doc, name="report.sarif"):
        path = self.root / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_valid_report_preserves_provenance(self):
        path = self._write(valid_report())
        findings = normalize_sarif(path)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["schema"], FINDING_SCHEMA)
        self.assertEqual(finding["source"]["tool"], "Semgrep")
        self.assertEqual(
            finding["source"]["rule_id"], "python.lang.security"
        )
        self.assertEqual(finding["location"]["file"], "app.py")
        self.assertEqual(finding["location"]["line"], 12)
        self.assertEqual(finding["message"], "example finding")
        self.assertEqual(finding["tool_level"], "error")
        self.assertEqual(finding["triage"], "unreviewed")
        self.assertEqual(finding["evidence"]["kind"], "external-sarif")
        self.assertEqual(finding["evidence"]["report"], "report.sarif")

    def test_partial_fingerprint_preferred_over_fallback(self):
        path = self._write(
            valid_report(
                result={
                    "partialFingerprints": {
                        "primaryLocationLineHash": "abc123"
                    }
                }
            )
        )
        findings = normalize_sarif(path)
        self.assertEqual(findings[0]["fingerprint"], "abc123")

    def test_fingerprint_fallback_is_stable_sha256(self):
        path = self._write(valid_report())
        first = normalize_sarif(path)[0]["fingerprint"]
        second = normalize_sarif(path)[0]["fingerprint"]
        self.assertTrue(first.startswith("sha256:"))
        self.assertEqual(first, second)

    def test_multiple_runs_keep_each_tool_and_results(self):
        doc = valid_report()
        second_run = {
            "tool": {"driver": {"name": "Gitleaks"}},
            "results": [
                {
                    "ruleId": "generic-api-key",
                    "message": {"text": "secret candidate"},
                    "level": "warning",
                }
            ],
        }
        doc["runs"].append(second_run)
        path = self._write(doc)
        findings = normalize_sarif(path)
        tools = {f["source"]["tool"] for f in findings}
        self.assertEqual(tools, {"Semgrep", "Gitleaks"})
        self.assertEqual(len(findings), 2)
        gitleaks = [
            f
            for f in findings
            if f["source"]["tool"] == "Gitleaks"
        ][0]
        self.assertEqual(gitleaks["tool_level"], "warning")

    def test_zero_result_run_still_lists_tool(self):
        doc = valid_report()
        doc["runs"].append(
            {"tool": {"driver": {"name": "Trivy"}}, "results": []}
        )
        path = self._write(doc)
        summary = import_sarif_report(path)
        self.assertEqual(summary["tools"], ["Semgrep", "Trivy"])
        self.assertEqual(summary["count"], 1)


class SarifNoSilentSeverityMappingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, doc):
        path = self.root / "report.sarif"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_sarif_level_is_never_mapped_to_severity(self):
        path = self._write(
            valid_report(result={"level": "note", "properties": {}})
        )
        finding = normalize_sarif(path)[0]
        self.assertEqual(finding["tool_level"], "note")
        self.assertEqual(finding["severity"], "unknown")

    def test_properties_severity_carried_verbatim(self):
        path = self._write(
            valid_report(result={"properties": {"severity": "custom-high"}})
        )
        finding = normalize_sarif(path)[0]
        # Verbatim: no normalization to a fixed severity ladder here.
        self.assertEqual(finding["severity"], "custom-high")


class SarifStrictValidationTests(unittest.TestCase):
    """Every rejection path fails loudly with the path in the message."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, doc, name="report.sarif"):
        path = self.root / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def _assert_rejected(self, path, fragment):
        with self.assertRaises(SarifImportError) as ctx:
            normalize_sarif(path)
        self.assertIn(str(path), str(ctx.exception))
        self.assertIn(fragment, str(ctx.exception))

    def test_missing_report_raises_with_path(self):
        missing = self.root / "missing.sarif"
        self._assert_rejected(missing, "not found")

    def test_invalid_json_raises(self):
        path = self.root / "broken.sarif"
        path.write_text("{not json", encoding="utf-8")
        self._assert_rejected(path, "Cannot read")

    def test_root_not_object_raises(self):
        path = self.root / "list.sarif"
        path.write_text("[]", encoding="utf-8")
        self._assert_rejected(path, "root must be an object")

    def test_wrong_version_raises(self):
        self._assert_rejected(
            self._write({"version": "1.0.0", "runs": []}),
            "Unsupported SARIF version",
        )

    def test_empty_runs_raises(self):
        self._assert_rejected(
            self._write({"version": "2.1.0", "runs": []}),
            "contains no runs",
        )

    def test_missing_runs_key_raises(self):
        self._assert_rejected(
            self._write({"version": "2.1.0"}), "contains no runs"
        )

    def test_missing_driver_name_raises(self):
        self._assert_rejected(
            self._write({"version": "2.1.0", "runs": [{"results": []}]}),
            "tool.driver.name",
        )

    def test_results_not_list_raises(self):
        doc = valid_report()
        doc["runs"][0]["results"] = {"ruleId": "x"}
        self._assert_rejected(self._write(doc), "must be a list")

    def test_non_dict_result_raises_not_skipped(self):
        doc = valid_report()
        doc["runs"][0]["results"].append("drifted entry")
        self._assert_rejected(self._write(doc), "is not an")


class SarifImportSummaryTests(unittest.TestCase):
    def test_import_summary_shape_and_scan_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "semgrep.sarif"
            path.write_text(json.dumps(valid_report()), encoding="utf-8")
            summary = import_sarif_report(path)
            self.assertEqual(summary["schema"], "mizan.import.v1")
            self.assertEqual(summary["report"], "semgrep.sarif")
            self.assertEqual(summary["tools"], ["Semgrep"])
            self.assertEqual(summary["count"], 1)
            self.assertIs(summary["scan_complete"], True)
            self.assertEqual(len(summary["findings"]), 1)


class SarifImportCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, doc):
        path = self.root / "report.sarif"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_cli_import_prints_summary(self):
        path = self._write(valid_report())
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["import-sarif", str(path)])
        self.assertEqual(code, 0)
        summary = json.loads(buffer.getvalue())
        self.assertEqual(summary["schema"], "mizan.import.v1")
        self.assertEqual(summary["count"], 1)
        self.assertEqual(summary["tools"], ["Semgrep"])

    def test_cli_missing_report_exits_incomplete(self):
        missing = self.root / "missing.sarif"
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(stderr):
                main(["import-sarif", str(missing)])
        # Exit contract: 2 = incomplete — a failed import is never a
        # clean pass, and the path reaches the operator via stderr.
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("missing.sarif", stderr.getvalue())

    def test_cli_output_flag_writes_file(self):
        path = self._write(valid_report())
        out = self.root / "normalized.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(
                ["import-sarif", str(path), "--output", str(out)]
            )
        self.assertEqual(code, 0)
        self.assertIn(
            "Report saved", buffer.getvalue()
        )  # house convention of save_or_print
        written = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(written["schema"], "mizan.import.v1")
        self.assertEqual(written["count"], 1)


if __name__ == "__main__":
    unittest.main()
