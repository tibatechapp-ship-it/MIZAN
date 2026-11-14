"""Wave-1 merge/triage/external-gate contract — docs/DEV_PLAN_V0150.md.

The wave-1 acceptance gates pinned here:

- Link, never erase: merging groups findings by fingerprint while every
  occurrence keeps its own tool, rule, and evidence; removing one
  report's list can never erase another tool's findings (regression).
- Undocumented suppression is rejected: triage decisions referencing
  fingerprints absent from the findings fail loudly, both at module
  level and at the CLI (exit 2, incomplete).
- The external gate blocks only on the verbatim severity carried from
  the source tool; ``unknown`` never blocks and triaged findings never
  block.
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mizan.cli import main
from mizan.integrations.merge import (
    EXTERNAL_GATE_SCHEMA,
    MERGED_SCHEMA,
    TRIAGE_SCHEMA,
    MergeError,
    apply_triage,
    gate_external_findings,
    merge_findings,
)
from mizan.integrations.sarif_import import FINDING_SCHEMA


def finding(tool="Semgrep", rule="rule.one", file="app.py", line=10,
            severity="high", fingerprint=None, **extra):
    entry = {
        "schema": FINDING_SCHEMA,
        "source": {"tool": tool, "rule_id": rule},
        "location": {"file": file, "line": line},
        "message": "example",
        "tool_level": "error",
        "severity": severity,
        "fingerprint": fingerprint or f"fp-{tool}-{rule}-{file}-{line}",
        "evidence": {"kind": "external-sarif", "report": "r.sarif"},
        "triage": "unreviewed",
    }
    entry.update(extra)
    return entry


class MergeFindingsTests(unittest.TestCase):
    def test_groups_by_fingerprint_and_keeps_everything(self):
        merged = merge_findings(
            [[finding()], [finding(rule="rule.two", line=11)]]
        )
        self.assertEqual(merged["schema"], MERGED_SCHEMA)
        self.assertEqual(merged["count_total"], 2)
        self.assertEqual(merged["count_unique"], 2)
        self.assertEqual(len(merged["groups"]), 2)
        self.assertIs(merged["scan_complete"], True)

    def test_cross_tool_same_fingerprint_links_both_occurrences(self):
        shared = "fp-shared-location"
        merged = merge_findings(
            [
                [finding(tool="Semgrep", fingerprint=shared)],
                [finding(tool="Gitleaks", rule="generic-api-key",
                         fingerprint=shared)],
            ]
        )
        self.assertEqual(merged["count_total"], 2)
        self.assertEqual(merged["count_unique"], 1)
        group = merged["groups"][0]
        tools = [o["source"]["tool"] for o in group["occurrences"]]
        self.assertEqual(tools, ["Semgrep", "Gitleaks"])
        # Every occurrence keeps its own rule evidence — link, not erase.
        self.assertEqual(
            group["occurrences"][1]["source"]["rule_id"],
            "generic-api-key",
        )

    def test_removing_one_report_does_not_erase_other_findings(self):
        """Wave-1 regression gate: deletion of a report is not deletion
        of another tool's evidence."""
        list_a = [finding(tool="Semgrep", rule="rule.a")]
        list_b = [finding(tool="Gitleaks", rule="rule.b")]
        merge_findings([list_a, list_b])  # linked once
        after_loss = merge_findings([list_b])  # report A gone
        self.assertEqual(after_loss["count_total"], 1)
        self.assertEqual(
            after_loss["groups"][0]["occurrences"][0]["source"]["tool"],
            "Gitleaks",
        )
        self.assertEqual(
            after_loss["groups"][0]["occurrences"][0]["source"]["rule_id"],
            "rule.b",
        )

    def test_empty_merge_input_rejected_loudly(self):
        with self.assertRaises(MergeError):
            merge_findings([])

    def test_non_finding_entry_rejected_loudly(self):
        with self.assertRaises(MergeError):
            merge_findings([["not-a-finding"]])

    def test_finding_without_fingerprint_rejected(self):
        broken = finding()
        broken["fingerprint"] = ""
        with self.assertRaises(MergeError):
            merge_findings([[broken]])


class ApplyTriageTests(unittest.TestCase):
    def test_apply_triage_sets_status_and_source(self):
        findings = [finding(), finding(rule="rule.two", line=11)]
        fingerprint = findings[0]["fingerprint"]
        result = apply_triage(findings, {fingerprint: "false_positive"})
        self.assertEqual(result["schema"], TRIAGE_SCHEMA)
        self.assertEqual(result["applied"], 1)
        self.assertEqual(result["decisions"], 1)
        self.assertEqual(findings[0]["triage"], "false_positive")
        self.assertEqual(findings[0]["triage_source"], "review-file")
        self.assertEqual(findings[1]["triage"], "unreviewed")

    def test_triage_unknown_fingerprint_rejected_loudly(self):
        findings = [finding()]
        with self.assertRaises(MergeError) as ctx:
            apply_triage(findings, {"fp-never-imported": "accepted"})
        self.assertIn("fp-never-imported", str(ctx.exception))
        self.assertIn("document the finding", str(ctx.exception))

    def test_triage_invalid_status_rejected(self):
        findings = [finding()]
        with self.assertRaises(MergeError):
            apply_triage(
                findings, {findings[0]["fingerprint"]: "whatever"}
            )

    def test_triage_decisions_must_be_object(self):
        with self.assertRaises(MergeError):
            apply_triage([finding()], ["accepted"])

    def test_triage_allows_only_documented_suppression(self):
        """The no-blind-nosec guarantee: an empty findings list makes
        every decision unknown."""
        with self.assertRaises(MergeError):
            apply_triage([], {"any": "accepted"})


class GateExternalFindingsTests(unittest.TestCase):
    def test_verbatim_severity_match_blocks(self):
        gate = gate_external_findings([finding(severity="high")], ["high"])
        self.assertEqual(gate["schema"], EXTERNAL_GATE_SCHEMA)
        self.assertEqual(gate["verdict"], "fail")
        self.assertEqual(gate["blocking_count"], 1)
        self.assertEqual(gate["blocking_findings"][0]["tool"], "Semgrep")

    def test_unknown_severity_never_blocks(self):
        gate = gate_external_findings(
            [finding(severity="unknown")], ["high", "critical"]
        )
        self.assertEqual(gate["verdict"], "pass")
        self.assertEqual(gate["blocking_count"], 0)
        self.assertEqual(gate["counts"], {"unknown": 1})

    def test_triaged_findings_never_block(self):
        findings = [finding(), finding(rule="rule.two", line=11)]
        apply_triage(
            findings,
            {
                findings[0]["fingerprint"]: "false_positive",
                findings[1]["fingerprint"]: "accepted",
            },
        )
        gate = gate_external_findings(findings, ["high"])
        self.assertEqual(gate["verdict"], "pass")

    def test_verbatim_means_no_case_folding(self):
        gate = gate_external_findings([finding(severity="HIGH")], ["high"])
        self.assertEqual(gate["verdict"], "pass")

    def test_blocking_list_type_rejected(self):
        with self.assertRaises(MergeError):
            gate_external_findings([finding()], "high")

    def test_gate_verdict_pass_with_zero_findings(self):
        gate = gate_external_findings([], ["high"])
        self.assertEqual(gate["verdict"], "pass")


class MergeAndTriageCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _sarif(self, tool="Semgrep", rule="rule.one", name=None,
               fingerprint=None):
        doc = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": tool}},
                    "results": [
                        {
                            "ruleId": rule,
                            "level": "error",
                            "message": {"text": "example"},
                            "properties": {"severity": "high"},
                            "partialFingerprints": {
                                "primaryLocationLineHash": (
                                    fingerprint or f"fp-{tool}-{rule}"
                                )
                            },
                        }
                    ],
                }
            ],
        }
        path = self.root / (name or f"{tool.lower()}.sarif")
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_cli_merge_two_reports_links_and_counts(self):
        a = self._sarif(tool="Semgrep", rule="rule.one")
        b = self._sarif(tool="Gitleaks", rule="generic-api-key")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["merge-findings", str(a), str(b)])
        self.assertEqual(code, 0)
        merged = json.loads(buffer.getvalue())
        self.assertEqual(merged["schema"], MERGED_SCHEMA)
        self.assertEqual(merged["count_total"], 2)
        self.assertEqual(merged["count_unique"], 2)

    def test_cli_merge_missing_report_exits_incomplete(self):
        a = self._sarif()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(stderr):
                main(
                    [
                        "merge-findings",
                        str(a),
                        str(self.root / "gone.sarif"),
                    ]
                )
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("gone.sarif", stderr.getvalue())

    def test_cli_merge_output_flag_writes_file(self):
        a = self._sarif()
        out = self.root / "merged.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(
                ["merge-findings", str(a), "--output", str(out)]
            )
        self.assertEqual(code, 0)
        written = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(written["schema"], MERGED_SCHEMA)
        self.assertEqual(written["count_total"], 1)

    def _import_summary(self, fingerprint="fp-x"):
        return {
            "schema": "mizan.import.v1",
            "report": "report.sarif",
            "tools": ["Semgrep"],
            "count": 1,
            "scan_complete": True,
            "findings": [finding(fingerprint=fingerprint)],
        }

    def test_cli_triage_applies_documented_decision(self):
        findings_path = self.root / "findings.json"
        findings_path.write_text(
            json.dumps(self._import_summary()), encoding="utf-8"
        )
        decisions_path = self.root / "decisions.json"
        decisions_path.write_text(
            json.dumps({"fp-x": "accepted"}), encoding="utf-8"
        )
        out = self.root / "triaged.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(
                [
                    "triage",
                    str(findings_path),
                    "--decisions",
                    str(decisions_path),
                    "--output",
                    str(out),
                ]
            )
        self.assertEqual(code, 0)
        written = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(written["schema"], TRIAGE_SCHEMA)
        self.assertEqual(written["applied"], 1)
        self.assertEqual(
            written["findings"][0]["triage"], "accepted"
        )

    def test_cli_triage_unknown_fingerprint_exits_incomplete(self):
        findings_path = self.root / "findings.json"
        findings_path.write_text(
            json.dumps(self._import_summary()), encoding="utf-8"
        )
        decisions_path = self.root / "decisions.json"
        decisions_path.write_text(
            json.dumps({"fp-ghost": "accepted"}), encoding="utf-8"
        )
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(stderr):
                main(
                    [
                        "triage",
                        str(findings_path),
                        "--decisions",
                        str(decisions_path),
                    ]
                )
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("fp-ghost", stderr.getvalue())

    def test_cli_triage_accepts_merged_summary(self):
        """The natural pipeline: merge-findings output feeds triage."""
        shared = "fp-shared-location"
        a = self._sarif(
            tool="Semgrep", rule="rule.one", fingerprint=shared
        )
        b = self._sarif(
            tool="Gitleaks", rule="generic-api-key", fingerprint=shared
        )
        merged_out = self.root / "merged.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(
                [
                    "merge-findings",
                    str(a),
                    str(b),
                    "--output",
                    str(merged_out),
                ]
            )
        self.assertEqual(code, 0)
        merged = json.loads(merged_out.read_text(encoding="utf-8"))
        fingerprint = merged["groups"][0]["fingerprint"]
        decisions_path = self.root / "decisions.json"
        decisions_path.write_text(
            json.dumps({fingerprint: "accepted"}), encoding="utf-8"
        )
        triaged_out = self.root / "triaged.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(
                [
                    "triage",
                    str(merged_out),
                    "--decisions",
                    str(decisions_path),
                    "--output",
                    str(triaged_out),
                ]
            )
        self.assertEqual(code, 0)
        written = json.loads(triaged_out.read_text(encoding="utf-8"))
        # Both linked occurrences (Semgrep + Gitleaks) are stamped.
        self.assertEqual(written["applied"], 2)
        self.assertEqual(
            written["findings"][0]["triage_source"], "review-file"
        )


if __name__ == "__main__":
    unittest.main()
