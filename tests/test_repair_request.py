"""Wave-3 contract tests — the structured repair request.

Acceptance gate from the plan (docs/DEV_PLAN_V0150.md, Wave 3):

* a verified JSON schema is published
  (docs/schemas/repair-request.v1.json) and stays consistent with the
  code validator — required keys and constants must agree both ways;
* the request REFUSES insufficient evidence ("don't guess; explain
  what is needed to verify") — every missing item is named, none is
  invented;
* ``human_review_required`` is exactly true — always;
* ``auto_appliable`` is exactly false — MIZAN proposes review
  suggestions, never auto-edits;
* the batch writer validates before writing and never produces a
  partial batch;
* finding identity: the wave-0 fingerprint (or its documented fallback
  formula) — linkable back through merge/triage.
"""

import json
import tempfile
import unittest
from pathlib import Path

from mizan.integrations.repair_request import (
    REPAIR_SCHEMA,
    RULE_GUIDANCE,
    RepairRequestError,
    build_repair_request,
    finding_id_for,
    validate_repair_request,
    write_repair_requests,
)
from mizan.integrations.sarif_import import _fallback_fingerprint

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "repair-request.v1.json"


def _finding(**overrides):
    finding = {
        "schema": "mizan.finding.v1",
        "source": {"tool": "MIZAN", "rule_id": "dynamic-execution"},
        "location": {"file": "app/core.py", "line": 42},
        "message": "eval() call on parsed user input",
        "tool_level": None,
    }
    finding.update(overrides)
    return finding


class BuildRequestTests(unittest.TestCase):
    def test_complete_finding_builds_valid_request(self):
        request = build_repair_request(_finding())
        validate_repair_request(request)  # must not raise
        self.assertEqual(request["schema"], REPAIR_SCHEMA)
        self.assertTrue(request["human_review_required"])
        self.assertFalse(request["proposed_fix"]["auto_appliable"])
        self.assertEqual(request["confidence"], "high")
        self.assertIn("review-suggestion", request["proposed_fix"]["kind"])
        self.assertTrue(request["proposed_fix"]["summary"])
        self.assertTrue(request["constraints"])
        self.assertTrue(request["verification"])

    def test_candidate_rule_gets_medium_confidence(self):
        request = build_repair_request(
            _finding(
                source={"tool": "MIZAN",
                        "rule_id": "hardcoded-secret-candidate"},
                message="password = \"hardcoded_123\"",
            )
        )
        self.assertEqual(request["confidence"], "medium")

    def test_unknown_external_rule_gets_low_confidence_no_invented_guidance(
        self,
    ):
        request = build_repair_request(
            _finding(
                source={"tool": "Semgrep OSS",
                        "rule_id": "some.external.rule"},
            )
        )
        self.assertEqual(request["confidence"], "low")
        self.assertEqual(
            request["proposed_fix"]["summary"], "",
            "no guidance must be invented for an unknown rule"
        )
        validate_repair_request(request)  # still a valid request

    def test_finding_id_prefers_existing_fingerprint(self):
        request = build_repair_request(_finding(fingerprint="sha256:abc"))
        self.assertEqual(request["finding_id"], "sha256:abc")

    def test_finding_id_fallback_matches_wave0_formula(self):
        request = build_repair_request(_finding())
        expected = _fallback_fingerprint(
            "MIZAN", "dynamic-execution", "app/core.py", 42,
            "eval() call on parsed user input",
        )
        self.assertEqual(request["finding_id"], expected)


class InsufficientEvidenceTests(unittest.TestCase):
    """The refusal IS the feature: name what must be verified."""

    def _assert_refusal_names(self, overrides, *fragments):
        with self.assertRaises(RepairRequestError) as ctx:
            build_repair_request(_finding(**overrides))
        self.assertIn("insufficient evidence", str(ctx.exception))
        self.assertIn("don't guess", str(ctx.exception))
        for fragment in fragments:
            self.assertIn(fragment, str(ctx.exception))

    def test_missing_line_is_refused_and_named(self):
        self._assert_refusal_names(
            {"location": {"file": "app/core.py", "line": None}},
            "location.line",
        )

    def test_missing_file_is_refused_and_named(self):
        self._assert_refusal_names(
            {"location": {"file": "", "line": 42}},
            "location.file",
        )

    def test_missing_rule_is_refused_and_named(self):
        self._assert_refusal_names(
            {"source": {"tool": "MIZAN", "rule_id": ""}},
            "source.rule_id",
        )

    def test_empty_message_is_refused_and_named(self):
        self._assert_refusal_names({"message": ""}, "message")

    def test_missing_tool_is_refused_and_named(self):
        self._assert_refusal_names(
            {"source": {"tool": "", "rule_id": "dynamic-execution"}},
            "source.tool",
        )

    def test_zero_line_is_refused(self):
        self._assert_refusal_names(
            {"location": {"file": "app/core.py", "line": 0}},
            "location.line",
        )

    def test_wrong_schema_marker_is_refused(self):
        with self.assertRaises(RepairRequestError):
            build_repair_request({"schema": "something.else"})


class ValidationTests(unittest.TestCase):
    def _mutated(self, **changes):
        request = build_repair_request(_finding())
        request.update(changes)
        return request

    def test_human_review_required_must_be_true(self):
        for bad in (False, None, "yes"):
            with self.assertRaises(RepairRequestError):
                validate_repair_request(
                    self._mutated(human_review_required=bad)
                )

    def test_auto_appliable_must_be_false(self):
        request = self._mutated(
            proposed_fix={
                "kind": "auto-edit", "auto_appliable": True,
                "summary": "x",
            }
        )
        with self.assertRaises(RepairRequestError):
            validate_repair_request(request)

    def test_confidence_limited_to_levels(self):
        with self.assertRaises(RepairRequestError):
            validate_repair_request(self._mutated(confidence="certain"))

    def test_empty_constraints_refused(self):
        with self.assertRaises(RepairRequestError):
            validate_repair_request(self._mutated(constraints=[]))

    def test_empty_verification_refused(self):
        with self.assertRaises(RepairRequestError):
            validate_repair_request(self._mutated(verification=[]))

    def test_wrong_schema_string_refused(self):
        with self.assertRaises(RepairRequestError):
            validate_repair_request(
                self._mutated(schema="repair-request.v2")
            )


class BatchWriterTests(unittest.TestCase):
    def test_batch_validates_every_request_before_writing(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "handoff" / "requests.json"
            batch = write_repair_requests(
                [_finding(), _finding(line=7)], out
            )
            self.assertEqual(batch["count"], 2)
            self.assertTrue(out.is_file())
            written = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(written["schema"], REPAIR_SCHEMA)
            self.assertEqual(len(written["requests"]), 2)
            for request in written["requests"]:
                validate_repair_request(request)

    def test_one_bad_finding_fails_the_whole_batch(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "requests.json"
            with self.assertRaises(RepairRequestError) as ctx:
                write_repair_requests(
                    [_finding(), _finding(message="")], out
                )
            self.assertIn("finding 1", str(ctx.exception))
            self.assertFalse(
                out.exists(),
                "a partial batch must never be written",
            )

    def test_empty_input_refused(self):
        with self.assertRaises(RepairRequestError):
            write_repair_requests([], None)


class AnalyzerShapeAdapterTests(unittest.TestCase):
    """mizan analyze → repair-request must work without a converter:
    the raw analyzer finding shape adapts 1:1, nothing invented."""

    def test_raw_analyzer_finding_is_adapted(self):
        raw = {
            "file": "app/core.py", "line": 9, "rule": "yaml-unsafe-load",
            "severity": "medium", "message": "yaml.unsafe_load() usage",
        }
        request = build_repair_request(raw)
        validate_repair_request(request)
        self.assertEqual(request["evidence"]["tool"], "MIZAN")
        self.assertEqual(request["evidence"]["rule_id"], "yaml-unsafe-load")
        self.assertEqual(request["evidence"]["line"], 9)
        self.assertEqual(request["evidence"]["tool_level"], "medium")
        self.assertEqual(request["confidence"], "high")

    def test_adapter_refuses_unrecognized_shape(self):
        with self.assertRaises(RepairRequestError) as ctx:
            build_repair_request({"something": "else"})
        self.assertIn("neither shape", str(ctx.exception))

    def test_adapter_still_refuses_missing_evidence(self):
        with self.assertRaises(RepairRequestError) as ctx:
            build_repair_request({"file": "a.py", "rule": "weak-crypto"})
        self.assertIn("location.line", str(ctx.exception))


class CliSmokeTests(unittest.TestCase):
    """Live smoke through the CLI: analyze → repair-request, plus the
    exit-2 refusal contract (mirrors the wave-0/1 smoke discipline)."""

    def _run_cli(self, *args):
        import subprocess
        import sys
        return subprocess.run(
            [sys.executable, "-m", "mizan.cli", *args],
            capture_output=True, text=True, timeout=120, check=False,
        )

    def test_analyze_to_repair_request_pipeline(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            target = ROOT / "tests" / "rules" / "fixtures" / "positive" / (
                "dynamic-execution"
            )
            report = td_path / "findings.json"
            scan = self._run_cli(
                "analyze", str(target), "--output", str(report)
            )
            self.assertEqual(scan.returncode, 0, scan.stderr)
            handoff = td_path / "requests.json"
            build = self._run_cli(
                "repair-request", str(report), "--output", str(handoff)
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertIn("human review required", build.stdout)
            batch = json.loads(handoff.read_text(encoding="utf-8"))
            self.assertEqual(batch["schema"], REPAIR_SCHEMA)
            self.assertGreaterEqual(batch["count"], 1)
            for request in batch["requests"]:
                validate_repair_request(request)

    def test_insufficient_evidence_exits_2_with_named_gap(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as td:
            broken = Path(td) / "missing_line.json"
            finding = {
                "file": "app/core.py", "line": None,
                "rule": "dynamic-execution", "severity": "high",
                "message": "eval() call",
            }
            broken.write_text(json.dumps([finding]), encoding="utf-8")
            result = self._run_cli("repair-request", str(broken))
            self.assertEqual(
                result.returncode, 2,
                "insufficient evidence must exit 2 (incomplete), "
                f"got {result.returncode}",
            )
            self.assertIn("location.line", result.stderr)
            self.assertIn("don't guess", result.stderr)


class SchemaConsistencyTests(unittest.TestCase):
    """The published JSON Schema and the code validator must agree."""

    def _schema(self):
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_schema_file_is_valid_json_with_contract_markers(self):
        schema = self._schema()
        self.assertEqual(schema["properties"]["schema"]["const"],
                         "repair-request.v1")
        self.assertEqual(
            schema["properties"]["human_review_required"]["const"], True
        )
        self.assertEqual(
            schema["properties"]["proposed_fix"]["properties"][
                "auto_appliable"]["const"], False
        )
        self.assertEqual(
            schema["properties"]["confidence"]["enum"],
            ["high", "medium", "low"],
        )

    def test_code_required_keys_are_covered_by_schema(self):
        schema = self._schema()
        required = set(schema["required"])
        sample = build_repair_request(_finding())
        self.assertLessEqual(
            set(sample.keys()), required,
            "the code validator builds fields the published schema "
            "does not require — schemas must not drift from code",
        )

    def test_every_documented_rule_has_guidance_entry(self):
        # RULE_GUIDANCE covers the measured security rules; an entry
        # must exist for every rule the guidance claims to cover.
        self.assertIn("dynamic-execution", RULE_GUIDANCE)
        self.assertIn("hardcoded-secret-candidate", RULE_GUIDANCE)
        self.assertIn("yaml-unsafe-load", RULE_GUIDANCE)


if __name__ == "__main__":
    unittest.main()
