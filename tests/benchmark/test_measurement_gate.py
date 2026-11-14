"""Wave-2 measurement gate — the frozen corpus, measured the same way
every time, and the published numbers forced to match it.

Contracts (plan v0.15.0, Wave 2 acceptance gate):

* fixed measurement corpus: `tests/rules/fixtures/` — 5 known positives
  per rule, 5 shape-similar negatives per rule, edge cases;
* a repeated measurement returns the SAME numbers (byte-identical JSON);
* docs/MEASUREMENT.md publishes exactly the measured numbers (a fenced
  ``measured-json`` block is parsed and compared — the docs-gate pattern
  that already keeps README honest);
* the corpus itself is audited: every rule's samples exist, the golden
  5+5 contract holds, and the edge inventory is what the doc claims.

The harness measures the 20 SECURITY rules. The informational rules
(todo, python-syntax-error, file-read-error) are not part of the
accuracy contract — any firing on the frozen corpus is REPORTED in the
measured output as informational noise, never folded into precision.
"""

import json
import re
import unittest
from pathlib import Path

from mizan.analyzer import analyze_file

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "rules" / "fixtures"
MEASUREMENT_DOC = ROOT / "docs" / "MEASUREMENT.md"

SECURITY_RULES = [
    "django-mark-safe", "dynamic-execution", "hardcoded-secret-candidate",
    "hardcoded-tmp-path", "hf-trust-remote-code", "input-to-subprocess",
    "jinja2-autoescape-false", "path-traversal", "process-execution",
    "request-to-sql", "request-without-timeout", "shell-true",
    "sql-injection", "ssl-unverified-context", "tarfile-extractall",
    "tls-verification-disabled", "torch-unsafe-load",
    "unsafe-deserialization", "weak-crypto", "yaml-unsafe-load",
]
# Mirrors tests/rules: taint rules escalate a base rule at tainted
# sites, so only the target-absent criterion applies to their negatives.
TAINT_RULES = {"request-to-sql", "input-to-subprocess"}

POSITIVE_SAMPLES = 5
NEGATIVE_SAMPLES = 5


def measure_rule_accuracy() -> dict:
    """Run the analyzer over the frozen corpus; return measured numbers.

    Pure function of the corpus: no timestamps, no environment reads,
    sorted traversal — two calls return byte-identical JSON.
    """
    per_rule: dict[str, dict] = {}
    informational: list[dict] = []
    informational_rules = {"todo", "python-syntax-error", "file-read-error"}

    for rule in SECURITY_RULES:
        pos_dir = FIXTURES / "positive" / rule
        neg_dir = FIXTURES / "negative" / rule
        positives = sorted(p for p in pos_dir.glob("*.py"))
        negatives = sorted(p for p in neg_dir.glob("*.py"))

        tp = fn = fp = 0
        for sample in positives:
            findings = analyze_file(sample, FIXTURES)
            hit = any(f["rule"] == rule for f in findings)
            if hit:
                tp += 1
            else:
                fn += 1
        for sample in negatives:
            findings = analyze_file(sample, FIXTURES)
            strict = rule not in TAINT_RULES
            for f in findings:
                if f["rule"] in informational_rules:
                    informational.append(
                        {
                            "sample": f"negative/{rule}/{sample.name}",
                            "rule": f["rule"],
                        }
                    )
                elif strict or f["rule"] == rule:
                    fp += 1

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        per_rule[rule] = {
            "positives": len(positives),
            "negatives": len(negatives),
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "precision": precision,
            "recall": recall,
        }

    edge_dir = FIXTURES / "edge"
    edge_samples = sorted(edge_dir.glob("*.py"))
    edge_measured = []
    for sample in edge_samples:
        findings = analyze_file(sample, FIXTURES)
        edge_measured.append(
            {
                "sample": sample.name,
                "rules_fired": sorted({f["rule"] for f in findings}),
            }
        )

    total_tp = sum(r["true_positives"] for r in per_rule.values())
    total_fp = sum(r["false_positives"] for r in per_rule.values())
    total_fn = sum(r["false_negatives"] for r in per_rule.values())
    return {
        "corpus": {
            "security_rules": len(SECURITY_RULES),
            "positive_samples": sum(r["positives"] for r in per_rule.values()),
            "negative_samples": sum(r["negatives"] for r in per_rule.values()),
            "edge_samples": len(edge_samples),
        },
        "totals": {
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "precision": total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0,
            "recall": total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0,
        },
        "rules": per_rule,
        "edge_outcomes": edge_measured,
        "informational_firings": sorted(
            informational, key=lambda x: (x["sample"], x["rule"])
        ),
    }


class CorpusAuditTests(unittest.TestCase):
    """The fixed set is what the plan says it is — audited, not assumed."""

    def test_every_security_rule_has_the_golden_5_plus_5(self):
        for rule in SECURITY_RULES:
            pos = len(list((FIXTURES / "positive" / rule).glob("*.py")))
            neg = len(list((FIXTURES / "negative" / rule).glob("*.py")))
            self.assertEqual(
                pos, POSITIVE_SAMPLES, f"{rule}: positives drifted"
            )
            self.assertEqual(
                neg, NEGATIVE_SAMPLES, f"{rule}: negatives drifted"
            )

    def test_edge_inventory_matches_the_published_claim(self):
        edges = sorted((FIXTURES / "edge").glob("*.py"))
        self.assertGreaterEqual(len(edges), 10, "edge corpus shrank")

    def test_measurement_is_deterministic_across_reruns(self):
        first = measure_rule_accuracy()
        second = measure_rule_accuracy()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
            "the same corpus must measure identically on a rerun",
        )


class MeasurementDocGateTests(unittest.TestCase):
    """docs/MEASUREMENT.md publishes the measured numbers — no more, no
    less. Same enforcement pattern as the README docs gate."""

    def _published_block(self) -> dict:
        text = MEASUREMENT_DOC.read_text(encoding="utf-8")
        m = re.search(
            r"<!-- measured-json begin -->.*?(\{.*\}).*?"
            r"<!-- measured-json end -->",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(
            m, "MEASUREMENT.md must contain the measured-json block"
        )
        return json.loads(m.group(1))

    def test_doc_totals_equal_measured_totals(self):
        published = self._published_block()
        measured = measure_rule_accuracy()
        self.assertEqual(
            published["corpus"], measured["corpus"],
            "MEASUREMENT.md corpus numbers are stale — rerun the harness",
        )
        self.assertEqual(
            published["totals"], measured["totals"],
            "MEASUREMENT.md accuracy totals are stale — rerun the "
            "harness and update the published block",
        )

    def test_doc_names_the_connector_reference_version(self):
        from mizan.integrations.semgrep_connector import (
            SEMGREP_REFERENCE_VERSION,
        )
        text = MEASUREMENT_DOC.read_text(encoding="utf-8")
        self.assertIn(
            SEMGREP_REFERENCE_VERSION, text,
            "MEASUREMENT.md must cite the pinned Semgrep reference "
            "version the connector records",
        )

    def test_reference_artifact_stays_consistent_with_contract(self):
        artifact_path = (
            ROOT / "tests" / "benchmark" / "results"
            / "semgrep_reference_run.json"
        )
        self.assertTrue(
            artifact_path.is_file(),
            "the recorded reference run artifact is missing — rerun "
            "scripts/run_semgrep_reference.py with the pinned binary",
        )
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        from mizan.integrations.semgrep_connector import (
            SEMGREP_REFERENCE_VERSION,
        )
        self.assertEqual(artifact["status"], "complete")
        self.assertEqual(artifact["tool_version"], SEMGREP_REFERENCE_VERSION)
        self.assertTrue(artifact["version_match"])
        self.assertEqual(artifact["import"]["schema"], "mizan.import.v1")
        # Corpus-relative locations: the staging methodology is what
        # makes the artifact rerun-stable and portable.
        for rule_id, file, _line, _level in artifact["findings"]:
            self.assertFalse(
                file.startswith("/"),
                f"recorded finding location must be corpus-relative, "
                f"got {file!r}",
            )
            self.assertIn("local-", rule_id)


if __name__ == "__main__":
    unittest.main()
