"""Acceptance tests for declarative custom rules (.mizan/rules.json).

Same contract the security rules are held to: positive + negative
samples, loud rejection of malformed policies, and gate integration —
custom findings block; a broken policies file never certifies a pass.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mizan.analyzer import analyze_repository  # noqa: E402
from mizan.custom_rules import load_custom_rules  # noqa: E402
from mizan.scanner import scan_repository  # noqa: E402

VALID_RULE = {
    "id": "custom-no-print",
    "severity": "medium",
    "languages": ["python"],
    "pattern": r"\bprint\s*\(",
    "message": "print() is forbidden in production code",
}


def _write_rules(root, doc):
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mizan").mkdir(exist_ok=True)
    (root / ".mizan" / "rules.json").write_text(
        doc if isinstance(doc, str) else json.dumps(doc),
        encoding="utf-8",
    )


class CustomRulesLoaderTests(unittest.TestCase):

    def test_missing_file_is_normal_case(self):
        with tempfile.TemporaryDirectory() as temp:
            rules, errors = load_custom_rules(temp)
            self.assertEqual(rules, [])
            self.assertEqual(errors, [])

    def test_valid_rule_loads(self):
        with tempfile.TemporaryDirectory() as temp:
            _write_rules(Path(temp), {"version": 1, "rules": [VALID_RULE]})
            rules, errors = load_custom_rules(temp)
            self.assertEqual(errors, [])
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["id"], "custom-no-print")

    def test_invalid_json_records_error(self):
        with tempfile.TemporaryDirectory() as temp:
            _write_rules(Path(temp), "{not json")
            rules, errors = load_custom_rules(temp)
            self.assertEqual(rules, [])
            self.assertEqual(len(errors), 1)
            self.assertIn("invalid JSON", errors[0]["error"])

    def test_unsupported_schema_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            _write_rules(Path(temp), {"version": 99, "rules": []})
            _, errors = load_custom_rules(temp)
            self.assertEqual(len(errors), 1)
            self.assertIn("schema version", errors[0]["error"])

    def test_bad_severity_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rule = dict(VALID_RULE, severity="apocalyptic")
            _write_rules(Path(temp), {"version": 1, "rules": [rule]})
            _, errors = load_custom_rules(temp)
            self.assertEqual(len(errors), 1)
            self.assertIn("severity", errors[0]["error"])

    def test_bad_regex_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rule = dict(VALID_RULE, pattern="([unclosed")
            _write_rules(Path(temp), {"version": 1, "rules": [rule]})
            _, errors = load_custom_rules(temp)
            self.assertEqual(len(errors), 1)
            self.assertIn("does not compile", errors[0]["error"])

    def test_non_namespaced_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            # a custom rule must never shadow a built-in rule id
            rule = dict(VALID_RULE, id="dynamic-execution")
            _write_rules(Path(temp), {"version": 1, "rules": [rule]})
            _, errors = load_custom_rules(temp)
            self.assertEqual(len(errors), 1)
            self.assertIn("custom-", errors[0]["error"])

    def test_duplicate_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            twin = dict(VALID_RULE, pattern=r"\bexit\s*\(")
            _write_rules(Path(temp), {"version": 1, "rules": [VALID_RULE, twin]})
            rules, errors = load_custom_rules(temp)
            self.assertEqual(len(rules), 1)
            self.assertEqual(len(errors), 1)
            self.assertIn("duplicate id", errors[0]["error"])

    def test_unknown_language_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rule = dict(VALID_RULE, languages=["cobol"])
            _write_rules(Path(temp), {"version": 1, "rules": [rule]})
            _, errors = load_custom_rules(temp)
            self.assertEqual(len(errors), 1)
            self.assertIn("unknown language", errors[0]["error"])

    def test_one_bad_rule_does_not_disable_the_others(self):
        with tempfile.TemporaryDirectory() as temp:
            good = dict(VALID_RULE, id="custom-ok-rule")
            bad = dict(VALID_RULE, id="custom-bad", severity="nope")
            _write_rules(Path(temp), {"version": 1, "rules": [bad, good]})
            rules, errors = load_custom_rules(temp)
            self.assertEqual([r["id"] for r in rules], ["custom-ok-rule"])
            self.assertEqual(len(errors), 1)


class CustomRulesScanTests(unittest.TestCase):

    def _repo_with_code(self, root):
        root.mkdir(parents=True, exist_ok=True)
        (root / "src").mkdir(exist_ok=True)
        (root / "src" / "app.py").write_text(
            'def handler():\n    print("never do this")\n',
            encoding="utf-8",
        )
        (root / "src" / "util.js").write_text(
            'eval(userInput);\n',
            encoding="utf-8",
        )

    def test_rule_fires_on_python_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo_with_code(root)
            _write_rules(root, {"version": 1, "rules": [VALID_RULE]})
            result = analyze_repository(root)
            self.assertEqual(result["custom_rules_loaded"], 1)
            hits = [f for f in result["findings"]
                    if f["rule"] == "custom-no-print"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["file"], "src/app.py")
            self.assertEqual(hits[0]["line"], 2)
            self.assertTrue(hits[0]["custom"])

    def test_no_hit_when_pattern_absent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo_with_code(root)
            rule = dict(VALID_RULE, pattern=r"\bgoto\s+\w+")
            _write_rules(root, {"version": 1, "rules": [rule]})
            result = analyze_repository(root)
            self.assertEqual(
                [f for f in result["findings"]
                 if f["rule"] == "custom-no-print"],
                [],
            )

    def test_language_and_path_excludes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo_with_code(root)
            # python-only rule must not fire on the JS file...
            rule = dict(VALID_RULE, pattern=r"\beval\s*\(")
            _write_rules(root, {"version": 1, "rules": [rule]})
            result = analyze_repository(root)
            self.assertEqual(
                [f for f in result["findings"]
                 if f["rule"] == "custom-no-print"],
                [],
            )
            # ...and path_excludes must silence the python file too
            rule2 = dict(VALID_RULE, pattern=r"\bprint\s*\(",
                         path_excludes=["src/*"])
            _write_rules(root, {"version": 1, "rules": [rule2]})
            result = analyze_repository(root)
            self.assertEqual(
                [f for f in result["findings"]
                 if f["rule"] == "custom-no-print"],
                [],
            )

    def test_generic_language_matches_js(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo_with_code(root)
            rule = dict(VALID_RULE, id="custom-no-eval",
                        languages=["generic"], pattern=r"\beval\s*\(")
            _write_rules(root, {"version": 1, "rules": [rule]})
            result = analyze_repository(root)
            hits = [f for f in result["findings"]
                    if f["rule"] == "custom-no-eval"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["file"], "src/util.js")

    def test_unified_scan_includes_custom_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo_with_code(root)
            _write_rules(root, {"version": 1, "rules": [VALID_RULE]})
            result = scan_repository(root)
            # plugin filtering must NOT have dropped the custom finding
            self.assertEqual(result["custom_findings_count"], 1)
            self.assertEqual(result["custom_rules_loaded"], 1)
            rules_seen = {f["rule"] for f in result["findings"]}
            # the custom hit AND the built-in eval finding both survive
            self.assertIn("custom-no-print", rules_seen)
            self.assertIn("dynamic-execution", rules_seen)
            self.assertEqual(result["findings_count"], 2)

    def test_broken_rules_file_reported_by_unified_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo_with_code(root)
            _write_rules(root, "{broken json")
            result = scan_repository(root)
            self.assertEqual(len(result["custom_rules_errors"]), 1)


if __name__ == "__main__":
    unittest.main()
