"""Go short-variable-declaration (':=') secret-detection boundary — v0.15.0-dev.

Provenance (measured, not invented):
- 2026-11-08: the 50-repo scan-remote field campaign surfaced that Go's
  two-character short variable declaration ':=' evades
  hardcoded-secret-candidate, whose assignment slot was the single
  character class '[:=]' — it cannot bridge ':=' (measured: ':' then the
  engine stalls on '='; the '=' start position is unreachable because
  '\\s*' cannot consume ':').
- A first candidate fix '(?::|=)' was critiqued and MEASURED to fail on
  ':=' for exactly the same reason (alternation picks ':', then '\\s*'
  sees '=').
- The corrected fix measured on three operator forms per the review
  spec: '=' fires, ':=' fires, '::=' stays silent. The shipped fix is
  '(?::?=|:)': the review spec PLUS the bare-colon alternative, because
  the baseline measurement proved the colon form (JS object properties,
  'password: "...\"') already fired before the change — pure '(?::?=)'
  would have silently shrunk that detected class.

Contract: nothing that fired before keeps firing (this file and the
golden suites guard it); only ':=' transitions silent -> fired.
"""
import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import SECRET_PATTERN_BARE, analyze_file

SECRET = "SuperRealSecret_1234567890"


def _scan(code: str, filename: str = "main.go"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / filename
        p.write_text(code, encoding="utf-8")
        return analyze_file(p, Path(td))


def _secret_findings(findings):
    return [f for f in findings
            if f["rule"] == "hardcoded-secret-candidate"]


class WalrusPositiveTests(unittest.TestCase):
    """':=' in Go must now fire — the measured gap is closed."""

    def test_go_walrus_fires(self):
        findings = _scan(
            f'package main\n\nfunc main() {{\n    password := "{SECRET}"\n}}\n')
        self.assertEqual(1, len(_secret_findings(findings)),
                         "Go ':=' secret must fire after the fix")

    def test_go_compound_keyword_walrus_fires(self):
        findings = _scan(
            f'package main\n\nfunc main() {{\n    my-api-key := "{SECRET}"\n}}\n')
        self.assertEqual(1, len(_secret_findings(findings)),
                         "compound keyword with ':=' must fire via the full pattern")

    def test_js_walrus_fires(self):
        findings = _scan(f'let password := "{SECRET}"\n', "config.js")
        self.assertEqual(1, len(_secret_findings(findings)))


class OperatorFormRegressionTests(unittest.TestCase):
    """Forms that fired BEFORE the fix must keep firing (no silent shrink)."""

    def test_plain_eq_still_fires(self):
        findings = _scan(f'password = "{SECRET}"\n')
        self.assertEqual(1, len(_secret_findings(findings)))

    def test_colon_form_still_fires(self):
        # JS object property — measured firing BEFORE the fix; '(?::?=)'
        # alone would have silenced this class.
        findings = _scan(f'const cfg = {{\n  password: "{SECRET}",\n}};\n',
                         "config.js")
        self.assertEqual(1, len(_secret_findings(findings)))


class BoundaryNegativeTests(unittest.TestCase):
    """Malformed/comparison operators must stay silent (unchanged contract)."""

    def test_double_colon_eq_silent(self):
        findings = _scan(f'password ::= "{SECRET}"\n')
        self.assertEqual([], _secret_findings(findings),
                         "'::=' is not an assignment — must not fire")

    def test_comparison_eq_silent(self):
        findings = _scan(f'password == "{SECRET}"\n')
        self.assertEqual([], _secret_findings(findings),
                         "'==' is a comparison, not an assignment leak")

    def test_placeholder_walrus_silent(self):
        findings = _scan('package main\n\nfunc main() {\n'
                         '    password := "changeme"\n}\n')
        self.assertEqual([], _secret_findings(findings),
                         "placeholder values stay exempt regardless of operator")


class RegexLevelBoundaryTests(unittest.TestCase):
    """The operator slot itself: the three review-spec cases, directly."""

    def test_spec_three_forms(self):
        self.assertTrue(bool(SECRET_PATTERN_BARE.search(f'password = "{SECRET}"')),
                        "'=' must match")
        self.assertTrue(bool(SECRET_PATTERN_BARE.search(f'password := "{SECRET}"')),
                        "':=' must match (the fix)")
        self.assertFalse(bool(SECRET_PATTERN_BARE.search(f'password ::= "{SECRET}"')),
                         "'::=' must not match")


if __name__ == "__main__":
    unittest.main()
