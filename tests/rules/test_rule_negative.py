"""Golden-set NEGATIVE layer — the real test of a rule.

Five clean samples per rule, shape-similar to the positives. Criterion:

  * EVERY rule: its own rule id must NOT fire (0 FP of the rule);
  * the 18 non-taint rules: ZERO findings of ANY kind on the sample
    (no collateral noise from hardcoded-secret-candidate, todo, ...) —
    the strict criterion the golden contract demands;
  * the 2 taint rules (request-to-sql, input-to-subprocess): only the
    target-absent criterion — they deliberately ESCALATE an existing
    medium rule (process-execution / sql-injection shape) at tainted
    sites, so a clean os.system("ls") legitimately still fires the
    base rule. Documented in RULE_ACCURACY.md.
"""

import unittest
from pathlib import Path

from mizan.analyzer import analyze_file

RULES_DIR = Path(__file__).resolve().parent / "fixtures" / "negative"
TAINT_RULES = {"request-to-sql", "input-to-subprocess"}

RULES = [
    "django-mark-safe", "dynamic-execution", "hardcoded-secret-candidate",
    "hardcoded-tmp-path", "hf-trust-remote-code", "input-to-subprocess",
    "jinja2-autoescape-false", "path-traversal", "process-execution",
    "request-to-sql", "request-without-timeout", "shell-true",
    "sql-injection", "ssl-unverified-context", "tarfile-extractall",
    "tls-verification-disabled", "torch-unsafe-load",
    "unsafe-deserialization", "weak-crypto", "yaml-unsafe-load",
]


def _load_rule_tests():
    for rule in RULES:
        strict = rule not in TAINT_RULES

        def make(rule=rule, strict=strict):
            def test(self):
                samples = sorted((RULES_DIR / rule).glob("*.py"))
                self.assertEqual(
                    len(samples), 5,
                    f"{rule}: golden contract is 5 negative samples")
                for sample in samples:
                    findings = analyze_file(sample, RULES_DIR)
                    hit = [f for f in findings if f["rule"] == rule]
                    self.assertEqual(
                        hit, [],
                        f"FALSE POSITIVE {rule}: {sample.name} fired "
                        f"({[(f['line'], f['rule']) for f in hit]})")
                    if strict:
                        self.assertEqual(
                            findings, [],
                            f"collateral noise on {sample.name}: "
                            f"{[(f['line'], f['rule']) for f in findings]}")
            return test
        setattr(RuleNegativeTests, f"test_neg_{rule}", make(rule))


class RuleNegativeTests(unittest.TestCase):
    """Methods are attached per-rule by _load_rule_tests() below the
    class definition — on THIS class, never on unittest.TestCase."""


_load_rule_tests()


class NegativeLayerContract(unittest.TestCase):

    def test_all_rules_have_negative_dirs(self):
        present = {d.name for d in RULES_DIR.iterdir() if d.is_dir()}
        self.assertEqual(set(RULES), present)


if __name__ == "__main__":
    unittest.main()
