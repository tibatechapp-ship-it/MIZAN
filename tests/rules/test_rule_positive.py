"""Golden-set POSITIVE layer — every rule must detect all 5 of its samples.

Samples are shape-distinct (different call shapes, receivers, scopes),
not five copies of one line. Fixtures are scanned per-file through the
real `analyze_file` entry (the tree-walker's tests//vendor exclusions
have their own dedicated edge test — golden sets measure DETECTION).
"""

import unittest
from pathlib import Path

from mizan.analyzer import analyze_file

RULES_DIR = Path(__file__).resolve().parent / "fixtures" / "positive"

# The 20 measured security rules (mizan plugins list, security plugin).
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
        def make(rule=rule):
            def test(self):
                samples = sorted((RULES_DIR / rule).glob("*.py"))
                self.assertEqual(
                    len(samples), 5,
                    f"{rule}: golden contract is 5 positive samples")
                for sample in samples:
                    findings = analyze_file(sample, RULES_DIR)
                    rules = {f["rule"] for f in findings}
                    self.assertIn(
                        rule, rules,
                        f"RECALL MISS {rule}: {sample.name} not detected "
                        f"(saw: {sorted(rules)})")
            return test
        setattr(RulePositiveTests, f"test_pos_{rule}", make(rule))


class RulePositiveTests(unittest.TestCase):
    """Methods are attached per-rule by _load_rule_tests() below the
    class definition — on THIS class, never on unittest.TestCase (the
    base class would leak the methods into every suite TestCase)."""


_load_rule_tests()


class PositiveLayerContract(unittest.TestCase):

    def test_all_rules_have_positive_dirs(self):
        present = {d.name for d in RULES_DIR.iterdir() if d.is_dir()}
        self.assertEqual(set(RULES), present,
                         "RULES list and fixture dirs drifted apart")


if __name__ == "__main__":
    unittest.main()
