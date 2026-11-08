"""Golden-set EDGE layer — the boundary cases that break naive rules.

Each fixture has an EXPECTED outcome measured against the documented
rule contract; where the expectation is a deliberate NO-detection, the
reason is stated (these are the honest limitations, they belong in
RULE_ACCURACY.md, not hidden).
"""

import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import analyze_file, analyze_repository

EDGE_DIR = Path(__file__).resolve().parent / "fixtures" / "edge"

# file -> (rule, must_fire, why)
EXPECT = {
    "01_secret_split_concat.py": (
        "hardcoded-secret-candidate", False,
        "split 'abc'+'def' concatenation is beyond the line regex — "
        "structural no-snippet control is the designed answer"),
    "02_env_password.py": (
        "hardcoded-secret-candidate", False,
        "os.environ lookups are not hardcoded secrets"),
    "03_sql_helper_fn.py": (
        "sql-injection", False,
        "no cross-procedural analysis (PoC limitation, documented) — "
        "the helper shape alone does not fire"),
    "04_nosec_comment.py": (
        "dynamic-execution", True,
        "MIZAN never lets an inline comment bury a finding (README: "
        "suppression is the baseline file's job)"),
    "05_literal_eval_safe.py": (
        "dynamic-execution", False,
        "ast.literal_eval is the SAFE alternative — must never fire"),
    "06_shell_true_constant.py": (
        "shell-true", True,
        "shell=True stays a shell boundary even on a constant command"),
    "07_fstring_sql_identifier.py": (
        "sql-injection", False,
        "identifier-position interpolation (FROM {table}) is documented "
        "scope-out — configuration identifier binding"),
    "08_pickle_constant_bytes.py": (
        "unsafe-deserialization", True,
        "constant payload is still the dangerous deserialization shape"),
    "09_import_alias_pickle.py": (
        "unsafe-deserialization", False,
        "import-alias resolution is not implemented (documented "
        "cross-cutting limitation)"),
    "10_zipfile_direct_extractall.py": (
        "tarfile-extractall", False,
        "zip format has no symlink traversal — direct "
        "zipfile.ZipFile(...).extractall() must respect the same "
        "carve-out as bound variables"),
    "11_eval_constant_string.py": (
        "dynamic-execution", True,
        "conservative Bandit-parity stance (B307): bare eval() fires on "
        "constants too — deviation from the requested negative, "
        "documented in RULE_ACCURACY.md"),
    "12_torch_alias.py": (
        "torch-unsafe-load", False,
        "import-alias resolution not implemented (same limitation)"),
    "13_full_load_not_flagged.py": (
        "yaml-unsafe-load", False,
        "yaml.full_load() is FullLoader — a PyYAML mitigation; NOT "
        "extended (measured decision), while load(Loader=FullLoader) "
        "stays flagged for Bandit B506 parity"),
    "14_tmp_segment_boundary.py": (
        "hardcoded-tmp-path", False,
        "'/template' must not match the /tmp prefix (segment boundary)"),
    "15_import_constant_lazy.py": (
        "dynamic-execution", False,
        "__import__('json') with a CONSTANT module name is the lazy-"
        "import idiom, not code execution from data (field-corrected, "
        "8/8 sites benign in the 10-repo run)"),
    "16_shell_true_single_report.py": (
        "shell-true", True,
        "constant-command shell=True still fires — AND exactly once "
        "(dedicated count test below)"),
}


class EdgeExpectations(unittest.TestCase):

    def test_edge_table_covers_every_fixture(self):
        on_disk = {p.name for p in EDGE_DIR.glob("*.py")}
        self.assertEqual(set(EXPECT), on_disk,
                         "edge table and fixtures drifted apart")

    def _scan(self, name):
        return analyze_file(EDGE_DIR / name, EDGE_DIR)

    def test_all_edge_expectations(self):
        for name, (rule, must_fire, why) in EXPECT.items():
            findings = self._scan(name)
            fired = any(f["rule"] == rule for f in findings)
            if must_fire:
                self.assertTrue(
                    fired, f"{name}: expected {rule} to fire — {why}")
            else:
                self.assertFalse(
                    fired,
                    f"{name}: {rule} fired unexpectedly — {why} "
                    f"(got {[(f['line'], f['rule']) for f in findings]})")

    def test_shell_true_reported_exactly_once(self):
        """Field regression (zyko tools_builtin): the old .run block
        survived the golden-set rewrite and emitted shell-true TWICE per
        site. One site = one finding."""
        findings = self._scan("16_shell_true_single_report.py")
        hits = [f for f in findings if f["rule"] == "shell-true"]
        self.assertEqual(len(hits), 1, hits)


class TreeExclusions(unittest.TestCase):
    """The directory-level contract: tests/ and vendor/ are never your
    attack surface (v0.9.0 P0 policy) — one eval() per tree, only the
    app copy may surface."""

    def test_tests_and_vendor_trees_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("eval(x)\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_x.py").write_text(
                "eval(x)\n", encoding="utf-8")
            (root / "vendor").mkdir()
            (root / "vendor" / "lib.py").write_text(
                "eval(x)\n", encoding="utf-8")
            (root / "test_root.py").write_text(
                "eval(x)\n", encoding="utf-8")
            result = analyze_repository(root)
            files = {f["file"] for f in result["findings"]}
            self.assertIn("app.py", files)
            self.assertNotIn(str(Path("tests") / "test_x.py"), files)
            self.assertNotIn(str(Path("vendor") / "lib.py"), files)
            self.assertNotIn("test_root.py", files)


if __name__ == "__main__":
    unittest.main()
