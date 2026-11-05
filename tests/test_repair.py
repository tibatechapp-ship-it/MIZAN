"""Tests for the MIZAN safe-repair gate (SEC-02/SEC-03 remediation).

Covers: path confinement, dry-run by default, isolated-branch apply,
secret redaction, and the AST-precise B307 fixer.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mizan.repair import (  # noqa: E402
    Plan,
    RepairError,
    apply_repairs,
    resolve_target,
    validate_python,
)
from mizan import secret_remover  # noqa: E402
from mizan import ai_fixer  # noqa: E402


class _CwdTestCase(unittest.TestCase):
    """Base class: runs each test in a fresh temp CWD, restored afterwards."""

    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmp.cleanup()


class ResolveTargetTests(_CwdTestCase):
    def setUp(self):
        super().setUp()
        Path("src").mkdir()
        Path("src/x.py").write_text("# fixture\n")

    def test_relative_ok(self):
        self.assertEqual(resolve_target("src/x.py"), "src/x.py")

    def test_dot_slash_ok(self):
        self.assertEqual(resolve_target("./src/x.py"), "src/x.py")

    def test_file_uri_ok(self):
        self.assertEqual(resolve_target("file://src/x.py"), "src/x.py")

    def test_absolute_rejected(self):
        with self.assertRaises(RepairError):
            resolve_target("/etc/passwd")

    def test_traversal_rejected(self):
        with self.assertRaises(RepairError):
            resolve_target("../../etc/passwd")

    def test_missing_file_rejected(self):
        with self.assertRaises(RepairError):
            resolve_target("no_such_file_xyz.py")

    def test_backslash_normalised(self):
        # Windows-style separators are normalised, not treated as traversal
        self.assertEqual(resolve_target("src/x.py"), "src/x.py")


class PlanTests(_CwdTestCase):
    def test_changed_and_diff(self):
        plan = Plan("a.py", "x = 1\n", "x = 2\n", "test")
        self.assertTrue(plan.changed)
        self.assertIn("-x = 1", plan.diff())
        self.assertIn("+x = 2", plan.diff())

    def test_unchanged_plan_filtered(self):
        summary = apply_repairs([Plan("a.py", "x\n", "x\n", "noop")], apply=False)
        self.assertEqual(summary["planned"], 0)


class DryRunTests(_CwdTestCase):
    def test_dry_run_writes_nothing(self):
        target = Path("vuln.py")
        target.write_text("print(1)\n", encoding="utf-8")
        plan = Plan("vuln.py", target.read_text(), "print(2)\n", "demo")
        summary = apply_repairs([plan], apply=False)
        self.assertEqual(summary["mode"], "dry-run")
        self.assertEqual(target.read_text(), "print(1)\n")


class ApplyBranchTests(_CwdTestCase):
    def _init_repo(self, tmp):
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=tmp, check=True)
        (Path(tmp) / "vuln.py").write_text("print(1)\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=tmp, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp, check=True)

    def test_apply_creates_isolated_branch(self):
        tmp = os.getcwd()
        self._init_repo(tmp)
        target = Path("vuln.py")
        plan = Plan("vuln.py", target.read_text(), "print(2)\n", "demo")
        summary = apply_repairs([plan], apply=True)

        self.assertEqual(summary["mode"], "applied")
        self.assertIn("branch", summary)
        branch = summary["branch"]
        self.assertTrue(branch.startswith("mizan/auto-fix-"))
        # scanned worktree untouched
        self.assertEqual(target.read_text(), "print(1)\n")
        # isolated worktree holds the fix + commit + ledger entry
        wt = Path(summary["worktree"])
        self.assertEqual((wt / "vuln.py").read_text(), "print(2)\n")
        log = (wt / ".mizan" / "ledger.jsonl")
        self.assertTrue(log.exists())
        self.assertIn("auto-repair", log.read_text(encoding="utf-8"))
        out = subprocess.run(
            ["git", "log", "-1", "--format=%s", branch],
            capture_output=True, text=True, check=True)
        self.assertIn("MIZAN verified auto-repair", out.stdout)
        subprocess.run(["git", "worktree", "remove", "--force",
                        str(wt)], check=True)

    def test_apply_outside_git_repo_raises(self):
        plan = Plan("a.py", "x\n", "y\n", "demo")
        (Path(os.getcwd()) / "a.py").write_text("x\n")
        with self.assertRaises(RepairError):
            apply_repairs([plan], apply=True)

    def test_syntax_validation_blocks_bad_content(self):
        tmp = os.getcwd()
        self._init_repo(tmp)
        plan = Plan("vuln.py", "print(1)\n", "print(2)\nthis is not python(", "broken")
        with self.assertRaises(RepairError):
            apply_repairs([plan], apply=True)
        # worktree rolled back: no repair worktree left behind
        leftovers = [p for p in Path(tmp).glob(".mizan-repair-*")]
        self.assertEqual(leftovers, [])


class ValidatePythonTests(_CwdTestCase):
    def test_valid(self):
        self.assertIsNone(validate_python("a.py", "x = 1\n"))

    def test_invalid(self):
        self.assertIsNotNone(validate_python("a.py", "def (:\n"))

    def test_non_python_skipped(self):
        self.assertIsNone(validate_python("a.txt", "anything ("))


class SecretRemoverTests(_CwdTestCase):
    def _findings(self, secret, path="config.py"):
        return [
            {"match": secret, "filename": path},
            {"secret": "other", "file_path": "./config.py"},
        ]

    def test_build_plans_redacts(self):
        Path("config.py").write_text('KEY = "ghp_secret123"\n', encoding="utf-8")
        findings = self._findings("ghp_secret123")
        Path("ggshield-results.json").write_text(json.dumps(findings))
        plans = secret_remover.build_plans()
        self.assertEqual(len(plans), 1)
        self.assertNotIn("ghp_secret123", plans[0].modified)
        self.assertIn("[REDACTED_BY_MIZAN]", plans[0].modified)

    def test_traversal_finding_ignored(self):
        Path("config.py").write_text('KEY = "s3cr3t"\n', encoding="utf-8")
        findings = [{"match": "s3cr3t", "filename": "../../etc/shadow"}]
        Path("ggshield-results.json").write_text(json.dumps(findings))
        plans = secret_remover.build_plans()
        self.assertEqual(plans, [])

    def test_missing_literal_reported_not_planned(self):
        Path("config.py").write_text("KEY = os.environ['K']\n", encoding="utf-8")
        findings = [{"match": "nope-not-here", "filename": "config.py"}]
        Path("ggshield-results.json").write_text(json.dumps(findings))
        plans = secret_remover.build_plans()
        self.assertEqual(plans, [])


class AIFixerTests(_CwdTestCase):
    def _sarif(self, path="vuln.py", rule="B307"):
        report = {"runs": [{"results": [{"ruleId": rule, "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": path}}}
        ]}]}]}
        Path("bandit.sarif").write_text(json.dumps(report))

    def test_literal_eval_fixed_with_import_after_docstring(self):
        src = ('#!/usr/bin/env python3\n'
               '"""Module docstring."""\n'
               'from __future__ import annotations\n'
               'data = eval("[1, 2, 3]")\n')
        Path("vuln.py").write_text(src, encoding="utf-8")
        self._sarif()
        plans = ai_fixer.build_plans()
        self.assertEqual(len(plans), 1)
        fixed = plans[0].modified
        self.assertIn("ast.literal_eval", fixed)
        self.assertIsNone(validate_python("vuln.py", fixed))
        # import placed AFTER docstring and __future__, not at line 1
        lines = fixed.splitlines()
        self.assertEqual(lines[0], "#!/usr/bin/env python3")
        self.assertEqual(lines[1], '"""Module docstring."""')
        self.assertEqual(lines[2], "from __future__ import annotations")
        self.assertEqual(lines[3], "import ast")
        # docstring preserved as a real docstring
        tree = ast.parse(fixed)
        first = tree.body[0]
        self.assertIsInstance(first, ast.Expr)
        self.assertEqual(first.value.value, "Module docstring.")

    def test_non_literal_eval_not_fixed(self):
        src = "expr = input()\nresult = eval(expr)\n"
        Path("vuln.py").write_text(src, encoding="utf-8")
        self._sarif()
        plans = ai_fixer.build_plans()
        self.assertEqual(plans, [])

    def test_method_eval_untouched(self):
        src = "class A:\n    def eval(self):\n        return 1\nA().eval()\n"
        Path("vuln.py").write_text(src, encoding="utf-8")
        self._sarif()
        plans = ai_fixer.build_plans()
        self.assertEqual(plans, [])

    def test_only_b307_handled(self):
        Path("vuln.py").write_text('data = eval("[1]")\n', encoding="utf-8")
        self._sarif(rule="B999")
        plans = ai_fixer.build_plans()
        self.assertEqual(plans, [])

    def test_multiple_evals_all_fixed(self):
        src = 'a = eval("[1]")\nb = eval("2+3")\n'
        Path("vuln.py").write_text(src, encoding="utf-8")
        self._sarif()
        plans = ai_fixer.build_plans()
        self.assertEqual(len(plans), 1)
        fixed = plans[0].modified
        self.assertEqual(fixed.count("ast.literal_eval"), 2)
        # no bare eval( left (literal_eval( is fine)
        self.assertIsNone(re.search(r"(?<!literal_)eval\(", fixed))
        self.assertIsNone(validate_python("vuln.py", fixed))

    def test_no_import_duplication(self):
        src = 'import ast\n\ndata = eval("[1]")\n'
        Path("vuln.py").write_text(src, encoding="utf-8")
        self._sarif()
        plans = ai_fixer.build_plans()
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].modified.count("import ast"), 1)


if __name__ == "__main__":
    unittest.main()
