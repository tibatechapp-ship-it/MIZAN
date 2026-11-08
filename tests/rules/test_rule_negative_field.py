"""Field-measured NEGATIVE layer — v0.14.0 (2026-11-08 campaign).

Source: the 50-repo `mizan scan-remote` field measurement plus MIZAN's own
self-scan (report/timeline.py:121). These are REAL shapes measured in the
wild that the sql-injection rule flagged as high severity although nothing
injectable remains at the site: the dynamic IN-clause placeholder idiom —
','.join("?" * len(STATUSES)) interpolated into an already-parameterized
query. The fix (analyzer.py): placeholder-builder expressions and names
BOUND to them (per-file pre-pass) are exempt; every unknown Name, unknown
call, and request-shaped value still fires.

Positive controls at the bottom of this file prove the rule still fires on
the injection shapes — the fix must never blunt the rule itself.
"""

import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import analyze_file


def _scan(code: str):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sample.py"
        p.write_text(code, encoding="utf-8")
        return analyze_file(p, Path(td))


class DynamicInClauseNegativeTests(unittest.TestCase):
    """The exact idiom measured in the field — must NOT fire sql-injection."""

    def _assert_no_sql(self, code, note):
        findings = _scan(code)
        self.assertEqual(
            [f for f in findings if f["rule"] == "sql-injection"], [],
            f"FALSE POSITIVE ({note}): "
            f"{[(f['line'], f['rule']) for f in findings]}")

    def test_join_of_question_times_len(self):
        # the measured shape (MIZAN report/timeline.py:119-126)
        self._assert_no_sql(
            'TERMINAL = ("closed", "fixed")\n'
            'placeholders = ",".join("?" * len(TERMINAL))\n'
            "cur.execute(\n"
            '    "SELECT id, repo FROM disclosures "\n'
            '    f"WHERE deadline < ? AND status NOT IN ({placeholders}) "\n'
            '    "ORDER BY deadline",\n'
            "    (now, *TERMINAL),\n"
            ")\n",
            "join('?' * len)")

    def test_direct_builder_inline_in_fstring(self):
        self._assert_no_sql(
            'cur.execute(f"SELECT id FROM t WHERE k IN '
            "({','.join('?' * len(cols))})\", vals)\n",
            "inline builder")

    def test_annassign_builder_and_reversed_mult(self):
        self._assert_no_sql(
            'import typing\n'
            'ph: str = len(STATUSES) * "?"\n'   # reversed operand order
            'cur.execute(f"SELECT 1 WHERE id IN ({ph})", ids)\n',
            "reversed mult")

    def test_lowercase_count_constant_interpolation(self):
        # an int count interpolated into a VALUES list — nothing injectable
        self._assert_no_sql(
            "n = len(rows)\n"
            'cur.execute(f"INSERT INTO t VALUES ({n}, ?)", (v,))\n',
            "len count")


class DynamicInClausePositiveControls(unittest.TestCase):
    """The fix must NOT blunt the rule — real injection shapes still fire."""

    def _assert_sql_fires(self, code, note):
        findings = _scan(code)
        self.assertTrue(
            any(f["rule"] == "sql-injection" for f in findings),
            f"MISSED INJECTION ({note}): {findings}")

    def test_plain_variable_in_value_position(self):
        self._assert_sql_fires(
            "name = user_input()\n"
            "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
            "plain variable")

    def test_unknown_call_in_value_position(self):
        self._assert_sql_fires(
            "cur.execute(f\"SELECT * FROM t WHERE k = {get_value()}\")\n",
            "unknown call")

    def test_non_builder_name_in_value_position(self):
        # identifier-position interpolation (FROM {tbl}) is deliberately
        # not flagged (RULE_ACCURACY decision) and request-tainted sites
        # escalate via request-to-sql — so probe a VALUE position here
        self._assert_sql_fires(
            "name = request.args.get('name')\n"
            "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
            "unknown name")

    def test_string_concat_still_fires(self):
        self._assert_sql_fires(
            "uid = request.args['id']\n"
            "cur.execute(\"SELECT * FROM u WHERE id = \" + uid)\n",
            "binop concat")


class TestPathSeverityDowngradeTests(unittest.TestCase):
    """v0.14.0 field fix: in test-fixture paths the two line-regex rules
    (hardcoded-secret-candidate, dynamic-execution) drop to "low" — the
    finding stays in the report (fail-loud intact), only the severity
    changes. Every OTHER rule keeps its severity everywhere."""

    def _scan_at(self, rel_path: str, code: str):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / rel_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code, encoding="utf-8")
            return analyze_file(p, Path(td))

    SECRET_LINE = 'API_TOKEN = "sk-live-abcdef1234567890"\n'
    EVAL_LINE = "const x = eval(userExpr);\n"

    def test_secret_downgraded_in_tests_dir(self):
        fs = self._scan_at("tests/unit/settings.py", self.SECRET_LINE)
        hit = [f for f in fs if f["rule"] == "hardcoded-secret-candidate"]
        self.assertEqual(len(hit), 1)          # still reported
        self.assertEqual(hit[0]["severity"], "low")

    def test_secret_keeps_high_in_source(self):
        fs = self._scan_at("src/app/settings.py", self.SECRET_LINE)
        hit = [f for f in fs if f["rule"] == "hardcoded-secret-candidate"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")

    def test_secret_downgraded_in_go_test_suffix(self):
        # field-measured shape: redact_test.go (Go convention). The rule's
        # measured Go surface is `token = "..."` (const/assign); the `:=`
        # shape is a documented P2 recall candidate, not part of v0.14.0.
        fs = self._scan_at("pkg/redact_test.go",
                           'token = "ghp_live_abcdef123456"\n')
        hit = [f for f in fs if f["rule"] == "hardcoded-secret-candidate"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "low")

    def test_dynamic_exec_downgraded_in_dot_test_ts(self):
        # field-measured shape: github-review-risk-floor.test.ts
        fs = self._scan_at("bin/github-review.test.ts", self.EVAL_LINE)
        hit = [f for f in fs if f["rule"] == "dynamic-execution"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "low")

    def test_dynamic_exec_keeps_high_in_source(self):
        fs = self._scan_at("src/app-runner.ts", self.EVAL_LINE)
        hit = [f for f in fs if f["rule"] == "dynamic-execution"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")

    def test_other_rules_not_downgraded_in_tests(self):
        # scope guard: the downgrade is ONLY the two measured rules —
        # sql-injection keeps "high" even under tests/
        code = (
            "name = user_input()\n"
            "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        )
        fs = self._scan_at("tests/queries.py", code)
        hit = [f for f in fs if f["rule"] == "sql-injection"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
