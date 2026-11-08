"""Taint-analysis PoC suite (v0.14.0-dev wave, docs/ROADMAP.md P1.2).

Flow 1 — request.* -> SQL           : rule ``request-to-sql`` (high)
Flow 2 — input()/sys.argv -> subprocess : rule ``input-to-subprocess`` (high)
Flow 3 — input() -> open            : existing ``path-traversal`` (deepened
                                      propagation; strict superset recall)

Contract under test:
  * dataflow rules fire ONLY on a confirmed source-to-sink path
    (precision by construction — clean sinks produce ZERO findings);
  * behavior is ADDITIVE: no pre-existing rule loses a finding
    (the full suite stays green);
  * request-to-sql never duplicates a line already covered by the
    structural sql-injection rule.

Direct-API tests (analyze_file on temp files) — fast, no subprocess.
"""

import os
import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import analyze_file
from mizan.taint import is_request_source
import ast


def scan_code(source: str):
    """Run the real analyzer on one virtual file; return its findings."""
    root = Path(tempfile.mkdtemp())
    target = root / "sample_taint.py"
    target.write_text(source, encoding="utf-8")
    return analyze_file(target, root)


def rules(source: str):
    return [f["rule"] for f in scan_code(source)]


class TaintRequestSourceUnit(unittest.TestCase):
    """Source-predicate semantics (unit level, no scan)."""

    def _pred(self, expr):
        return is_request_source(ast.parse(expr, mode="eval").body)

    def test_request_data_attrs_are_sources(self):
        for expr in ("request.args", "request.form.get('x')",
                     "request.headers['X']", "request.GET.get('id')",
                     "request.json", "request.values.get('q')"):
            self.assertTrue(self._pred(expr), expr)

    def test_non_data_request_members_are_not_sources(self):
        for expr in ("request", "request.method",
                     "request.url", "response.data"):
            self.assertFalse(self._pred(expr), expr)


class Flow1RequestToSql(unittest.TestCase):
    """request.* reaching execute() through tainted query variables."""

    def test_tainted_variable_reaches_execute(self):
        src = ("from flask import request\n"
               "sql = request.values.get('q')\n"
               "cursor.execute(sql)\n")
        found = rules(src)
        self.assertIn("request-to-sql", found)

    def test_taint_through_fstring_assignment(self):
        src = ("from flask import request\n"
               "q = f\"SELECT * FROM u WHERE id={request.args.get('id')}\"\n"
               "cursor.execute(q)\n")
        found = rules(src)
        self.assertIn("request-to-sql", found)

    def test_taint_through_str_wrapper(self):
        src = ("from flask import request\n"
               "uid = str(request.form.get('uid'))\n"
               "cursor.executemany('INSERT INTO t VALUES (' + uid + ')')\n")
        found = rules(src)
        # BinOp shape is covered by the structural sql-injection rule
        # (same site); the dataflow rule must not duplicate the line.
        self.assertIn("sql-injection", found)
        self.assertNotIn("request-to-sql", found)

    def test_severity_is_high(self):
        src = ("from flask import request\n"
               "sql = request.values.get('q')\n"
               "cursor.execute(sql)\n")
        finding = next(f for f in scan_code(src)
                       if f["rule"] == "request-to-sql")
        self.assertEqual(finding["severity"], "high")

    def test_parameterized_query_is_clean(self):
        src = ("from flask import request\n"
               "q = request.args.get('q')\n"
               "cursor.execute('SELECT * FROM u WHERE n = ?', (q,))\n")
        found = rules(src)
        self.assertNotIn("request-to-sql", found)
        self.assertNotIn("sql-injection", found)


class Flow2InputToSubprocess(unittest.TestCase):
    """input()/sys.argv reaching process sinks through tainted names."""

    def test_input_to_subprocess_run(self):
        src = ("import subprocess\n"
               "cmd = input()\n"
               "subprocess.run(cmd, shell=False)\n")
        found = rules(src)
        self.assertIn("input-to-subprocess", found)
        self.assertNotIn("shell-true", found)

    def test_sysargv_to_os_system(self):
        src = ("import os, sys\n"
               "target = sys.argv[1]\n"
               "os.system('ping ' + target)\n")
        found = rules(src)
        self.assertIn("input-to-subprocess", found)
        # escalation pairing: structural medium + dataflow high
        self.assertIn("process-execution", found)

    def test_taint_chain_three_hops(self):
        src = ("import subprocess\n"
               "a = input()\n"
               "b = a\n"
               "c = str(b)\n"
               "subprocess.check_output(c)\n")
        found = rules(src)
        self.assertIn("input-to-subprocess", found)

    def test_for_loop_propagation(self):
        src = ("import os, sys\n"
               "for p in sys.argv[1:]:\n"
               "    os.system(p)\n")
        found = rules(src)
        self.assertIn("input-to-subprocess", found)

    def test_severity_is_high(self):
        src = ("import subprocess\n"
               "cmd = input()\n"
               "subprocess.run(cmd)\n")
        finding = next(f for f in scan_code(src)
                       if f["rule"] == "input-to-subprocess")
        self.assertEqual(finding["severity"], "high")

    def test_request_taint_out_of_flow2_scope(self):
        # PoC scope: flow 2 tracks input()/sys.argv only (documented).
        # A request-tainted command must NOT fire the input rule.
        src = ("import subprocess\n"
               "from flask import request\n"
               "cmd = request.args.get('cmd')\n"
               "subprocess.run(cmd)\n")
        found = rules(src)
        self.assertNotIn("input-to-subprocess", found)

    def test_clean_subprocess_is_silent(self):
        src = ("import subprocess\n"
               "subprocess.run(['ls', '-la'])\n")
        self.assertEqual(rules(src), [])


class Flow3InputToOpen(unittest.TestCase):
    """Existing path-traversal rule — recall deepened, never regressed."""

    def test_direct_input_open_still_fires(self):
        src = "path = input()\nopen(path)\n"
        self.assertIn("path-traversal", rules(src))

    def test_deepened_concat_open_new_recall(self):
        # the v0.9.0 shallow pass missed this shape (assignment through
        # concatenation); the fixpoint engine catches it.
        src = "name = input()\npath = 'data/' + name\nopen(path)\n"
        found = rules(src)
        self.assertIn("path-traversal", found)

    def test_constant_open_is_silent(self):
        src = "open('/etc/passwd')\n"
        self.assertEqual(rules(src), [])


class NonSinkAndNonSource(unittest.TestCase):
    """No sink or no source => zero dataflow findings."""

    def test_input_without_sink_is_silent(self):
        src = "x = input()\nprint(len(x))\n"
        self.assertEqual(rules(src), [])

    def test_request_method_is_not_a_data_source(self):
        src = ("from flask import request\n"
               "m = request.method\n"
               "cursor.execute('SELECT * FROM t WHERE k = %s' % m)\n")
        found = rules(src)
        # request.method is not client data -> no request-to-sql; the
        # structural sql-injection rule still covers the % shape.
        self.assertNotIn("request-to-sql", found)
        self.assertIn("sql-injection", found)

    def test_constant_sql_is_silent(self):
        src = "cursor.execute('SELECT 1')\n"
        self.assertEqual(rules(src), [])


if __name__ == "__main__":
    unittest.main()
