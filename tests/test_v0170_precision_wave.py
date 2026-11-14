"""v0.17.0-dev wave 1 — golden negatives from the measured field evidence.

Every negative below corresponds to a false-positive site MEASURED in the
nexus-core PR #95 evidence scan (report digest 07af33c5..., scan commit
1371c54, engine 0.16.0-dev -> 0.16.0) or in the 100-repo frozen-corpus
rerun. The contract: the measured negative stops firing, the measured
positive keeps firing, and the conservative direction is to keep
flagging whenever a fragment cannot be proven literal/whitelisted.
"""
import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import analyze_repository


def _rules(root):
    result = analyze_repository(str(root))
    return result, [f["rule"] for f in result["findings"]]


class CompileSyntaxCheckNegatives(unittest.TestCase):
    """nexus-core measured sites: self_improve.py:222, tester.py:37,
    multilang_analyzer.py:45, code_guardian.py:194, agent_loop/tools.py:222
    — bare compile() in try/except SyntaxError is a syntax check."""

    def _code(self):
        return (
            "def test_improvement(original_path, improved_code):\n"
            "    try:\n"
            "        compile(improved_code, original_path, 'exec')\n"
            "    except SyntaxError:\n"
            "        return False\n"
            "    return True\n"
        )

    def test_bare_compile_is_not_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(self._code(), encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("dynamic-execution", rules)

    def test_assigned_compile_result_unused_is_not_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(
                "bytecode = compile(src, '<test>', 'exec')\n",
                encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("dynamic-execution", rules)

    def test_compile_result_consumed_by_exec_still_fires_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(
                "exec(compile(src, '<test>', 'exec'))\n", encoding="utf-8")
            result, rules = _rules(root)
            self.assertEqual(rules.count("dynamic-execution"), 1)

    def test_dynamic_import_from_data_still_fires(self):
        # nexus-core src/cli/main.py:292 — the measured true positive.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(
                "mod = __import__(f'src.agents.{agent_name}', "
                "fromlist=['*'])\n", encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("dynamic-execution", rules)


class WhitelistSqlNegatives(unittest.TestCase):
    """nexus-core measured sites: session_store.py:301/486/741 and
    memory/engine.py:147 — fragments literal/whitelist-built, values
    bound via ? parameters."""

    LITERAL_APPENDS = (
        "def update(self, conv_id, title=None, agent=None):\n"
        "    sets = []\n"
        "    params = []\n"
        "    if title is not None:\n"
        "        sets.append('title = ?')\n"
        "        params.append(title)\n"
        "    if agent is not None:\n"
        "        sets.append('agent = ?')\n"
        "        params.append(agent)\n"
        "    sets.append('updated_at = ?')\n"
        "    params.append(now())\n"
        "    conn.execute(\n"
        "        f\"UPDATE conversations SET {', '.join(sets)} WHERE id = ?\",\n"
        "        tuple(params),\n"
        "    )\n"
    )

    def test_literal_append_join_with_params_is_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(self.LITERAL_APPENDS,
                                            encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("sql-injection", rules)

    def test_whitelist_comprehension_with_params_is_clean(self):
        code = (
            "def update_session(self, session_id, **fields):\n"
            "    allowed = {'topic', 'rounds', 'status'}\n"
            "    sets = [f'{k} = ?' for k in fields if k in allowed]\n"
            "    params = [fields[k] for k in fields if k in allowed]\n"
            "    conn.execute(\n"
            "        f\"UPDATE sessions SET {', '.join(sets)} WHERE id = ?\",\n"
            "        tuple(params),\n"
            "    )\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("sql-injection", rules)

    def test_ternary_where_fragment_with_params_is_clean(self):
        # nexus-core memory/engine.py:144-150 measured shape.
        code = (
            "def retrieve(self, agent_name=None):\n"
            "    where_clause = 'WHERE agent_name = ?' if agent_name else ''\n"
            "    params = (agent_name,) if agent_name else ()\n"
            "    cursor.execute(\n"
            "        'SELECT id FROM memories ' + where_clause\n"
            "        + ' ORDER BY id DESC LIMIT 50',\n"
            "        params,\n"
            "    )\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("sql-injection", rules)


class SqlInjectionRegressions(unittest.TestCase):
    """The true-positive shapes must keep firing exactly as before."""

    def test_fstring_value_interpolation_still_fires(self):
        code = ("def q(name):\n"
                "    cursor.execute(f\"SELECT * FROM users "
                "WHERE name = '{name}'\")\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("sql-injection", rules)

    def test_join_over_untracked_variable_still_fires(self):
        # Value-position join (VALUES (...)) over an untracked variable:
        # the measured contract — no provenance, no suppression.
        code = ("def q(cols, cid):\n"
                "    conn.execute(\n"
                "        f\"INSERT INTO t VALUES ({', '.join(cols)}, ?)\",\n"
                "        (cid,),\n"
                "    )\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("sql-injection", rules)

    def test_poisoned_append_keeps_firing(self):
        code = ("def q(user_cols, cid):\n"
                "    safe = []\n"
                "    safe.append('name = %s')\n"
                "    safe.append(user_cols)\n"
                "    conn.execute(\n"
                "        f\"INSERT INTO t VALUES ({', '.join(safe)}, ?)\",\n"
                "        (cid,),\n"
                "    )\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("sql-injection", rules)

    def test_column_position_join_was_never_flagged(self):
        # Pre-existing contract (unchanged by this wave): an interpolation
        # in a COLUMN position is not the sql-injection value-position rule.
        code = ("def q(cols):\n"
                "    cursor.execute(f'SELECT {\", \".join(cols)} FROM t')\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("sql-injection", rules)

    def test_whitelist_shape_without_params_still_fires(self):
        # Conservative: the measured negatives ALL bind values via ?;
        # an unparameterized build keeps the finding.
        code = ("def q(fields):\n"
                "    allowed = {'topic', 'status'}\n"
                "    sets = [f'{k} = ?' for k in fields if k in allowed]\n"
                "    conn.execute(f'UPDATE t SET {\", \".join(sets)}')\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("sql-injection", rules)

    def test_format_call_still_fires(self):
        code = ("def q(name):\n"
                "    cursor.execute('SELECT * FROM users WHERE "
                "name = {}'.format(name))\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("sql-injection", rules)


class EllipsisSecretNegative(unittest.TestCase):
    """nexus-core measured site: tech_targets.py:49 — 'sk-abc123...'
    inside a task-description string is documentation, not a credential."""

    def test_ellipsized_value_is_not_a_secret(self):
        code = ("TASKS = [\n"
                "    {'id': 's1_2', 'task': \"Review: api_key = "
                "'sk-abc123...' hardcoded. List it.\", 'verify': 'x'},\n"
                "]\n")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertNotIn("hardcoded-secret-candidate", rules)

    def test_plausible_real_secret_still_fires(self):
        code = "API_KEY = 'ak_live_9d81be2244ff'\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(code, encoding="utf-8")
            _, rules = _rules(root)
            self.assertIn("hardcoded-secret-candidate", rules)


if __name__ == "__main__":
    unittest.main()
