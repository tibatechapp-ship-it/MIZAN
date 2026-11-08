"""Documented-FP status pin — 10 hand-classified false positives
(RULE_ACCURACY.md §5, 10-repo field measurement, 14.9% = 10/67).

Each test pins the MEASURED status against the current engine
(re-measured 2026-11-08 on v0.15.0-dev with the ':=' fix). Pinning is
deliberate: a future exemption or a regression must be a CONSCIOUS
decision, never a silent drift. Original repo clones are gone from the
sandbox, so sites are reproduced as the minimal documented shapes —
provenance is stated per test; nothing here is invented.
"""
import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import analyze_file


def _scan(code: str, filename: str = "sample.py"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / filename
        p.write_text(code, encoding="utf-8")
        return analyze_file(p, Path(td))


def _rules(findings):
    return sorted({f["rule"] for f in findings})


class FP1to2_SelfReferentialTmp(unittest.TestCase):
    """analyzer.py:683-684 (was 548-549): the detector's own '/tmp'
    default constants. Root cause: self-referential — code about the
    rule triggers the rule. Decision recorded in §5: no fix, docs only."""

    def test_tmp_assignment_shape_fires(self):
        res = _scan('TMP_DIR = "/tmp"\n')
        self.assertIn("hardcoded-tmp-path", _rules(res))

    def test_tmp_call_arg_shape_fires(self):
        res = _scan('open("/tmp/out.txt", "w")\n')
        self.assertIn("hardcoded-tmp-path", _rules(res))


class FP3_TimelineJoinIdiom(unittest.TestCase):
    """report/timeline.py:121: the dynamic-IN placeholder idiom. FIXED in
    0.14.0 (placeholder-builder exemption). Re-measured silent on the
    v0.15.0-dev engine — this test guards that the fix holds."""

    def test_join_question_times_len_stays_silent(self):
        res = _scan(
            'TERMINAL = ("closed", "fixed")\n'
            'placeholders = ",".join("?" * len(TERMINAL))\n'
            "cur.execute(\n"
            '    "SELECT id, repo FROM disclosures "\n'
            '    f"WHERE deadline < ? AND status NOT IN ({placeholders}) "\n'
            '    "ORDER BY deadline",\n'
            "    (now, *TERMINAL),\n"
            ")\n")
        self.assertNotIn("sql-injection", _rules(res))


class FP4_ExecCommandJsAmbiguity(unittest.TestCase):
    """seekfeek clipboard.ts:40: exec('copy') is the execCommand clipboard
    idiom, not dynamic execution. Root cause: JS line-regex ambiguity.
    Future family (documented): JS golden coverage first, then a
    constant-argument exemption. Currently still fires — pinned."""

    def test_exec_copy_still_fires(self):
        res = _scan("const save = () => exec('copy');\n", "clipboard.ts")
        self.assertIn("dynamic-execution", _rules(res))


class FP5_CandidateGuardValue(unittest.TestCase):
    """seekfeek publish-npm-baseline.ts:918: descriptive guard value
    ('keyless-installed-web-no-call') on a secret-keyword line. The rule
    is a *candidate* by design — it feeds manual triage, never a blocking
    claim. Behavior intended; pinned."""

    def test_descriptive_guard_value_fires_as_candidate(self):
        res = _scan('const token = "keyless-installed-web-no-call";\n',
                    "publish-npm-baseline.ts")
        self.assertIn("hardcoded-secret-candidate", _rules(res))


class FP6to9_SqlFragmentShapes(unittest.TestCase):
    """nexus session_store.py / memory/engine.py: dynamic SQL over internal
    column fragments with parameterized values. Original clones are gone,
    so the exact multi-line shapes are unreproducible here; the minimal
    parameterized-fragment shapes below measured SILENT on the current
    engine — pinned so any future over-firing is visible. The deeper
    dataflow family stays documented (ROADMAP P3)."""

    def test_ts_fragment_select_stays_silent(self):
        res = _scan(
            'const cols = "id, name";\n'
            'db.query(`SELECT ${cols} FROM users WHERE id = ?`, [id]);\n',
            "store.ts")
        self.assertNotIn("sql-injection", _rules(res))
        self.assertNotIn("request-to-sql", _rules(res))

    def test_py_parameterized_fragment_stays_silent(self):
        res = _scan(
            'cols = "id, name"\n'
            'cur.execute(f"SELECT {cols} FROM users WHERE id = %s", (id,))\n')
        self.assertNotIn("sql-injection", _rules(res))


class FP10_SelfReferentialSecretString(unittest.TestCase):
    """nexus tech_targets.py:49: a literal 'api_key = ...' STRING inside a
    detector test task — code about detection triggers the secret rule.
    Same self-referential family as FP1-2; docs only. Fires — pinned."""

    def test_self_referential_sample_fires(self):
        res = _scan(
            'FAKE_SAMPLE = "api_key = \'sk-abc123deadbeef\'"  '
            "# detector test input\n")
        self.assertIn("hardcoded-secret-candidate", _rules(res))


if __name__ == "__main__":
    unittest.main()
