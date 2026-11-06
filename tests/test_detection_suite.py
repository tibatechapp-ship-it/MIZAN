"""Detection capability suite (external audit wave — packages A-1 / A-2).

Measures ACTUAL current behavior of `mizan scan` end-to-end (real CLI,
real subprocess) against the acceptance table of the audit memo:

A-1 positives  : each sample MUST be detected under its expected rule id.
A-2 negatives  : each sample MUST produce ZERO findings.

NOTE on rule ids: the memo expects `subprocess-shell`; the registry's
actual id for `subprocess.run(x, shell=True)` is `shell-true` (mizan.plugins).
Rules `unsafe-deserialization`, `yaml-unsafe-load`, `sql-injection`,
`path-traversal`, `weak-crypto` are expected MISSING in v0.8.3 — if the
corresponding tests FAIL, that confirms the gap documented in the memo
(no code was modified to make them pass).

This file is a measuring instrument. It intentionally asserts the memo's
acceptance criteria so failures surface raw.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_scan(tmp_path: Path, files: dict) -> dict:
    """Write `files` (relative path -> content) and run the real CLI scan."""
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "mizan.cli", "scan", str(tmp_path),
         "--format", "json"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode in (0, 1), (
        f"scan crashed (rc={proc.returncode})\nSTDERR:\n{proc.stderr}"
    )
    return json.loads(proc.stdout)


def fired_rules(result: dict) -> set:
    return {f["rule"] for f in result.get("findings", [])}


# --------------------------------------------------------------------------
# A-1 — positive samples (MUST be detected)
# --------------------------------------------------------------------------

POSITIVES = [
    ("pickle", "sample_pickle.py",
     "import pickle\nimport sys\npickle.loads(sys.stdin.read())\n",
     "unsafe-deserialization"),
    ("yaml-unsafe", "sample_yaml.py",
     "import yaml\nwith open('cfg.yaml') as f:\n    cfg = yaml.load(f)\n",
     "yaml-unsafe-load"),
    ("subprocess-shell", "sample_subproc.py",
     "import subprocess\nimport sys\nsubprocess.run(sys.argv[1], shell=True)\n",
     "shell-true"),  # memo's `subprocess-shell` == registry's `shell-true`
    ("sql-concat", "sample_sql.py",
     "user = input()\ncursor.execute(\"SELECT * FROM users WHERE name='\" + user + \"'\")\n",
     "sql-injection"),
    ("sql-self-concat", "sample_sql_self.py",
     "user = input()\nself.cursor.execute(\"SELECT * FROM users WHERE name='%s'\" % user)\n",
     "sql-injection"),
    ("path-traversal", "sample_path.py",
     "name = input()\nwith open(name) as f:\n    data = f.read()\n",
     "path-traversal"),
    ("weak-crypto", "sample_md5.py",
     "import hashlib\nhashlib.md5(b'data')\n",
     "weak-crypto"),
    ("hardcoded-secret", "sample_secret.py",
     'password = "hardcoded_123"\n',
     "hardcoded-secret-candidate"),
    ("eval-dynamic", "sample_eval.py",
     "user_input = input()\neval(user_input)\n",
     "dynamic-execution"),
]


@pytest.mark.a1_positive
@pytest.mark.parametrize("name,rel,code,expected_rule", POSITIVES,
                         ids=[p[0] for p in POSITIVES])
def test_a1_positive_detected(tmp_path, name, rel, code, expected_rule):
    result = run_scan(tmp_path, {rel: code})
    rules = fired_rules(result)
    assert expected_rule in rules, (
        f"[{name}] expected rule '{expected_rule}' NOT detected. "
        f"fired rules: {sorted(rules) or 'NONE'}"
    )


# --------------------------------------------------------------------------
# A-2 — negative samples (MUST produce ZERO findings)
# --------------------------------------------------------------------------

NEGATIVES = [
    ("yaml-safe", "safe_yaml.py",
     "import yaml\nwith open('cfg.yaml') as f:\n    cfg = yaml.safe_load(f)\n"),
    ("subprocess-list", "safe_subproc.py",
     "import subprocess\nsubprocess.run(['ls', '-la'])\n"),
    ("plain-open", "plain_open.py",
     "with open('config.txt') as f:\n    data = f.read()\n"),
    ("strong-hash", "safe_hash.py",
     "import hashlib\nhashlib.sha256(b'data')\n"),
    ("i18n-json", "i18n/ar.json",
     '{"password": "كلمة المرور", "token": "رمز الدخول"}\n'),
    ("test-fixture", "tests/test_x.py",
     'def test_login():\n    password = "test123456"\n    assert password\n'),
    ("vendored-min-js", "vendor/lib.min.js",
     'var e=eval("1+2");document.write(e);\n'),
]


@pytest.mark.a2_negative
@pytest.mark.parametrize("name,rel,content", NEGATIVES,
                         ids=[n[0] for n in NEGATIVES])
def test_a2_negative_zero_findings(tmp_path, name, rel, content):
    result = run_scan(tmp_path, {rel: content})
    findings = result.get("findings", [])
    assert not findings, (
        f"[{name}] FALSE POSITIVE — {len(findings)} finding(s) on a clean sample: "
        f"{[(f['rule'], f['line']) for f in findings]}"
    )


@pytest.mark.a2_negative
def test_a2_tayf_real_scenario_i18n_ts(tmp_path):
    """The memo's tayf case: a .ts i18n dictionary — keys are labels, not secrets.

    (The i18n/ar.json row above is trivially clean because .json is not a
    scanned extension; THIS .ts variant is the real false-positive driver.)
    """
    result = run_scan(tmp_path, {
        "src/i18n/dictionary.ts":
            'export const dict = {\n'
            '  password: "كلمة المرور",\n'
            '  api_key: "مفتاح الواجهة",\n'
            '  token: "رمز الدخول",\n'
            '};\n',
    })
    findings = result.get("findings", [])
    assert not findings, (
        f"[tayf-real-scenario] FALSE POSITIVE — {len(findings)} finding(s) on "
        f"an i18n dictionary: {[(f['rule'], f['line']) for f in findings]}"
    )


# --------------------------------------------------------------------------
# Precision guards (v0.9.0 wave — locked in from the 20-repo sweep)
# --------------------------------------------------------------------------

@pytest.mark.a1_positive
def test_precision_sql_fstring_value_position(tmp_path):
    """f-string interpolating a variable in a VALUE position is injectable."""
    result = run_scan(tmp_path, {
        "sample_fsql.py":
            "name = input()\n"
            "cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n",
    })
    assert "sql-injection" in fired_rules(result), (
        f"f-string SQL value interpolation not detected: {fired_rules(result)}"
    )


@pytest.mark.a2_negative
def test_precision_sql_fstring_identifier_position(tmp_path):
    """Binding config identifiers (table names) via f-string is standard."""
    result = run_scan(tmp_path, {
        "sample_fsql_ok.py":
            "class Store:\n"
            "    table = 'items'\n"
            "    def init(self):\n"
            "        self._conn.execute(\n"
            "            f\"CREATE TABLE IF NOT EXISTS {self.table} "
            "(id TEXT UNIQUE)\"\n"
            "        )\n",
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on identifier-position f-string: "
        f"{[(f['rule'], f['line']) for f in result.get('findings', [])]}"
    )


@pytest.mark.a2_negative
def test_precision_sql_pragma_constant(tmp_path):
    """PRAGMA user_version = {SCHEMA_VERSION} interpolates a constant."""
    result = run_scan(tmp_path, {
        "sample_pragma.py":
            "SCHEMA_VERSION = 3\n"
            "conn.execute(f\"PRAGMA user_version = {SCHEMA_VERSION}\")\n",
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on constant PRAGMA interpolation: "
        f"{[(f['rule'], f['line']) for f in result.get('findings', [])]}"
    )


@pytest.mark.a2_negative
def test_precision_weak_crypto_usedforsecurity_false(tmp_path):
    result = run_scan(tmp_path, {
        "sample_md5_ok.py":
            "import hashlib\n"
            "hashlib.md5(b'data', usedforsecurity=False)\n",
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on usedforsecurity=False: "
        f"{[(f['rule'], f['line']) for f in result.get('findings', [])]}"
    )


@pytest.mark.a2_negative
def test_precision_safe_deserializers(tmp_path):
    result = run_scan(tmp_path, {
        "sample_safe_deser.py":
            "import json\nimport yaml\n"
            "data = json.loads(raw)\n"
            "cfg = yaml.load(stream, Loader=yaml.SafeLoader)\n",
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on safe deserializers: "
        f"{[(f['rule'], f['line']) for f in result.get('findings', [])]}"
    )


@pytest.mark.a2_negative
def test_precision_js_exec_in_comments_and_signatures(tmp_path):
    """RegExp .exec(, prose 'exec (' in comments — not dynamic execution."""
    result = run_scan(tmp_path, {
        "lib/exec_notes.ts":
            "// The launcher to probe and exec (test hook over the system).\n"
            "const m = /^(?<p>x)$/.exec(argument)\n",
        "lib/types.ts":
            "interface Runner {\n"
            "  exec(file: string, args: string[]): string\n"
            "}\n",
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on JS comments/RegExp.exec/signatures: "
        f"{[(f['rule'], f['file'], f['line']) for f in result.get('findings', [])]}"
    )


@pytest.mark.a1_positive
def test_precision_js_real_eval_still_detected(tmp_path):
    """The JS boundary fix must NOT disable real dynamic execution."""
    result = run_scan(tmp_path, {
        "lib/dangerous.js": "const out = eval(userInput);\n",
    })
    assert "dynamic-execution" in fired_rules(result), (
        f"real JS eval() not detected: {fired_rules(result)}"
    )


@pytest.mark.a2_negative
def test_precision_placeholder_secret_values(tmp_path):
    """smoke/example/placeholder marker values are not secrets."""
    result = run_scan(tmp_path, {
        "scripts/smoke_runtime.py":
            'api_key = "sk-keyless-smoke"\n'
            'password = "my-example-value"\n',
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on placeholder secret values: "
        f"{[(f['rule'], f['line']) for f in result.get('findings', [])]}"
    )


@pytest.mark.a2_negative
def test_precision_os_introspection_not_process_execution(tmp_path):
    """platform.system() / Message.system() are not command execution."""
    result = run_scan(tmp_path, {
        "sample_osinfo.py":
            "import platform\nos_name = platform.system().lower()\n"
            "class Message:\n"
            "    @staticmethod\n"
            "    def system(text):\n"
            "        return text\n"
            "messages.append(Message.system('hi'))\n",
    })
    assert not result.get("findings"), (
        f"FALSE POSITIVE on OS introspection/builders: "
        f"{[(f['rule'], f['line']) for f in result.get('findings', [])]}"
    )
