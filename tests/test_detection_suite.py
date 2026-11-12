"""Detection capability suite (external FP audit wave — packages A-1 / A-2).

Measures ACTUAL current behavior of `mizan scan` end-to-end (real CLI,
real subprocess) against the acceptance table of the audit memo:

A-1 positives  : each sample MUST be detected under its expected rule id.
A-2 negatives  : each sample MUST produce ZERO findings.

Pure unittest (repo CI contract: `python -m unittest discover -s tests`);
also runs green under pytest.

Rule-id note: the memo expects `subprocess-shell`; the registry's actual
id for `subprocess.run(x, shell=True)` is `shell-true` (mizan.plugins).
Rules `unsafe-deserialization`, `yaml-unsafe-load`, `sql-injection`,
`path-traversal`, `weak-crypto` were MISSING in v0.8.3 — the v0.9.0 wave
added them; this suite is their acceptance + precision guard.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_scan(root: Path):
    """Run the real CLI scan on `root` and return the parsed JSON report."""
    proc = subprocess.run(
        [sys.executable, "-m", "mizan.cli", "scan", str(root),
         "--format", "json"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode in (0, 1), (
        f"scan crashed (rc={proc.returncode})\nSTDERR:\n{proc.stderr}"
    )
    return json.loads(proc.stdout)


def scan_files(files: dict):
    """Write `files` (relative path -> content) into a temp dir and scan."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return run_scan(root)


def fired_rules(result) -> set:
    return {f["rule"] for f in result.get("findings", [])}


# A-1 positive samples: (case, rel path, code, expected rule)
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
     "user = input()\n"
     "cursor.execute(\"SELECT * FROM users WHERE name='\" + user + \"'\")\n",
     "sql-injection"),
    ("sql-self-concat", "sample_sql_self.py",
     "user = input()\n"
     "self.cursor.execute(\"SELECT * FROM users WHERE name='%s'\" % user)\n",
     "sql-injection"),
    ("sql-fstring-value", "sample_fsql.py",
     "name = input()\n"
     "cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n",
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
    ("hardcoded-secret-mixed-ref", "sample_mixed_secret.py",
     'password = "Bearer $REAL_TOKEN"\n'
     'deploy_key = "prefix-$VAR-suffix"\n',
     "hardcoded-secret-candidate"),
    ("eval-dynamic", "sample_eval.py",
     "user_input = input()\neval(user_input)\n",
     "dynamic-execution"),
]

# A-2 negative samples: (case, rel path, content) -> MUST be zero findings
NEGATIVES = [
    ("yaml-safe", "safe_yaml.py",
     "import yaml\nwith open('cfg.yaml') as f:\n"
     "    cfg = yaml.safe_load(f)\n"),
    ("yaml-safeloader", "safe_yaml2.py",
     "import yaml\nwith open('cfg.yaml') as f:\n"
     "    cfg = yaml.load(f, Loader=yaml.SafeLoader)\n"),
    ("subprocess-list", "safe_subproc.py",
     "import subprocess\nsubprocess.run(['ls', '-la'])\n"),
    ("plain-open", "plain_open.py",
     "with open('config.txt') as f:\n    data = f.read()\n"),
    ("strong-hash", "safe_hash.py",
     "import hashlib\nhashlib.sha256(b'data')\n"),
    ("usedforsecurity-false", "safe_md5.py",
     "import hashlib\nhashlib.md5(b'data', usedforsecurity=False)\n"),
    ("safe-deserializers", "safe_deser.py",
     "import json\n"
     "data = json.loads(raw)\n"),
    ("i18n-json", "i18n/ar.json",
     '{"password": "كلمة المرور", "token": "رمز الدخول"}\n'),
    ("test-fixture", "tests/test_x.py",
     'def test_login():\n    password = "test123456"\n    assert password\n'),
    ("vendored-min-js", "vendor/lib.min.js",
     'var e=eval("1+2");document.write(e);\n'),
    ("js-exec-comments-regexp", "lib/exec_notes.ts",
     "// The launcher to probe and exec (test hook over the system).\n"
     "const m = /^(?<p>x)$/.exec(argument)\n"),
    ("js-ts-signature", "lib/types.ts",
     "interface Runner {\n"
     "  exec(file: string, args: string[]): string\n"
     "}\n"),
    ("sql-identifier-fstring", "store.py",
     "class Store:\n"
     "    table = 'items'\n"
     "    def init(self):\n"
     "        self._conn.execute(\n"
     "            f\"CREATE TABLE IF NOT EXISTS {self.table} "
     "(id TEXT UNIQUE)\"\n"
     "        )\n"),
    ("sql-pragma-constant", "pragma.py",
     "SCHEMA_VERSION = 3\n"
     "conn.execute(f\"PRAGMA user_version = {SCHEMA_VERSION}\")\n"),
    ("os-introspection", "osinfo.py",
     "import platform\nos_name = platform.system().lower()\n"
     "class Message:\n"
     "    @staticmethod\n"
     "    def system(text):\n"
     "        return text\n"
     "messages.append(Message.system('hi'))\n"),
    ("placeholder-secrets", "scripts/smoke_runtime.py",
     'api_key = "sk-keyless-smoke"\n'
     'password = "my-example-value"\n'
     'token = "CHANGEME"\n'),
    ("env-reference-secrets", "env_passed.py",
     'password = "$MIZAN_PR_TOKEN"\n'
     'db_token = "${DB_PASS}"\n'
     'api_token = "$GITHUB_PERSONAL_ACCESS_TOKEN"\n'
     "helper = 'echo password=\"$MIZAN_PR_TOKEN\"; f'\n"),
]


class DetectionSuiteTests(unittest.TestCase):

    def test_a1_positives_detected(self):
        for case, rel, code, expected in POSITIVES:
            with self.subTest(case=case, expected=expected):
                result = scan_files({rel: code})
                rules = fired_rules(result)
                self.assertIn(
                    expected, rules,
                    f"[{case}] expected '{expected}', fired: {sorted(rules)}")

    def test_a2_negatives_zero_findings(self):
        for case, rel, content in NEGATIVES:
            with self.subTest(case=case):
                result = scan_files({rel: content})
                hits = [
                    (f["rule"], f["file"], f["line"])
                    for f in result.get("findings", [])
                ]
                self.assertEqual(
                    [], result.get("findings", []),
                    f"[{case}] FALSE POSITIVE: {hits}")

    def test_a2_tayf_real_scenario_i18n_ts(self):
        """The memo's tayf case: a .ts i18n dictionary — labels, not secrets.

        (The i18n/ar.json row above is trivially clean because .json is
        not a scanned extension; THIS .ts variant is the real FP driver.)
        """
        result = scan_files({
            "src/i18n/dictionary.ts":
                'export const dict = {\n'
                '  password: "كلمة المرور",\n'
                '  api_key: "مفتاح الواجهة",\n'
                '  token: "رمز الدخول",\n'
                '};\n',
        })
        self.assertEqual([], result.get("findings", []))

    def test_precision_js_real_eval_still_detected(self):
        """The JS boundary fix must NOT disable real dynamic execution."""
        result = scan_files({"lib/dangerous.js": "const out = eval(ui);\n"})
        self.assertIn("dynamic-execution", fired_rules(result))


if __name__ == "__main__":
    unittest.main()
