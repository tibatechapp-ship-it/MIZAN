"""Bandit-parity wave 1 acceptance suite (docs/BANDIT_PARITY.md).

Contract under test: nine Bandit rules ADOPTED by reimplementation in the
MIZAN AST engine (no Bandit code copied — Apache-2.0 Bandit semantics,
MIT MIZAN code). Each rule gets:

  A-1 positive : the dangerous construct MUST fire under its rule id.
  A-2 negative : the mitigated / out-of-scope construct MUST NOT fire.

Plus two structural guards:

  A-3 registry : every adopted rule id is registered in mizan.plugins.
  A-4 severity : the documented severity classification is locked.

Two execution layers, mirroring tests/test_detection_suite.py:

  unit : mizan.analyzer.analyze_file() directly (fast, per-case precise);
  e2e  : the real CLI (`python -m mizan.cli scan`, real subprocess).

Pure unittest (repo CI contract: `python -m unittest discover -s tests`);
also runs green under pytest.

Deviations from Bandit recall asserted here as NEGATIVES (documented in
docs/BANDIT_PARITY.md, "Deviations" section): session receivers out of
B113 scope, weights_only=True exempts torch.load, filter="data"/"tar"
exempts extractall, zipfile receivers out of B202 scope (direct calls,
assignments AND with-bindings), /tmp literals in docstrings and bare
expressions are not flagged while list/tuple ARGUMENT elements are.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mizan.analyzer import analyze_file  # noqa: E402
from mizan.plugins import list_plugins  # noqa: E402

WAVE1_RULES = frozenset({
    "tls-verification-disabled",       # B501-equiv
    "ssl-unverified-context",          # B323-equiv
    "request-without-timeout",         # B113-equiv
    "torch-unsafe-load",               # B614-equiv
    "hf-trust-remote-code",            # B615-equiv (trust_remote_code)
    "jinja2-autoescape-false",         # B701-equiv
    "django-mark-safe",                # B703-equiv
    "tarfile-extractall",              # B202-equiv
    "hardcoded-tmp-path",              # B108-equiv
})

WAVE2_RULES = frozenset({
    "hardcoded-bind-all-interfaces",   # B104-equiv
    "flask-debug-enabled",             # B201-equiv
    "paramiko-exec-command",           # B601-equiv
    "telnetlib-import",                # B401-equiv
    "ftplib-import",                   # B402-equiv
    "ssl-insecure-version",            # B502+B503-equiv
    "hf-unpinned-download",            # B615 expansion
})


def analyze_code(code: str, filename: str = "sample_case.py"):
    """Run the real analyzer on `code` inside a temp repo; return findings."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        path = root / filename
        path.write_text(code, encoding="utf-8")
        return analyze_file(path, root)


def fired_rules(code: str) -> set:
    return {f["rule"] for f in analyze_code(code)}


# A-1 positives: (case, code, expected rule)
POSITIVES = [
    ("b501-verify-false",
     "import requests\n"
     "r = requests.get('https://svc.internal/api', timeout=5, verify=False)\n",
     "tls-verification-disabled"),
    ("b323-unverified-context",
     "import ssl\n"
     "ctx = ssl._create_unverified_context()\n",
     "ssl-unverified-context"),
    ("b113-no-timeout",
     "import requests\n"
     "r = requests.get('https://svc.internal/api')\n",
     "request-without-timeout"),
    ("b614-torch-load",
     "import torch\n"
     "model = torch.load('ckpt.pt')\n",
     "torch-unsafe-load"),
    ("b615-trust-remote-code",
     "from transformers import AutoModel\n"
     "m = AutoModel.from_pretrained('org/name', trust_remote_code=True)\n",
     "hf-trust-remote-code"),
    ("b701-autoescape-false",
     "import jinja2\n"
     "env = jinja2.Environment(autoescape=False)\n",
     "jinja2-autoescape-false"),
    ("b703-mark-safe",
     "from django.utils.safestring import mark_safe\n"
     "html = mark_safe(user_html)\n",
     "django-mark-safe"),
    ("b202-extractall",
     "import tarfile\n"
     "tar = tarfile.open('bundle.tgz')\n"
     "tar.extractall()\n",
     "tarfile-extractall"),
    ("b108-tmp-arg",
     "import os\n"
     "entries = os.listdir('/tmp/app-cache')\n",
     "hardcoded-tmp-path"),
    ("b108-tmp-assign",
     "cache_dir = '/var/tmp/app-cache'\n",
     "hardcoded-tmp-path"),
    ("b108-tmp-list-arg",
     "import subprocess\n"
     "subprocess.run(['ls', '/tmp/app-cache'])\n",
     "hardcoded-tmp-path"),
    # -- wave 2 -------------------------------------------------------
    ("b104-bind-arg",
     "import socket\n"
     "sock.bind(('0.0.0.0', 8080))\n",
     "hardcoded-bind-all-interfaces"),
    ("b104-bind-assign",
     "HOST = '0.0.0.0'\n",
     "hardcoded-bind-all-interfaces"),
    ("b104-bind-kwarg",
     "uvicorn.run(app, host='0.0.0.0', port=8080)\n",
     "hardcoded-bind-all-interfaces"),
    ("b104-bind-getenv-default",
     "import os\n"
     "host = os.getenv('HOST', '0.0.0.0')\n",
     "hardcoded-bind-all-interfaces"),
    ("b201-flask-debug",
     "app.run(debug=True)\n",
     "flask-debug-enabled"),
    ("b601-paramiko-exec",
     "client.exec_command('ls -la')\n",
     "paramiko-exec-command"),
    ("b401-telnetlib",
     "import telnetlib\n"
     "tn = telnetlib.Telnet('legacy.host')\n",
     "telnetlib-import"),
    ("b402-ftplib",
     "from ftplib import FTP\n"
     "f = FTP('host')\n",
     "ftplib-import"),
    ("b502-ssl-wrap-bad-version",
     "import ssl\n"
     "sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv3)\n",
     "ssl-insecure-version"),
    ("b503-ssl-context-bad-default",
     "import ssl\n"
     "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n",
     "ssl-insecure-version"),
    ("b615-hf-unpinned-method",
     "from transformers import AutoModel\n"
     "m = AutoModel.from_pretrained('org/name')\n",
     "hf-unpinned-download"),
    ("b615-hf-unpinned-bare",
     "from datasets import load_dataset\n"
     "ds = load_dataset('squad')\n",
     "hf-unpinned-download"),
    ("b615-hf-revision-main",
     "from datasets import load_dataset\n"
     "ds = load_dataset('squad', revision='main')\n",
     "hf-unpinned-download"),
    ("b615-hf-revision-none",
     "from datasets import load_dataset\n"
     "ds = load_dataset('squad', revision=None)\n",
     "hf-unpinned-download"),
]

# A-2 negatives: (case, code, expected rule that must NOT fire)
NEGATIVES = [
    ("b113-mitigated-timeout+verify-true",
     "import requests\n"
     "r = requests.get('https://svc.internal/api', timeout=5, verify=True)\n",
     {"request-without-timeout", "tls-verification-disabled"}),
    ("b113-session-receiver-out-of-scope",
     "session = build_session()\n"
     "r = session.get('https://svc.internal/api')\n",
     {"request-without-timeout"}),
    ("b323-default-context",
     "import ssl\n"
     "ctx = ssl.create_default_context()\n",
     {"ssl-unverified-context"}),
    ("b614-mitigated-weights-only",
     "import torch\n"
     "model = torch.load('ckpt.pt', weights_only=True)\n",
     {"torch-unsafe-load"}),
    ("b615-no-trust-remote-code",
     "from transformers import AutoModel\n"
     "m = AutoModel.from_pretrained('org/name')\n",
     {"hf-trust-remote-code"}),
    ("b701-autoescape-true",
     "import jinja2\n"
     "env = jinja2.Environment(autoescape=True)\n",
     {"jinja2-autoescape-false"}),
    ("b202-pep706-filter-data",
     "import tarfile\n"
     "tar = tarfile.open('bundle.tgz')\n"
     "tar.extractall(filter='data')\n",
     {"tarfile-extractall"}),
    ("b202-zipfile-out-of-scope",
     "import zipfile\n"
     "zf = zipfile.ZipFile('bundle.zip')\n"
     "zf.extractall()\n",
     {"tarfile-extractall"}),
    ("b202-with-zipfile-binding-out-of-scope",
     "import zipfile\n"
     "with zipfile.ZipFile('bundle.zip') as zf:\n"
     "    zf.extractall()\n",
     {"tarfile-extractall"}),
    ("b108-docstring-not-flagged",
     "def render(s):\n"
     "    \"\"\"Examples use /tmp/demo.txt as the scratch path.\"\"\"\n"
     "    return s\n",
     {"hardcoded-tmp-path"}),
    ("b108-segment-boundary",
     "scratch = '/tmpfile'\n",
     {"hardcoded-tmp-path"}),
    ("b703-similar-name-not-flagged",
     "from app.html import mark_safe_ex\n"
     "html = mark_safe_ex(user_html)\n",
     {"django-mark-safe"}),
    ("b501-dict-value-not-call-kwarg",
     "config = {'verify': False}\n",
     {"tls-verification-disabled"}),
    # -- wave 2 -------------------------------------------------------
    ("b104-loopback-quiet",
     "import socket\n"
     "sock.bind(('127.0.0.1', 8080))\n",
     {"hardcoded-bind-all-interfaces"}),
    ("b104-similar-strings-quiet",
     "PROXY = '0.0.0.1'\n"
     "ADDR = '::1'\n",
     {"hardcoded-bind-all-interfaces"}),
    ("b104-ipv6-fragments-quiet",
     "addr = address.split('::', 1)\n"
     "plain = address.startswith('::')\n",
     {"hardcoded-bind-all-interfaces"}),
    ("b104-ipv6-only-quiet",
     "ADDR = '::'\n",
     {"hardcoded-bind-all-interfaces"}),
    ("b201-debug-false-quiet",
     "app.run(debug=False)\n",
     {"flask-debug-enabled"}),
    ("b201-no-debug-quiet",
     "app.run(port=8080)\n",
     {"flask-debug-enabled"}),
    ("b201-bare-run-not-attribute",
     "run(debug=True)\n",
     {"flask-debug-enabled"}),
    ("b601-other-method-quiet",
     "client.exec_api('ls')\n",
     {"paramiko-exec-command"}),
    ("b601-bare-quiet",
     "exec_command('ls')\n",
     {"paramiko-exec-command"}),
    ("b401-telnetlib3-quiet",
     "import telnetlib3\n",
     {"telnetlib-import"}),
    ("b402-unrelated-imports-quiet",
     "import paramiko\n"
     "import ftplibish\n",
     {"ftplib-import", "telnetlib-import"}),
    ("b502-modern-tls-quiet",
     "import ssl\n"
     "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n",
     {"ssl-insecure-version"}),
    ("b502-default-context-quiet",
     "import ssl\n"
     "ctx = ssl.create_default_context()\n",
     {"ssl-insecure-version", "ssl-unverified-context"}),
    ("b502-from-import-bare-quiet",
     "from ssl import PROTOCOL_SSLv3\n"
     "v = PROTOCOL_SSLv3\n",
     {"ssl-insecure-version"}),
    ("b615-pinned-commit-quiet",
     "from transformers import AutoModel\n"
     "m = AutoModel.from_pretrained('org/name', revision='e7a1b2c3')\n",
     {"hf-unpinned-download"}),
    ("b615-dynamic-revision-quiet",
     "from datasets import load_dataset\n"
     "ds = load_dataset('squad', revision=cfg['rev'])\n",
     {"hf-unpinned-download"}),
    ("b615-bare-from-pretrained-quiet",
     "from_pretrained('m')\n",
     {"hf-unpinned-download"}),
    ("b615-seaborn-local-loader-quiet",
     "import seaborn as sns\n"
     "mpg = sns.load_dataset('mpg')\n",
     {"hf-unpinned-download"}),
    ("b615-offline-builder-quiet",
     "from datasets import load_dataset\n"
     "ds = load_dataset('json', data_files='rows.jsonl')\n",
     {"hf-unpinned-download"}),
]


class TestBanditParityPositives(unittest.TestCase):
    """A-1: every adopted rule fires on its dangerous construct."""

    def test_positive_fires(self):
        for case, code, expected in POSITIVES:
            with self.subTest(case=case):
                self.assertIn(expected, fired_rules(code),
                              f"{case}: expected {expected} to fire")

    def test_positive_severities_match_documented_contract(self):
        severity_by_rule = {
            "tls-verification-disabled": "high",
            "ssl-unverified-context": "high",
            "request-without-timeout": "low",
            "torch-unsafe-load": "high",
            "hf-trust-remote-code": "high",
            "jinja2-autoescape-false": "high",
            "django-mark-safe": "medium",
            "tarfile-extractall": "high",
            "hardcoded-tmp-path": "low",
            "hardcoded-bind-all-interfaces": "medium",
            "flask-debug-enabled": "high",
            "paramiko-exec-command": "medium",
            "telnetlib-import": "high",
            "ftplib-import": "high",
            "ssl-insecure-version": "high",
            "hf-unpinned-download": "medium",
        }
        severities = {f["rule"]: f["severity"] for f in analyze_code(
            "\n".join(code for _, code, _ in POSITIVES))}
        for rule, severity in severity_by_rule.items():
            self.assertEqual(severities.get(rule), severity,
                             f"{rule}: severity contract drifted")


class TestBanditParityNegatives(unittest.TestCase):
    """A-2: mitigated / out-of-scope constructs never fire (precision)."""

    def test_negative_does_not_fire(self):
        for case, code, forbidden in NEGATIVES:
            with self.subTest(case=case):
                fired = fired_rules(code)
                overlap = fired & forbidden
                self.assertFalse(overlap,
                                 f"{case}: {sorted(overlap)} fired unexpectedly")


class TestBanditParityRegistry(unittest.TestCase):
    """A-3: adopted rules are registered built-ins."""

    def test_wave1_rules_registered(self):
        registered = {r for p in list_plugins() for r in p["rules"]}
        missing = WAVE1_RULES - registered
        self.assertFalse(missing, f"unregistered wave-1 rules: {sorted(missing)}")

    def test_wave2_rules_registered(self):
        registered = {r for p in list_plugins() for r in p["rules"]}
        missing = WAVE2_RULES - registered
        self.assertFalse(missing, f"unregistered wave-2 rules: {sorted(missing)}")


class TestBanditParityEndToEnd(unittest.TestCase):
    """A-1/A-2 through the real CLI (real subprocess, JSON report)."""

    POSITIVE_FILE = (
        "import requests\n"
        "import ssl\n"
        "import torch\n"
        "from transformers import AutoModel\n"
        "\n"
        "r1 = requests.get('https://svc.internal/api', timeout=5, verify=False)\n"
        "ctx = ssl._create_unverified_context()\n"
        "model = torch.load('ckpt.pt')\n"
        "m = AutoModel.from_pretrained('org/name', trust_remote_code=True)\n"
    )

    NEGATIVE_FILE = (
        "import requests\n"
        "import torch\n"
        "r1 = requests.get('https://svc.internal/api', timeout=5)\n"
        "model = torch.load('ckpt.pt', weights_only=True)\n"
    )

    def run_cli_scan(self, files: dict) -> dict:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for rel, content in files.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
            proc = subprocess.run(
                [sys.executable, "-m", "mizan.cli", "scan", str(root),
                 "--format", "json"],
                capture_output=True, text=True, timeout=120, env=env,
            )
            self.assertIn(proc.returncode, (0, 1),
                          f"scan crashed (rc={proc.returncode})\n{proc.stderr}")
            return json.loads(proc.stdout)

    def test_end_to_end_positives_reach_the_report(self):
        result = self.run_cli_scan({"sample_e2e_pos.py": self.POSITIVE_FILE})
        fired = {f["rule"] for f in result.get("findings", [])}
        for rule in ("tls-verification-disabled", "ssl-unverified-context",
                     "torch-unsafe-load", "hf-trust-remote-code"):
            self.assertIn(rule, fired, f"CLI report missed {rule}")

    def test_end_to_end_negatives_stay_silent(self):
        result = self.run_cli_scan({"sample_e2e_neg.py": self.NEGATIVE_FILE})
        fired = {f["rule"] for f in result.get("findings", [])}
        overlap = fired & WAVE1_RULES
        self.assertFalse(overlap,
                         f"CLI report fired wave-1 rules on clean code: "
                         f"{sorted(overlap)}")

    WAVE2_POSITIVE_FILE = (
        "import socket\n"
        "import ssl\n"
        "import telnetlib\n"
        "\n"
        "sock = socket.socket()\n"
        "sock.bind(('0.0.0.0', 8080))\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n"
        "tn = telnetlib.Telnet('legacy.host')\n"
    )

    WAVE2_NEGATIVE_FILE = (
        "import socket\n"
        "import ssl\n"
        "\n"
        "sock = socket.socket()\n"
        "sock.bind(('127.0.0.1', 8080))\n"
        "ctx = ssl.create_default_context()\n"
    )

    def test_wave2_end_to_end_positives_reach_the_report(self):
        result = self.run_cli_scan({"sample_wave2_pos.py": self.WAVE2_POSITIVE_FILE})
        fired = {f["rule"] for f in result.get("findings", [])}
        for rule in ("hardcoded-bind-all-interfaces", "ssl-insecure-version",
                     "telnetlib-import"):
            self.assertIn(rule, fired, f"CLI report missed {rule}")

    def test_wave2_end_to_end_negatives_stay_silent(self):
        result = self.run_cli_scan({"sample_wave2_neg.py": self.WAVE2_NEGATIVE_FILE})
        fired = {f["rule"] for f in result.get("findings", [])}
        overlap = fired & WAVE2_RULES
        self.assertFalse(overlap,
                         f"CLI report fired wave-2 rules on clean code: "
                         f"{sorted(overlap)}")


if __name__ == "__main__":
    unittest.main()
