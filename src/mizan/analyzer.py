"""Read-only static source analyzer.

v0.9.0 — precision wave (external FP audit, 20 real repositories):

P0 — noise reduction (456 findings -> target <50 real):
  * EXCLUDE_PATTERNS: test fixtures, vendored bundles, i18n/locales,
    docs/legacy, *.min.js / *.bundle.js are skipped entirely — code you
    did not write and data that is not code are not your attack surface.
  * hardcoded-secret-candidate: placeholder/dictionary values
    ("password = 'hardcoded'", "apiKey = 'test123456'") no longer fire.
  * dynamic-execution on JS/TS: the naive per-line `eval|exec` regex
    matched RegExp.prototype.exec() 230 times on ONE repository. The
    pattern now requires a bare call boundary (no `.method(` / word
    prefix), so regex engines keep working while real eval() still fires.
  * process-execution: only os.system / os.popen (qualified or imported
    bare) fire — Message.system(...) / platform.system() are builders and
    OS introspection, not command execution.

P1 — the five missing detection rules (each with positive + negative
coverage in tests/test_detection_suite.py):
  unsafe-deserialization, yaml-unsafe-load, sql-injection,
  path-traversal, weak-crypto.

v0.13.0 — Bandit-parity wave 1 (docs/BANDIT_PARITY.md):
  Nine rules adopted by REIMPLEMENTATION in this AST engine — no Bandit
  code copied; rule semantics informed by the Apache-2.0 Bandit project:
  tls-verification-disabled (B501), ssl-unverified-context (B323),
  request-without-timeout (B113), torch-unsafe-load (B614),
  hf-trust-remote-code (B615), jinja2-autoescape-false (B701),
  django-mark-safe (B703), tarfile-extractall (B202),
  hardcoded-tmp-path (B108). B101/B110/B112/B311/B607 are deliberately
  rejected as structural noise; every deviation from Bandit recall is
  documented in docs/BANDIT_PARITY.md.

v0.15.0-dev — Bandit-parity wave 2 (docs/BANDIT_PARITY.md):
  Severity/confidence re-verified per-check from bandit.readthedocs.io
  before each decision. Adopted: hardcoded-bind-all-interfaces (B104,
  M/M), flask-debug-enabled (B201, H/H), paramiko-exec-command (B601,
  M/M), telnetlib-import (B401, high), ftplib-import (B402, high),
  ssl-insecure-version (B502 H/H + B503 M/M; the B504 no-version LOW
  case is rejected as modern-defaults noise), and hf-unpinned-download
  (B615 expansion — the wave-1 deferred candidate, adopted through the
  measured FP gate: 25 targets / 3,997 files, 71 raw hits hand-checked,
  6 false positives + 2 offline-builder calls found and the semantics
  corrected BEFORE adoption; final gate run: 62 hits, 0 false
  positives). Pre-existing parity
  recorded: B102/B307→dynamic-execution, B605→process-execution,
  B602→shell-true. Rejected: B105/B106/B107 (v0.14.0 narrowing),
  B603/B604/B606 (receiver-blind noise), B609 (B607 noise family).
  Deferred: B313-B320 XML/XXE and B704 Markup (need taint for
  precision), B508/B509, B610/B611, B612.

v0.15.0-dev — Bandit-parity wave 3 (docs/BANDIT_PARITY.md):
  Adopted through the same measured pipeline (severity/semantics
  verified verbatim from the per-check pages and plugin sources):
  weak-crypto-key-size (B505 — RSA/DSA high<1024/medium<2048, EC
  high<160/medium<224; constant-integer sizes only — dynamic, string
  and missing sizes stay quiet per the Bandit 2048 default; EC curves
  resolved through the Bandit curve registry, unknown curves quiet)
  and bidi-override-chars (B613 — Trojan Source, CVE-2021-42574; the
  BIDI_CHARACTERS tuple verified verbatim incl. U+200F; text-level
  check extended from Python-only to every scannable language —
  documented MIZAN extension). Wave-3 FP gate: 25 targets, 8 hits
  hand-checked with raw-codepoint dumps — 0 structural false
  positives, 8 context-dependent (defensive bidi-sanitizer
  definitions in one field repo); weak-crypto measured-zero by
  absence. 603 tests green.

v0.14.0-dev — taint-analysis proof of concept (docs/ROADMAP.md P1.2):
  Module ``taint.py`` propagates two measured source families (input():
  ``input()``/``sys.argv``; request: ``request.<data-attr>`` chains) to
  plain-name taint sets, and two new dataflow rules fire ONLY on a
  confirmed source-to-sink path: ``request-to-sql`` (high) and
  ``input-to-subprocess`` (high). The shallow single-pass
  _collect_input_taints is replaced by the fixpoint engine (path-traversal
  recall deepens; behavior remains additive — no existing finding is
  removed).
"""

import ast
import fnmatch
import os
import re
from pathlib import Path

from ._version import __version__
from . import taint as _taint
from .custom_rules import apply_custom_rules, load_custom_rules

IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build",
    ".mypy_cache", ".pytest_cache",
    # v0.9.0 P0: non-source trees — fixtures/vendored/i18n are not your
    # attack surface (external FP audit: 20 real repositories).
    "__tests__", "tests", "vendor", "i18n", "locales", "translations",
}

# v0.9.0 P0: file-level exclusions (relative posix path or basename).
EXCLUDE_GLOBS = (
    "*/tests/*", "*/test_*.py", "*/__tests__/*",
    "*/vendor/*", "*/node_modules/*", "*/dist/*", "*/build/*",
    "*/i18n/*", "*/locales/*", "*/translations/*",
    "*/docs/legacy/*", "docs/legacy/*",
    "*.min.js", "*.bundle.js",
)

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".go", ".rs", ".php", ".rb"
}

SECRET_PATTERN = re.compile(
    r"""(?i)\b(?:[a-z0-9]+[_-])+(api[_-]?key|secret|password|token)\b
    \s*(?::?=|:)\s*["'](?P<value>[^"']{8,})["']""",
    re.VERBOSE
)

# Same shape with the bare keyword (PASSWORD = ... / token = ...).
SECRET_PATTERN_BARE = re.compile(
    r"""(?i)\b(api[_-]?key|secret|password|token)\b
    \s*(?::?=|:)\s*["'](?P<value>[^"']{8,})["']""",
    re.VERBOSE
)

# v0.9.0 P0: values that are placeholders / dictionary words, not secrets.
PLACEHOLDER_VALUES = frozenset({
    "password", "password1", "password123", "passwort", "motdepasse",
    "changeme", "change_me", "change-me", "example", "examples",
    "sample", "placeholder", "dummy", "fake", "hardcoded", "redacted",
    "todo", "tbd", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx",
    "xxxxxxxx", "12345678", "123456789", "1234567890", "qwertyuiop",
    "api_key", "apikey", "api-key", "token", "secret",
    "my_password", "your_password", "your-password",
    "your_api_key", "your-api-key", "your_secret", "your-secret",
    "none", "null", "undefined", "test", "test123456", "test123",
    "topsecret", "top_secret", "sup3rs3cret",
})

TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX)\s*:")

# Lines that are pure comments in non-Python sources — eval/exec mentioned
# in prose ("to probe and exec (test hook)") is documentation, not code.
NONPY_COMMENT_PREFIXES = ("//", "/*", "*", "#", "<!--")

# TypeScript/flow method SIGNATURES ("exec(file: string): string") are
# declarations — a call expression never ends in `): Type`.
NONPY_SIGNATURE_PATTERN = re.compile(
    r"^\s*[A-Za-z_$][\w$]*\s*\(.*\)\s*:\s*[A-Za-z_$][\w$<>\[\].|\s]*$"
)

# v0.9.0 P0: bare-call boundary only — `(?<![.\w$])` rejects RegExp
# `.exec(` / `obj.eval(` method calls that produced 288 false positives.
NONPY_EVAL_PATTERN = re.compile(r"(?<![A-Za-z0-9_.$])(eval|exec)\s*\(")

# Substrings that mark a value as obviously non-secret.
PLACEHOLDER_MARKERS = ("example", "sample", "dummy", "fake",
                       "placeholder", "smoke", "lorem", "redact")

# v0.9.0 P1: modules whose (de)serializers yield arbitrary code execution.
UNSAFE_DESERIALIZERS = frozenset({
    "pickle", "cPickle", "marshal", "dill", "shelve",
})

# v0.14.0 field-measured (2026-11-08, 50-repo scan-remote campaign):
# 2999/3374 (89%) of hardcoded-secret-candidate and 272/387 (70%) of
# dynamic-execution findings sit in test-fixture paths. Test fixtures are
# not credential leaks and not production dynamic execution. The finding
# STAYS in the report (fail-loud contract intact — nothing is dropped)
# but its severity is downgraded to "low" so gates stay signal-bearing.
TEST_PATH_PATTERN = re.compile(
    r"(^|/)(tests?|__tests__|specs?|fixtures|smoke|mocks?|testdata)(/|\.|$)"
    r"|\.(test|spec)\.[a-z]+$|_test\.[a-z]+$|(^|/)test_[^/]*\.py$"
)

# The two line-regex rules whose field FP population is dominated by test
# fixtures — the only rules the test-path downgrade applies to.
TEST_DOWNGRADED_RULES = frozenset({
    "hardcoded-secret-candidate", "dynamic-execution",
})

# v0.13.0 Bandit-parity wave 1 (B113-equiv): HTTP verb methods audited for
# a missing `timeout` keyword on literal `requests.*` receivers.
HTTP_VERB_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "request",
})

# v0.13.0: PEP 706 tarfile extraction filters that neutralize path
# traversal / symlink attacks (B202-equiv mitigation).
TARFILE_SAFE_FILTERS = frozenset({"data", "tar"})

# v0.15.0-dev Bandit-parity wave 2 (docs/BANDIT_PARITY.md).

# B104-equiv: bind-all interface literals — value positions only, same
# position discipline as B108 (call arguments, assignment values, one
# nesting level into list/tuple/set literals). Verified from the Bandit
# source: the exact literal "0.0.0.0" ONLY. The "::" IPv6 extension was
# measured and REJECTED by the wave-2 FP gate (4 false positives in one
# IPv6-validator file — string-manipulation arguments, not bind hosts).
BIND_ALL_INTERFACES = frozenset({"0.0.0.0"})

# B502/B503-equiv: weak SSL/TLS protocol versions. Qualified `ssl.*`
# references only (from-imported bare names are out of scope — same
# deviation family as B113; aliasing is not resolved).
WEAK_SSL_PROTOCOLS = frozenset({
    "PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
    "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
})

# B401/B402-equiv: stdlib plaintext-protocol modules, flagged at the
# import level (severity parity with Bandit's blacklist entries).
INSECURE_PROTOCOL_IMPORTS = {
    "telnetlib": "telnetlib-import",
    "ftplib": "ftplib-import",
}

# B615 expansion (the wave-1 deferred candidate, measured into adoption
# by the 24-repo FP gate): Hugging Face Hub entry points that download
# code/weights and must pin an immutable revision.
HF_DOWNLOAD_METHODS = frozenset({
    "from_pretrained", "load_dataset", "hf_hub_download",
    "snapshot_download",
})
# B615: function-style entry points are normally called BARE
# (`from datasets import load_dataset; load_dataset(...)`), so the bare
# Name-call form fires for them too. `from_pretrained` is a method call
# in real usage (AutoModel.from_pretrained) — the bare form does not
# fire (documented deviation).
HF_FUNCTION_STYLE = frozenset({
    "load_dataset", "hf_hub_download", "snapshot_download",
})
# B615: refs that do NOT pin a revision. A non-constant revision (e.g. a
# variable read from config) is treated as pinned — it cannot be proven
# mutable statically (documented deviation).
UNPINNED_REVISIONS = frozenset({None, "main"})

# -- v0.15.0-dev Bandit-parity wave 3 (docs/BANDIT_PARITY.md) --------

# B505-equiv: weak key sizes. Thresholds verified verbatim from the
# Bandit plugin config (weak_cryptographic_key.py gen_config):
# RSA/DSA high=1024, medium=2048; EC high=160, medium=224. HIGH below
# the lower threshold, MEDIUM between the two, quiet at/above medium.
WEAK_KEY_SIZE_THRESHOLDS = {
    "RSA": (1024, 2048),
    "DSA": (1024, 2048),
    "EC": (160, 224),
}

# B505 pycrypto/pycryptodome form: <Root>.PublicKey.<RSA|DSA>.generate
# (both package roots, per the Bandit qual table).
PYCRYPTO_KEY_ROOTS = frozenset({"Crypto", "Cryptodome"})

# B505 EC curve registry (Bandit curve_key_sizes, verbatim). Unknown
# curves default to 224 bits in Bandit — which classifies quiet — so
# only mapped curves below 224 can fire (SECP192R1 192, SECT163K1 163,
# SECT163R2 163 — all MEDIUM by the verified thresholds).
EC_CURVE_KEY_SIZES = {
    "SECT571K1": 571, "SECT571R1": 570, "SECP521R1": 521,
    "BrainpoolP512R1": 512, "SECT409K1": 409, "SECT409R1": 409,
    "BrainpoolP384R1": 384, "SECP384R1": 384, "SECT283K1": 283,
    "SECT283R1": 283, "BrainpoolP256R1": 256, "SECP256K1": 256,
    "SECP256R1": 256, "SECT233K1": 233, "SECT233R1": 233,
    "SECP224R1": 224, "SECP192R1": 192, "SECT163K1": 163,
    "SECT163R2": 163,
}

# B613-equiv: Trojan Source bidi control characters — the Bandit
# BIDI_CHARACTERS tuple verified verbatim from the plugin source
# (trojansource.py, versionadded 1.7.10): U+202A-E (embeddings and
# overrides), U+2066-2069 (isolates) and U+200F (RTL MARK).
# High/Medium per the per-check page; CWE-838.
BIDI_CHARS_RE = re.compile("[\u202a-\u202e\u2066-\u2069\u200f]")

# B615: measured wave-2 precision carve-outs (24-repo FP gate):
# - seaborn's sns.load_dataset / seaborn.load_dataset is a local CSV
#   loader, not a Hub download (2 measured false positives) — receivers
#   rooted at these names are out of scope.
# - load_dataset("json"|"csv"|"text"|"parquet", data_files=...) is the
#   OFFLINE builder idiom (measured: 2 sites, both local) — a constant
#   builder name as the first argument does not reach the Hub.
HF_NON_HUB_RECEIVERS = frozenset({"sns", "seaborn"})
LOCAL_DATASET_BUILDERS = frozenset({"json", "csv", "text", "parquet"})


def _is_placeholder(value: str) -> bool:
    """True when a secret-candidate value is a dictionary/placeholder word."""
    norm = value.strip().lower()
    compact = re.sub(r"[\s_-]+", "", norm)
    if norm in PLACEHOLDER_VALUES or compact in PLACEHOLDER_VALUES:
        return True
    # template/interpolation placeholders: '{{tools}}', '{token}' —
    # a credential is never a brace-wrapped slot name (field FP class,
    # seekfeek TOOLS_TOKEN site)
    if (norm.startswith("{{") and norm.endswith("}}")) or (
            norm.startswith("{") and norm.endswith("}")):
        return True
    if any(marker in norm for marker in PLACEHOLDER_MARKERS):
        return True
    # degenerate values: "********", "----------", "1111111111"
    return len(set(norm)) <= 2


# v0.15.0-dev: a PURE shell runtime variable reference ("$MIZAN_PR_TOKEN",
# "${DB_PASS}") dereferences at run time — nothing is hardcoded. This is
# the env-passing pattern MIZAN itself mandates for tokens (the git
# credential-helper protocol in repair.py), so it must not fire as a
# "hardcoded" candidate. Brace-wrapped slots ({var}) are already handled
# in _is_placeholder; anything beyond a single bare $reference — literal
# text around it ("Bearer $TOKEN", "prefix-$VAR-suffix") — still fires.
ENV_REFERENCE_PATTERN = re.compile(
    r"""^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}      # ${VAR} — braced shell/JS
        |\$[A-Za-z_][A-Za-z0-9_]*           # $VAR  — bare shell/JS
       )$""",
    re.VERBOSE,
)


def _is_env_reference(value: str) -> bool:
    """True when a secret-candidate value is a pure shell variable reference."""
    return bool(ENV_REFERENCE_PATTERN.fullmatch(value.strip()))


# A f-string interpolation sitting AFTER one of these tails is in a VALUE
# position (comparable / assignable) — that is where injection happens.
# Interpolation in identifier positions (FROM {table}, INTO {tbl}) is the
# standard way to bind configuration identifiers and is not flagged.
_SQL_VALUE_TAIL = re.compile(
    r"(?:=|==|!=|<>|\bLIKE\s|\bIN\s*\(|\bVALUES\s*\(|\bSET\s|,)\s*[\"']?\s*$"
)


def _is_placeholder_builder(node):
    """True for the dynamic IN-clause placeholder idiom: expressions that
    can only ever produce '?' text or an integer count — e.g.
    ``",".join("?" * len(STATUSES))``. Field-measured (v0.14.0, 2026-11-08
    campaign + MIZAN self-scan report/timeline.py:121): interpolating such
    values into a query that is already parameterized leaves nothing
    injectable, but the old rule flagged the site as high severity.
    Deliberately FALSE for every Name not tracked as builder-bound, every
    unknown call, and anything request-shaped — the taint rule
    (request-to-sql) still covers tainted sites.
    """
    if isinstance(node, ast.Call):
        func = node.func
        # len(...) always returns an int — a count cannot carry SQL syntax
        if isinstance(func, ast.Name) and func.id == "len" and len(node.args) == 1:
            return True
        # "sep".join(<builder parts>) — placeholder text assembly
        if (isinstance(func, ast.Attribute) and func.attr == "join"
                and isinstance(func.value, ast.Constant)
                and isinstance(func.value.value, str)
                and all(_is_placeholder_builder(a) for a in node.args)):
            return True
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left_q = (isinstance(node.left, ast.Constant)
                  and isinstance(node.left.value, str)
                  and set(node.left.value) <= {"?"})
        right_q = (isinstance(node.right, ast.Constant)
                   and isinstance(node.right.value, str)
                   and set(node.right.value) <= {"?"})
        if left_q and _is_placeholder_builder(node.right):
            return True
        if right_q and _is_placeholder_builder(node.left):
            return True
        return False
    if isinstance(node, ast.Constant):
        return (isinstance(node.value, str)
                and set(node.value) <= {"?"})
    return False


def _fstring_has_value_interpolation(node, placeholder_vars=None):
    """True when any f-string interpolation lands in a SQL value position
    and the interpolated expression is not an ALL_CAPS constant and not a
    placeholder-builder (dynamic IN-clause idiom, see
    _is_placeholder_builder / builder-bound names)."""
    placeholder_vars = placeholder_vars or set()
    literal_before = ""
    for part in node.values:
        if isinstance(part, ast.Constant):
            literal_before += str(part.value)
            continue
        # part is ast.FormattedValue
        expr = part.value
        expr_is_const = (
            isinstance(expr, ast.Name) and expr.id.isupper()
        ) or (
            isinstance(expr, ast.Attribute) and expr.attr.isupper()
        )
        expr_is_builder = (
            (isinstance(expr, ast.Name) and expr.id in placeholder_vars)
            or _is_placeholder_builder(expr)
        )
        if (not expr_is_const and not expr_is_builder
                and _SQL_VALUE_TAIL.search(literal_before)):
            return True
        literal_before = ""
    return False


class PythonSecurityVisitor(ast.NodeVisitor):
    """Detect security-sensitive Python constructs."""

    def __init__(self, tainted_names=None, zipfile_vars=None,
                 request_tainted=None, placeholder_vars=None):
        self.findings = []
        self.tainted_names = tainted_names or set()
        # v0.14.0-dev PoC: plain names tainted by ``request.*`` data
        # (Flask/Django request attributes), used by ``request-to-sql``.
        self.request_tainted = request_tainted or set()
        # v0.14.0: names bound to dynamic-IN placeholder builders (e.g.
        # placeholders = ",".join("?" * len(STATUSES))) — exempted from the
        # f-string sql-injection shape; pre-pass collected per file.
        self.placeholder_vars = placeholder_vars or set()
        # v0.13.0: variable names assigned from zipfile.* constructors —
        # B202-equiv scope carve-out (tar symlink traversal does not apply
        # to the zip format).
        self.zipfile_vars = zipfile_vars or set()

    def add(self, node, rule, severity, message):
        self.findings.append({
            "line": getattr(node, "lineno", 0),
            "rule": rule,
            "severity": severity,
            "message": message,
        })

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _root_name(node):
        """Root module name of an attribute chain: pickle.loads -> pickle."""
        while isinstance(node, ast.Attribute):
            node = node.value
        if isinstance(node, ast.Name):
            return node.id
        return None

    @staticmethod
    def _dotted_name(node):
        """Full dotted name of a Name/Attribute chain ("a.b.c") — None
        when any segment is not a plain name (calls, subscripts and
        other expressions break the chain, deliberately: they cannot be
        resolved statically and guessing would fabricate receivers)."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _kwarg(node, arg_name):
        """Keyword value for `arg_name` in a Call node, else None."""
        for kw in node.keywords:
            if kw.arg == arg_name:
                return kw.value
        return None

    @staticmethod
    def _is_sys_argv(node):
        """True for sys.argv expressions (root of a path-taint chain)."""
        if isinstance(node, ast.Subscript):
            node = node.value
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "argv"
            and isinstance(node.value, ast.Name)
            and node.value.id == "sys"
        )

    def _is_input_source(self, node):
        """True for input() calls and names derived from input()/sys.argv."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "input":
            return True
        if isinstance(node, ast.Name) and node.id in self.tainted_names:
            return True
        return self._is_sys_argv(node)

    # -- visitor ----------------------------------------------------------

    def visit_Call(self, node):
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr

        if name in {"eval", "exec", "compile", "__import__"}:
            # v0.12.3 — bare-call boundary on the Python AST path too.
            # The v0.9.0 JS/TS fix required a bare call boundary for the
            # same reason: a receiver call (PyTorch Module.eval(),
            # sqlite exec, re.compile, ...) is a method on an object,
            # not the builtins. The 100-repo field benchmark caught
            # AutoModel.from_pretrained(...).eval() flagged as dynamic
            # code execution in a real repository.
            # Golden-set wave (RULE_ACCURACY.md): bare compile() and
            # __import__() are dynamic code execution like eval/exec —
            # the bare-call boundary keeps re.compile / obj.compile
            # quiet. FIELD correction (10-repo run): __import__ with a
            # CONSTANT module name is the standard lazy-import idiom
            # (8/8 measured sites) — only a variable/computed module
            # name is code execution from data.
            if isinstance(node.func, ast.Name):
                if name == "__import__" and node.args and isinstance(
                        node.args[0], ast.Constant):
                    pass
                else:
                    self.add(
                        node, "dynamic-execution", "high",
                        "Dynamic code execution detected."
                    )

        # v0.9.0 P0: os.system / os.popen only — Message.system(...) and
        # platform.system() are not command execution.
        is_qualified_os = (
            isinstance(node.func, ast.Attribute)
            and name in {"system", "popen"}
            and (
                (isinstance(node.func.value, ast.Name)
                 and node.func.value.id == "os")
                or (isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "os")
            )
        )
        is_bare = isinstance(node.func, ast.Name) and name in {"system", "popen"}
        if is_qualified_os or is_bare:
            self.add(
                node, "process-execution", "medium",
                "Process execution requires security review."
            )

        # Golden-set wave: shell=True is a shell boundary on EVERY
        # subprocess launcher, not only .run — call/Popen/check_call/
        # check_output/getoutput carry the identical injection risk
        # (Bandit B602/B603 family). Receiver must be subprocess-rooted:
        # obj.run(shell=True) on arbitrary objects is not a shell.
        if (
            name in {"run", "Popen", "call", "check_call", "check_output",
                     "getoutput", "getstatusoutput"}
            and isinstance(node.func, ast.Attribute)
            and self._root_name(node.func.value) == "subprocess"
        ):
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    self.add(
                        node, "shell-true", "high",
                        "Subprocess shell execution may introduce "
                        "command injection risks."
                    )

        # v0.14.0-dev PoC — flow 2 (input()/sys.argv -> subprocess):
        # fires ONLY on a confirmed source-to-sink path, so a clean
        # subprocess call produces nothing (precision by construction).
        # Escalates os.system/os.popen sites that already carry
        # process-execution medium: tainted data makes them high.
        if (
            (
                isinstance(node.func, ast.Attribute)
                and self._root_name(node.func) == "subprocess"
                and name in {"run", "Popen", "call", "check_call",
                             "check_output", "getoutput", "getstatusoutput"}
            )
            or is_qualified_os or is_bare
        ):
            for arg in node.args:
                if _taint.expr_tainted(arg, self.tainted_names,
                                       _taint.is_input_source):
                    self.add(
                        node, "input-to-subprocess", "high",
                        "Command string reaches a process sink from "
                        "input()/sys.argv — injection path confirmed by "
                        "dataflow."
                    )
                    break

        # -- v0.9.0 P1 rules ---------------------------------------------

        # unsafe-deserialization: pickle.loads / dill.load / marshal.loads…
        # Golden-set wave: shelve.open deserializes values via pickle on
        # access — same arbitrary-code family, added to recall.
        deser_root = (
            self._root_name(node.func.value)
            if isinstance(node.func, ast.Attribute) else None
        )
        if (
            isinstance(node.func, ast.Attribute)
            and (
                (name in {"load", "loads"}
                 and deser_root in UNSAFE_DESERIALIZERS)
                or (name == "open" and deser_root == "shelve")
            )
        ):
            self.add(
                node, "unsafe-deserialization", "high",
                "Deserializing untrusted data with %s can execute "
                "arbitrary code." % deser_root
            )

        # yaml-unsafe-load: yaml.load without a SafeLoader.
        # Golden-set wave: yaml.unsafe_load added (it is UnsafeLoader —
        # strictly more dangerous than bare load). yaml.full_load() is
        # deliberately NOT flagged: FullLoader is a PyYAML mitigation
        # (documented decision, RULE_ACCURACY.md); load(Loader=
        # FullLoader) stays flagged for Bandit B506 parity.
        if (
            name in {"load", "unsafe_load"}
            and isinstance(node.func, ast.Attribute)
            and self._root_name(node.func.value) == "yaml"
        ):
            loader = None
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader = kw.value
            if loader is None and len(node.args) >= 2:
                loader = node.args[1]
            loader_repr = str(
                getattr(loader, "attr", None)
                or PythonSecurityVisitor._root_name(loader)
                or ""
            )
            if loader is None or "safe" not in str(loader_repr).lower():
                self.add(
                    node, "yaml-unsafe-load", "medium",
                    "yaml.load without SafeLoader can construct "
                    "arbitrary objects from untrusted input."
                )

        # sql-injection: execute() with concatenated / f-string SQL.
        # Golden-set wave: "...{}".format(x) on a string literal added —
        # the identical value-injection shape as concat/f-string.
        if (
            name in {"execute", "executemany", "executescript"}
            and isinstance(node.func, ast.Attribute)
            and node.args
        ):
            arg0 = node.args[0]
            format_call = (
                isinstance(arg0, ast.Call)
                and isinstance(arg0.func, ast.Attribute)
                and arg0.func.attr == "format"
                and isinstance(arg0.func.value, ast.Constant)
                and isinstance(arg0.func.value.value, str)
            )
            injectable = isinstance(arg0, ast.BinOp) or format_call or (
                isinstance(arg0, ast.JoinedStr)
                and _fstring_has_value_interpolation(
                    arg0, self.placeholder_vars)
            )
            if injectable:
                self.add(
                    node, "sql-injection", "high",
                    "SQL built by string concatenation or interpolation — "
                    "use parameterized queries."
                )

        # v0.14.0-dev PoC — flow 1 (request.* -> SQL): fires ONLY when the
        # query argument is tainted by request data AND the shape is one
        # the structural sql-injection rule does NOT already cover (those
        # sites already fired above) — no duplicate finding per line.
        if (
            name in {"execute", "executemany", "executescript"}
            and isinstance(node.func, ast.Attribute)
            and node.args
            and not injectable
            and _taint.expr_tainted(node.args[0], self.request_tainted,
                                    _taint.is_request_source)
        ):
            self.add(
                node, "request-to-sql", "high",
                "Query text reaches execute() from request.* data — "
                "injection path confirmed by dataflow; parameterize."
            )

        # path-traversal: open(<user-controlled path>).
        if name == "open" and node.args and not isinstance(
                node.func, ast.Attribute):
            if self._is_input_source(node.args[0]):
                self.add(
                    node, "path-traversal", "medium",
                    "File path derived from user input — validate/normalize "
                    "against traversal."
                )

        # weak-crypto: hashlib.md5 / hashlib.sha1 / hashlib.new("md5").
        if isinstance(node.func, ast.Attribute) and \
                self._root_name(node.func.value) == "hashlib":
            weak = node.func.attr in {"md5", "sha1"}
            if not weak and node.func.attr == "new" and node.args and \
                    isinstance(node.args[0], ast.Constant) and \
                    isinstance(node.args[0].value, str):
                weak = node.args[0].value.strip().lower() in {"md5", "sha1"}
            if weak and not any(
                    kw.arg == "usedforsecurity"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                    for kw in node.keywords):
                self.add(
                    node, "weak-crypto", "medium",
                    "%s is cryptographically broken for security purposes."
                    % node.func.attr.upper()
                )

        # -- v0.13.0 Bandit-parity wave 1 (docs/BANDIT_PARITY.md) --------

        # tls-verification-disabled (B501-equiv): the verify=False keyword
        # itself is the dangerous signal regardless of the client library.
        verify_kw = self._kwarg(node, "verify")
        if isinstance(verify_kw, ast.Constant) and verify_kw.value is False:
            self.add(
                node, "tls-verification-disabled", "high",
                "TLS certificate verification explicitly disabled "
                "(verify=False) — man-in-the-middle exposure."
            )

        # ssl-unverified-context (B323-equiv): ssl._create_unverified_context()
        # (qualified or star-imported bare) disables validation globally.
        if name == "_create_unverified_context" and (
                isinstance(node.func, ast.Name)
                or (isinstance(node.func, ast.Attribute)
                    and self._root_name(node.func.value) == "ssl")):
            self.add(
                node, "ssl-unverified-context", "high",
                "ssl._create_unverified_context() disables certificate "
                "validation for the process."
            )

        # request-without-timeout (B113-equiv): qualified requests.* HTTP
        # verb calls without a timeout keyword. Deliberately narrower than
        # Bandit recall: session-like receivers (session.get(...)) are out
        # of scope — documented deviation, keeps the rule FP-free.
        if (name in HTTP_VERB_METHODS
                and isinstance(node.func, ast.Attribute)
                and self._root_name(node.func.value) == "requests"
                and self._kwarg(node, "timeout") is None):
            self.add(
                node, "request-without-timeout", "low",
                "HTTP request without an explicit timeout can hang "
                "indefinitely (availability exposure)."
            )

        # torch-unsafe-load (B614-equiv): torch.load deserializes via
        # pickle unless weights_only=True is explicit (PyTorch mitigation).
        if (name == "load"
                and isinstance(node.func, ast.Attribute)
                and self._root_name(node.func.value) == "torch"):
            weights_only = self._kwarg(node, "weights_only")
            safe = (isinstance(weights_only, ast.Constant)
                    and weights_only.value is True)
            if not safe:
                self.add(
                    node, "torch-unsafe-load", "high",
                    "torch.load deserializes via pickle — arbitrary code "
                    "execution from untrusted checkpoints (use "
                    "weights_only=True)."
                )

        # hf-trust-remote-code (B615-equiv): any call opting into executing
        # code fetched from a remote model repository.
        trc = self._kwarg(node, "trust_remote_code")
        if isinstance(trc, ast.Constant) and trc.value is True:
            self.add(
                node, "hf-trust-remote-code", "high",
                "trust_remote_code=True executes arbitrary code from a "
                "remote model repository."
            )

        # jinja2-autoescape-false (B701-equiv): explicit autoescape=False.
        autoescape = self._kwarg(node, "autoescape")
        if isinstance(autoescape, ast.Constant) and autoescape.value is False:
            self.add(
                node, "jinja2-autoescape-false", "high",
                "autoescape=False disables HTML escaping — cross-site "
                "scripting exposure."
            )

        # django-mark-safe (B703-equiv): mark_safe bypasses escaping.
        if name == "mark_safe":
            self.add(
                node, "django-mark-safe", "medium",
                "mark_safe() marks content XSS-safe without escaping — "
                "audit the input path."
            )

        # tarfile-extractall (B202-equiv): extractall without a PEP 706
        # safe filter. zipfile receivers are NOT flagged — tar symlink
        # traversal does not apply to the zip format (documented
        # deviation from Bandit recall). Golden-set wave: the carve-out
        # now also covers a DIRECT zipfile.ZipFile(...) call receiver,
        # not only bound variables (measured FP, fixed).
        if name == "extractall" and isinstance(node.func, ast.Attribute):
            filt = self._kwarg(node, "filter")
            filter_safe = (isinstance(filt, ast.Constant)
                           and isinstance(filt.value, str)
                           and filt.value in TARFILE_SAFE_FILTERS)
            receiver_root = self._root_name(node.func.value)
            direct_zip_call = (
                isinstance(node.func.value, ast.Call)
                and self._root_name(node.func.value.func) == "zipfile"
            )
            if (receiver_root not in ({"zipfile"} | self.zipfile_vars)
                    and not direct_zip_call and not filter_safe):
                self.add(
                    node, "tarfile-extractall", "high",
                    "extractall without filter= can write outside the "
                    "target directory (path traversal)."
                )

        # hardcoded-tmp-path (B108-equiv): /tmp and /var/tmp literals in
        # call-argument positions (list/tuple elements included) —
        # docstrings and bare expression strings are not flagged
        # (documented precision deviation).
        for arg in node.args:
            self._check_tmp_value(node, arg)
        for kw in node.keywords:
            self._check_tmp_value(node, kw.value)

        # -- v0.15.0-dev Bandit-parity wave 2 (docs/BANDIT_PARITY.md) ----

        # hardcoded-bind-all-interfaces (B104-equiv): bind-all literals in
        # the same value positions as B108 — call arguments (list/tuple
        # elements included) and assignment values.
        for arg in node.args:
            self._check_bind_all_value(node, arg)
        for kw in node.keywords:
            self._check_bind_all_value(node, kw.value)

        # flask-debug-enabled (B201-equiv, HIGH/HIGH verified): .run(
        # debug=True) exposes the Werkzeug debugger — arbitrary code
        # execution. Bandit semantics kept receiver-agnostic: a debug=
        # True run call is the debugger flag regardless of framework.
        debug_kw = self._kwarg(node, "debug")
        if (name == "run"
                and isinstance(node.func, ast.Attribute)
                and isinstance(debug_kw, ast.Constant)
                and debug_kw.value is True):
            self.add(
                node, "flask-debug-enabled", "high",
                "run(debug=True) exposes the interactive debugger — "
                "arbitrary code execution in production."
            )

        # paramiko-exec-command (B601-equiv, MEDIUM/MEDIUM verified):
        # exec_command runs a remote shell command over SSH.
        if name == "exec_command" and isinstance(node.func, ast.Attribute):
            self.add(
                node, "paramiko-exec-command", "medium",
                "SSH exec_command runs a remote shell command — validate "
                "the command source."
            )

        # hf-unpinned-download (B615 expansion, MEDIUM/HIGH verified):
        # Hugging Face Hub downloads without an immutable revision pin —
        # missing, None, or the mutable "main" ref. A non-constant
        # revision is treated as pinned (documented deviation).
        if name in HF_DOWNLOAD_METHODS and (
                isinstance(node.func, ast.Attribute)
                or (name in HF_FUNCTION_STYLE
                    and isinstance(node.func, ast.Name))):
            # Measured precision carve-outs (wave-2 FP gate). NOTE: no
            # early return — visit_Call must always reach generic_visit.
            carve_out = (
                (isinstance(node.func, ast.Attribute)
                 and self._root_name(node.func.value)
                 in HF_NON_HUB_RECEIVERS)          # seaborn local loader
                or (node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and node.args[0].value in LOCAL_DATASET_BUILDERS)
            )                                      # offline builder idiom
            if not carve_out:
                rev = self._kwarg(node, "revision")
                unpinned = rev is None or (
                    isinstance(rev, ast.Constant)
                    and rev.value in UNPINNED_REVISIONS)
                if unpinned:
                    self.add(
                        node, "hf-unpinned-download", "medium",
                        "Hugging Face download without a pinned revision — "
                        "artifacts can change under you (pin a commit "
                        "hash)."
                    )

        # weak-crypto-key-size (B505-equiv, wave 3): constant-integer
        # key sizes below the verified Bandit thresholds.
        self._check_weak_key_size(node)

        self.generic_visit(node)

    def visit_Attribute(self, node):
        # ssl-insecure-version (B502/B503-equiv, HIGH/HIGH + MEDIUM/
        # MEDIUM verified): any qualified reference to a weak SSL/TLS
        # protocol constant — attribute position or ssl_version= kwarg
        # alike. B504 (no ssl_version at all) is deliberately NOT
        # flagged: Bandit rates it LOW and modern ssl defaults are sane
        # (documented rejection — noise).
        if (node.attr in WEAK_SSL_PROTOCOLS
                and isinstance(node.value, ast.Name)
                and node.value.id == "ssl"):
            self.add(
                node, "ssl-insecure-version", "high",
                "Weak SSL/TLS protocol version — downgrade and "
                "decryption exposure (use modern defaults)."
            )
        self.generic_visit(node)

    def visit_Import(self, node):
        # telnetlib-import (B401-equiv) / ftplib-import (B402-equiv):
        # plaintext-protocol stdlib modules, import level (Bandit
        # blacklist semantics: severity high).
        for alias in node.names:
            rule = INSECURE_PROTOCOL_IMPORTS.get(
                alias.name.split(".")[0])
            if rule:
                self.add(
                    node, rule, "high",
                    "Plaintext-protocol module (%s) — credentials and "
                    "data cross the wire unencrypted." % alias.name
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        rule = INSECURE_PROTOCOL_IMPORTS.get(
            (node.module or "").split(".")[0]) if node.module else None
        if rule:
            self.add(
                node, rule, "high",
                "Plaintext-protocol module (%s) — credentials and data "
                "cross the wire unencrypted." % node.module
            )
        self.generic_visit(node)

    def visit_Assign(self, node):
        # hardcoded-tmp-path (B108-equiv): assignment value positions.
        self._check_tmp_value(node, node.value)
        # hardcoded-bind-all-interfaces (B104-equiv): same positions.
        self._check_bind_all_value(node, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._check_tmp_value(node, node.value)
            self._check_bind_all_value(node, node.value)
        self.generic_visit(node)

    def _int_const(self, node):
        """Integer literal value (bool excluded) — None for anything
        else. A non-constant or string key size cannot be proven weak
        statically, so it stays quiet (Bandit: string sizes 'can't be
        processed'; same deviation family as B615's non-constant
        revision treated as pinned)."""
        if (isinstance(node, ast.Constant)
                and isinstance(node.value, int)
                and not isinstance(node.value, bool)):
            return node.value
        return None

    def _curve_size(self, curve):
        """Map an EC curve argument to its Bandit-registry bit size, or
        None: unknown/dynamic curves cannot be proven weak and stay
        quiet (Bandit defaults unmapped curves to 224 bits, which
        classifies quiet — same outcome)."""
        name = None
        if isinstance(curve, ast.Call):
            func = curve.func
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                # bare from-import idiom:
                # `from ...asymmetric.ec import SECP192R1` — the curve
                # name itself is the unambiguous signal.
                name = func.id
        return EC_CURVE_KEY_SIZES.get(name) if name else None

    def _emit_weak_key_size(self, node, kind, size):
        """Classify a resolved key size against the verified Bandit
        thresholds and emit the finding (or stay quiet)."""
        if size is None:
            return
        high, medium = WEAK_KEY_SIZE_THRESHOLDS[kind]
        if size < high:
            severity, threshold = "high", high
        elif size < medium:
            severity, threshold = "medium", medium
        else:
            return
        self.add(
            node, "weak-crypto-key-size", severity,
            "%s key sizes below %d bits are considered breakable."
            % (kind, threshold)
        )

    def _check_weak_key_size(self, node):
        """weak-crypto-key-size (B505-equiv, wave 3). Qualified tail
        matching, per the verified Bandit qual tables:
        * pycrypto/pycryptodome: <Crypto|Cryptodome>.PublicKey.<RSA|DSA>
          .generate with bits= or arg position 0;
        * cryptography.io: rsa|dsa|ec.generate_private_key — key_size=
          or arg position (RSA: 1, DSA: 0), EC resolved via the curve
          registry. Tail matching covers the full dotted chains AND the
          from-import alias receivers ("rsa.generate_private_key(...)"
          — the canonical idiom); receiver-agnostic like B201/B601
          (documented deviation: MIZAN resolves no imports). Missing
          sizes stay quiet (Bandit defaults them to a safe 2048)."""
        qual = self._dotted_name(node.func)
        if not qual:
            return
        parts = qual.split(".")
        # pycrypto/pycryptodome: the canonical idiom is the from-import
        # alias form (`from Crypto.PublicKey import RSA; RSA.generate(
        # 512)`) — a two-segment chain (B615 bare-form precedent: the
        # alias IS the measured dominant idiom). Full dotted chains
        # fire only under the REAL package roots (Crypto/Cryptodome,
        # per the Bandit qual table) — a foreign root with a PublicKey
        # segment is NOT a pycrypto call and stays quiet.
        if (len(parts) >= 2 and parts[-1] == "generate"
                and parts[-2] in ("RSA", "DSA")
                and (len(parts) == 2
                     or parts[0] in PYCRYPTO_KEY_ROOTS)):
            bits = self._int_const(self._kwarg(node, "bits"))
            if bits is None and node.args:
                bits = self._int_const(node.args[0])
            self._emit_weak_key_size(node, parts[-2], bits)
            return
        if (len(parts) >= 2 and parts[-1] == "generate_private_key"
                and parts[-2] in ("rsa", "dsa", "ec")):
            kind = parts[-2].upper()
            if kind == "EC":
                curve = self._kwarg(node, "curve")
                if curve is None and node.args:
                    curve = node.args[0]
                size = self._curve_size(curve)
                if size is not None:
                    self._emit_weak_key_size(node, kind, size)
                return
            bits = self._int_const(self._kwarg(node, "key_size"))
            pos = 1 if kind == "RSA" else 0
            if bits is None and len(node.args) > pos:
                bits = self._int_const(node.args[pos])
            self._emit_weak_key_size(node, kind, bits)

    def _check_tmp_value(self, node, value):
        """Flag /tmp and /var/tmp literals in value positions, one nesting
        level into list/tuple/set literals (segment-boundary safe)."""
        if isinstance(value, ast.Constant):  # accept node or raw value
            value = value.value
        if isinstance(value, str) and (
                value == "/tmp" or value.startswith("/tmp/")
                or value == "/var/tmp" or value.startswith("/var/tmp/")):
            self.add(
                node, "hardcoded-tmp-path", "low",
                "Hardcoded temp path invites symlink races and predictable "
                "filenames — use tempfile."
            )
        elif isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            for elt in value.elts:
                if isinstance(elt, ast.Constant):
                    self._check_tmp_value(node, elt.value)

    def _check_bind_all_value(self, node, value):
        """Flag bind-all interface literals ("0.0.0.0" — the exact
        literal ONLY, per the verified Bandit B104 semantics and the
        wave-2 measured rejection of the "::" extension) in value
        positions, one nesting level into list/tuple/set literals — the
        B104 value-position discipline mirroring _check_tmp_value."""
        if isinstance(value, ast.Constant):  # accept node or raw value
            value = value.value
        if isinstance(value, str) and value in BIND_ALL_INTERFACES:
            self.add(
                node, "hardcoded-bind-all-interfaces", "medium",
                "Binding to 0.0.0.0 exposes the service on every "
                "network interface — bind explicitly."
            )
        elif isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            for elt in value.elts:
                if isinstance(elt, ast.Constant):
                    self._check_bind_all_value(node, elt.value)


def _collect_placeholder_vars(tree):
    """Names bound to dynamic-IN placeholder builders (v0.14.0 sql-injection
    FP fix): ``placeholders = ",".join("?" * len(TERMINAL))`` shapes — the
    dynamic IN-clause idiom. Bounded: direct Assign/AnnAssign targets only.
    """
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_placeholder_builder(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    names.add(tgt.id)
        elif (isinstance(node, ast.AnnAssign) and node.value is not None
                and _is_placeholder_builder(node.value)
                and isinstance(node.target, ast.Name)):
            names.add(node.target.id)
    return names


def _collect_zipfile_vars(tree):
    """Names bound to zipfile.* instances (B202-equiv scope carve-out):
    assignment targets AND with-item bindings."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                expr, optional = item.context_expr, item.optional_vars
                if (isinstance(expr, ast.Call)
                        and isinstance(expr.func, ast.Attribute)
                        and PythonSecurityVisitor._root_name(expr.func) == "zipfile"
                        and isinstance(optional, ast.Name)):
                    names.add(optional.id)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and \
                    PythonSecurityVisitor._root_name(func) == "zipfile":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
    return names


def _collect_input_taints(tree):
    """v0.14.0-dev: input()/sys.argv taint via the fixpoint engine.

    Supersedes the v0.9.0 shallow single-pass version (direct assignment
    only); behavior is a strict superset — every name the old pass found,
    the fixpoint engine still finds, plus taint flowing through wrapper
    expressions. Feeds the existing path-traversal rule and the new
    input-to-subprocess dataflow rule.
    """
    return _taint.propagate(tree, _taint.is_input_source)


def _collect_request_taints(tree):
    """v0.14.0-dev PoC: plain names tainted by ``request.*`` data."""
    return _taint.propagate(tree, _taint.is_request_source)


def _is_excluded(rel_posix, filename):
    """v0.9.0 P0 exclusion check (memo EXCLUDE_PATTERNS)."""
    prefixed = "/" + rel_posix
    for pattern in EXCLUDE_GLOBS:
        if pattern.startswith("*/"):
            if fnmatch.fnmatch(prefixed, pattern):
                return True
        elif fnmatch.fnmatch(filename, pattern) or \
                fnmatch.fnmatch(rel_posix, pattern):
            return True
    return False


def iter_source_files(root):
    """Yield scannable source files under root, skipping excluded trees."""
    for current, dirs, filenames in os.walk(root):
        dirs[:] = sorted(
            name for name in dirs if name not in IGNORED_DIRS
        )

        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            rel = path.relative_to(root).as_posix()
            if _is_excluded(rel, filename):
                continue
            yield path


def analyze_file(path, root, custom_rules=()):
    """Analyze one source file and return its findings.

    ``custom_rules`` (v0.11.0): compiled rules loaded from the repo's
    ``.mizan/rules.json`` — applied here so they flow through the SAME
    pipeline (fingerprint, baseline, gate) as built-in rules.
    """
    findings = []

    try:
        content = path.read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        return [{
            "file": str(path.relative_to(root)),
            "line": 0,
            "rule": "file-read-error",
            "severity": "warning",
            "message": str(exc),
        }]

    if path.suffix.lower() == ".py":
        try:
            tree = ast.parse(content, filename=str(path))
            visitor = PythonSecurityVisitor(
                tainted_names=_collect_input_taints(tree),
                zipfile_vars=_collect_zipfile_vars(tree),
                request_tainted=_collect_request_taints(tree),
                placeholder_vars=_collect_placeholder_vars(tree),
            )
            visitor.visit(tree)

            for item in visitor.findings:
                findings.append({
                    "file": str(path.relative_to(root)),
                    **item,
                })
        except SyntaxError as exc:
            findings.append({
                "file": str(path.relative_to(root)),
                "line": exc.lineno or 0,
                "rule": "python-syntax-error",
                "severity": "warning",
                "message": "Python source could not be parsed.",
            })

    else:
        for number, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(NONPY_COMMENT_PREFIXES) or \
                    NONPY_SIGNATURE_PATTERN.match(line):
                continue
            if NONPY_EVAL_PATTERN.search(line):
                findings.append({
                    "file": str(path.relative_to(root)),
                    "line": number,
                    "rule": "dynamic-execution",
                    "severity": "high",
                    "message": "Potential dynamic code execution.",
                })

    for number, line in enumerate(content.splitlines(), 1):
        match = (SECRET_PATTERN.search(line)
                 or SECRET_PATTERN_BARE.search(line))
        if (match and not _is_placeholder(match.group("value"))
                and not _is_env_reference(match.group("value"))):
            findings.append({
                "file": str(path.relative_to(root)),
                "line": number,
                "rule": "hardcoded-secret-candidate",
                "severity": "high",
                "message": "Possible hardcoded credential. "
                           "Manual verification required.",
            })

        if TODO_PATTERN.search(line):
            findings.append({
                "file": str(path.relative_to(root)),
                "line": number,
                "rule": "todo",
                "severity": "info",
                "message": "Unresolved development marker.",
            })

        # bidi-override-chars (B613-equiv, wave 3): Trojan Source bidi
        # control characters (CVE-2021-42574), verified verbatim from
        # the Bandit plugin. Text-level BY DESIGN — the attack lives in
        # strings and comments, where an AST cannot see it. Bandit
        # scans Python files; MIZAN's per-line loop covers every
        # scannable language (documented extension) and reports every
        # affected line instead of only the first (Bandit returns after
        # one issue per file).
        if BIDI_CHARS_RE.search(line):
            findings.append({
                "file": str(path.relative_to(root)),
                "line": number,
                "rule": "bidi-override-chars",
                "severity": "high",
                "message": "Bidirectional control character (Trojan "
                           "Source, CVE-2021-42574) — the rendered order "
                           "of this line differs from its parsed order.",
            })

    # v0.14.0 field-measured downgrade: in test-fixture paths the two
    # line-regex rules fire overwhelmingly on fixtures (89% secrets /
    # 70% dynamic-execution in the 2026-11-08 campaign). The findings
    # REMAIN in the report — only the severity drops to "low"; nothing
    # is silently dropped and the fail-loud contract is intact.
    try:
        rel_posix = path.relative_to(root).as_posix().lower()
    except ValueError:
        rel_posix = path.as_posix().lower()
    if TEST_PATH_PATTERN.search(rel_posix):
        for item in findings:
            if (item.get("rule") in TEST_DOWNGRADED_RULES
                    and item.get("severity") == "high"):
                item["severity"] = "low"

    if custom_rules:
        findings.extend(apply_custom_rules(
            content,
            str(path.relative_to(root)),
            path.suffix.lower(),
            custom_rules,
        ))

    return findings


def analyze_repository(directory="."):
    """Analyze a repository directory and return the analyzer section."""
    root = Path(directory).expanduser().resolve()

    if not root.is_dir():
        raise ValueError(f"Invalid repository directory: {root}")

    findings = []
    scanned = 0

    # v0.11.0: repo-local declarative policies (.mizan/rules.json). A
    # missing file is the normal case; a broken file yields explicit
    # errors surfaced here AND treated as an incomplete gate source by
    # the CLI — a scan that could not load its policies never certifies
    # a clean pass.
    custom_rules, custom_errors = load_custom_rules(root)

    for path in iter_source_files(root):
        scanned += 1
        findings.extend(analyze_file(path, root, custom_rules=custom_rules))

    return {
        "engine": "MIZAN AST Analyzer",
        "version": __version__,
        "repository": str(root),
        "files_scanned": scanned,
        "findings_count": len(findings),
        "findings": findings,
        "custom_rules_loaded": len(custom_rules),
        "custom_rules_errors": custom_errors,
        "mode": "read-only",
        "execution_performed": False,
    }
