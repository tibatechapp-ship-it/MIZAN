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
"""

import ast
import fnmatch
import os
import re
from pathlib import Path

from ._version import __version__
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
    r"""(?i)\b(api[_-]?key|secret|password|token)\b
    \s*[:=]\s*["'](?P<value>[^"']{8,})["']""",
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

# v0.13.0 Bandit-parity wave 1 (B113-equiv): HTTP verb methods audited for
# a missing `timeout` keyword on literal `requests.*` receivers.
HTTP_VERB_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "request",
})

# v0.13.0: PEP 706 tarfile extraction filters that neutralize path
# traversal / symlink attacks (B202-equiv mitigation).
TARFILE_SAFE_FILTERS = frozenset({"data", "tar"})


def _is_placeholder(value: str) -> bool:
    """True when a secret-candidate value is a dictionary/placeholder word."""
    norm = value.strip().lower()
    compact = re.sub(r"[\s_-]+", "", norm)
    if norm in PLACEHOLDER_VALUES or compact in PLACEHOLDER_VALUES:
        return True
    if any(marker in norm for marker in PLACEHOLDER_MARKERS):
        return True
    # degenerate values: "********", "----------", "1111111111"
    return len(set(norm)) <= 2


# A f-string interpolation sitting AFTER one of these tails is in a VALUE
# position (comparable / assignable) — that is where injection happens.
# Interpolation in identifier positions (FROM {table}, INTO {tbl}) is the
# standard way to bind configuration identifiers and is not flagged.
_SQL_VALUE_TAIL = re.compile(
    r"(?:=|==|!=|<>|\bLIKE\s|\bIN\s*\(|\bVALUES\s*\(|\bSET\s|,)\s*[\"']?\s*$"
)


def _fstring_has_value_interpolation(node):
    """True when any f-string interpolation lands in a SQL value position
    and the interpolated expression is not an ALL_CAPS constant."""
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
        if not expr_is_const and _SQL_VALUE_TAIL.search(literal_before):
            return True
        literal_before = ""
    return False


class PythonSecurityVisitor(ast.NodeVisitor):
    """Detect security-sensitive Python constructs."""

    def __init__(self, tainted_names=None, zipfile_vars=None):
        self.findings = []
        self.tainted_names = tainted_names or set()
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

        if name in {"eval", "exec"}:
            # v0.12.3 — bare-call boundary on the Python AST path too.
            # The v0.9.0 JS/TS fix required a bare call boundary for the
            # same reason: a receiver call (PyTorch Module.eval(),
            # sqlite exec, ...) is a method on an object, not the
            # eval()/exec() builtins. The 100-repo field benchmark
            # caught AutoModel.from_pretrained(...).eval() flagged as
            # dynamic code execution in a real repository.
            if isinstance(node.func, ast.Name):
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

        if name == "run" and isinstance(node.func, ast.Attribute):
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

        # -- v0.9.0 P1 rules ---------------------------------------------

        # unsafe-deserialization: pickle.loads / dill.load / marshal.loads…
        if (
            name in {"load", "loads"}
            and isinstance(node.func, ast.Attribute)
            and self._root_name(node.func.value) in UNSAFE_DESERIALIZERS
        ):
            self.add(
                node, "unsafe-deserialization", "high",
                "Deserializing untrusted data with %s can execute "
                "arbitrary code." % self._root_name(node.func.value)
            )

        # yaml-unsafe-load: yaml.load without a SafeLoader.
        if (
            name == "load"
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
        if (
            name in {"execute", "executemany", "executescript"}
            and isinstance(node.func, ast.Attribute)
            and node.args
        ):
            arg0 = node.args[0]
            injectable = isinstance(arg0, ast.BinOp) or (
                isinstance(arg0, ast.JoinedStr)
                and _fstring_has_value_interpolation(arg0)
            )
            if injectable:
                self.add(
                    node, "sql-injection", "high",
                    "SQL built by string concatenation or interpolation — "
                    "use parameterized queries."
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
        # deviation from Bandit recall).
        if name == "extractall" and isinstance(node.func, ast.Attribute):
            filt = self._kwarg(node, "filter")
            filter_safe = (isinstance(filt, ast.Constant)
                           and isinstance(filt.value, str)
                           and filt.value in TARFILE_SAFE_FILTERS)
            receiver_root = self._root_name(node.func.value)
            if receiver_root not in ({"zipfile"} | self.zipfile_vars) \
                    and not filter_safe:
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

        self.generic_visit(node)

    def visit_Assign(self, node):
        # hardcoded-tmp-path (B108-equiv): assignment value positions.
        self._check_tmp_value(node, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._check_tmp_value(node, node.value)
        self.generic_visit(node)

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
    """Shallow single-pass taint: names assigned from input()/sys.argv.

    Deliberately NOT deep taint analysis (explicitly out of scope for this
    wave) — just enough to catch `open(name)` two lines after
    `name = input()` without flagging every variable on earth.
    """
    tainted = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = node.value
            from_input = (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "input"
            ) or PythonSecurityVisitor._is_sys_argv(value)
            if from_input:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
    return tainted


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
        match = SECRET_PATTERN.search(line)
        if match and not _is_placeholder(match.group("value")):
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
