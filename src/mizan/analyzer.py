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
"""

import ast
import fnmatch
import os
import re
from pathlib import Path

from ._version import __version__

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

    def __init__(self, tainted_names=None):
        self.findings = []
        self.tainted_names = tainted_names or set()

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

        self.generic_visit(node)


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


def analyze_file(path, root):
    """Analyze one source file and return its findings."""
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
                tainted_names=_collect_input_taints(tree)
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

    return findings


def analyze_repository(directory="."):
    """Analyze a repository directory and return the analyzer section."""
    root = Path(directory).expanduser().resolve()

    if not root.is_dir():
        raise ValueError(f"Invalid repository directory: {root}")

    findings = []
    scanned = 0

    for path in iter_source_files(root):
        scanned += 1
        findings.extend(analyze_file(path, root))

    return {
        "engine": "MIZAN AST Analyzer",
        "version": __version__,
        "repository": str(root),
        "files_scanned": scanned,
        "findings_count": len(findings),
        "findings": findings,
        "mode": "read-only",
        "execution_performed": False,
    }
