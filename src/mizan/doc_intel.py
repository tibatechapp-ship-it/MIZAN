"""MIZAN Documentation Intelligence — v0.10.0.

MIZAN no longer only checks whether the CODE is healthy; it also checks
whether the DOCUMENTATION that explains that code is healthy, complete,
and still matches reality (Documentation Intelligence module).

What it does (read-only, zero dependencies):

* Documentation Scanner      — inventories every markdown/RST document.
* Link verification          — local links and heading anchors that point
                               at nothing are reported (doc-broken-link).
* Documentation-Code mapping — every doc gets the set of source files it
                               actually covers; every public source module
                               that NO document covers is reported
                               (doc-orphan-code) and the mapping is
                               returned as ``metrics["doc_code_map"]``.
* Stale-reference detection  — backticked paths and ``symbol()`` names in
                               docs that no longer exist in the code
                               (doc-stale-reference).
* API endpoint analyzer      — FastAPI/Flask/Express-style routes are
                               discovered in source and checked against the
                               documentation (doc-undocumented-endpoint).
* Documentation coverage     — public Python functions/classes without a
                               docstring (doc-missing-docstring), docstrings
                               too shallow to be useful
                               (doc-shallow-docstring, < 4 words), and the
                               overall coverage percentage.
* README quality             — missing README, missing install/usage
                               sections, and shell commands that reference
                               files which do not exist (doc-readme-quality).
* Change impact              — when the latest commit touched a source
                               file AFTER the doc that describes it was
                               last updated, the doc is flagged for review
                               (doc-needs-review). Git-aware, read-only.
                               Scope: the LATEST commit only — older
                               history is out of scope by design, and
                               shallow clones degrade to a safe no-op.

Precision-first (the v0.9.0 lesson): every rule is built to stay silent
unless the evidence is concrete. External URLs (http/https/mailto/tel)
are COUNTED but never judged — no network is ever contacted, so a
network failure can never be misread as a broken link. Ambiguous
references (pattern vocabulary, dotted calls, exclusion-tree mentions,
output redirections, fenced code-example content) are skipped rather
than guessed, and noisy rules are capped. Suggestions are REPORT-ONLY —
the module never writes to the scanned repository (doc-scan cannot
mutate your docs).
"""

import ast
import os
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote

from ._version import __version__
from .analyzer import (
    IGNORED_DIRS,
    NONPY_COMMENT_PREFIXES,
    SOURCE_EXTENSIONS,
    iter_source_files,
)

ENGINE_NAME = "MIZAN Documentation Intelligence"

DOC_EXTENSIONS = {".md", ".rst"}
MAX_DOC_FILES = 400

# Findings caps — coverage-style rules stay advisory, never a wall of noise.
CAPS = {
    "doc-stale-reference": 30,
    "doc-undocumented-endpoint": 30,
    "doc-missing-docstring": 30,
    "doc-shallow-docstring": 30,
    "doc-orphan-code": 20,
    "doc-needs-review": 10,
    "doc-readme-quality": 10,
}

# Backticked tokens ending in "()" whose last segment is here are generic
# vocabulary (builtins, shell words, placeholders) — never stale references.
# The METHOD_VOCABULARY block covers method names documentation quotes when
# explaining RULE PATTERNS ("execute() built by concatenation") — such
# mentions describe a construct, not a repo-local symbol claim.
BUILTIN_SYMBOLS = frozenset({
    "input", "open", "print", "eval", "exec", "len", "int", "str",
    "float", "bool", "list", "dict", "set", "tuple", "super", "self",
    "cls", "main", "run", "start", "init", "setup", "teardown", "test",
    "true", "false", "none", "null", "undefined", "const", "let", "var",
    "function", "return", "import", "export", "class", "def", "async",
    "await", "if", "for", "while", "pip", "npm", "npx", "yarn", "python",
    "python3", "node", "git", "curl", "wget", "cd", "ls", "echo", "cat",
    "make", "sudo", "apt", "brew", "docker", "compose", "kubectl",
    "pytest", "mizan", "http", "https", "get", "post", "put", "delete",
    "patch", "head", "options", "your_function", "yourmethod", "example",
    "foo", "bar", "baz", "myapp", "app", "api", "router", "server",
    # generic method vocabulary quoted in pattern explanations
    "execute", "executemany", "executescript", "load", "loads", "dump",
    "dumps", "compile", "match", "search", "findall", "system", "popen",
    "read", "write", "close", "fetch", "parse", "join", "split",
    "format", "strip", "replace", "append", "update", "create",
    "build", "check", "validate", "handle", "process", "call", "apply",
    "bind", "emit", "scan", "analyze", "inspect",
})

# Tool-config file vocabulary: `.mizan/...` paths that MIZAN reads or
# creates in the SCANNED repository (its own policies / baseline / cache).
# Docs quote them as instructions to the user, not as claims about THIS
# repo's tree — never judged (same doctrine as output-recipe and
# directory-vocabulary exclusions).
MIZAN_CONFIG_VOCABULARY = frozenset({
    ".mizan/rules.json",
    ".mizan/baseline.json",
    ".mizan/osv-cache.json",
})

# Tokens that end with one of these extensions are treated as path
# references (a slash is ALWAYS required — bare filenames are too
# ambiguous to judge, the v0.9.0 precision principle).
PATH_EXTENSIONS = frozenset({
    "py", "js", "jsx", "ts", "tsx", "java", "go", "rs", "php", "rb",
    "json", "yml", "yaml", "toml", "md", "rst", "txt", "sh", "bash",
    "cfg", "ini", "html", "css", "scss", "sql", "env", "lock", "xml",
    "conf", "ipynb", "tf", "hcl", "proto",
})

SHELL_FENCE_LANGS = frozenset({
    "bash", "sh", "shell", "zsh", "console", "terminal", "cmd",
    "powershell", "ps1",
})

README_SECTIONS = {
    "install": ("install", "installation", "getting started", "setup",
                "quickstart", "quick start", "build", "التثبيت", "التشغيل"),
    "usage": ("usage", "using", "how to use", "examples", "example",
              "getting started", "quickstart", "quick start",
              "الاستخدام", "الاستعمال"),
}

MD_LINK = re.compile(
    r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?[^)]*\)"
)
MD_HTML_LINK = re.compile(
    r"""<a\s[^>]*?href=["']([^"']+)["']""", re.IGNORECASE
)
MD_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
FENCE = re.compile(r"^(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)\s*$")
BACKTICK = re.compile(r"`([^`\n]+)`")

PY_ENDPOINT = re.compile(
    r"@(?:[\w.]+\.)?(?:app|router|api|bp|blueprint)\."
    r"(get|post|put|delete|patch|route)\(\s*['\"]([^'\"]+)['\"]"
)
JS_ENDPOINT = re.compile(
    r"\b(?:app|router|api)\.(get|post|put|delete|patch|all)\("
    r"\s*['\"`]([^'\"`]+)['\"`]"
)
# Flask's @app.route and Express's .all() are method-agnostic handlers.
ANY_METHOD = {"ROUTE", "ALL"}
JS_FUNCTION = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("
)
TOKEN_SYMBOL = re.compile(r"^[A-Za-z_][\w.]*\(\)$")

DYNAMIC_SEGMENT = re.compile(r"^[:<{*].*[}>]?$")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

EXPLICIT_ANCHOR = re.compile(
    r"<a\s[^>]*?(?:id|name)=[\"']([^\"']+)[\"']", re.IGNORECASE
)
# Any URI scheme (dsh-session:…, obsidian://, C:\…) — a link with a
# scheme is by definition NOT a repo-relative file path; only http(s),
# mailto, tel, data and file are "known external", everything else is
# a custom/app scheme. Either way: counted, never judged.
URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _github_anchor(text):
    """GitHub-style slug for a heading (github-slugger semantics).

    Verified semantics that matter in practice: punctuation and symbols
    are REMOVED (em-dash U+2014 included — it is Pd), a literal hyphen
    '-' is KEPT, and every space becomes one hyphen WITHOUT collapsing
    runs (``a — b`` → ``a--b``, ``a - b`` → ``a---b``).
    """
    slug = text.strip().lower()
    kept = []
    for char in slug:
        if char in ("-", " "):
            kept.append(char)
            continue
        category = unicodedata.category(char)
        if category.startswith(("P", "S")):
            continue
        kept.append(char)
    return "".join(kept).replace(" ", "-")


def _heading_anchors(text):
    """Collect every valid anchor target of a markdown document:
    GitHub-style heading slugs (with duplicate ``-1``/``-2`` suffixes)
    PLUS explicit HTML anchors (``<a id=...>`` / ``<a name=...>``) that
    authors place manually — links to them are valid by construction."""
    anchors = set()
    counts = {}
    for line in text.splitlines():
        for match in EXPLICIT_ANCHOR.finditer(line):
            anchors.add(match.group(1))
        match = MD_HEADING.match(line.strip())
        if not match:
            continue
        base = _github_anchor(match.group(2))
        n = counts.get(base, 0)
        counts[base] = n + 1
        anchors.add(base if n == 0 else f"{base}-{n}")
    return anchors


def _fenced_line_numbers(text):
    """Line numbers that sit INSIDE a fenced code block (```/~~~).

    Fenced content is CODE EXAMPLES, not document prose: a markdown link
    or an inline token written inside a fence is demo material
    (``@[label](dsh-session:…)`` inside a TS snippet) — never a claim
    about the repository. Only fence-OUTSIDE lines are judged for links
    and backtick references; shell-command paths inside shell fences keep
    their own dedicated check (_shell_command_paths).
    """
    fenced = set()
    in_fence = False
    for number, line in enumerate(text.splitlines(), 1):
        fence = FENCE.match(line.strip())
        if fence:
            in_fence = not in_fence
            fenced.add(number)
            continue
        if in_fence:
            fenced.add(number)
    return fenced


def _is_comment_line(line):
    stripped = line.strip()
    return stripped.startswith(NONPY_COMMENT_PREFIXES)


def _find_doc_files(root):
    docs = []
    for current, dirs, filenames in os.walk(root):
        dirs[:] = sorted(
            d for d in dirs
            if d not in IGNORED_DIRS
            and not d.startswith(".")
            and d not in {"node_modules", "vendor"}
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.suffix.lower() in DOC_EXTENSIONS:
                docs.append(path)
                if len(docs) >= MAX_DOC_FILES:
                    return docs
    return docs


def _read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _exists_within(root, candidate):
    """True when candidate is an existing file/dir inside root."""
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return False
    return resolved.exists()


# --------------------------------------------------------------------------
# doc reference extraction
# --------------------------------------------------------------------------

def _extract_doc_refs(text, skip_lines=None):
    """Per-line backticked references (fenced code lines are skipped).

    Returns (path_refs, symbol_refs) where each entry is
    ``(line_number, token)``. Precision rules: a token is a PATH reference
    only when it contains a slash and ends with a known extension; a token
    is a SYMBOL reference only when it ends in ``()`` and looks like an
    identifier (no spaces, not all-caps).
    """
    path_refs, symbol_refs = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if skip_lines and number in skip_lines:
            continue
        for span in BACKTICK.findall(line):
            token = span.strip()
            if not token or " " in token or token.startswith(("-", "$")):
                continue
            if "/" in token or "\\" in token:
                # FILE references only: a slash + a known extension. Bare
                # directory mentions ("tests/", "vendor/") are usually
                # pattern vocabulary in prose (changelogs explain which
                # trees a scanner EXCLUDES) — ambiguous, never judged.
                ext = token.rsplit(".", 1)[-1].lower() if "." in token else ""
                if ext in PATH_EXTENSIONS:
                    path_refs.append((number, token))
                continue
            if TOKEN_SYMBOL.match(token):
                name = token[:-2].split(".")[-1]
                if (
                    len(name) >= 4
                    and name.lower() not in BUILTIN_SYMBOLS
                    and not name.isupper()
                    # dotted calls (X.y()) are attribute access on an
                    # external/instance object — unknowable, never judged
                    and "." not in token[:-2]
                ):
                    symbol_refs.append((number, token))
    return path_refs, symbol_refs


def _resolve_ref(root, doc_path, token):
    """Resolve a backticked path against repo root and the doc's directory."""
    token = token.replace("\\", "/")
    for base in (root, doc_path.parent):
        candidate = (base / token).resolve() if not token.startswith("/") \
            else (root / token.lstrip("/")).resolve()
        if _exists_within(root, candidate):
            return True
    return False


def _shell_command_paths(text):
    """File references inside shell fenced blocks (README commands).

    Output redirections (``--output x.json``, ``-o x.json``, ``> x.json``)
    name files that are CREATED, not required — they must not be judged.
    """
    OUTPUT_FLAGS = {"--output", "-o", "--out", ">", ">>", "--report"}
    refs = []
    in_fence = False
    fence_is_shell = False
    for number, line in enumerate(text.splitlines(), 1):
        fence = FENCE.match(line.strip())
        if fence:
            in_fence = not in_fence
            fence_is_shell = fence.group(2).lower() in SHELL_FENCE_LANGS \
                if in_fence else False
            continue
        if not in_fence or not fence_is_shell:
            continue
        command = line.strip()
        for prefix in ("$ ", "> ", "# "):
            if command.startswith(prefix):
                command = command[len(prefix):]
        if command.startswith("#") or not command:
            continue
        tokens = command.split()
        for index, token in enumerate(tokens):
            if index > 0 and tokens[index - 1] in OUTPUT_FLAGS:
                continue
            if "/" not in token or token.startswith("-"):
                continue
            if token.endswith("/") or (
                "." in token.rsplit("/", 1)[-1]
                and token.rsplit(".", 1)[-1].lower() in PATH_EXTENSIONS
            ):
                refs.append((number, token))
    return refs


# --------------------------------------------------------------------------
# code-side collectors
# --------------------------------------------------------------------------

def _collect_python_symbols(files):
    """Public module-level function/class names + docstring coverage.

    Quality, not just presence: a docstring of fewer than 4 words cannot
    meaningfully describe a symbol — such "shallow" docstrings are
    reported separately (doc-shallow-docstring) so a 100% coverage number
    cannot be gamed with filler.
    """
    symbols = set()
    total = 0
    documented = 0
    missing = []  # (file, line, name)
    shallow = []  # (file, line, name)
    for path in files:
        if path.suffix.lower() != ".py" or path.name == "__init__.py":
            continue
        try:
            tree = ast.parse(
                path.read_text(encoding="utf-8", errors="replace"),
                filename=str(path),
            )
        except (SyntaxError, ValueError, OSError):
            continue
        for node in tree.body:
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if node.name.startswith("_"):
                continue
            symbols.add(node.name)
            total += 1
            docstring = ast.get_docstring(node)
            if docstring is None:
                missing.append((path, node.lineno, node.name))
            else:
                documented += 1
                if len(docstring.split()) < 4:
                    shallow.append((path, node.lineno, node.name))
    return symbols, total, documented, missing, shallow


def _collect_js_symbols(files):
    symbols = set()
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
            continue
        text = _read(path)
        if not text:
            continue
        for line in text.splitlines():
            if _is_comment_line(line):
                continue
            symbols.update(JS_FUNCTION.findall(line))
    return symbols


def _collect_endpoints(files):
    """Discover HTTP endpoints declared in source (FastAPI/Flask/Express)."""
    endpoints = []
    for path in files:
        text = _read(path)
        if not text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line):
                continue
            for regex in (PY_ENDPOINT, JS_ENDPOINT):
                match = regex.search(line)
                if match:
                    method = match.group(1).upper()
                    endpoints.append({
                        "file": path,
                        "line": number,
                        "method": "ANY" if method in ANY_METHOD else method,
                        "path": match.group(2),
                    })
                    break  # one route per line — `@app.get(` also fits the JS pattern
    return endpoints


def _endpoint_signature(path):
    """Static prefix of a route: dynamic segments are dropped. A fully
    dynamic or root route returns None (cannot be judged — skipped)."""
    segments = [
        segment for segment in unquote(path).split("/")
        if segment and not DYNAMIC_SEGMENT.match(segment)
    ]
    return "/" + "/".join(segments) if segments else None


# --------------------------------------------------------------------------
# git helpers (read-only)
# --------------------------------------------------------------------------

def _git(root, args, timeout=10):
    try:
        return subprocess.run(
            ["git", "-C", str(root)] + args,
            capture_output=True, text=True, timeout=timeout, check=True,
        ).stdout
    except (
        subprocess.SubprocessError, OSError, FileNotFoundError
    ):
        return None


def _git_change_context(root):
    """(commit_time, changed_files) of the latest commit, or None."""
    if not (Path(root) / ".git").exists():
        return None
    stamp = _git(root, ["log", "-1", "--format=%ct"])
    if not stamp or not stamp.strip().isdigit():
        return None
    names = _git(
        root, ["log", "-1", "--name-only", "--pretty=format:"]
    ) or ""
    changed = {line.strip() for line in names.splitlines() if line.strip()}
    return int(stamp.strip()), changed


def _git_file_time(root, rel):
    stamp = _git(root, ["log", "-1", "--format=%ct", "--", rel])
    return int(stamp.strip()) if stamp and stamp.strip().isdigit() else None


# --------------------------------------------------------------------------
# main scanner
# --------------------------------------------------------------------------

def scan_documentation_repository(directory="."):
    """Run the Documentation Intelligence pass (read-only)."""
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Invalid repository directory: {root}")

    findings = []

    def add(file, line, rule, severity, message, suggestion=None):
        finding = {
            "file": file, "line": line, "rule": rule,
            "severity": severity, "message": message,
        }
        if suggestion:
            finding["suggestion"] = suggestion
        findings.append(finding)

    # -- inventory -------------------------------------------------------
    doc_files = _find_doc_files(root)
    docs_text = {}
    for path in doc_files:
        text = _read(path)
        if text is None:
            add(
                str(path.relative_to(root)), 0, "doc-read-error", "warning",
                "Documentation file could not be read.",
            )
            continue
        docs_text[path] = text

    # -- code inventory ----------------------------------------------------
    source_files = list(iter_source_files(root))
    py_symbols, sym_total, sym_documented, sym_missing, sym_shallow = \
        _collect_python_symbols(source_files)
    py_symbols |= _collect_js_symbols(source_files)

    # -- link verification + reference extraction -------------------------
    anchors_cache = {}
    all_path_refs = []      # (doc, line, token)
    all_symbol_refs = []    # (doc, line, token)
    broken_links = 0
    total_links_checked = 0
    external_links_skipped = 0
    doc_code_map = {}

    for doc_path, text in docs_text.items():
        rel = str(doc_path.relative_to(root))
        valid_paths = set()
        anchors = _heading_anchors(text)
        fenced_lines = _fenced_line_numbers(text)
        anchors_cache[doc_path] = anchors

        for number, line in enumerate(text.splitlines(), 1):
            if number in fenced_lines:
                continue
            targets = [
                m.group(1) for m in MD_LINK.finditer(line)
            ] + [m.group(1) for m in MD_HTML_LINK.finditer(line)]
            for target in targets:
                if URI_SCHEME.match(target):
                    # External/custom-scheme references are COUNTED but
                    # never judged: no network is contacted, so a network
                    # failure can never be misread as a broken link.
                    external_links_skipped += 1
                    continue
                path_part, _, anchor = target.partition("#")
                path_part = unquote(path_part).split("?")[0]
                if not path_part:
                    # same-file anchor
                    if anchor and anchor not in anchors:
                        broken_links += 1
                        add(
                            rel, number, "doc-broken-link", "medium",
                            f"Link anchor #{anchor} does not match any "
                            "heading in this document.",
                            suggestion=f"Use one of: "
                                       f"{', '.join(sorted(anchors)[:5])}…"
                            if anchors else None,
                        )
                    continue
                if path_part.startswith("/"):
                    candidate = root / path_part.lstrip("/")
                else:
                    candidate = doc_path.parent / path_part
                if _exists_within(root, candidate):
                    total_links_checked += 1
                    if anchor and candidate.suffix.lower() in DOC_EXTENSIONS:
                        target_text = _read(candidate) or ""
                        target_anchors = anchors_cache.get(candidate)
                        if target_anchors is None:
                            target_anchors = _heading_anchors(target_text)
                            anchors_cache[candidate] = target_anchors
                        if anchor not in target_anchors:
                            broken_links += 1
                            add(
                                rel, number, "doc-broken-link", "medium",
                                f"Anchor #{anchor} does not exist in "
                                f"{path_part}.",
                            )
                    continue
                # Not found — but only judge repo-relative links; anything
                # escaping the repo root is unknowable (monorepo/env-specific).
                try:
                    (doc_path.parent / path_part).resolve().relative_to(root)
                except ValueError:
                    continue
                broken_links += 1
                add(
                    rel, number, "doc-broken-link", "medium",
                    f"Local link target does not exist: {path_part}",
                )

        path_refs, symbol_refs = _extract_doc_refs(
            text, skip_lines=fenced_lines
        )
        all_path_refs.extend((doc_path, n, t) for n, t in path_refs)
        all_symbol_refs.extend((doc_path, n, t) for n, t in symbol_refs)
        for _, token in path_refs:
            resolved = _resolve_ref(root, doc_path, token)
            if resolved:
                candidate = (root / token).resolve()
                if candidate.suffix.lower() in SOURCE_EXTENSIONS and \
                        candidate.is_file():
                    valid_paths.add(
                        str(candidate.relative_to(root))
                    )
        doc_code_map[rel] = sorted(valid_paths)

    # -- stale path references -------------------------------------------
    stale_count = 0
    for doc_path, number, token in all_path_refs:
        if stale_count >= CAPS["doc-stale-reference"]:
            break
        if token.replace("\\", "/").lower() in MIZAN_CONFIG_VOCABULARY:
            continue  # tool-config vocabulary — an instruction, not a claim
        if _resolve_ref(root, doc_path, token):
            continue
        # References escaping the repo root (../../shared/x.py) are
        # environment-specific — unknowable, so never judged (precision).
        try:
            (doc_path.parent / token).resolve().relative_to(root)
        except ValueError:
            continue
        stale_count += 1
        add(
            str(doc_path.relative_to(root)), number, "doc-stale-reference",
            "medium",
            f"Documentation references a path that does not exist: {token}",
            suggestion="Update or remove the stale reference.",
        )

    # -- stale symbol references -----------------------------------------
    for doc_path, number, token in all_symbol_refs:
        if stale_count >= CAPS["doc-stale-reference"]:
            break
        name = token[:-2].split(".")[-1]
        if name in py_symbols:
            continue
        stale_count += 1
        add(
            str(doc_path.relative_to(root)), number, "doc-stale-reference",
            "medium",
            f"Documentation references a symbol that does not exist in "
            f"the code: {name}",
            suggestion="Update or remove the stale reference.",
        )

    # -- API endpoint analyzer ---------------------------------------------
    endpoints = _collect_endpoints(source_files)
    docs_blob = "\n".join(docs_text.values())
    endpoints_documented = 0
    undocumented_count = 0
    for endpoint in endpoints:
        signature = _endpoint_signature(endpoint["path"])
        if signature is None:
            endpoints_documented += 1  # fully dynamic routes: unjudgeable
            continue
        if signature.lower() in docs_blob.lower() or \
                f"`{endpoint['path']}`" in docs_blob:
            endpoints_documented += 1
            continue
        if undocumented_count < CAPS["doc-undocumented-endpoint"]:
            undocumented_count += 1
            add(
                str(endpoint["file"].relative_to(root)), endpoint["line"],
                "doc-undocumented-endpoint", "low",
                f"API endpoint {endpoint['method']} "
                f"{endpoint['path']} is not documented.",
                suggestion=f"Document {endpoint['method']} {endpoint['path']} "
                           "in the API documentation.",
            )
        else:
            continue

    # -- docstring coverage + quality ---------------------------------------
    for path, line, name in sym_missing:
        if findings_count_rule(findings, "doc-missing-docstring") >= \
                CAPS["doc-missing-docstring"]:
            break
        add(
            str(path.relative_to(root)), line, "doc-missing-docstring",
            "info",
            f"Public symbol '{name}' has no docstring.",
            suggestion=f"Add a docstring explaining what {name} does.",
        )
    for path, line, name in sym_shallow:
        if findings_count_rule(findings, "doc-shallow-docstring") >= \
                CAPS["doc-shallow-docstring"]:
            break
        add(
            str(path.relative_to(root)), line, "doc-shallow-docstring",
            "info",
            f"Docstring of '{name}' is too shallow to describe it "
            f"(fewer than 4 words).",
            suggestion=f"Describe what {name} does, its inputs and its "
                       "effect.",
        )

    # -- README quality -----------------------------------------------------
    readme = None
    for name in ("README.md", "README.rst", "readme.md", "Readme.md"):
        candidate = root / name
        if candidate.is_file():
            readme = candidate
            break
    if readme is None:
        add(
            "README.md", 0, "doc-readme-quality", "medium",
            "No README file at the repository root.",
            suggestion="Add a README.md with installation and usage.",
        )
    else:
        text = docs_text.get(readme, "") or _read(readme) or ""
        rel = str(readme.relative_to(root))
        headings_blob = " ".join(
            m.group(2).lower()
            for m in (MD_HEADING.match(l.strip())
                      for l in text.splitlines()) if m
        )
        missing_sections = [
            section for section, words in README_SECTIONS.items()
            if not any(w in headings_blob for w in words)
        ]
        if missing_sections:
            add(
                rel, 0, "doc-readme-quality", "low",
                "README is missing essential sections: "
                + ", ".join(missing_sections) + ".",
                suggestion="Add '" + "', '".join(missing_sections)
                           + "' headings.",
            )
        for number, token in _shell_command_paths(text):
            if not _resolve_ref(root, readme, token):
                add(
                    rel, number, "doc-readme-quality", "low",
                    f"README command references a file that does not "
                    f"exist: {token}",
                )

    # -- orphan code (docs ↔ code mapping) --------------------------------
    referenced = {
        target for paths in doc_code_map.values() for target in paths
    }
    code_files = [
        str(p.relative_to(root)) for p in source_files
        if p.name not in {"__init__.py", "__main__.py", "conftest.py"}
    ]
    orphans = [
        f for f in sorted(code_files)
        if f not in referenced
        and f not in {"README.md", "CHANGELOG.md"}
    ]
    for rel in orphans[:CAPS["doc-orphan-code"]]:
        add(
            rel, 0, "doc-orphan-code", "info",
            "No documentation references this source module.",
            suggestion="Mention this module in the relevant documentation "
                       "or add a module docstring pointer.",
        )

    # -- change impact (git) ------------------------------------------------
    git_context = _git_change_context(root)
    stale_candidates = 0
    needs_review = 0
    if git_context:
        commit_time, changed_files = git_context
        ref_index = {}
        for doc_path, number, token in all_path_refs:
            if not _resolve_ref(root, doc_path, token):
                continue
            candidate = (root / token.replace("\\", "/")).resolve()
            try:
                ref_index.setdefault(
                    str(candidate.relative_to(root)), []
                ).append((doc_path, number))
            except ValueError:
                continue
        for changed in sorted(changed_files):
            if changed not in ref_index:
                continue
            if Path(changed).suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            for doc_path, number in ref_index[changed]:
                stale_candidates += 1
                doc_rel = str(doc_path.relative_to(root))
                doc_time = _git_file_time(root, doc_rel)
                if doc_time is not None and doc_time < commit_time:
                    if needs_review >= CAPS["doc-needs-review"]:
                        continue
                    needs_review += 1
                    add(
                        doc_rel, number, "doc-needs-review", "info",
                        f"'{changed}' changed in the latest commit after "
                        f"the last update of this document — review "
                        f"whether this section still matches reality.",
                    )

    # -- metrics & section --------------------------------------------------
    documented_code = len(referenced)
    findings.sort(key=lambda f: (f["rule"], f["file"], f["line"]))

    section = {
        "engine": ENGINE_NAME,
        "version": __version__,
        "repository": str(root),
        "mode": "read-only",
        "execution_performed": False,
        "docs_found": len(docs_text),
        "findings_count": len(findings),
        "findings": findings,
        "metrics": {
            "docs_found": len(docs_text),
            "local_links_checked": total_links_checked,
            "broken_links": broken_links,
            "code_files": len(code_files),
            "documented_code_files": documented_code,
            "doc_coverage_pct": round(
                100.0 * documented_code / len(code_files), 1
            ) if code_files else 100.0,
            "public_symbols_python": sym_total,
            "documented_symbols": sym_documented,
            "docstring_coverage_pct": round(
                100.0 * sym_documented / sym_total, 1
            ) if sym_total else 100.0,
            "endpoints_total": len(endpoints),
            "endpoints_documented": endpoints_documented,
            "shallow_docstrings": len(sym_shallow),
            "external_links_skipped": external_links_skipped,
            "stale_doc_code_candidates": stale_candidates,
            "git_change_impact_available": git_context is not None,
            "doc_code_map": doc_code_map,
        },
    }
    return section


def findings_count_rule(findings, rule):
    """Count findings matching one rule id."""
    return sum(1 for f in findings if f["rule"] == rule)


RULE_LABELS = {
    "doc-broken-link": "Broken doc links / anchors",
    "doc-stale-reference": "Stale doc references",
    "doc-undocumented-endpoint": "Undocumented API endpoints",
    "doc-missing-docstring": "Missing docstrings",
    "doc-shallow-docstring": "Shallow docstrings (< 4 words)",
    "doc-readme-quality": "README quality",
    "doc-orphan-code": "Undocumented modules",
    "doc-needs-review": "Docs needing review after change",
    "doc-read-error": "Unreadable docs",
}


def render_doc_intel_text(section):
    """Compact human-readable summary for terminal use."""
    metrics = section["metrics"]
    lines = [
        f"{ENGINE_NAME} v{section['version']}",
        f"Repository: {section['repository']}",
        "",
        f"Docs found            : {metrics['docs_found']}",
        f"Local links checked   : {metrics['local_links_checked']}"
        f"  (broken: {metrics['broken_links']},"
        f" external skipped: {metrics['external_links_skipped']})",
        f"Doc coverage          : {metrics['documented_code_files']}"
        f"/{metrics['code_files']} source files "
        f"({metrics['doc_coverage_pct']}%)",
        f"Docstring coverage    : {metrics['documented_symbols']}"
        f"/{metrics['public_symbols_python']} public symbols "
        f"({metrics['docstring_coverage_pct']}%,"
        f" shallow: {metrics['shallow_docstrings']})",
        f"API endpoints         : {metrics['endpoints_documented']}"
        f"/{metrics['endpoints_total']} documented",
        f"Git change-impact     : "
        f"{'available' if metrics['git_change_impact_available'] else 'unavailable (not a git repo)'}",
        "",
        "Findings by rule:",
    ]
    by_rule = {}
    for finding in section["findings"]:
        by_rule.setdefault(finding["rule"], []).append(finding)
    if not by_rule:
        lines.append("  (none — documentation matches reality)")
    for rule in sorted(by_rule):
        label = RULE_LABELS.get(rule, rule)
        lines.append(f"  [{rule}] {label}: {len(by_rule[rule])}")
        for finding in by_rule[rule][:5]:
            lines.append(
                f"    - {finding['file']}:{finding['line']} "
                f"{finding['message']}"
            )
        remaining = len(by_rule[rule]) - 5
        if remaining > 0:
            lines.append(f"    … and {remaining} more")
    return "\n".join(lines)
