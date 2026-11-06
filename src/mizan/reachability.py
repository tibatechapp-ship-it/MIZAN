"""Shallow reachability annotation for dependency (OSV) findings.

Gap this addresses (competitive analysis, v0.11.0): advanced engines
check whether the application code actually touches a vulnerable
dependency. MIZAN adds the *shallow* version of that signal — one
read-only import scan, zero dependencies — with an honesty contract
that is stricter than the marketing of those engines:

* ``reachability: "imported"``     — a matching import/use was found.
* ``reachability: "not-imported"`` — no matching import was found in
  scannable source. This is **NOT a claim of unexploitability**:
  runtime loading, plugin systems, reflection and re-exports all evade
  a static import scan. For that reason reachability NEVER changes a
  finding's severity — it is triage metadata only. The one severity
  change MIZAN makes is the deterministic dev-dependency cap in
  ``dependency_scanner`` (documented there).
* Matching is name-normalized (PEP 503 style: case/punctuation-free)
  plus a tiny curated alias table for famous PyPI import-name splits.
  Absence from that table is not evidence of anything — when a name
  cannot be matched confidently the answer stays ``not-imported``
  and the severity is untouched, so a wrong match can only *inform*,
  never *dismiss*.
"""

import ast
import re
from pathlib import Path

from .analyzer import iter_source_files

# Curated, tiny, verifiable: normalized PyPI name -> possible import roots.
# (Pillow→PIL, opencv-python→cv2, …). Deliberately NOT a database.
_PYPI_IMPORT_ALIASES = {
    "pillow": ("pil",),
    "opencvpython": ("cv2",),
    "opencvcontribpython": ("cv2",),
    "pyyaml": ("yaml",),
    "pycryptodome": ("crypto", "cryptodome"),
    "pythondateutil": ("dateutil",),
    "beautifulsoup4": ("bs4",),
    "scikitlearn": ("sklearn",),
    "pythondotenv": ("dotenv",),
    "msgpackpython": ("msgpack",),
    "protobuff": ("google", "protobuf"),
}

_JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

# require("pkg") / require('pkg')
_JS_REQUIRE_RE = re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]""")
# import x from "pkg" / import "pkg" / import("pkg") / export x from "pkg"
_JS_FROM_RE = re.compile(r"""\bfrom\s*['"]([^'"]+)['"]""")
_JS_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]""")
_JS_BARE_RE = re.compile(r"""\bimport\s+['"]([^'"]+)['"]""")
# "module/path" (go import lines — string-literal based, best-effort)
_GO_IMPORT_RE = re.compile(r'''"([A-Za-z0-9._/-]+)"''')
# use tokio::…  /  extern crate tokio;
_RUST_USE_RE = re.compile(r"""\buse\s+([A-Za-z0-9_]+)\s*(::|;)""")
_RUST_EXTERN_RE = re.compile(r"""\bextern\s+crate\s+([A-Za-z0-9_]+)""")
# use Vendor\Package\Class;
_PHP_USE_RE = re.compile(r"""\buse\s+([A-Za-z0-9_\\\\]+)\s*;""")


def _norm(name):
    """Case/punctuation-free comparison form (PEP 503 spirit)."""
    return re.sub(r"[-_.]+", "", str(name).strip().lower())


def _python_import_roots(path):
    try:
        tree = ast.parse(
            path.read_text(encoding="utf-8", errors="replace"),
            filename=str(path),
        )
    except (SyntaxError, ValueError, OSError):
        return set()
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(_norm(alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(_norm(node.module.split(".")[0]))
    return roots


def _js_import_names(text):
    names = set()
    for regex in (_JS_REQUIRE_RE, _JS_FROM_RE, _JS_IMPORT_RE, _JS_BARE_RE):
        for spec in regex.findall(text):
            spec = spec.strip()
            if spec.startswith(("node:", ".", "/", "~")):
                continue
            if spec.startswith("@"):
                # @scope/pkg — keep scope+name (first two path segments)
                parts = spec.split("/", 2)
                if len(parts) >= 2:
                    names.add(_norm(parts[0] + parts[1]))
            else:
                names.add(_norm(spec.split("/")[0]))
    return names


def _go_import_paths(text):
    return {m.strip("/") for m in _GO_IMPORT_RE.findall(text)}


def _rust_import_roots(text):
    roots = set(_RUST_USE_RE.findall(text))
    roots = {m[0] if isinstance(m, tuple) else m for m in roots}
    roots.update(_RUST_EXTERN_RE.findall(text))
    return {_norm(r) for r in roots}


def _php_use_paths(text):
    return {_norm(p.replace("\\", "/")) for p in _PHP_USE_RE.findall(text)}


def collect_imports(root):
    """One read-only pass over source files, grouped by ecosystem family.

    Returns ``{"python": set, "npm": set, "go": set, "rust": set,
    "php": set}`` of normalized import names.
    """
    root = Path(root)
    out = {"python": set(), "npm": set(), "go": set(), "rust": set(),
           "php": set()}
    for path in iter_source_files(root):
        suffix = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            out["python"].update(_python_import_roots(path))
        elif suffix in _JS_EXT:
            out["npm"].update(_js_import_names(text))
        elif suffix == ".go":
            out["go"].update(_go_import_paths(text))
        elif suffix == ".rs":
            out["rust"].update(_rust_import_roots(text))
        elif suffix == ".php":
            out["php"].update(_php_use_paths(text))
    return out


def _was_imported(ecosystem, name, imports):
    """Best-effort: does any collected import match this dependency name?"""
    if ecosystem == "PyPI":
        target = _norm(name)
        if target in imports["python"]:
            return True
        return any(alias in imports["python"]
                   for alias in _PYPI_IMPORT_ALIASES.get(target, ()))
    if ecosystem == "npm":
        return _norm(name) in imports["npm"]
    if ecosystem == "Go":
        # any import inside the module's path tree
        n = str(name).strip("/")
        return any(p == n or p.startswith(n + "/") for p in imports["go"])
    if ecosystem == "crates.io":
        return _norm(name) in imports["rust"]
    if ecosystem == "Packagist":
        target = _norm(name)  # vendor/pkg -> vendorpkg
        for use in imports["php"]:
            parts = use.split("/")
            if len(parts) >= 2 and _norm(parts[0] + parts[1]) == target:
                return True
        return False
    return False


def annotate_reachability(findings, root, imports=None):
    """Add ``reachability`` metadata to OSV findings (in place, returns count).

    Only findings carrying a ``vuln`` record (dependency findings) are
    annotated. Severity and message are NEVER modified — see the module
    docstring for the honesty contract.
    """
    if imports is None:
        imports = collect_imports(root)
    annotated = 0
    for finding in findings:
        if not isinstance(finding, dict) or \
                not isinstance(finding.get("vuln"), dict):
            continue
        dep = finding.get("dependency") or {}
        ecosystem = dep.get("ecosystem", "PyPI")
        name = dep.get("name", "")
        if ecosystem not in ("PyPI", "npm", "Go", "crates.io", "Packagist"):
            finding["reachability"] = "unknown-ecosystem"
        elif _was_imported(ecosystem, name, imports):
            finding["reachability"] = "imported"
        else:
            finding["reachability"] = "not-imported"
        annotated += 1
    return annotated
