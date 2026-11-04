"""Read-only static source analyzer."""

import ast
import os
import re
from pathlib import Path

IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build",
    ".mypy_cache", ".pytest_cache"
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".go", ".rs", ".php", ".rb"
}

SECRET_PATTERN = re.compile(
    r"""(?i)\b(api[_-]?key|secret|password|token)\b
    \s*[:=]\s*["'][^"']{8,}["']""",
    re.VERBOSE
)

TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX)\s*:")


class PythonSecurityVisitor(ast.NodeVisitor):
    """Detect security-sensitive Python constructs."""

    def __init__(self):
        self.findings = []

    def add(self, node, rule, severity, message):
        self.findings.append({
            "line": getattr(node, "lineno", 0),
            "rule": rule,
            "severity": severity,
            "message": message,
        })

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

        if name in {"system", "popen"}:
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
                        "Subprocess shell execution may introduce command injection risks."
                    )

        self.generic_visit(node)


def iter_source_files(root):
    for current, dirs, filenames in os.walk(root):
        dirs[:] = sorted(
            name for name in dirs if name not in IGNORED_DIRS
        )

        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.suffix.lower() in SOURCE_EXTENSIONS:
                yield path


def analyze_file(path, root):
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
            visitor = PythonSecurityVisitor()
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
            if re.search(r"\b(eval|exec)\s*\(", line):
                findings.append({
                    "file": str(path.relative_to(root)),
                    "line": number,
                    "rule": "dynamic-execution",
                    "severity": "high",
                    "message": "Potential dynamic code execution.",
                })

    for number, line in enumerate(content.splitlines(), 1):
        if SECRET_PATTERN.search(line):
            findings.append({
                "file": str(path.relative_to(root)),
                "line": number,
                "rule": "hardcoded-secret-candidate",
                "severity": "high",
                "message": "Possible hardcoded credential. Manual verification required.",
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
        "version": "0.2.0",
        "repository": str(root),
        "files_scanned": scanned,
        "findings_count": len(findings),
        "findings": findings,
        "mode": "read-only",
        "execution_performed": False,
    }
