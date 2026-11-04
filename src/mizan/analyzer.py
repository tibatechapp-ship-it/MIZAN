"""Read-only static source analyzer."""

from pathlib import Path
import re

IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".mypy_cache",
    ".pytest_cache"
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".go", ".rs", ".php", ".rb"
}

PATTERNS = [
    (
        "dynamic-execution",
        "high",
        re.compile(r"\b(eval|exec)\s*\("),
        "Dynamic code execution detected."
    ),
    (
        "shell-true",
        "high",
        re.compile(r"\bshell\s*=\s*True\b"),
        "Subprocess shell execution may introduce command injection risks."
    ),
    (
        "hardcoded-secret-candidate",
        "high",
        re.compile(
            r"""(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"']{8,}["']"""
        ),
        "Possible hardcoded credential. Verify manually; false positives are possible."
    ),
    (
        "todo",
        "info",
        re.compile(r"\b(TODO|FIXME|XXX)\b"),
        "Unresolved development marker."
    ),
]


def iter_source_files(root: Path):
    """Yield supported source files without entering ignored directories."""
    for current, dirs, files in __import__("os").walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)

        for filename in sorted(files):
            path = Path(current) / filename
            if path.suffix.lower() in SOURCE_EXTENSIONS:
                yield path


def analyze_file(path: Path, root: Path):
    findings = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [{
            "file": str(path.relative_to(root)),
            "line": 0,
            "rule": "file-read-error",
            "severity": "warning",
            "message": str(exc),
        }]

    for number, line in enumerate(content.splitlines(), start=1):
        for rule, severity, pattern, message in PATTERNS:
            if pattern.search(line):
                findings.append({
                    "file": str(path.relative_to(root)),
                    "line": number,
                    "rule": rule,
                    "severity": severity,
                    "message": message,
                })

    return findings


def analyze_repository(directory: str):
    root = Path(directory).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {root}")

    findings = []
    scanned = 0

    for path in iter_source_files(root):
        scanned += 1
        findings.extend(analyze_file(path, root))

    return {
        "engine": "MIZAN",
        "version": "0.1.0",
        "repository": str(root),
        "files_scanned": scanned,
        "findings_count": len(findings),
        "findings": findings,
    }
