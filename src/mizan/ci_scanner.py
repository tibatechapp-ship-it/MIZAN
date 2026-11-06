"""Read-only CI/CD configuration scanner."""

import os
import re
from pathlib import Path

import yaml

from ._version import __version__

IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build",
    ".pytest_cache", ".mypy_cache",
}

def find_ci_files(root):
    for current, dirs, filenames in os.walk(root):
        dirs[:] = sorted(
            d for d in dirs if d not in IGNORED_DIRS
        )

        for filename in sorted(filenames):
            path = Path(current) / filename
            relative = path.relative_to(root).as_posix()

            if (
                relative.startswith(".github/workflows/")
                and path.suffix.lower() in {".yml", ".yaml"}
            ) or filename == ".gitlab-ci.yml":
                yield path


def inspect_ci_file(path, root):
    findings = []
    relative = path.relative_to(root).as_posix()

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError as exc:
        return [{
            "file": relative,
            "line": 0,
            "rule": "ci-file-read-error",
            "severity": "warning",
            "message": str(exc),
        }]

    try:
        yaml.safe_load(content)
    except yaml.YAMLError:
        return [{
            "file": relative,
            "line": 0,
            "rule": "invalid-yaml",
            "severity": "high",
            "message": "CI configuration contains invalid YAML.",
        }]

    rules = [
        (
            r"(?m)^\s*permissions\s*:\s*write-all\s*$",
            "excessive-permissions",
            "high",
            "Workflow grants write-all permissions."
        ),
        (
            r"(?m)^\s*pull_request_target\s*:",
            "pull-request-target",
            "warning",
            "Review privileged pull_request_target workflows carefully."
        ),
        (
            r"(?m)^\s*persist-credentials\s*:\s*true\s*$",
            "persisted-git-credentials",
            "medium",
            "Checkout persists Git credentials in the workspace."
        ),
        (
            r"(?m)^\s*continue-on-error\s*:\s*true\s*$",
            "continue-on-error",
            "medium",
            "A workflow step may ignore execution failures."
        ),
        (
            r"(?m)^\s*uses\s*:\s*[^#\s]+@(?![0-9a-fA-F]{40}\s*(?:#.*)?$)[^\s]+",
            "unpinned-action",
            "medium",
            "Action is not pinned to a full commit SHA."
        ),
    ]

    for pattern, rule, severity, message in rules:
        for match in re.finditer(pattern, content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append({
                "file": relative,
                "line": line,
                "rule": rule,
                "severity": severity,
                "message": message,
            })

    return findings


def scan_ci_repository(directory="."):
    root = Path(directory).expanduser().resolve()

    if not root.is_dir():
        raise ValueError(f"Invalid repository directory: {root}")

    findings = []
    files = list(find_ci_files(root))

    for path in files:
        findings.extend(inspect_ci_file(path, root))

    return {
        "engine": "MIZAN CI/CD Scanner",
        "version": __version__,
        "repository": str(root),
        "files_scanned": len(files),
        "findings_count": len(findings),
        "findings": findings,
        "mode": "read-only",
        "execution_performed": False,
    }
