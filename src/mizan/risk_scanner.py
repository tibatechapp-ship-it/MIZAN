"""Read-only Git change risk assessment."""

import subprocess
from pathlib import Path

from ._version import __version__

HIGH_RISK = {
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "Dockerfile",
    "docker-compose.yml",
    ".github/workflows",
    "src/mizan/cli.py",
}

SECURITY_TERMS = {
    "auth", "security", "permission", "crypto",
    "password", "secret", "token", "middleware",
}


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def scan_change_risk(directory="."):
    root = Path(directory).expanduser().resolve()

    if not root.is_dir():
        raise ValueError("Invalid repository directory.")

    git_root = git(root, "rev-parse", "--show-toplevel")

    if not git_root:
        raise ValueError("Directory is not inside a Git repository.")

    raw = git(root, "status", "--porcelain")

    changes = []

    if raw:
        for line in raw.splitlines():
            if len(line) < 4:
                continue

            status = line[:2]
            filename = line[3:].split(" -> ")[-1].strip('"')

            changes.append({
                "status": status,
                "file": filename,
            })

    score = 0
    findings = []

    for item in changes:
        filename = item["file"]
        lowered = filename.lower()
        basename = Path(filename).name

        if basename in HIGH_RISK or ".github/workflows/" in lowered:
            score += 15
            findings.append({
                "file": filename,
                "rule": "critical-component-changed",
                "severity": "high",
                "message": "Critical configuration or engine component changed.",
            })

        elif any(term in lowered for term in SECURITY_TERMS):
            score += 12
            findings.append({
                "file": filename,
                "rule": "security-component-changed",
                "severity": "medium",
                "message": "Security-sensitive component changed.",
            })

        else:
            score += 2

    score = min(score, 100)

    if score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    return {
        "engine": "MIZAN Change Risk Analyzer",
        "version": __version__,
        "repository": git_root,
        "changed_files_count": len(changes),
        "changed_files": changes,
        "risk_score": score,
        "risk_level": level,
        "findings_count": len(findings),
        "findings": findings,
        "mode": "read-only",
        "execution_performed": False,
    }
