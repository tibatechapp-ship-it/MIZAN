"""Read-only Git repository inspection."""

import subprocess
from pathlib import Path

from ._version import __version__


def run_git(root, *args):
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


def scan_git_repository(directory="."):
    root = Path(directory).expanduser().resolve()

    if not root.is_dir():
        raise ValueError(f"Invalid directory: {root}")

    git_root = run_git(root, "rev-parse", "--show-toplevel")

    if not git_root:
        raise ValueError("Directory is not inside a Git repository")

    branch = run_git(root, "branch", "--show-current")
    commit = run_git(root, "rev-parse", "HEAD")
    status = run_git(root, "status", "--short")
    remotes = run_git(root, "remote")

    recent = run_git(
        root,
        "log",
        "-5",
        "--format=%h|%s|%aI"
    )

    changes = status.splitlines() if status else []

    commits = []

    if recent:
        for line in recent.splitlines():
            parts = line.split("|", 2)

            if len(parts) == 3:
                commits.append({
                    "hash": parts[0],
                    "message": parts[1],
                    "date": parts[2],
                })

    return {
        "engine": "MIZAN Git Scanner",
        "version": __version__,
        "repository": git_root,
        "branch": branch,
        "commit": commit,
        "working_tree_clean": not bool(changes),
        "changed_files_count": len(changes),
        "changed_files": changes,
        "remotes": remotes.splitlines() if remotes else [],
        "recent_commits": commits,
        "mode": "read-only",
        "execution_performed": False,
    }
