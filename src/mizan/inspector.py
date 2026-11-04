"""Repository structure inspection."""

from pathlib import Path
from .analyzer import IGNORED_DIRS


def inspect_repository(directory: str):
    root = Path(directory).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Directory does not exist: {root}")

    directories = []
    files = []

    for current, dirs, filenames in __import__("os").walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)

        relative = Path(current).relative_to(root)
        if str(relative) != ".":
            directories.append(str(relative))

        for filename in sorted(filenames):
            path = Path(current) / filename
            files.append(str(path.relative_to(root)))

    return {
        "repository": str(root),
        "directories_count": len(directories),
        "files_count": len(files),
        "directories": directories,
        "files": files,
    }
