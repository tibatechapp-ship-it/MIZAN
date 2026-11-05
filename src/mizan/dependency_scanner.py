"""Offline dependency manifest inspection."""

import json
import re

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from pathlib import Path

from mizan._version import __version__

MAX_MANIFEST_SIZE = 2 * 1024 * 1024

MANIFESTS = {
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "composer.json",
}


def parse_requirements(path):
    dependencies = []

    for line in path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "-")):
            continue

        match = re.match(
            r"^([A-Za-z0-9_.-]+)\s*(.*)$", line
        )

        if match:
            dependencies.append({
                "name": match.group(1),
                "constraint": match.group(2).strip(),
                "source": path.name,
            })

    return dependencies


def parse_manifest(path):
    name = path.name

    if name == "requirements.txt":
        return parse_requirements(path)

    if name == "package.json":
        data = json.loads(path.read_text(encoding="utf-8"))
        result = []

        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
        ):
            for package, version in data.get(section, {}).items():
                result.append({
                    "name": package,
                    "constraint": str(version),
                    "source": name,
                })

        return result

    if name == "pyproject.toml":
        data = tomllib.loads(
            path.read_text(encoding="utf-8")
        )
        dependencies = data.get("project", {}).get(
            "dependencies", []
        )

        return [
            {
                "name": item.split(";")[0].split("[")[0].split("<")[0]
                    .split(">")[0].split("=")[0].strip(),
                "constraint": item,
                "source": name,
            }
            for item in dependencies
        ]

    if name == "Cargo.toml":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        result = []

        for section in (
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
        ):
            for package, constraint in data.get(section, {}).items():
                result.append({
                    "name": package,
                    "constraint": str(constraint),
                    "source": name,
                })

        return result

    if name == "composer.json":
        data = json.loads(path.read_text(encoding="utf-8"))
        result = []

        for section in ("require", "require-dev"):
            for package, version in data.get(section, {}).items():
                if package != "php":
                    result.append({
                        "name": package,
                        "constraint": str(version),
                        "source": name,
                    })

        return result

    if name == "go.mod":
        result = []

        for line in path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            match = re.match(
                r"^\s*([A-Za-z0-9._/-]+)\s+(v\S+)", line
            )
            if match:
                result.append({
                    "name": match.group(1),
                    "constraint": match.group(2),
                    "source": name,
                })

        return result

    if name == "Pipfile":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        result = []

        for section in ("packages", "dev-packages"):
            for package, version in data.get(section, {}).items():
                result.append({
                    "name": package,
                    "constraint": str(version),
                    "source": name,
                })

        return result

    return []


def scan_dependencies(directory="."):
    root = Path(directory).expanduser().resolve()

    if not root.is_dir():
        raise ValueError(f"Invalid directory: {root}")

    ignored = {
        ".git", ".venv", "venv", "node_modules",
        "__pycache__", "dist", "build"
    }

    manifests = []
    dependencies = []
    findings = []

    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue

        if not path.is_file() or path.name not in MANIFESTS:
            continue

        if path.stat().st_size > MAX_MANIFEST_SIZE:
            findings.append({
                "file": str(path.relative_to(root)),
                "rule": "manifest-too-large",
                "severity": "warning",
                "message": "Manifest exceeds the scanning size limit.",
            })
            continue

        try:
            items = parse_manifest(path)
            manifests.append(str(path.relative_to(root)))
            dependencies.extend(items)

        except (ValueError, OSError, json.JSONDecodeError) as exc:
            findings.append({
                "file": str(path.relative_to(root)),
                "rule": "invalid-dependency-manifest",
                "severity": "warning",
                "message": str(exc)[:200],
            })

    return {
        "engine": "MIZAN Dependency Scanner",
        "version": __version__,
        "repository": str(root),
        "manifests_scanned": len(manifests),
        "manifests": manifests,
        "dependencies_count": len(dependencies),
        "dependencies": dependencies,
        "findings_count": len(findings),
        "findings": findings,
        "vulnerability_database_checked": False,
        "mode": "read-only",
        "execution_performed": False,
    }
