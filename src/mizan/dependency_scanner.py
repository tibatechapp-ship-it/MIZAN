"""Dependency manifest inspection + OSV.dev vulnerability check."""

import json
import os
import re

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from pathlib import Path

from mizan._version import __version__
from mizan.vulnerabilities import check_vulnerabilities_batch, severity_of

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

    # RW-204: the full-scan gate must see OSV findings. This section
    # previously NEVER queried OSV (`vulnerability_database_checked` was
    # hardcoded False) while the report promised "deps/OSV" gating — a
    # silent coverage hole. One batched round-trip (offline-aware via
    # MIZAN_OFFLINE / MIZAN_OSV_CACHE); failures are surfaced as
    # ``osv_errors`` / ``osv_unchecked`` and drive the gate's
    # "incomplete" decision — never cached as a clean result.
    osv_results = check_vulnerabilities_batch(
        dependencies, use_cache=os.environ.get("MIZAN_OSV_CACHE") == "1"
    )
    osv_errors = []
    osv_unchecked = []
    for entry in osv_results:
        dep = {k: v for k, v in entry.items()
               if k in ("name", "version", "ecosystem", "manifest")}
        source = entry.get("source")
        if source in ("scan-error", "detail-error"):
            osv_errors.append({
                **dep, "source": source,
                "error": entry.get("error", ""),
                "vuln_ids": entry.get("vuln_ids", []),
            })
        elif source == "offline-miss":
            osv_unchecked.append({**dep, "source": source})
        for vuln in entry.get("vulns", []):
            findings.append({
                "file": dep.get("manifest") or dep.get("name", ""),
                "rule": f"osv-{vuln.get('id', 'unknown')}",
                "severity": severity_of(vuln),
                "message": f"{dep.get('name', '?')}@{dep.get('version', '?')}: "
                           f"{vuln.get('summary') or vuln.get('id', '')}",
                "dependency": dep,
                "vuln": vuln,
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
        "vulnerability_database_checked": True,
        "osv_errors": osv_errors,
        "osv_unchecked": osv_unchecked,
        "mode": "read-only",
        "execution_performed": False,
    }
