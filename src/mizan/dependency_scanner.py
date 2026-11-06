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
from mizan.reachability import annotate_reachability
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


def _is_requirements_file(name):
    """v0.11.0: requirements*.txt — including requirements-dev.txt — are
    dependency manifests (previously only exact 'requirements.txt' was
    scanned, so dev-pinned dependency sets went entirely unseen)."""
    return name == "requirements.txt" or (
        name.startswith("requirements") and name.endswith(".txt")
    )


def parse_requirements(path):
    """Parse a requirements*.txt file into dependency records."""
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


def _pypi_records(path, records):
    """Tag requirements/pyproject records with ecosystem + dev scope.

    v0.11.0: ``requirements-dev.txt`` / ``requirements_dev.txt`` style
    filenames mark a dev-scoped dependency set (a documented filename
    convention, not a guess about content).
    """
    scope = "dev" if "dev" in Path(path).stem.lower() else "runtime"
    return [dict(record, ecosystem="PyPI", scope=scope) for record in records]


def parse_manifest(path):
    """Parse a dependency manifest into dependency records."""
    name = path.name

    if _is_requirements_file(name):
        return _pypi_records(path, parse_requirements(path))

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
                    "ecosystem": "npm",
                    # v0.11.0: devDependencies never ship to production
                    # runtimes — deterministic scope, used for the
                    # documented dev-severity cap on OSV findings.
                    "scope": "dev" if section == "devDependencies"
                             else "runtime",
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
                "ecosystem": "PyPI",
                "scope": "runtime",
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
                    "ecosystem": "crates.io",
                    # dev- AND build-dependencies are not shipped inside
                    # the produced artifact (simplification documented in
                    # the CHANGELOG).
                    "scope": "runtime" if section == "dependencies"
                             else "dev",
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
                        "ecosystem": "Packagist",
                        "scope": "dev" if section == "require-dev"
                                 else "runtime",
                    })

        return result

    if name == "go.mod":
        result = []

        # v0.11.0: also parse single-line `require mod v1` forms and
        # require-blocks (the previous line regex only matched dep lines
        # that started the line, missing the common one-line require).
        in_block = False
        for line in path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line == "require (":
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if in_block:
                match = re.match(r"([A-Za-z0-9._/-]+)\s+(v\S+)", line)
            else:
                match = re.match(
                    r"(?:require\s+)?([A-Za-z0-9._/-]+)\s+(v\S+)", line
                )
            if match:
                result.append({
                    "name": match.group(1),
                    "constraint": match.group(2),
                    "source": name,
                    "ecosystem": "Go",
                    "scope": "runtime",
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
                    "ecosystem": "PyPI",
                    "scope": "dev" if section == "dev-packages"
                             else "runtime",
                })

        return result

    return []


def scan_dependencies(directory="."):
    """Scan dependency manifests and return the dependencies section."""
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

        if not path.is_file() or not (
            path.name in MANIFESTS or _is_requirements_file(path.name)
        ):
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
    dev_capped = 0
    for entry in osv_results:
        dep = {k: v for k, v in entry.items()
               if k in ("name", "version", "ecosystem", "manifest", "scope")}
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
            severity = severity_of(vuln)
            finding = {
                "file": dep.get("manifest") or dep.get("name", ""),
                "rule": f"osv-{vuln.get('id', 'unknown')}",
                "severity": severity,
                "message": f"{dep.get('name', '?')}@{dep.get('version', '?')}: "
                           f"{vuln.get('summary') or vuln.get('id', '')}",
                "dependency": dep,
                "vuln": vuln,
            }
            # v0.11.0 — deterministic dev-dependency cap. devDependencies /
            # dev-packages / require-dev never ship to production runtimes,
            # so a CRITICAL/HIGH OSV record on them is capped at "medium"
            # (below the default gate) with the original severity PRESERVED
            # in "original_severity" — visible, never hidden, and the cap
            # is undone by gating on "critical,high,medium" explicitly.
            if dep.get("scope") == "dev" and \
                    str(severity).upper() in ("CRITICAL", "HIGH"):
                finding["severity"] = "medium"
                finding["original_severity"] = str(severity).upper()
                finding["scope"] = "dev"
                dev_capped += 1
            findings.append(finding)

    # v0.11.0 — shallow reachability annotation (informational ONLY:
    # "not-imported" never downgrades anything; see reachability.py).
    reachability_annotated = annotate_reachability(findings, root)

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
        "dev_severity_capped": dev_capped,
        "reachability_annotated": reachability_annotated,
        "reachability_mode": "shallow import scan — informational, never severity-changing",
        "vulnerability_database_checked": True,
        "osv_errors": osv_errors,
        "osv_unchecked": osv_unchecked,
        "mode": "read-only",
        "execution_performed": False,
    }
