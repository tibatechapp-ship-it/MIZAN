"""OSV.dev client and dependency extraction for vulnerability scanning."""

import json
import os
import re
import urllib.error
import urllib.request

from mizan.detector import (
    iter_locked_packages,
    _read_pyproject_dependencies,
)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 15

_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([^\s;#]+)")

_SEVERITY_ALIASES = {
    "MODERATE": "MEDIUM",
    "IMPORTANT": "HIGH",
    "TRIVIAL": "LOW",
}


def check_vulnerabilities(name, version, ecosystem):
    """Query OSV.dev. Returns list of vuln dicts (empty on failure)."""
    if os.environ.get("MIZAN_DISABLE_OSV"):
        return []

    payload = json.dumps({
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        OSV_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []
    return data.get("vulns", [])


def parse_requirements_txt(path):
    """Yield {name, version, ecosystem} from exact pins in requirements.txt."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = _PIN_RE.match(line)
        if match:
            yield {
                "name": match.group(1),
                "version": match.group(2),
                "ecosystem": "PyPI",
            }


def parse_dependencies(files):
    """Extract deduplicated [{name, version, ecosystem, manifest}] from files."""
    seen = set()
    result = []

    for dep in iter_locked_packages(files):
        key = (dep["name"], dep["ecosystem"], dep["version"])
        if key not in seen:
            seen.add(key)
            dep["manifest"] = "<lockfile>"
            result.append(dep)

    for path in files:
        if path.name == "pyproject.toml":
            for dep in _read_pyproject_dependencies(path):
                key = (dep["name"], dep["ecosystem"], dep["version"])
                if key not in seen:
                    seen.add(key)
                    dep["manifest"] = path.name
                    result.append(dep)
        elif path.name == "requirements.txt":
            for dep in parse_requirements_txt(path):
                key = (dep["name"], dep["ecosystem"], dep["version"])
                if key not in seen:
                    seen.add(key)
                    dep["manifest"] = path.name
                    result.append(dep)

    return result


def severity_of(vuln):
    """Best-effort normalized severity string from an OSV record."""
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict):
        sev = db.get("severity")
        if isinstance(sev, str):
            upper = sev.upper()
            return _SEVERITY_ALIASES.get(upper, upper)
    return "UNKNOWN"
