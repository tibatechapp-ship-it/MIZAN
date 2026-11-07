"""OSV.dev client and dependency extraction for vulnerability scanning.

Q1 performance hardening (P1):
  * ``check_vulnerabilities_batch`` — ONE round-trip for N packages via the
    OSV ``querybatch`` endpoint, followed by detail fetches only for
    packages that actually have vulnerabilities.
  * Local JSON cache (``.mizan/osv-cache.json``, TTL default 24h) with
    negative caching — repeated scans of unchanged manifests hit nothing.
  * Offline mode (``MIZAN_OFFLINE=1`` or ``offline=True``): serve from the
    cache only; unreachable packages are reported as ``unknown`` instead
    of failing the whole scan.
"""

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

from mizan.detector import (
    iter_locked_packages,
    _read_pyproject_dependencies,
)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 15
# OSV rejects oversized querybatch payloads with HTTP 400 (field-proven:
# a 1024-dependency monorepo failed while subsets passed). Keep every
# round-trip comfortably under that ceiling.
OSV_BATCH_CHUNK = 100
OSV_MAX_ATTEMPTS = 3
_OSV_RETRY_SLEEP = 0.6

CACHE_DIR = ".mizan"
CACHE_FILE = "osv-cache.json"
CACHE_VERSION = 1
DEFAULT_CACHE_TTL = 24 * 3600

_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([^\s;#]+)")

_SEVERITY_ALIASES = {
    "MODERATE": "MEDIUM",
    "IMPORTANT": "HIGH",
    "TRIVIAL": "LOW",
}


def _offline_requested(explicit=None):
    if explicit is not None:
        return bool(explicit)
    return os.environ.get("MIZAN_OFFLINE", "") not in ("", "0")


def _cache_ttl():
    raw = os.environ.get("MIZAN_OSV_CACHE_TTL")
    try:
        return max(0, int(raw)) if raw else DEFAULT_CACHE_TTL
    except ValueError:
        return DEFAULT_CACHE_TTL


def _cache_key(ecosystem, name, version):
    raw = f"{ecosystem}|{name}|{version}"
    # Non-security use: local OSV cache filename only. usedforsecurity=False
    # documents that intent and is honored by MIZAN's own weak-crypto rule.
    return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()


def _cache_load():
    path = os.path.join(CACHE_DIR, CACHE_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"version": CACHE_VERSION, "entries": {}}
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
        return {"version": CACHE_VERSION, "entries": {}}
    data.setdefault("entries", {})
    return data


def _cache_save(cache):
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, CACHE_FILE)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        pass  # cache is best-effort; never fail a scan over it


def _cache_get(cache, ecosystem, name, version):
    """Return the cached vuln list if fresh, else None (miss)."""
    key = _cache_key(ecosystem, name, version)
    entry = cache["entries"].get(key)
    if not isinstance(entry, dict):
        return None
    cached_at = entry.get("cached_at", 0)
    if time.time() - cached_at > _cache_ttl():
        return None
    vulns = entry.get("vulns")
    return vulns if isinstance(vulns, list) else None


def _cache_put(cache, ecosystem, name, version, vulns):
    key = _cache_key(ecosystem, name, version)
    cache["entries"][key] = {
        "vulns": vulns,
        "cached_at": time.time(),
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
    }


def _post_json(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_vulnerabilities(name, version, ecosystem):
    """Query OSV.dev or raise OsvScanError if the check cannot complete."""
    if os.environ.get("MIZAN_DISABLE_OSV"):
        raise OsvScanError("OSV vulnerability checks are disabled")

    if _offline_requested() or os.environ.get("MIZAN_OSV_CACHE") == "1":
        cache = _cache_load()
        cached = _cache_get(cache, ecosystem, name, version)
        if cached is not None:
            return cached
        if _offline_requested():
            raise OsvScanError(
                f"offline mode: no cached OSV result for "
                f"{ecosystem}/{name}@{version}"
            )

    payload = {
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }

    try:
        data = _post_json(OSV_API_URL, payload)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise OsvScanError(f"OSV query failed: {exc}") from exc

    if not isinstance(data, dict):
        raise OsvScanError("OSV returned an invalid response")

    vulns = data.get("vulns", [])
    if not isinstance(vulns, list):
        raise OsvScanError("OSV returned an invalid vulnerabilities list")

    if os.environ.get("MIZAN_OSV_CACHE") == "1":
        cache = _cache_load()
        _cache_put(cache, ecosystem, name, version, vulns)
        _cache_save(cache)

    return vulns


def check_vulnerabilities_batch(packages, offline=None, use_cache=True):
    """Check many packages with batched round-trips (≤100 queries each).

    ``packages`` is a list of ``{name, version, ecosystem}`` dicts.
    Returns a list aligned with the input order; each item adds
    ``vulns`` (full OSV records) and ``source`` in
    ``cache | batch | batch+detail | offline-miss``.

    Protocol: OSV ``querybatch`` returns only vulnerability IDs, so
    full records (severity, summary) are fetched with a single per-
    package query, but ONLY for packages that actually have findings.
    """
    packages = list(packages)
    results = [None] * len(packages)

    cache = _cache_load() if use_cache else {"version": CACHE_VERSION, "entries": {}}

    misses = []
    for idx, pkg in enumerate(packages):
        eco = pkg.get("ecosystem", "PyPI")
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if use_cache:
            cached = _cache_get(cache, eco, name, version)
            if cached is not None:
                results[idx] = {
                    **pkg, "vulns": cached, "source": "cache",
                }
                continue
        misses.append(idx)

    if misses:
        if _offline_requested(offline):
            for idx in misses:
                results[idx] = {
                    **packages[idx], "vulns": [],
                    "source": "offline-miss",
                }
        else:
            queries = [
                {
                    "package": {
                        "name": packages[idx].get("name", ""),
                        "ecosystem": packages[idx].get("ecosystem", "PyPI"),
                    },
                    "version": packages[idx].get("version", ""),
                }
                for idx in misses
            ]
            # Field-proven (100-repo benchmark, 2026-11): OSV ``querybatch``
            # rejects oversized payloads with HTTP 400 — a real monorepo
            # with 1024 transitive dependencies failed deterministically
            # while subsets passed. Chunk every round-trip, retry
            # transient errors, and degrade ONE failing chunk to
            # per-item queries instead of failing the whole scan.
            for c_start in range(0, len(misses), OSV_BATCH_CHUNK):
                chunk_positions = range(
                    c_start, min(c_start + OSV_BATCH_CHUNK, len(misses)))
                chunk_payload = {
                    "queries": [queries[p] for p in chunk_positions]
                }
                data = None
                last_exc = None
                for attempt in range(OSV_MAX_ATTEMPTS):
                    try:
                        data = _post_json(OSV_BATCH_URL, chunk_payload)
                        last_exc = None
                        break
                    except (urllib.error.HTTPError, urllib.error.URLError,
                            OSError, json.JSONDecodeError) as exc:
                        last_exc = exc
                        if attempt + 1 < OSV_MAX_ATTEMPTS:
                            time.sleep(_OSV_RETRY_SLEEP)

                batch_results = None
                if last_exc is None:
                    batch_results = (
                        data.get("results") if isinstance(data, dict) else None)

                if not isinstance(batch_results, list):
                    # This chunk failed after retries (or the mirror/mock
                    # replied without a valid payload): fall back to
                    # sequential single queries for THIS chunk only —
                    # other chunks stay batched.
                    for pos in chunk_positions:
                        idx = misses[pos]
                        pkg = packages[idx]
                        try:
                            vulns = check_vulnerabilities(
                                pkg.get("name", ""), pkg.get("version", ""),
                                pkg.get("ecosystem", "PyPI"),
                            )
                        except OsvScanError as exc:
                            # RW-203: a failed query is NOT a clean result.
                            # Record the failure explicitly and never cache
                            # an empty list that would make an outage look
                            # like "no vulnerabilities" on every later run.
                            results[idx] = {
                                **pkg, "vulns": [],
                                "source": "scan-error",
                                "error": str(exc),
                            }
                            continue
                        results[idx] = {
                            **pkg, "vulns": vulns, "source": "single-fallback",
                        }
                        if use_cache:
                            _cache_put(cache, pkg.get("ecosystem", "PyPI"),
                                       pkg.get("name", ""), pkg.get("version", ""), vulns)
                    continue

                for pos_in_chunk, pos in enumerate(chunk_positions):
                    idx = misses[pos]
                    entry = (batch_results[pos_in_chunk]
                             if pos_in_chunk < len(batch_results) else {})
                    vuln_ids = entry.get("vuln_ids", []) if isinstance(entry, dict) else []
                    pkg = packages[idx]
                    if not vuln_ids:
                        results[idx] = {**pkg, "vulns": [], "source": "batch"}
                        if use_cache:
                            _cache_put(cache, pkg.get("ecosystem", "PyPI"),
                                       pkg.get("name", ""), pkg.get("version", ""), [])
                        continue

                    # full records only where they matter
                    try:
                        vulns = check_vulnerabilities(
                            pkg.get("name", ""), pkg.get("version", ""),
                            pkg.get("ecosystem", "PyPI"),
                        )
                    except OsvScanError as exc:
                        # RW-203: the batch said "vulnerable" but detail fetch
                        # failed — record the failure, keep vuln_ids for the
                        # report, and NEVER cache the empty result.
                        results[idx] = {
                            **pkg, "vulns": [],
                            "source": "detail-error",
                            "error": str(exc),
                            "vuln_ids": vuln_ids,
                        }
                        continue
                    results[idx] = {
                        **pkg, "vulns": vulns,
                        "source": "batch+detail",
                        "vuln_ids": vuln_ids,
                    }
                    if use_cache:
                        _cache_put(cache, pkg.get("ecosystem", "PyPI"),
                                   pkg.get("name", ""), pkg.get("version", ""), vulns)

    if use_cache and misses and not _offline_requested(offline):
        _cache_save(cache)

    return results


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
class OsvScanError(RuntimeError):
    """Raised when OSV vulnerability scanning cannot be completed."""
