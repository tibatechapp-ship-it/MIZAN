"""MIZAN Security — unified severity gate and baseline (delta) scanning.

Q2 wave (v0.8.0). Two features that the strongest scanners
(CodeQL, Semgrep, Snyk) built their adoption on, rebuilt in MIZAN's
own style — one lightweight engine, zero extra dependencies:

* **Severity gate** — normalize every scanner's severity vocabulary
  (repo findings use ``high/medium/warning/info``, OSV records use
  UPPERCASE ``CRITICAL/HIGH/MODERATE/IMPORTANT/TRIVIAL/LOW``) onto one
  canonical ladder, then fail the build only on findings at or above a
  chosen threshold. Opt-in via ``mizan scan --gate``; the default
  remains a reporter (Q1 policy).

* **Baseline (delta scanning)** — fingerprint every finding
  (sha256 of rule|file|line|message, or dependency@version|vuln-id for
  OSV records), save the known set to ``.mizan/baseline.json``, and
  gate ONLY on new findings. This kills alert fatigue — the #1 reason
  teams abandon security scanners — without ever hiding a regression.
"""

import hashlib
import json
import time
from pathlib import Path

from ._version import __version__

BASELINE_SCHEMA = "mizan-baseline/1"
DEFAULT_BASELINE_PATH = ".mizan/baseline.json"
DEFAULT_BLOCKING = ("critical", "high")

# Canonical ladder, highest priority first. ``warning`` keeps its own
# rung (repo-scan vocabulary) and never blocks by default; unknown
# spellings are reported but never gate (no invented evidence).
SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "warning": 3,
    "low": 4,
    "info": 5,
    "unknown": 6,
}

_SEVERITY_ALIASES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",     # OSV/GH ecosystem alias
    "IMPORTANT": "high",      # OSV/GH ecosystem alias
    "LOW": "low",
    "TRIVIAL": "low",         # OSV/GH ecosystem alias
    "WARNING": "warning",
    "WARN": "warning",
    "INFO": "info",
    "UNKNOWN": "unknown",
}


def normalize_severity(raw):
    """Map any severity spelling onto the canonical ladder.

    Accepts both vocabularies already used inside MIZAN (lowercase
    repo findings and UPPERCASE OSV records). Unknown values become
    ``unknown`` — they are surfaced, never silently dropped, and never
    gate the build.
    """
    if raw is None:
        return "unknown"
    return _SEVERITY_ALIASES.get(str(raw).strip().upper(), "unknown")


def fingerprint(finding):
    """Return a stable 16-hex-char fingerprint for one finding dict.

    Code findings  : rule | file | line | message
    OSV findings   : osv | name@version | vuln-id   (independent of line noise)
    """
    if isinstance(finding, dict) and isinstance(finding.get("vuln"), dict):
        dep = finding.get("dependency") or {}
        key = "osv|{name}@{version}|{vid}".format(
            name=dep.get("name", ""),
            version=dep.get("version", ""),
            vid=finding["vuln"].get("id", ""),
        )
    else:
        key = "|".join([
            str(finding.get("rule", "")),
            str(finding.get("file", "")),
            str(finding.get("line", 0)),
            str(finding.get("message", "")),
        ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def collect_findings(result):
    """Recursively gather every ``findings`` list from a scan result tree.

    Works across the nested shapes of ``full_scan_repository`` (analysis,
    scanner, dependencies, ...) without hard-coding section names.
    """
    collected = []
    if isinstance(result, dict):
        findings = result.get("findings")
        if isinstance(findings, list):
            collected.extend(f for f in findings if isinstance(f, dict))
        for value in result.values():
            if isinstance(value, (dict, list)) and value is not findings:
                collected.extend(collect_findings(value))
    elif isinstance(result, list):
        for item in result:
            collected.extend(collect_findings(item))
    return collected


def validate_blocking(severities):
    """Validate gate severities against the canonical ladder.

    Accepts any case; returns the normalized lowercase tuple. Raises
    ``ValueError`` naming the invalid entries — the gate must fail
    loudly on a typo (``--gate critial``) instead of silently passing
    the build (fail-open).
    """
    normalized = tuple(
        str(s).strip().lower() for s in severities if str(s).strip()
    )
    invalid = [s for s in normalized if s not in SEVERITY_RANK]
    if invalid:
        raise ValueError(
            f"Unknown gate severity: {', '.join(invalid)} "
            f"(valid: {', '.join(SEVERITY_RANK)})"
        )
    if not normalized:
        return tuple(DEFAULT_BLOCKING)
    return normalized


def dedupe_findings(findings):
    """Drop duplicate findings (same fingerprint AND severity).

    ``full_scan_repository`` reports the code pass twice (under
    ``analysis`` and ``scanner`` sections) — the gate must count a
    finding once, not once per section that saw it.
    """
    seen = set()
    unique = []
    for finding in findings:
        key = (fingerprint(finding), normalize_severity(finding.get("severity")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def gate_findings(findings, blocking=DEFAULT_BLOCKING):
    """Split findings into (blocking, allowed) by normalized severity."""
    blocking_list, allowed = [], []
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        if severity in blocking:
            blocking_list.append(finding)
        else:
            allowed.append(finding)
    return blocking_list, allowed


def save_baseline(findings, path=DEFAULT_BASELINE_PATH, note=""):
    """Persist the current findings' fingerprints as the known set."""
    fingerprints = {}
    for finding in findings:
        fingerprints[fingerprint(finding)] = {
            "rule": str(finding.get("rule", "")),
            "file": str(finding.get("file", "")),
            "line": finding.get("line", 0),
            "severity": normalize_severity(finding.get("severity")),
        }
    doc = {
        "schema": BASELINE_SCHEMA,
        "tool": "MIZAN Security",
        "version": __version__,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "count": len(fingerprints),
        "note": note,
        "fingerprints": fingerprints,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return doc


def load_baseline(path=DEFAULT_BASELINE_PATH):
    """Load and validate a baseline document."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema") != BASELINE_SCHEMA:
        raise ValueError(
            f"Unsupported baseline schema: {doc.get('schema')!r} "
            f"(expected {BASELINE_SCHEMA!r})"
        )
    return doc


def filter_baseline(findings, baseline):
    """Return (new_findings, known_count) versus a baseline document."""
    known = set(baseline.get("fingerprints", {}))
    new = [f for f in findings if fingerprint(f) not in known]
    return new, len(findings) - len(new)


def apply_gate(findings, blocking=DEFAULT_BLOCKING, baseline_path=None,
               incomplete_sources=None):
    """Full gate decision: baseline filtering + severity threshold.

    Returns a result dict suitable for embedding in a scan report under
    the ``"gate"`` key:
    ``{"decision": "pass"|"fail"|"incomplete", "blocking_findings": [...], ...}``.

    ``incomplete_sources`` (RW-202): names of scanners / data sources that
    could not run (e.g. ``scanners_failed`` entries or an OSV outage).
    A partial scan must never certify a clean pass: blocking findings
    still decide ``fail`` (stronger signal), otherwise any incomplete
    source forces ``"incomplete"`` — surfaced with a distinct exit code
    (2) by the CLI, so CI can distinguish
    *complete & clean* from *could not fully verify*.
    """
    # Normalize case ("CRITICAL" == "critical") and refuse typos loudly:
    # a misspelled threshold would otherwise silently gate nothing.
    blocking = validate_blocking(blocking)
    findings = dedupe_findings(findings)
    known_count = 0
    if baseline_path:
        baseline = load_baseline(baseline_path)
        findings, known_count = filter_baseline(findings, baseline)

    blocking_findings, allowed = gate_findings(findings, blocking=blocking)
    incomplete = [str(s) for s in (incomplete_sources or []) if str(s).strip()]
    if blocking_findings:
        decision = "fail"
    elif incomplete:
        decision = "incomplete"
    else:
        decision = "pass"
    return {
        "tool": "MIZAN Security",
        "mode": "gate",
        "blocking_severities": list(blocking),
        "baseline": str(baseline_path) if baseline_path else None,
        "known_suppressed": known_count,
        "evaluated": len(findings),
        "blocking_count": len(blocking_findings),
        "blocking_findings": blocking_findings,
        "incomplete_sources": incomplete,
        "decision": decision,
    }
