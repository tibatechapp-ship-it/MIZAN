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

F-03 (2026-11-26 live audit, four measured reproductions in one day):
the original code fingerprint anchored on the LINE NUMBER, so any
insert/delete above a finding shifted its line and the suppressed
finding re-fired as "new" — burning the gate on unchanged content.
Baseline schema ``mizan-baseline/2`` anchors code findings on the
offending line's CONTENT instead: same text at a moved line = same
fingerprint (a pure shift no longer re-fires); the text itself changing
re-fires honestly. Schema /1 baselines keep the line-anchored formula
(backward compatible, limitation documented); a /2 baseline used
without the scan root refuses loudly instead of mis-comparing.
"""

import hashlib
import json
import time
from functools import lru_cache
from pathlib import Path

from ._version import __version__

BASELINE_SCHEMA = "mizan-baseline/1"
BASELINE_SCHEMA_V2 = "mizan-baseline/2"
BASELINE_SCHEMES = (BASELINE_SCHEMA, BASELINE_SCHEMA_V2)
SCHEME_LINE = "line-anchored"
SCHEME_CONTENT = "content-anchored"
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


def _read_lines(root, file_path):
    """Return the tuple of lines of ``root/file_path`` (UTF-8, errors
    replaced), or ``None`` when the file cannot be read — a missing
    anchor degrades to the line-anchored formula, never to an invented
    identity. Cached per (root, file): the gate fingerprints every
    finding and re-reading one file per finding would multiply the I/O
    for no informational gain."""
    try:
        path = Path(root) / str(file_path)
        return tuple(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except (OSError, ValueError):
        return None


def _line_content(root, file_path, line):
    """Return the stripped text of 1-based ``line`` inside
    ``root/file_path``, or ``None`` when no root is given, the line is
    absent/zero, or the file cannot be read."""
    if not root or not line:
        return None
    try:
        index = int(line) - 1
    except (TypeError, ValueError):
        return None
    if index < 0:
        return None
    lines = _read_lines(root, file_path)
    if lines is None or index >= len(lines):
        return None
    return lines[index].strip()


def fingerprint(finding, root=None):
    """Return a stable 16-hex-char fingerprint for one finding dict.

    Code findings, without a scan root (or when the line's content
    cannot be read): rule | file | line | message — the historical
    line-anchored identity (BM-104..106), preserved verbatim for /1
    baselines.

    Code findings, with a scan root and a readable line: rule | file |
    LINE CONTENT | message, tagged ``ca1|`` — the F-03 content-anchored
    identity. A pure line shift (insert/delete above the finding)
    keeps this fingerprint stable; the finding re-fires only when the
    offending text itself changes. Two findings with identical rule,
    file, content AND message deliberately share one fingerprint —
    they are indistinguishable to suppression, so accepting one
    accepts both (measured trade-off, documented).

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
        content = _line_content(root, finding.get("file", ""),
                                finding.get("line", 0))
        if content is not None:
            key = "ca1|" + "|".join([
                str(finding.get("rule", "")),
                str(finding.get("file", "")),
                content,
                str(finding.get("message", "")),
            ])
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


def dedupe_findings(findings, root=None):
    """Drop duplicate findings (same fingerprint AND severity).

    ``full_scan_repository`` reports the code pass twice (under
    ``analysis`` and ``scanner`` sections) — the gate must count a
    finding once, not once per section that saw it. The root is
    threaded through so a content-anchored comparison dedupes under
    the SAME scheme the baseline filter will use.
    """
    seen = set()
    unique = []
    for finding in findings:
        key = (fingerprint(finding, root=root),
               normalize_severity(finding.get("severity")))
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


def save_baseline(findings, path=DEFAULT_BASELINE_PATH, note="", root=None):
    """Persist the current findings' fingerprints as the known set.

    With a scan ``root``, the baseline is saved as schema
    ``mizan-baseline/2`` (content-anchored — F-03): findings whose
    offending line is readable anchor on the line's content, so later
    line shifts do not re-fire them. Without a root the historical
    ``mizan-baseline/1`` (line-anchored) is written unchanged.
    """
    fingerprints = {}
    for finding in findings:
        fingerprints[fingerprint(finding, root=root)] = {
            "rule": str(finding.get("rule", "")),
            "file": str(finding.get("file", "")),
            "line": finding.get("line", 0),
            "severity": normalize_severity(finding.get("severity")),
        }
    if root is not None:
        schema = BASELINE_SCHEMA_V2
    else:
        schema = BASELINE_SCHEMA
    doc = {
        "schema": schema,
        "fingerprint_scheme": (
            SCHEME_CONTENT if root is not None else SCHEME_LINE
        ),
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
    """Load and validate a baseline document.

    Both ``mizan-baseline/1`` (line-anchored) and
    ``mizan-baseline/2`` (content-anchored, F-03) are accepted; any
    other schema is refused loudly — a foreign or newer format must
    never be silently compared with the wrong formula.
    """
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema") not in BASELINE_SCHEMES:
        raise ValueError(
            f"Unsupported baseline schema: {doc.get('schema')!r} "
            f"(expected one of {BASELINE_SCHEMES!r})"
        )
    return doc


def filter_baseline(findings, baseline, root=None):
    """Return (new_findings, known_count) versus a baseline document.

    The comparison scheme follows the baseline's schema: /1 compares
    line-anchored fingerprints (historical), /2 compares
    content-anchored fingerprints and therefore REQUIRES the scan root
    — a /2 baseline used without one refuses loudly instead of
    mis-comparing every finding into "new".
    """
    scheme = (
        SCHEME_CONTENT
        if baseline.get("schema") == BASELINE_SCHEMA_V2
        else SCHEME_LINE
    )
    if scheme == SCHEME_CONTENT and not root:
        raise ValueError(
            "content-anchored baseline (mizan-baseline/2) requires the "
            "scan root for comparison — pass root=... (the CLI threads "
            "the scanned path automatically)"
        )
    # Scheme consistency is enforced HERE, not just by the caller: a /1
    # baseline compares line-anchored fingerprints even when a root was
    # threaded in — mixing schemes would mis-compare every finding into
    # "new" and silently burn the gate (the exact F-03 failure shape).
    fp_root = root if scheme == SCHEME_CONTENT else None
    known = set(baseline.get("fingerprints", {}))
    new = [
        f for f in findings
        if fingerprint(f, root=fp_root) not in known
    ]
    return new, len(findings) - len(new)


def apply_gate(findings, blocking=DEFAULT_BLOCKING, baseline_path=None,
               incomplete_sources=None, root=None):
    """Full gate decision: baseline filtering + severity threshold.

    Returns a result dict suitable for embedding in a scan report under
    the ``"gate"`` key:
    ``{"decision": "pass"|"fail"|"incomplete", "blocking_findings": [...], ...}``.

    ``root`` (F-03): the scanned path, threaded from the CLI so a
    content-anchored (``mizan-baseline/2``) baseline can compare
    fingerprints against the real line contents. A /2 baseline without
    a root refuses loudly; /1 baselines and baseline-less runs are
    unchanged. The report surfaces which baseline schema and
    fingerprint scheme were used — the anchoring is visible, never
    implicit.

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
    baseline = load_baseline(baseline_path) if baseline_path else None
    scheme = (
        SCHEME_CONTENT
        if baseline is not None
        and baseline.get("schema") == BASELINE_SCHEMA_V2
        else SCHEME_LINE
    )
    if scheme == SCHEME_CONTENT and not root:
        raise ValueError(
            "content-anchored baseline (mizan-baseline/2) requires the "
            "scan root for comparison — pass root=... (the CLI threads "
            "the scanned path automatically)"
        )
    fp_root = root if scheme == SCHEME_CONTENT else None
    findings = dedupe_findings(findings, root=fp_root)
    known_count = 0
    if baseline is not None:
        findings, known_count = filter_baseline(
            findings, baseline, root=root
        )

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
        "baseline_schema": (
            baseline.get("schema") if baseline is not None else None
        ),
        "fingerprint_scheme": scheme if baseline is not None else None,
        "known_suppressed": known_count,
        "evaluated": len(findings),
        "blocking_count": len(blocking_findings),
        "blocking_findings": blocking_findings,
        "incomplete_sources": incomplete,
        "decision": decision,
    }
