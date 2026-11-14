"""Merge & triage for normalized findings — wave 1 of DEV_PLAN_V0150.md.

The governing principle is "link, never erase":

- ``merge_findings`` groups normalized ``mizan.finding.v1`` entries by
  their stable fingerprint. Every occurrence from every tool is kept
  verbatim inside its group — a finding is never dropped because another
  tool disagreed, and removing one report from the merge can never erase
  another tool's evidence.
- ``apply_triage`` applies documented review decisions. Decisions that
  reference unknown fingerprints fail loudly: suppression without a
  documented finding is rejected (MIZAN does not honor blind ``# nosec``-
  style suppression).
- ``gate_external_findings`` gates on the verbatim severity carried from
  the source tool's properties. ``unknown`` never blocks; triaged
  findings never block; only severities explicitly listed in the
  blocking set fail the gate. Verbatim means verbatim: no case-folding,
  no severity-ladder normalization without documented triage.
"""

from __future__ import annotations

from typing import Any

from .sarif_import import FINDING_SCHEMA

MERGED_SCHEMA = "mizan.merged.v1"
TRIAGE_SCHEMA = "mizan.triage.v1"
EXTERNAL_GATE_SCHEMA = "mizan.external_gate.v1"

TRIAGE_STATUSES = ("unreviewed", "accepted", "false_positive")
_APPLY_STATUSES = ("accepted", "false_positive")


class MergeError(ValueError):
    """Raised when merge/triage input is missing, invalid, or unknown."""


def _validate_finding(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict) or finding.get("schema") != FINDING_SCHEMA:
        raise MergeError(
            f"merge expects {FINDING_SCHEMA} entries; got "
            f"{type(finding).__name__} without the schema marker"
        )
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise MergeError(
            f"finding from {finding.get('source', {}).get('tool', '?')!r} "
            "has no fingerprint — cannot link without losing data"
        )
    return finding


def merge_findings(findings_lists: list[list[dict[str, Any]]]) -> dict[str, Any]:
    """Group findings by fingerprint across every source list.

    Groups preserve first-seen order and every occurrence verbatim, so
    the merge is a link layer, not a dedup-that-drops layer.
    """
    if not findings_lists:
        raise MergeError(
            "merge-findings requires at least one findings list"
        )

    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    total = 0

    for index, findings in enumerate(findings_lists):
        if not isinstance(findings, list):
            raise MergeError(
                f"findings list {index} must be a list of "
                f"{FINDING_SCHEMA} entries"
            )
        for finding in findings:
            validated = _validate_finding(finding)
            fingerprint = validated["fingerprint"]
            total += 1
            if fingerprint not in grouped:
                grouped[fingerprint] = []
                order.append(fingerprint)
            grouped[fingerprint].append(validated)

    return {
        "schema": MERGED_SCHEMA,
        "count_total": total,
        "count_unique": len(order),
        "scan_complete": True,
        "groups": [
            {"fingerprint": fp, "occurrences": grouped[fp]}
            for fp in order
        ],
    }


def apply_triage(
    findings: list[dict[str, Any]],
    decisions: dict[str, str],
) -> dict[str, Any]:
    """Apply documented triage decisions to normalized findings.

    Every decision must reference a fingerprint that exists in the
    findings, and every status must be one of ``accepted`` /
    ``false_positive``. Anything else fails loudly — suppression is only
    possible against a documented, imported finding.
    """
    if not isinstance(decisions, dict):
        raise MergeError("triage decisions must be an object")

    for fingerprint, status in decisions.items():
        if status not in _APPLY_STATUSES:
            raise MergeError(
                f"invalid triage status {status!r} for {fingerprint!r} "
                f"(allowed: {', '.join(_APPLY_STATUSES)})"
            )

    by_fingerprint: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        validated = _validate_finding(finding)
        by_fingerprint.setdefault(validated["fingerprint"], []).append(
            validated
        )

    unknown = [
        fingerprint for fingerprint in decisions
        if fingerprint not in by_fingerprint
    ]
    if unknown:
        preview = ", ".join(repr(fp) for fp in unknown[:5])
        raise MergeError(
            f"triage decisions reference {len(unknown)} fingerprint(s) "
            f"absent from the findings: {preview} — document the finding "
            "first; suppression without a documented finding is rejected"
        )

    applied = 0
    for fingerprint, status in decisions.items():
        for finding in by_fingerprint[fingerprint]:
            finding["triage"] = status
            finding["triage_source"] = "review-file"
            applied += 1

    return {
        "schema": TRIAGE_SCHEMA,
        "applied": applied,
        "decisions": len(decisions),
        "findings": findings,
    }


def gate_external_findings(
    findings: list[dict[str, Any]],
    blocking: list[str],
) -> dict[str, Any]:
    """Gate external findings on their verbatim severity.

    Blocking is an exact match against the severity the source tool put
    in SARIF ``properties.severity``. ``unknown`` never blocks and
    triaged findings never block. The verdict is ``fail`` only when at
    least one unreviewed finding sits at a listed severity.
    """
    if not isinstance(blocking, list) or not all(
        isinstance(item, str) for item in blocking
    ):
        raise MergeError("blocking severities must be a list of strings")

    counts: dict[str, int] = {}
    blocking_findings: list[dict[str, Any]] = []

    for finding in findings:
        validated = _validate_finding(finding)
        severity = validated.get("severity")
        counts[severity] = counts.get(severity, 0) + 1
        if validated.get("triage", "unreviewed") != "unreviewed":
            continue
        if severity in blocking:
            blocking_findings.append(
                {
                    "fingerprint": validated["fingerprint"],
                    "tool": validated["source"]["tool"],
                    "rule_id": validated["source"]["rule_id"],
                    "file": validated["location"]["file"],
                    "line": validated["location"]["line"],
                    "severity": severity,
                }
            )

    return {
        "schema": EXTERNAL_GATE_SCHEMA,
        "blocking": list(blocking),
        "counts": counts,
        "blocking_count": len(blocking_findings),
        "blocking_findings": blocking_findings,
        "verdict": "fail" if blocking_findings else "pass",
    }
