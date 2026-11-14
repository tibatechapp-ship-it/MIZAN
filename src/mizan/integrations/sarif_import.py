"""SARIF 2.1.0 import — normalize external scanner reports into MIZAN.

Wave 0 of docs/DEV_PLAN_V0150.md (the "merge, don't erase" contract):

- Read-only: this module never executes the scanned code and never
  modifies the user's tree; it only parses a report file.
- Provenance is preserved: every finding keeps the originating tool
  (``tool.driver.name``), its rule id, its original SARIF ``level``, and
  the report it came from. MIZAN does NOT silently map SARIF levels to
  MIZAN severities — that judgment belongs to documented triage later.
- No silent clean: a missing, unreadable, or structurally invalid report
  raises :class:`SarifImportError` with the path in the message. A failed
  import is never reported as an empty (clean) result set.
- Stable identity: SARIF ``partialFingerprints`` win when present;
  otherwise a deterministic SHA-256 fingerprint (tool, rule, file, line,
  message) makes later merge/dedup waves possible without losing data.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
FINDING_SCHEMA = "mizan.finding.v1"
IMPORT_SCHEMA = "mizan.import.v1"

_FINGERPRINT_KEYS = (
    "primaryLocationLineHash",
    "primaryLocationFingerprint",
)


class SarifImportError(ValueError):
    """Raised when a SARIF report is missing, unreadable, or invalid."""


def _fallback_fingerprint(
    tool: str,
    rule_id: str,
    file_path: str,
    line: int | None,
    message: str,
) -> str:
    """Deterministic identity for reports without partialFingerprints."""
    identity = "\0".join(
        (tool, rule_id, file_path, str(line or 0), message)
    )
    return "sha256:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _parse_sarif(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (normalized findings, tool names) for one SARIF report."""
    if not path.is_file():
        raise SarifImportError(f"SARIF report not found: {path}")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SarifImportError(
            f"Cannot read SARIF report {path}: {exc}"
        ) from exc

    if not isinstance(document, dict):
        raise SarifImportError(f"SARIF root must be an object: {path}")

    if document.get("version") != SARIF_VERSION:
        raise SarifImportError(
            f"Unsupported SARIF version in {path}: "
            f"{document.get('version')!r} (expected {SARIF_VERSION})"
        )

    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifImportError(f"SARIF report contains no runs: {path}")

    findings: list[dict[str, Any]] = []
    tool_names: list[str] = []

    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise SarifImportError(
                f"SARIF run {index} is not an object: {path}"
            )

        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        tool_name = driver.get("name") if isinstance(driver, dict) else None
        if not isinstance(tool_name, str) or not tool_name:
            raise SarifImportError(
                f"SARIF run {index} is missing tool.driver.name: {path}"
            )
        tool_names.append(tool_name)

        results = run.get("results", [])
        if not isinstance(results, list):
            raise SarifImportError(
                f"SARIF run {index} results must be a list: {path}"
            )

        for position, result in enumerate(results):
            if not isinstance(result, dict):
                # Strict, per the no-silent-clean contract: a malformed
                # entry fails the import instead of being skipped.
                raise SarifImportError(
                    f"SARIF run {index} result {position} is not an "
                    f"object: {path}"
                )

            rule_id = str(result.get("ruleId") or "unknown")

            message = ""
            message_obj = result.get("message")
            if isinstance(message_obj, dict):
                message = str(message_obj.get("text") or "")

            file_path = ""
            line = None
            locations = result.get("locations")
            if (
                isinstance(locations, list)
                and locations
                and isinstance(locations[0], dict)
            ):
                physical = locations[0].get("physicalLocation")
                if isinstance(physical, dict):
                    artifact = physical.get("artifactLocation")
                    if isinstance(artifact, dict):
                        file_path = str(artifact.get("uri") or "")
                    region = physical.get("region")
                    if isinstance(region, dict):
                        raw_line = region.get("startLine")
                        # bool is an int subclass in Python; reject it.
                        if isinstance(raw_line, int) and not isinstance(
                            raw_line, bool
                        ):
                            line = raw_line

            severity = "unknown"
            properties = result.get("properties")
            if isinstance(properties, dict):
                raw_severity = properties.get("severity")
                if raw_severity is not None:
                    # Carried verbatim — no normalization to a fixed
                    # severity ladder without documented triage.
                    severity = str(raw_severity)

            fingerprint = None
            fingerprints = result.get("partialFingerprints")
            if isinstance(fingerprints, dict):
                for key in _FINGERPRINT_KEYS:
                    value = fingerprints.get(key)
                    if isinstance(value, str) and value:
                        fingerprint = value
                        break
            if fingerprint is None:
                fingerprint = _fallback_fingerprint(
                    tool_name, rule_id, file_path, line, message
                )

            findings.append(
                {
                    "schema": FINDING_SCHEMA,
                    "source": {
                        "tool": tool_name,
                        "rule_id": rule_id,
                    },
                    "location": {"file": file_path, "line": line},
                    "message": message,
                    # Provenance: the SARIF level travels as-is and is
                    # deliberately NOT mapped to a MIZAN severity here.
                    "tool_level": result.get("level"),
                    "severity": severity,
                    "fingerprint": fingerprint,
                    "evidence": {
                        "kind": "external-sarif",
                        "report": path.name,
                    },
                    "triage": "unreviewed",
                }
            )

    return findings, tool_names


def normalize_sarif(report_path: str | Path) -> list[dict[str, Any]]:
    """Convert a SARIF 2.1.0 report into ``mizan.finding.v1`` entries."""
    findings, _ = _parse_sarif(Path(report_path))
    return findings


def import_sarif_report(report_path: str | Path) -> dict[str, Any]:
    """Import one SARIF report; return the normalized import summary.

    ``tools`` lists every run's driver name (including runs with zero
    results) so a report is never summarized as if a scanner never spoke.
    """
    path = Path(report_path)
    findings, tools = _parse_sarif(path)
    return {
        "schema": IMPORT_SCHEMA,
        "report": path.name,
        "tools": tools,
        "count": len(findings),
        # The import itself either completed fully or raised; there is
        # no partial state. Downstream consumers still treat a missing
        # report as an incomplete scan, never as a clean one.
        "scan_complete": True,
        "findings": findings,
    }
