"""Stable finding fingerprints — dedup across scans (REPORT_SECURITY req. 2).

The same finding found in two scans must produce the SAME id, so no
duplicate disclosure is ever drafted. The identity is the finding's
semantic location, not its redacted text: rule + file + line + message.
"""

import hashlib


def _message_of(finding: dict) -> str:
    return str(finding.get("message") or finding.get("description") or "")


def fingerprint(finding: dict) -> str:
    """sha256 over rule|file|line|message, first 16 hex chars.

    Computed on the RAW finding (before any redaction) so the id is
    stable across scans regardless of redaction-policy changes.
    """
    basis = "|".join([
        str(finding.get("rule", "")),
        str(finding.get("file", "")),
        str(finding.get("line", "")),
        _message_of(finding),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
