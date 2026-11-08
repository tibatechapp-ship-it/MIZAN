"""Local 90-day disclosure tracker — SQLite on disk, no sync, no network.

State machine (extended per review: disputed/wontfix/duplicate/withdrawn):

    draft -> sent -> acknowledged -> fixed | published
                       -> disputed | wontfix | duplicate | withdrawn

Terminal statuses stop the 90-day overdue clock (a disputed finding is
not an overdue one). Dedup: the row id IS the finding fingerprint, so
recording the same finding twice updates instead of duplicating.

The evidence chain lives in the ``chain`` table: every report hash links
to the previous one (genesis prev_hash = 64 zeros).
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .ids import fingerprint

__all__ = ["Timeline", "STATUSES", "TERMINAL", "DISCLOSURE_DAYS"]

STATUSES = ("draft", "sent", "acknowledged", "disputed", "wontfix",
            "duplicate", "withdrawn", "fixed", "published")
TERMINAL = ("fixed", "published", "withdrawn", "wontfix", "duplicate",
            "disputed")
DISCLOSURE_DAYS = 90

_SCHEMA = """
CREATE TABLE IF NOT EXISTS disclosures (
    id TEXT PRIMARY KEY,
    repo TEXT,
    rule TEXT,
    severity TEXT,
    cwe TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    first_seen TEXT,
    deadline TEXT,
    status TEXT,
    contact TEXT,
    report_path TEXT,
    finding_json TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS chain (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT,
    report_hash TEXT,
    prev_hash TEXT,
    created_at TEXT
);
"""

GENESIS_HASH = "0" * 64


def default_db_path() -> Path:
    override = os.environ.get("MIZAN_REPORT_DB")
    if override:
        return Path(override)
    return Path.home() / ".mizan" / "disclosures.db"


class Timeline:
    """Disclosure state, local only. Pass db_path explicitly in tests."""

    def __init__(self, db_path=None):
        self.db_path = Path(db_path or default_db_path())
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(_SCHEMA)

    # -- chain ----------------------------------------------------------
    def last_hash(self) -> str:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT report_hash FROM chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else GENESIS_HASH

    # -- recording -------------------------------------------------------
    def record_draft(self, finding: dict, contact: dict, report_path: str,
                     cvss_score: float, cvss_severity: str,
                     report_hash: str) -> str:
        """Insert/update the disclosure row and extend the evidence chain."""
        fid = fingerprint(finding)
        now = datetime.now(timezone.utc)
        deadline = now + timedelta(days=DISCLOSURE_DAYS)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO disclosures VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, str(finding.get("repo", "")),
                 str(finding.get("rule", "")),
                 str(finding.get("severity", "")),
                 str(finding.get("cwe", "")),
                 float(cvss_score), str(cvss_severity),
                 now.isoformat(), deadline.isoformat(), "draft",
                 str(contact.get("email") or contact.get("url") or ""),
                 str(report_path),
                 json.dumps(finding, ensure_ascii=False, sort_keys=True),
                 ""),
            )
            conn.execute(
                "INSERT INTO chain (id, report_hash, prev_hash, created_at) "
                "VALUES (?,?,?,?)",
                (fid, report_hash, self.last_hash(), now.isoformat()),
            )
        return fid

    # -- queries ---------------------------------------------------------
    def overdue(self, now: datetime = None) -> list:
        """Disclosures past the 90-day deadline in a non-terminal status."""
        now = (now or datetime.now(timezone.utc)).isoformat()
        placeholders = ",".join("?" * len(TERMINAL))
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT id, repo, rule, deadline, status FROM disclosures "
                f"WHERE deadline < ? AND status NOT IN ({placeholders}) "
                "ORDER BY deadline",
                (now, *TERMINAL),
            ).fetchall()

    def set_status(self, fid: str, status: str) -> None:
        if status not in STATUSES:
            raise ValueError(
                f"invalid status {status!r}; allowed: {STATUSES}"
            )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE disclosures SET status = ? WHERE id = ?", (status, fid)
            )

    def entry(self, fid: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(
                "SELECT * FROM disclosures WHERE id = ?", (fid,)
            ).fetchone()

    def all_entries(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(
                "SELECT * FROM disclosures ORDER BY first_seen"
            ).fetchall()
