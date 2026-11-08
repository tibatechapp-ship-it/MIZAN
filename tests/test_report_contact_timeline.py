"""Contact discovery (local-only) and the 90-day timeline: dedup,
overdue semantics, terminal statuses, status validation.
"""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mizan.report.contact import find_contact
from mizan.report.ids import fingerprint
from mizan.report.timeline import DISCLOSURE_DAYS, Timeline

FINDING = {
    "rule": "path-traversal",
    "file": "app/routes.py",
    "line": 77,
    "severity": "high",
    "message": "open(sys.argv[1]) without validation",
    "repo": "demo-repo",
}


class ContactDiscoveryTests(unittest.TestCase):
    def test_security_md_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "SECURITY.md").write_text(
                "Report to acme-security@example.com or "
                "https://example.com/security\n", encoding="utf-8")
            result = find_contact(Path(tmp))
            self.assertEqual(result["email"], "acme-security@example.com")
            self.assertEqual(result["source"], "SECURITY.md")
            self.assertIsNone(result["policy"])

    def test_github_security_md_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = Path(tmp) / ".github"
            gh.mkdir()
            (gh / "SECURITY.md").write_text("ping ops@example.org\n",
                                            encoding="utf-8")
            result = find_contact(Path(tmp))
            self.assertEqual(result["email"], "ops@example.org")
            self.assertEqual(result["source"], ".github/SECURITY.md")

    def test_security_txt_rfc9116(self):
        with tempfile.TemporaryDirectory() as tmp:
            wk = Path(tmp) / ".well-known"
            wk.mkdir()
            (wk / "security.txt").write_text(
                "Contact: mailto:sec@example.net\nExpires: 2027-01-01T00:00:00Z\n",
                encoding="utf-8")
            result = find_contact(Path(tmp))
            self.assertEqual(result["email"], "sec@example.net")
            self.assertEqual(result["source"], ".well-known/security.txt")

    def test_no_contact_found_is_honest(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = find_contact(Path(tmp))
            self.assertEqual(result["policy"], "NO_CONTACT_FOUND")
            self.assertIsNone(result["email"])
            self.assertIsNone(result["url"])

    def test_policy_file_without_channel_is_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "SECURITY.md").write_text(
                "# Policy\nReport via the repository issue tracker.\n",
                encoding="utf-8")
            result = find_contact(Path(tmp))
            self.assertEqual(result["source"], "SECURITY.md")
            self.assertIsNone(result["email"])
            self.assertEqual(result["policy"], "CONTACT_FILE_FOUND_NO_CHANNEL")

    def test_security_txt_without_contact_is_distinct(self):
        """A security.txt naming no Contact: is the same honest third
        state — file exists, channel does not (policy field consistent
        with the SECURITY.md branch, P1 gap #4)."""
        with tempfile.TemporaryDirectory() as tmp:
            wk = Path(tmp) / ".well-known"
            wk.mkdir()
            (wk / "security.txt").write_text(
                "Expires: 2027-01-01T00:00:00Z\n", encoding="utf-8")
            result = find_contact(Path(tmp))
            self.assertEqual(result["source"], ".well-known/security.txt")
            self.assertIsNone(result["email"])
            self.assertIsNone(result["url"])
            self.assertEqual(result["policy"],
                             "CONTACT_FILE_FOUND_NO_CHANNEL")


class TimelineTests(unittest.TestCase):
    def _timeline(self, tmp):
        return Timeline(Path(tmp) / "disclosures.db")

    def test_dedup_same_finding_same_id_single_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = self._timeline(tmp)
            contact = {"email": "sec@example.com"}
            fid = timeline.record_draft(
                FINDING, contact, str(tmp), 7.5, "High", "h" * 64)
            self.assertEqual(fid, fingerprint(FINDING))
            timeline.record_draft(FINDING, contact, str(tmp), 7.5, "High",
                                  "g" * 64)
            with sqlite3.connect(timeline.db_path) as conn:
                count = conn.execute(
                    "SELECT COUNT(*) FROM disclosures").fetchone()[0]
            self.assertEqual(count, 1)  # INSERT OR REPLACE — no duplicate

    def test_fresh_draft_not_overdue(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = self._timeline(tmp)
            timeline.record_draft(FINDING, {"email": "s@e.com"}, str(tmp),
                                  7.5, "High", "h" * 64)
            self.assertEqual(timeline.overdue(), [])

    def test_91_days_past_deadline_is_overdue(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = self._timeline(tmp)
            fid = timeline.record_draft(FINDING, {"email": "s@e.com"},
                                        str(tmp), 7.5, "High", "h" * 64)
            past = (datetime.now(timezone.utc)
                    - timedelta(days=DISCLOSURE_DAYS + 1)).isoformat()
            with sqlite3.connect(timeline.db_path) as conn:
                conn.execute("UPDATE disclosures SET deadline = ?",
                             (past,))
            rows = timeline.overdue()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], fid)

    def test_terminal_statuses_stop_the_clock(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = self._timeline(tmp)
            fid = timeline.record_draft(FINDING, {"email": "s@e.com"},
                                        str(tmp), 7.5, "High", "h" * 64)
            past = (datetime.now(timezone.utc)
                    - timedelta(days=DISCLOSURE_DAYS + 1)).isoformat()
            for status in ("fixed", "published", "withdrawn", "wontfix",
                           "duplicate", "disputed"):
                with sqlite3.connect(timeline.db_path) as conn:
                    conn.execute(
                        "UPDATE disclosures SET deadline = ?, status = ?",
                        (past, status))
                self.assertEqual(timeline.overdue(), [],
                                 f"{status} must stop the overdue clock")
            # a non-terminal status resumes the clock
            timeline.set_status(fid, "acknowledged")
            self.assertEqual(len(timeline.overdue()), 1)

    def test_invalid_status_fails_loud(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = self._timeline(tmp)
            fid = timeline.record_draft(FINDING, {"email": "s@e.com"},
                                        str(tmp), 7.5, "High", "h" * 64)
            with self.assertRaises(ValueError):
                timeline.set_status(fid, "maybe")

    def test_status_set_extends_chain_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = self._timeline(tmp)
            timeline.record_draft(FINDING, {"email": "s@e.com"}, str(tmp),
                                  7.5, "High", "a" * 64)
            timeline.record_draft(FINDING, {"email": "s@e.com"}, str(tmp),
                                  7.5, "High", "b" * 64)
            # two chain links, one disclosure row
            with sqlite3.connect(timeline.db_path) as conn:
                links = conn.execute(
                    "SELECT COUNT(*) FROM chain").fetchone()[0]
            self.assertEqual(links, 2)


if __name__ == "__main__":
    unittest.main()
