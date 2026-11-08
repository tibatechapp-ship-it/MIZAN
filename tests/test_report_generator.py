"""Generator + gate validation: XSS escaping, no-snippet default, secret
safety, dedup ids, evidence chain, SARIF shape — and the mandatory
no-network proof for the whole local pipeline.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mizan.report import triage
from mizan.report.generator import generate
from mizan.report.ids import fingerprint
from mizan.report.timeline import Timeline

XSS_SNIPPET = 'print("<script>alert(1)</script>")'


def base_finding():
    return {
        "rule": "unsafe-deserialization",
        "file": "pkg/loader.py",
        "line": 41,
        "severity": "high",
        "message": "pickle.loads on request data",
        "snippet": 'password = "hunter2actual"\n'
                   + XSS_SNIPPET,
    }


CONTACT = {"email": "security@example.com", "url": None, "policy": None,
           "source": "SECURITY.md"}


class XssEscapingTests(unittest.TestCase):
    def test_every_field_escaped_and_csp_present(self):
        finding = dict(base_finding())
        finding["file"] = "<img src=x onerror=alert(2)>.py"
        finding["message"] = 'prints "<script>alert(1)</script>"'
        payload = generate(finding, "repo-x", CONTACT,
                           include_snippet=True)
        html_doc = payload["html"]
        self.assertIn(
            'content="default-src \'none\'; style-src \'unsafe-inline\'"',
            html_doc)
        self.assertNotIn("<script>alert(1)</script>", html_doc)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_doc)
        self.assertNotIn("<img src=x", html_doc)
        # escaped, therefore inert: the payload survives only as text
        self.assertIn("&lt;img src=x onerror=alert(2)&gt;", html_doc)
        # the snippet itself (executed through redact then escaped)
        self.assertNotIn(XSS_SNIPPET, html_doc)


class SnippetPolicyTests(unittest.TestCase):
    def test_default_no_snippet_anywhere(self):
        payload = generate(base_finding(), "repo-x", CONTACT)
        body = payload["markdown"] + payload["html"] + json.dumps(payload)
        self.assertNotIn("hunter2actual", body)
        self.assertNotIn("```", payload["markdown"])  # no code fence at all
        self.assertIn("No source snippet is included by default",
                      payload["markdown"])

    def test_optin_snippet_is_redacted(self):
        payload = generate(base_finding(), "repo-x", CONTACT,
                           include_snippet=True)
        body = payload["markdown"] + payload["html"]
        self.assertNotIn("hunter2actual", body)       # secret never survives
        self.assertIn("[REDACTED]", body)             # generic marker present
        self.assertIn("pickle.loads", body)           # non-secret code kept


class FingerprintAndChainTests(unittest.TestCase):
    def test_stable_id_and_dedup_semantics(self):
        self.assertEqual(fingerprint(base_finding()),
                         fingerprint(base_finding()))
        changed = dict(base_finding())
        changed["line"] = 42
        self.assertNotEqual(fingerprint(base_finding()),
                            fingerprint(changed))

    def test_evidence_chain_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            timeline = Timeline(Path(tmp) / "chain.db")
            self.assertEqual(timeline.last_hash(), "0" * 64)
            first = generate(base_finding(), "repo-x", CONTACT,
                             prev_hash=timeline.last_hash())
            timeline.record_draft(base_finding(), CONTACT, str(tmp),
                                  first["cvss"]["score"],
                                  first["cvss"]["severity"],
                                  first["hash"])
            second = generate(base_finding(), "repo-x", CONTACT,
                              prev_hash=timeline.last_hash())
            self.assertEqual(second["prev_hash"], first["hash"])
            self.assertNotEqual(first["hash"], second["hash"])


class SarifShapeTests(unittest.TestCase):
    def test_sarif_210_structure(self):
        payload = generate(base_finding(), "repo-x", CONTACT)
        sarif = payload["sarif"]
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "MIZAN Security")
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "unsafe-deserialization")
        self.assertEqual(result["level"], "error")  # cvss 9.8 -> Critical
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["region"]
            ["startLine"], 41)


class TriageGateTests(unittest.TestCase):
    def _valid_triage(self, fid):
        return {
            "finding_id": fid,
            "answers": {
                "exploitable_path": True,
                "default_env_safe": True,
                "nosec_justified": False,
                "test_or_example_only": False,
                "reachable_in_prod": True,
                "external_mitigation": False,
                "affected_version_confirmed": True,
                "local_poc_reproduced": True,
                "authorized_to_disclose": True,
                "contact_verified": True,
            },
        }

    def test_gate_accepts_a_clean_high_finding(self):
        fid = fingerprint(base_finding())
        failures = triage.check(base_finding(), self._valid_triage(fid),
                                fid, fid)
        self.assertEqual(failures, [])

    def test_gate_blocks_low_or_warning_severity(self):
        finding = dict(base_finding())
        finding["severity"] = "warning"   # MIZAN emits warning for lower sev
        fid = fingerprint(finding)
        failures = triage.check(finding, self._valid_triage(fid), fid, fid)
        self.assertTrue(any("not report-eligible" in f for f in failures))

    def test_gate_blocks_confirm_mismatch(self):
        fid = fingerprint(base_finding())
        failures = triage.check(base_finding(), self._valid_triage(fid),
                                fid, "0000000000000000")
        self.assertTrue(any("confirm" in f.lower() for f in failures))

    def test_gate_blocks_unanswered_questions(self):
        fid = fingerprint(base_finding())
        failures = triage.check(base_finding(), {"finding_id": fid},
                                fid, fid)
        self.assertEqual(
            len([f for f in failures if "unanswered" in f]),
            len(triage.QUESTIONS))

    def test_gate_blocks_wrong_safety_answers(self):
        fid = fingerprint(base_finding())
        triage_doc = self._valid_triage(fid)
        triage_doc["answers"]["test_or_example_only"] = True
        failures = triage.check(base_finding(), triage_doc, fid, fid)
        self.assertTrue(any("blocking triage answer" in f for f in failures))


class NoNetworkTests(unittest.TestCase):
    """The mandatory proof: the whole local pipeline never opens a socket."""

    def test_pipeline_never_touches_network(self):
        import socket
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / ".github").mkdir(parents=True)
            (repo / ".github" / "SECURITY.md").write_text(
                "Contact: security@example.com\n", encoding="utf-8")
            with mock.patch.object(socket, "socket",
                                   side_effect=AssertionError("network!")), \
                 mock.patch("urllib.request.urlopen",
                            side_effect=AssertionError("network!")):
                from mizan.report.contact import find_contact
                contact = find_contact(repo)
                self.assertEqual(contact["email"], "security@example.com")
                timeline = Timeline(Path(tmp) / "net.db")
                payload = generate(base_finding(), "repo", contact,
                                   prev_hash=timeline.last_hash())
                timeline.record_draft(base_finding(), contact, str(tmp),
                                      payload["cvss"]["score"],
                                      payload["cvss"]["severity"],
                                      payload["hash"])
                self.assertFalse(timeline.overdue())


if __name__ == "__main__":
    unittest.main()
