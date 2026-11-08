"""MIZAN report — local-only disclosure-report toolkit.

Modules: cvss (v3.1 arithmetic), cwe (embedded subset), redact
(three-layer secret safety), triage (the mandatory manual gate),
timeline (local 90-day tracker + evidence chain), generator
(in-memory md/html/sarif/json), cli (the ``mizan report`` commands).

Design contract: docs/REPORT_SECURITY.md. Headlines — the default
report carries NO source snippets; generation is gated behind a
10-question manual triage; every HTML field is escaped under a strict
CSP; and the honest claim is "no unvetted external dependencies",
never "zero attack surface".
"""
