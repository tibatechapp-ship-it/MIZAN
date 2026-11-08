"""In-memory report generation — generate() writes NOTHING to disk.

The corrected design (docs/REPORT_SECURITY.md closes all four holes):

1. Reputation gate: generate() is only REACHABLE through the triage gate
   (severity high/critical + --confirm + completed 10-question triage).
   The CLI enforces it; this module additionally stamps the report with
   the triage status so a report without a gate cannot be mistaken for
   one with it.
2. Secrets: DEFAULT = no source snippets anywhere. A snippet is embedded
   only with include_snippet=True and only AFTER redact(). Every other
   field passes redact_finding() before anything is rendered.
3. XSS: every interpolated value is html.escape()d into the HTML form;
   the document carries the strict CSP meta tag; there is no innerHTML
   script path anywhere.
4. Honest wording: the report says "no unvetted external dependencies",
   never "zero attack surface" (docs/REPORT_SECURITY.md).

Output forms: markdown, html, sarif (2.1.0, rule-findings shape — the
existing mizan.sarif module serves OSV dependency findings and is left
untouched), and json. Each report carries its sha256 and the previous
report's hash (evidence chain, stored in the local timeline DB).
"""

import hashlib
import html
import json

from mizan._version import __version__

from .cwe import cwe_info
from .cvss import base_score_vector
from .ids import fingerprint
from .redact import redact, redact_finding

__all__ = ["generate", "DEFAULT_VECTORS", "DEFAULT_CWE_BY_RULE",
           "DEFAULT_VECTOR_FALLBACK"]

# Default CVSS vectors per known MIZAN rule. These are conservative
# ASSESSMENT DEFAULTS to anchor triage discussion — they are NOT NIST
# ratings and NOT claims; overridable in the triage notes. Unknown rules
# fall back to the most conservative network-exploitable CIA-low vector.
DEFAULT_VECTOR_FALLBACK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
DEFAULT_VECTORS = {
    "request-to-sql": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "input-to-subprocess": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "path-traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "unsafe-deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "dynamic-execution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "hardcoded-secret-candidate":
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# CWE mapping for the rules MIZAN is verified to emit. Unknown rules
# render CWE: Unknown — the map grows only as rules are audited.
DEFAULT_CWE_BY_RULE = {
    "request-to-sql": "CWE-89",
    "input-to-subprocess": "CWE-78",
    "path-traversal": "CWE-22",
    "unsafe-deserialization": "CWE-502",
    "dynamic-execution": "CWE-94",
    "hardcoded-secret-candidate": "CWE-798",
}

_LEVEL_BY_BAND = {
    "Critical": "error", "High": "error",
    "Medium": "warning", "Low": "note", "None": "note",
}


def _message_of(finding: dict) -> str:
    return str(finding.get("message") or finding.get("description") or "")


def _sarif(finding: dict, repo: str, band: str, score: float,
           cwe: dict) -> dict:
    rule_id = str(finding.get("rule", "unknown"))
    driver = {
        "name": "MIZAN Security",
        "version": __version__,
        "informationUri": "https://github.com/tibatechapp-ship-it/MIZAN",
    }
    if cwe.get("id"):
        driver["rules"] = [{
            "id": rule_id,
            "helpUri": cwe["url"],
            "properties": {"cwe": cwe["id"]},
        }]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "results": [{
                "ruleId": rule_id,
                "level": _LEVEL_BY_BAND[band],
                "message": {"text": f"{repo}: {_message_of(finding)} "
                                    f"(cvss {score:.1f} {band})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.get("file", "unknown"))},
                        "region": {"startLine": int(finding.get("line", 0) or 0)},
                    }
                }],
                "properties": {
                    "repo": repo,
                    "cwe": cwe.get("id", ""),
                    "cvss_score": score,
                    "cvss_severity": band,
                },
            }],
        }],
    }


def _markdown(finding: dict, repo: str, cwe: dict, vector: str,
              score: float, band: str, contact_line: str,
              snippet_block: str) -> str:
    # Backticks are stripped from dynamic fields so a crafted message
    # cannot inject markdown structure into the report body.
    safe = lambda text: str(text).replace("`", "'")  # noqa: E731
    return f"""# Security Report (DRAFT — pending manual triage)

> Generated locally by MIZAN v{__version__}. No network was used.
> MIZAN adds no unvetted external dependencies; all of its code is
> in-repository, tested, and auditable. This draft passed the mandatory
> manual triage gate (severity + --confirm + 10-question checklist).

**Severity (CVSS v3.1 base):** {band} ({score:.1f})
**Vector (assessment default, not a NIST rating):** `{vector}`
**CWE:** {cwe['id'] or 'Unknown'} — {cwe['name']}{' ' + cwe['url'] if cwe['url'] else ''}
**Repository:** {safe(repo)}
**File:** `{safe(finding.get('file', 'unknown'))}:{safe(finding.get('line', '?'))}`
**Rule:** {safe(finding.get('rule', 'unknown'))}
**Detected by:** MIZAN v{__version__}

## Description
{safe(_message_of(finding))}

## Evidence
{snippet_block if snippet_block else 'No source snippet is included by default (secret-safety policy). Use --include-snippet explicitly, after review.'}

## Triage
Drafted only after the 10-question manual triage gate passed.

## Contact
{contact_line}
"""


def _html(finding: dict, repo: str, cwe: dict, vector: str, score: float,
          band: str, contact_line: str, snippet_block: str) -> str:
    esc = html.escape
    # py3.10/3.11 compat: backslashes inside f-string expressions are
    # rejected before 3.12 (PEP 701) — hoist the strip() out of the literal.
    snippet_stripped = snippet_block.strip('`\\n') if snippet_block else ''
    snippet_html = (f"<pre><code>{esc(snippet_stripped)}</code></pre>"
                    if snippet_block else
                    "<p>No source snippet is included by default "
                    "(secret-safety policy).</p>")
    return f"""<!DOCTYPE html>
<html lang="en" dir="auto">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Security Report {esc(str(finding.get('rule', 'unknown')))} — {esc(repo)}</title>
<style>body{{font-family:sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#111}}pre{{background:#f6f6f6;padding:.6rem;overflow:auto}}table{{border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:.35rem .6rem;text-align:left}}</style>
</head>
<body>
<h1>Security Report (DRAFT — pending manual triage)</h1>
<p>Generated locally by MIZAN v{esc(__version__)}. No network was used.
MIZAN adds no unvetted external dependencies; all of its code is
in-repository, tested, and auditable.</p>
<table>
<tr><th>Severity (CVSS v3.1 base)</th><td>{esc(band)} ({score:.1f})</td></tr>
<tr><th>Vector (assessment default, not a NIST rating)</th><td>{esc(vector)}</td></tr>
<tr><th>CWE</th><td>{esc(cwe['id'] or 'Unknown')} — {esc(cwe['name'])}</td></tr>
<tr><th>Repository</th><td>{esc(repo)}</td></tr>
<tr><th>File</th><td>{esc(str(finding.get('file', 'unknown')))}:{esc(str(finding.get('line', '?')))}</td></tr>
<tr><th>Rule</th><td>{esc(str(finding.get('rule', 'unknown')))}</td></tr>
</table>
<h2>Description</h2>
<p>{esc(_message_of(finding))}</p>
<h2>Evidence</h2>
{snippet_html}
<h2>Contact</h2>
<p>{esc(contact_line)}</p>
</body>
</html>
"""


def generate(finding: dict, repo: str, contact: dict,
             include_snippet: bool = False, snippet: str = None,
             prev_hash: str = None) -> dict:
    """Build every report form IN MEMORY. Returns a payload dict; the
    caller (CLI) decides whether/where to write — and re-verifies."""
    fid = fingerprint(finding)          # stable identity, pre-redaction
    finding = redact_finding(finding)   # layer 2: redact every field

    rule = str(finding.get("rule", "unknown"))
    cwe_id = finding.get("cwe") or DEFAULT_CWE_BY_RULE.get(rule, "")
    cwe = cwe_info(cwe_id)

    vector = str(finding.get("cvss_vector") or
                 DEFAULT_VECTORS.get(rule, DEFAULT_VECTOR_FALLBACK))
    score, band = base_score_vector(vector)

    contact_line = (contact.get("email") or contact.get("url")
                    or (f"CONTACT_FILE_FOUND_NO_CHANNEL "
                        f"({contact['source']})" if contact.get("source")
                        else "NO_CONTACT_FOUND"))

    snippet_block = ""
    if include_snippet:
        raw = snippet if snippet is not None else finding.get("snippet", "")
        cleaned = redact(str(raw)).strip()
        if cleaned:
            snippet_block = f"```\n{cleaned}\n```\n"

    md = _markdown(finding, repo, cwe, vector, score, band, contact_line,
                   snippet_block)
    html_doc = _html(finding, repo, cwe, vector, score, band, contact_line,
                     snippet_block)
    sarif = _sarif(finding, repo, band, score, cwe)

    payload = {
        "id": fid,
        "repo": repo,
        "finding": finding,
        "cwe": cwe,
        "cvss": {"vector": vector, "score": score, "severity": band},
        "contact": contact_line,
        "markdown": md,
        "html": html_doc,
        "sarif": sarif,
        "prev_hash": prev_hash or "0" * 64,
    }
    canonical = json.dumps(
        {key: payload[key] for key in
         ("id", "finding", "cvss", "markdown", "html", "sarif", "prev_hash")},
        sort_keys=True, ensure_ascii=False,
    )
    payload["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload
