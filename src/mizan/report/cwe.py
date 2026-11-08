"""Embedded CWE database — the subset MIZAN actually names, no fetch, no network.

Names are transcribed from the CWE dictionary (cwe.mitre.org). A one-time
manual verification of every name against the live dictionary is recorded
as a pending task in docs/REPORT_SECURITY.md (honest status, not claimed
as verified). URLs are deterministic (definitions/<n>.html).

Only CWEs that MIZAN rules can actually emit are listed — no 900-entry
pretense of coverage.
"""

__all__ = ["CWE_DB", "cwe_info", "cwe_url"]

CWE_DB = {
    "CWE-22":  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-78":  "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79":  "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89":  "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94":  "Improper Control of Code Generation ('Code Injection')",
    "CWE-95":  "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-295": "Improper Certificate Validation",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-377": "Insecure Temporary File",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-759": "Use of a One-Way Hash without a Salt",
    "CWE-778": "Insufficient Logging",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
}


def cwe_url(cwe_id: str) -> str:
    number = str(cwe_id).split("-", 1)[1]
    if not number.isdigit():
        raise ValueError(f"malformed CWE id: {cwe_id!r}")
    return f"https://cwe.mitre.org/data/definitions/{int(number)}.html"


def cwe_info(cwe_id: str) -> dict:
    """Lookup with an honest fallback: unknown ids render as Unknown."""
    cwe_id = str(cwe_id or "")
    if cwe_id in CWE_DB:
        return {"id": cwe_id, "name": CWE_DB[cwe_id], "url": cwe_url(cwe_id)}
    return {"id": cwe_id or "", "name": "Unknown", "url": ""}
