"""Secret redaction — defense-in-depth, NOT the primary control.

Honest threat statement (docs/REPORT_SECURITY.md, hole #2): regex
redaction alone CANNOT catch split strings, base64-decoded secrets, env
values printed at runtime, or unknown providers. That is exactly why the
PRIMARY control in this module is structural and lives in generator.py:

    DEFAULT: reports contain NO source snippets at all.

redact() is the SECOND layer (applied to every field of every report),
and the CLI applies a THIRD layer: after writing any report file it
re-reads it from disk and runs scan_text_for_secrets(); any hit deletes
the file and fails loud. Three layers, each tested.

In-memory only. No network. No dependencies.
"""

import re

__all__ = ["SECRET_PATTERNS", "redact", "redact_finding",
           "scan_text_for_secrets"]

# (compiled pattern, replacement, label) — applied in order; order matters
# (the private-key block must run before the generic key=value net).
SECRET_PATTERNS = [
    (re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"),
     "[REDACTED-PRIVATE-KEY-BLOCK]", "pem"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "[REDACTED-GITHUB-TOKEN]", "github-ghp"),
    (re.compile(r"gh[oupsr]_[A-Za-z0-9]{36,}"), "[REDACTED-GITHUB-TOKEN]", "github-oauth"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "[REDACTED-GITHUB-PAT]", "github-pat"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "[REDACTED-ANTHROPIC-KEY]", "anthropic"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "[REDACTED-API-KEY]", "openai-like"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED-AWS-ACCESS-KEY]", "aws-akia"),
    (re.compile(r"(?i)aws.{0,25}['\"][A-Za-z0-9/+=]{40}['\"]"),
     "[REDACTED-AWS-SECRET-KEY]", "aws-secret"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
     "[REDACTED-JWT]", "jwt"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED-SLACK-TOKEN]", "slack"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "[REDACTED-GOOGLE-API-KEY]", "google"),
    (re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"), "[REDACTED-GOOGLE-OAUTH]", "google-oauth"),
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "[REDACTED-STRIPE-SECRET]", "stripe"),
    (re.compile(r"whsec_[A-Za-z0-9]{16,}"), "[REDACTED-STRIPE-WEBHOOK]", "stripe-whsec"),
    (re.compile(r"shpat_[A-Za-z0-9]{32}"), "[REDACTED-SHOPIFY-TOKEN]", "shopify"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
     "[REDACTED-SENDGRID-KEY]", "sendgrid"),
    (re.compile(r"EAAA[A-Za-z0-9+/=]{30,}"), "[REDACTED-SQUARE-TOKEN]", "square"),
    (re.compile(r"npm_[A-Za-z0-9]{36}"), "[REDACTED-NPM-TOKEN]", "npm"),
    (re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}"), "[REDACTED-PYPI-TOKEN]", "pypi"),
    (re.compile(r"\bbot\d{6,10}:[A-Za-z0-9_-]{30,}"), "[REDACTED-TELEGRAM-BOT]", "telegram"),
    (re.compile(r"(?i)DefaultEndpointsProtocol=[^;\s]*;AccountName=[^;\s]*;"
                r"AccountKey=[A-Za-z0-9+/=]{40,}"), "[REDACTED-AZURE-STORAGE]", "azure"),
    (re.compile(r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|amqp|redis)://[^\s:@/]+:[^\s@/]+@"),
     "[REDACTED-DATABASE-URL]", "db-url"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{20,}"), "Bearer [REDACTED]", "bearer"),
    (re.compile(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}"), "[REDACTED-HASH]", "bcrypt"),
    (re.compile(r"\$argon2(?:id|i|d)\$[^\"'\s]{20,}"), "[REDACTED-HASH]", "argon2"),
    # The widest net, last: an assignment/JSON key from the secret
    # vocabulary — optionally quoted ("token" : "...", JSON style) —
    # holding a quoted value of 8+ chars. Prose like "the token bucket
    # algorithm" is untouched (no assignment context).
    (re.compile(
        r"""(?i)["']?\b(api[_-]?key|apikey|secret|secret[_-]?key|"""
        r"""client[_-]?secret|token|access[_-]?token|auth[_-]?token|"""
        r"""password|passwd|pwd|access[_-]?key|private[_-]?key)\b["']?"""
        r"""(\s*[:=>]+\s*)["']([^"']{8,})["']"""),
     r"\1\2[REDACTED]", "generic-assignment"),
]


def redact(text: str) -> str:
    """Apply every pattern, in memory, and return the sanitized text."""
    for pattern, repl, _label in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_finding(finding: dict) -> dict:
    """Redact every string field of a finding. Dict-shape preserving."""
    return {
        key: redact(value) if isinstance(value, str) else value
        for key, value in finding.items()
    }


def scan_text_for_secrets(text: str) -> list:
    """Third-layer verifier: which patterns STILL hit this text?

    The replacement markers ('[REDACTED-...]') contain no secret-shaped
    material, so a clean report yields []. Any non-empty result means a
    leak — callers must fail loud.
    """
    return [label for pattern, _repl, label in SECRET_PATTERNS
            if pattern.search(text or "")]
