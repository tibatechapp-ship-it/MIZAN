"""Declarative custom rules — ``.mizan/rules.json`` (read-only, zero-dep).

Closes the "custom rules" gap vs. pattern-rule engines in MIZAN's own
style: no new query language, no new dependency — a JSON file of per-line
regex rules that flow through the SAME fingerprint / baseline / gate
pipeline as built-in rules (nothing special-cased downstream).

Schema (v1)::

    {
      "version": 1,
      "rules": [
        {
          "id": "custom-no-eval",          # MUST start with "custom-"
          "severity": "high",              # canonical ladder (lowercase)
          "languages": ["python"],         # python | js | ts | generic
          "pattern": "\\\\beval\\\\s*\\\\(",   # Python ``re`` syntax
          "message": "eval() is forbidden by policy",
          "path_excludes": ["tests/*"]     # optional fnmatch globs
        }
      ]
    }

Precision contract (the project's fail-loud doctrine):

* An invalid rules file NEVER fails a scan silently. Every rejection is
  listed in ``custom_rules_errors``; the CLI gate treats non-empty
  errors as an incomplete source — a scan that could not load the
  policies it was given must not certify a clean pass.
* Rejected rules are dropped individually (with their reason), not en
  masse — one typo must not disable the other five policies.
* Rule ids are namespaced under ``custom-`` so they can never shadow or
  collide with a built-in rule id.
* Unknown severities / languages / regexes are rejected at load time,
  never at scan time.
"""

import fnmatch
import json
import re
from pathlib import Path

RULES_PATH = ".mizan/rules.json"
RULES_SCHEMA_VERSION = 1

VALID_SEVERITIES = ("critical", "high", "medium", "warning", "low", "info")

# Language families a custom rule can target. ``generic`` matches every
# scannable source extension (kept in sync with analyzer.SOURCE_EXTENSIONS).
LANGUAGE_SUFFIXES = {
    "python": {".py"},
    "js": {".js", ".jsx", ".mjs", ".cjs"},
    "ts": {".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "rust": {".rs"},
    "php": {".php"},
    "ruby": {".rb"},
}
GENERIC_SUFFIXES = {s for suffixes in LANGUAGE_SUFFIXES.values() for s in suffixes}

_ID_RE = re.compile(r"^custom-[a-z0-9][a-z0-9-]*$")

# Non-Python comment prefixes (kept in sync with analyzer.NONPY_COMMENT_PREFIXES):
# a policy pattern hitting a comment line is prose, not code.
_NONPY_COMMENT_PREFIXES = ("//", "/*", "*", "#", "<!--")


def _validate_rule(index, raw, seen_ids):
    """Validate one raw rule entry. Returns (rule, error) — exactly one is None."""
    if not isinstance(raw, dict):
        return None, f"rule #{index}: expected an object, got {type(raw).__name__}"

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not _ID_RE.match(rule_id):
        return None, (
            f"rule #{index}: id {rule_id!r} must match 'custom-<lowercase-ids>' "
            "(custom ids are namespaced so they can never shadow built-in rules)"
        )
    if rule_id in seen_ids:
        return None, f"rule #{index}: duplicate id {rule_id!r}"

    severity = raw.get("severity")
    if severity not in VALID_SEVERITIES:
        return None, (
            f"rule {rule_id!r}: severity {severity!r} is not one of "
            f"{', '.join(VALID_SEVERITIES)}"
        )

    languages = raw.get("languages")
    if (
        not isinstance(languages, list)
        or not languages
        or not all(isinstance(l, str) for l in languages)
    ):
        return None, f"rule {rule_id!r}: 'languages' must be a non-empty list"
    unknown = [l for l in languages if l != "generic" and l not in LANGUAGE_SUFFIXES]
    if unknown:
        return None, (
            f"rule {rule_id!r}: unknown language(s) {', '.join(map(repr, unknown))} "
            f"(valid: generic, {', '.join(sorted(LANGUAGE_SUFFIXES))})"
        )

    pattern = raw.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return None, f"rule {rule_id!r}: 'pattern' must be a non-empty regex string"
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return None, f"rule {rule_id!r}: pattern does not compile: {exc}"

    message = raw.get("message")
    if not isinstance(message, str) or not message.strip():
        return None, f"rule {rule_id!r}: 'message' must be a non-empty string"

    path_excludes = raw.get("path_excludes", [])
    if path_excludes is None:
        path_excludes = []
    if not isinstance(path_excludes, list) or \
            not all(isinstance(p, str) for p in path_excludes):
        return None, f"rule {rule_id!r}: 'path_excludes' must be a list of globs"

    rule = {
        "id": rule_id,
        "severity": severity,
        "languages": list(languages),
        "pattern": compiled,
        "message": message,
        "path_excludes": list(path_excludes),
    }
    seen_ids.add(rule_id)
    return rule, None


def load_custom_rules(root):
    """Load ``<root>/.mizan/rules.json``.

    Returns ``(rules, errors)``. A missing file is the normal case and
    yields ``([], [])``; a present-but-broken file yields every rejection
    in ``errors`` — never a silent skip.
    """
    path = Path(root) / RULES_PATH
    if not path.is_file():
        return [], []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [{"rule": RULES_PATH, "error": f"unreadable: {exc}"}]

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [{"rule": RULES_PATH, "error": f"invalid JSON: {exc}"}]

    if not isinstance(doc, dict):
        return [], [{"rule": RULES_PATH, "error": "top level must be an object"}]

    version = doc.get("version")
    if version != RULES_SCHEMA_VERSION:
        return [], [{
            "rule": RULES_PATH,
            "error": f"unsupported rules schema version {version!r} "
                     f"(expected {RULES_SCHEMA_VERSION})",
        }]

    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list):
        return [], [{"rule": RULES_PATH, "error": "'rules' must be a list"}]

    rules, errors = [], []
    seen_ids = set()
    for index, raw in enumerate(raw_rules):
        rule, error = _validate_rule(index, raw, seen_ids)
        if error is not None:
            errors.append({"rule": raw.get("id", f"#{index}"), "error": error})
        else:
            rules.append(rule)
    return rules, errors


def _rule_applies(rule, suffix, rel_posix):
    """True when a compiled rule should run against one file."""
    if "generic" in rule["languages"]:
        allowed = True
    else:
        allowed = any(
            suffix in LANGUAGE_SUFFIXES[lang]
            for lang in rule["languages"]
        )
    if not allowed:
        return False
    for glob in rule["path_excludes"]:
        if fnmatch.fnmatch(rel_posix, glob):
            return False
    return True


def apply_custom_rules(content, rel_posix, suffix, rules):
    """Run matching custom rules over one file's content.

    Line-based matching — the same granularity as the built-in
    secret/TODO rules. Findings carry ``"custom": True`` so reports can
    label their origin; fingerprints/gating are identical to built-ins.
    """
    findings = []
    applicable = [r for r in rules if _rule_applies(r, suffix, rel_posix)]
    if not applicable:
        return findings

    skip_comments = suffix != ".py"
    for number, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if skip_comments and stripped.startswith(_NONPY_COMMENT_PREFIXES):
            continue
        for rule in applicable:
            if rule["pattern"].search(line):
                findings.append({
                    "file": rel_posix,
                    "line": number,
                    "rule": rule["id"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "custom": True,
                })
    return findings
