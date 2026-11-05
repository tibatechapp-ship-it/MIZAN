"""MIZAN secret redaction — SAFE mode (SEC-02 remediation).

Reads a GitGuardian findings file and proposes redacting the leaked
values from the scanned worktree. Behaviour:

  * DRY-RUN by default: prints the unified diffs, writes nothing.
  * ``--apply``: commits the redactions on an ISOLATED git branch
    (see repair.py) so the scanned worktree is never mutated, and logs
    the decision in the MIZAN Ledger.
  * Finding paths are confined to the worktree (no traversal).

IMPORTANT (SEC-04): redacting the file does NOT remove the secret from
git history. After any leak: rotate/revoke the key at its provider AND
purge history (e.g. ``git filter-repo``). This tool prints that warning
on every run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from mizan.repair import (
    Plan,
    RepairError,
    add_apply_argument,
    main_guard,
    resolve_target,
)

DEFAULT_PLACEHOLDER = "[REDACTED_BY_MIZAN]"
HISTORY_WARNING = (
    "⚠️  SEC-04 reminder: redacting the worktree does NOT purge the secret from "
    "git history.\n   1) Revoke/rotate the key at its provider NOW.\n"
    "   2) Purge history (e.g. git filter-repo) and force-push with coordination."
)


def _extract_findings(data):
    """GitGuardian may return a list or a dict with a findings key."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", [])
    return []


def build_plans(findings_file: str | None = None,
                placeholder: str = DEFAULT_PLACEHOLDER) -> list[Plan]:
    """Compute redaction plans from a GitGuardian findings file."""
    findings_file = findings_file or "ggshield-results.json"
    print(f"🛡️  [MIZAN] تحليل تقرير الأسرار: {findings_file}")

    if not os.path.exists(findings_file):
        print("⚠️  لم يتم العثور على تقرير GitGuardian. لا توجد اقتراحات.")
        return []

    with open(findings_file, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise RepairError(f"failed to parse findings file: {exc}") from exc

    plans: list[Plan] = []
    skipped = 0
    for finding in _extract_findings(data):
        secret_value = finding.get("match") or finding.get("secret")
        raw_path = finding.get("filename") or finding.get("file_path")
        if not secret_value or not raw_path:
            skipped += 1
            continue

        try:
            file_path = resolve_target(raw_path)
        except RepairError as exc:
            print(f"🚫 [MIZAN] تجاهل نتيجة مشبوهة: {exc}")
            skipped += 1
            continue

        with open(file_path, "r", encoding="utf-8") as code_file:
            content = code_file.read()

        if secret_value not in content:
            print(f"ℹ️  [MIZAN] القيمة غير موجودة حرفياً في {file_path} "
                  "(مشفرة أو بصيغة مختلفة) — يلزم تدخل بشري.")
            skipped += 1
            continue

        plans.append(Plan(
            file=file_path,
            original=content,
            modified=content.replace(secret_value, placeholder),
            description=f"redact leaked secret in {file_path}",
        ))

    print(f"🧮 [MIZAN] خطط مقترحة: {len(plans)} — نتائج متجاهَلة: {skipped}")
    return plans


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="MIZAN secret redaction (dry-run by default; "
                    "--apply commits on an isolated branch)"
    )
    parser.add_argument("--input", default=None,
                        help="path to the GitGuardian findings JSON")
    add_apply_argument(parser)
    args = parser.parse_args(argv)

    print(HISTORY_WARNING)
    try:
        plans = build_plans(findings_file=args.input)
        from mizan.repair import apply_repairs
        apply_repairs(plans, apply=args.apply)
    except RepairError as exc:
        print(f"❌ [MIZAN] repair aborted: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
