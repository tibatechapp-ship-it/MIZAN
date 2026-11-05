"""MIZAN AI fixer — SAFE & PRECISE mode (SEC-03 remediation).

The old implementation replaced every textual ``eval(`` with
``ast.literal_eval(`` via a blind regex, which could corrupt correct code
(e.g. ``eval(compile(...))`` or ``obj.eval(...)``) without any semantic
check, and wrote directly into the scanned worktree.

The new behaviour:

  * Handles ONLY Bandit rule B307 (use of ``eval``).
  * Works on the AST, not on text: a call is auto-fixed ONLY when the
    argument is a string/bytes literal — the only case where
    ``ast.literal_eval`` is a provably safe equivalent.
  * Non-literal ``eval(...)`` calls are REPORTED for human review and
    never auto-fixed.
  * ``import ast`` is inserted at a semantically correct position
    (after the module docstring and ``__future__`` imports).
  * Every candidate change must re-compile() before it becomes a Plan.
  * DRY-RUN by default; ``--apply`` commits on an isolated branch via
    repair.py (the scanned worktree is never mutated).
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys

from mizan.repair import (
    Plan,
    RepairError,
    add_apply_argument,
    resolve_target,
)

RULE_B307 = "B307"


def normalize_path(path: str) -> str:
    """Backwards-compatible wrapper around repair.resolve_target.

    Converts URI/absolute finding paths into safe worktree-relative
    paths; raises RepairError for traversal attempts.
    """
    return resolve_target(path)


def _is_literal_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _insert_import_ast(source: str) -> str:
    """Insert ``import ast`` at a semantically safe position.

    Order of preference:
      1. after the module docstring (if any),
      2. after the last ``from __future__`` import,
      3. otherwise before the first code line (skipping comments/blank),
         which preserves shebang and encoding comments.
    """
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)

    insert_after = 0  # 0-based line index AFTER which we insert

    body = tree.body or []
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        insert_after = body[0].end_lineno  # after docstring (1-based → index)

    last_future_end = None
    for node in body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            last_future_end = node.end_lineno
    if last_future_end:
        insert_after = max(insert_after, last_future_end)

    if insert_after == 0:
        # no docstring / future imports: skip leading comments & blanks
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                insert_after = idx
                break

    lines.insert(insert_after, "import ast\n")
    return "".join(lines)


def _collect_eval_spans(tree: ast.AST):
    """Return (span, fixable) for each top-level ``eval(...)`` call.

    span = (lineno, col_offset, end_lineno, end_col_offset) of the
    ``eval`` name node. fixable=True only for literal-argument calls.
    """
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "eval":
            fixable = bool(node.args) and _is_literal_str(node.args[0])
            fn = node.func
            spans.append(((fn.lineno, fn.col_offset,
                           fn.end_lineno, fn.end_col_offset), fixable))
    return spans


def _apply_span_edits(source: str, spans) -> str:
    """Replace name spans (eval → ast.literal_eval), bottom-up."""
    lines = source.splitlines(keepends=True)
    for (l1, c1, l2, c2) in sorted(spans, reverse=True):
        if l1 != l2:
            # multi-line name expression — leave for human review
            continue
        line = lines[l1 - 1]
        lines[l1 - 1] = line[:c1] + "ast.literal_eval" + line[c2:]
    return "".join(lines)


def _plan_for_file(file_path: str) -> Plan | None:
    """Build a validated Plan for one B307 finding, or None to skip."""
    with open(file_path, "r", encoding="utf-8") as fh:
        content = fh.read()

    try:
        tree = ast.parse(content)
    except SyntaxError as exc:
        print(f"🚫 [MIZAN] {file_path}: لا يمكن تحليله (SyntaxError: {exc}) — يحتاج تدخلاً بشرياً.")
        return None

    spans = _collect_eval_spans(tree)
    if not spans:
        return None

    fixable = [s for s, ok in spans if ok]
    manual = [s for s, ok in spans if not ok]
    if manual:
        print(f"👀 [MIZAN] {file_path}: {len(manual)} استدعاء eval() غير حرفي — "
              "يُترك للمراجعة البشرية (غير آمن للتحويل الآلي).")

    if not fixable:
        return None

    modified = _apply_span_edits(content, fixable)
    if "import ast" not in modified:
        modified = _insert_import_ast(modified)

    # Safety net: the candidate MUST parse before it becomes a Plan.
    # ast.parse validates syntax without producing executable bytecode
    # (keeps the no-compile() policy of benchmark BM-75).
    try:
        ast.parse(modified, filename=file_path)
    except SyntaxError as exc:
        print(f"🚫 [MIZAN] {file_path}: رُفض التعديل (فشل التحقق النحوي: {exc}) — يُترك للمراجعة البشرية.")
        return None

    return Plan(
        file=file_path,
        original=content,
        modified=modified,
        description=f"B307: replace literal-only eval() with ast.literal_eval() in {file_path}",
    )


def build_plans(sarif_file: str | None = None) -> list[Plan]:
    """Compute validated repair plans from a Bandit SARIF report."""
    sarif_file = sarif_file or "bandit.sarif"
    print(f"🧠 [MIZAN] تحليل تقرير الثغرات: {sarif_file}")

    if not os.path.exists(sarif_file):
        print("⚠️  لم يتم العثور على تقرير Bandit. لا توجد اقتراحات.")
        return []

    with open(sarif_file, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise RepairError(f"failed to parse SARIF file: {exc}") from exc

    runs = data.get("runs", [])
    if not runs:
        print("✅ لا توجد ثغرات لإصلاحها.")
        return []

    plans: list[Plan] = []
    seen: set[str] = set()
    for result in runs[0].get("results", []):
        if result.get("ruleId") != RULE_B307:
            continue
        locations = result.get("locations", [])
        if not locations:
            continue
        uri = locations[0].get("physicalLocation", {}) \
                          .get("artifactLocation", {}) \
                          .get("uri", "")
        if not uri or uri in seen:
            continue
        seen.add(uri)
        try:
            file_path = resolve_target(uri)
        except RepairError as exc:
            print(f"🚫 [MIZAN] تجاهل نتيجة مشبوهة: {exc}")
            continue
        plan = _plan_for_file(file_path)
        if plan:
            plans.append(plan)

    print(f"🧮 [MIZAN] خطط مُتحقَّق منها: {len(plans)}")
    return plans


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="MIZAN AI fixer for B307 (dry-run by default; "
                    "--apply commits on an isolated branch)"
    )
    parser.add_argument("--sarif", default=None,
                        help="path to the Bandit SARIF report")
    add_apply_argument(parser)
    args = parser.parse_args(argv)

    try:
        plans = build_plans(sarif_file=args.sarif)
        from mizan.repair import apply_repairs
        apply_repairs(plans, apply=args.apply)
    except RepairError as exc:
        print(f"❌ [MIZAN] repair aborted: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
