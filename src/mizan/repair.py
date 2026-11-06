"""Safe repair infrastructure for MIZAN (SEC-02 / SEC-03 remediation).

Every automated modification of scanned code MUST pass through this gate:

  1. resolve_target()   — refuse paths outside the scanned worktree
                          (no absolute paths, no ``..`` traversal,
                          no symlinks — a link can point outside the
                          tree and a write through it would follow).
  2. Plan               — a change is computed up-front as an immutable
                          Plan (file, original, modified, description).
  3. validate           — semantic checks. Python files must compile()
                          before anything is written.
  4. Dry-run by default — prints unified diffs and writes NOTHING.
  5. --apply            — edits land on an ISOLATED git worktree bound to
                          a dedicated branch (``mizan/auto-fix-<ts>``).
                          The scanned worktree is never mutated; the
                          operator pushes the branch and opens a PR for
                          human review. No network operations, no pushes.
  6. Rollback           — on any validation or write failure the
                          temporary worktree is removed entirely.
  7. Ledger             — every applied decision is recorded in the
                          MIZAN Ledger (accountability log).
"""

from __future__ import annotations

import ast
import dataclasses
import difflib
import os
import subprocess
import sys
import time

LEDGER_ACTOR = "joint"


class RepairError(Exception):
    """Raised when a safe repair cannot proceed."""


def resolve_target(raw: str) -> str:
    """Normalise a finding's path and confine it to the current worktree.

    Raises RepairError for absolute paths, traversal (``..``) and
    anything that would escape the scanned tree.
    """
    path = raw or ""
    if path.startswith("file://"):
        path = path[len("file://"):]
    path = path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]

    if os.path.isabs(path) or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise RepairError(f"refusing absolute path from finding: {raw!r}")

    parts = [p for p in path.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise RepairError(f"refusing path traversal in finding: {raw!r}")
    if not parts:
        raise RepairError(f"empty path in finding: {raw!r}")

    clean = "/".join(parts)
    if not os.path.exists(clean):
        raise RepairError(f"target does not exist in worktree: {clean!r}")
    if os.path.islink(clean):
        raise RepairError(
            f"refusing symlink path from finding: {clean!r} — a write "
            "through the link would follow it outside the scanned tree"
        )
    return clean


@dataclasses.dataclass(frozen=True)
class Plan:
    """A computed, validated-before-write change to one file."""

    file: str
    original: str
    modified: str
    description: str

    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.modified.splitlines(keepends=True),
                fromfile=f"a/{self.file}",
                tofile=f"b/{self.file}",
            )
        )

    @property
    def changed(self) -> bool:
        return self.original != self.modified


def validate_python(path: str, content: str) -> str | None:
    """Return an error message if `content` is not valid Python, else None.

    Uses ast.parse() (pure syntax validation, no executable bytecode)
    instead of compile() — keeping the no-dynamic-code policy (BM-75).
    """
    if not path.endswith(".py"):
        return None
    try:
        ast.parse(content, filename=path)
    except SyntaxError as exc:
        return f"syntax check failed: {exc}"
    return None


def _run_git(args: list[str], cwd: str | None = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RepairError(
            f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def _is_git_repo() -> bool:
    try:
        _run_git(["rev-parse", "--is-inside-work-tree"])
        return True
    except (RepairError, FileNotFoundError):
        return False


def apply_repairs(plans: list[Plan], apply: bool = False) -> dict:
    """Dry-run by default; with apply=True, commit plans on an isolated branch.

    Returns a summary dict describing what happened. Raises RepairError on
    any failure (after rolling back the temporary worktree).
    """
    plans = [p for p in plans if p.changed]

    if not apply:
        for plan in plans:
            print(plan.diff(), end="" if plan.diff().endswith("\n") else "\n")
        print(
            f"\n[Dry-run] {len(plans)} change(s) proposed. "
            "Nothing was written. Re-run with --apply to commit them on an isolated branch."
        )
        return {"mode": "dry-run", "planned": len(plans)}

    if not plans:
        print("[MIZAN] No changes to apply.")
        return {"mode": "applied", "planned": 0}

    if not _is_git_repo():
        raise RepairError(
            "--apply requires a git repository: repairs are committed on an "
            "isolated branch so the scanned worktree stays untouched."
        )

    branch = f"mizan/auto-fix-{time.strftime('%Y%m%d-%H%M%S')}"
    worktree = os.path.abspath(f".mizan-repair-{int(time.time())}")

    try:
        _run_git(["worktree", "add", "-b", branch, worktree])
        committed_files = []
        worktree_root = os.path.realpath(worktree)
        for plan in plans:
            target = os.path.join(worktree, plan.file)
            if not os.path.exists(target):
                print(f"⚠️  [MIZAN] skip (not in HEAD tree): {plan.file}")
                continue
            # RW-201 defence in depth: a symlink (even one committed to
            # HEAD) must never be written through — open() would follow
            # it and land OUTSIDE the isolated worktree.
            if os.path.islink(target):
                print(
                    f"⚠️  [MIZAN] skip (symlink — refusing to write through "
                    f"it, may point outside the worktree): {plan.file}"
                )
                continue
            real = os.path.realpath(target)
            if real != worktree_root and not real.startswith(worktree_root + os.sep):
                print(
                    f"⚠️  [MIZAN] skip (resolved path escapes the isolated "
                    f"worktree): {plan.file}"
                )
                continue
            error = validate_python(plan.file, plan.modified)
            if error:
                raise RepairError(f"{plan.file}: {error}")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(plan.modified)
            committed_files.append(plan.file)

        if not committed_files:
            raise RepairError("no applicable changes inside the HEAD tree")

        # Accountability: record the decision in the Ledger, inside the PR.
        try:
            from mizan.ledger import add_entry

            os.makedirs(os.path.join(worktree, ".mizan"), exist_ok=True)
            add_entry(
                "auto-repair applied on branch "
                f"{branch}: {', '.join(committed_files)}",
                actor=LEDGER_ACTOR,
                ledger_path=os.path.join(worktree, ".mizan", "ledger.jsonl"),
            )
        except ImportError:
            pass

        _run_git(["add", *committed_files], cwd=worktree)
        _run_git(
            ["commit", "-m", "fix: MIZAN verified auto-repair\n\n"
             + "\n".join(f"- {p.description}" for p in plans)
             + "\n\nGenerated by MIZAN safe-repair. Review before merging."],
            cwd=worktree,
        )
    except Exception:
        _run_git(["worktree", "remove", "--force", worktree])
        raise

    print(
        f"✅ [MIZAN] {len(committed_files)} repair(s) committed on isolated branch "
        f"`{branch}` (worktree: {worktree}).\n"
        f"   The scanned worktree was NOT modified.\n"
        f"   Next steps:\n"
        f"     git push -u origin {branch}\n"
        f"     gh pr create --fill   # open a PR for human review"
    )
    return {"mode": "applied", "branch": branch, "worktree": worktree,
            "files": committed_files}


def add_apply_argument(parser) -> None:
    """Standard CLI flag shared by all repair entry points."""
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit proposed repairs on an isolated branch "
             "(default: dry-run, writes nothing)",
    )


def main_guard(module_name: str, build_plans_fn, extra_arg: str | None = None) -> int:
    """Shared __main__ entry for the repair scripts."""
    import argparse

    parser = argparse.ArgumentParser(
        description=f"MIZAN safe repair: {module_name} "
                    "(dry-run by default; --apply commits on an isolated branch)"
    )
    if extra_arg:
        parser.add_argument(extra_arg.lstrip("-").replace("-", "_"),
                            default=None,
                            help=f"path to the {extra_arg} input file")
    add_apply_argument(parser)
    args = parser.parse_args()

    kwargs = {}
    if extra_arg:
        kwargs[extra_arg.lstrip("-").replace("-", "_")] = args.__dict__[
            extra_arg.lstrip("-").replace("-", "_")
        ]
    try:
        plans = build_plans_fn(**kwargs)
        apply_repairs(plans, apply=args.apply)
    except RepairError as exc:
        print(f"❌ [MIZAN] repair aborted: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    print("This module is a library; run secret_remover.py or ai_fixer.py.", file=sys.stderr)
    sys.exit(2)
