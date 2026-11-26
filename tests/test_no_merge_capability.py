"""F-01 guard (2026-11-26 live audit): no executable path may approve
or merge PRs — ever.

MIZAN's stated policy is "final merge is human" (repair-request,
verify-repair, README). The 2026-11-26 live audit (F-01, high)
demonstrated — with a stubbed gh — that the deleted-from-policy
capability still existed in the CLI (``approve --approve --merge``)
and in the composite Action (``approve-prs`` / ``merge-prs`` inputs).
The capability was removed outright; this guard keeps every executable
surface (``src/`` and ``action/``) free of the merge/review calls
again. Documentation and tests may mention the removal by name — the
guard reads only executable surfaces.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
ACTION_YML = ROOT / "action" / "action.yml"

# Every banned pattern is a literal that would have to appear in source
# for the capability to come back (the old code built these argv lists).
BANNED_PATTERNS = (
    '"pr", "merge"',        # argv list: ["gh", "pr", "merge", ...]
    '"pr", "review"',       # argv list: ["gh", "pr", "review", ...]
    "gh pr merge",          # shell / yaml / docs-in-code
    "gh pr review",
    "def approve_pr",
    "def merge_pr",
)


class NoMergeCapabilityGuard(unittest.TestCase):
    def _executable_surfaces(self):
        surfaces = sorted(SRC.rglob("*.py"))
        if ACTION_YML.is_file():
            surfaces.append(ACTION_YML)
        self.assertTrue(surfaces, "executable surfaces must exist")
        return surfaces

    def test_no_pr_merge_or_review_calls_anywhere(self):
        for surface in self._executable_surfaces():
            text = surface.read_text(encoding="utf-8", errors="replace")
            for banned in BANNED_PATTERNS:
                self.assertNotIn(
                    banned, text,
                    f"{surface.relative_to(ROOT)} contains {banned!r} — "
                    "the PR approve/merge capability was deleted by the "
                    "F-01 audit decision (final merge is human) and must "
                    "never come back",
                )

    def test_approve_module_has_no_subprocess_writes_to_gh_state(self):
        # The only gh calls that remain are READ-ONLY (pr view / pr
        # checks). Approving or merging is a state write on GitHub —
        # assert the module only ever invokes read-only subcommands.
        approval = (SRC / "mizan" / "approval.py").read_text(
            encoding="utf-8"
        )
        allowed_gh = ('"gh", "pr", "view"', '"gh", "pr", "checks"')
        for allowed in allowed_gh:
            self.assertIn(
                allowed, approval,
                f"approval.py lost its read-only {allowed} call — "
                "update this guard consciously, never silently",
            )
        self.assertNotIn('"gh", "pr"', approval.replace(
            '"gh", "pr", "view"', "").replace('"gh", "pr", "checks"', ""),
            "approval.py must not call any gh pr subcommand other than "
            "the read-only view/checks pair",
        )

    def test_action_yml_declares_no_approve_inputs(self):
        text = ACTION_YML.read_text(encoding="utf-8")
        for name in (
            "approve-prs", "merge-prs",
            "approve-exclude-paths", "approve-allowed-authors",
        ):
            self.assertNotIn(
                name, text,
                f"input {name!r} was deleted with the approve/merge step "
                "(F-01) and must never return",
            )


if __name__ == "__main__":
    unittest.main()
