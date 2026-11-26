"""Read-only PR eligibility assessment — report-only by design (F-01).

2026-11-26 live-audit decision (F-01, high): MIZAN's stated policy is
"final merge is human" — yet this module used to carry executive
approve/merge helpers that invoked gh's review and merge subcommands
with ``--approve`` / ``--auto``. The capability contradicted the policy,
so it is deleted outright: there is no flag, no policy file, and no
exception that can bring it back. A guard test
(``tests/test_no_merge_capability.py``) enforces that no executable
surface (``src/`` or ``action/``) may ever contain those subcommand
invocations again.

What remains is exactly what a human needs to decide:

* ``is_pr_eligible`` — a READ-ONLY assessment over ``gh pr view`` /
  ``gh pr checks`` (no state is ever written);
* ``measure_report_findings`` — findings are MEASURED from a scan
  report file (SARIF or MIZAN JSON), never trusted from a flag
  (F-02: an eligibility gate that accepts a number validates a claim
  instead of measuring it).

Exit contract for the CLI ``approve`` command:
  0 = eligible (report-only: prints the measured basis, takes no action)
  1 = blocked (reason stated)
  2 = refusal — report missing / unreadable / malformed / unrecognized;
      a report that cannot be measured is NEVER counted as "0 findings"
      (same doctrine as RW-205 in the Action scan step).
"""

import json
import subprocess
from pathlib import Path


DEFAULT_EXCLUDE_PATHS = (
    ".github/",
    "Dockerfile",
    "Dockerfile.",
    ".env",
    "secrets/",
    "k8s/",
    "terraform/",
    "helm/",
)

DEFAULT_ALLOWED_AUTHORS = (
    "dependabot[bot]",
    "renovate[bot]",
    "github-actions[bot]",
)


def _run(cmd, timeout=60):
    """Run subprocess, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def _path_is_excluded(path, exclude_paths):
    """Check if a file path matches any excluded pattern.

    Patterns:
    - "dir/" -> prefix match (e.g. ".github/" matches ".github/workflows/x.yml")
    - "prefix.*" -> prefix match without *
    - "Dockerfile." -> prefix match for "Dockerfile.prod", "Dockerfile.dev", etc.
    - "Dockerfile" -> exact match only
    """
    if not path:
        return False
    for ex in exclude_paths:
        if not ex:
            continue
        if path == ex:
            return True
        if ex.endswith("/") and path.startswith(ex):
            return True
        if ex.endswith("*") and path.startswith(ex[:-1]):
            return True
        if ex.endswith(".") and path.startswith(ex):
            return True
    return False


def measure_report_findings(report_path):
    """Measure the findings count from a scan report file.

    Accepts SARIF (``runs[].results[]``) or MIZAN JSON
    (``findings[]`` / ``findings_count``). Returns
    ``(count, meta)`` where ``meta`` states the source format and how
    the count was derived. Raises ``ValueError`` naming the path and
    the reason for every missing / unreadable / malformed /
    unrecognized report — a report that cannot be measured is never
    treated as zero findings (F-02 / RW-205 doctrine).
    """
    path = Path(report_path)
    if not path.is_file():
        raise ValueError(f"report file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"report {path} is not valid JSON: {exc}") from exc

    # SARIF: runs[].results[]
    if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
        runs = doc["runs"]
        if not runs:
            raise ValueError(
                f"report {path} looks like SARIF but has an empty "
                "'runs' array — refusing to count it as clean"
            )
        for run in runs:
            if not isinstance(run, dict) or \
                    not isinstance(run.get("results"), list):
                raise ValueError(
                    f"report {path} looks like SARIF but a 'runs' entry "
                    "has no 'results' list — refusing to guess"
                )
        count = sum(len(r["results"]) for r in runs)
        return count, {
            "format": "sarif",
            "runs": len(runs),
            "derived": "sum of len(runs[].results[])",
        }

    # MIZAN JSON: findings[] (+ optional findings_count summary field)
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        count = len(doc["findings"])
        declared = doc.get("findings_count")
        meta = {
            "format": "mizan-json",
            "derived": "len(findings[])",
        }
        if isinstance(declared, int) and declared != count:
            meta["declared_findings_count_mismatch"] = declared
        return count, meta

    if isinstance(doc, dict) and isinstance(doc.get("findings_count"), int):
        # Summary-only document: the declared counter is the only
        # signal — measured-adjacent, honestly labeled as declared.
        return doc["findings_count"], {
            "format": "mizan-json-summary",
            "derived": "declared findings_count (no findings[] list present)",
        }

    if isinstance(doc, list):
        if doc and not all(isinstance(x, dict) for x in doc):
            raise ValueError(
                f"report {path} is a JSON list whose entries are not "
                "finding objects — unrecognized format"
            )
        return len(doc), {
            "format": "bare-findings-list",
            "derived": "len(list)",
        }

    raise ValueError(
        f"report {path} is not a recognized format — expected SARIF "
        "(runs[].results[]) or MIZAN JSON (findings[]); refusing to "
        "treat it as zero findings"
    )


def is_pr_eligible(
    pr_number,
    findings_count=0,
    exclude_paths=DEFAULT_EXCLUDE_PATHS,
    allowed_authors=DEFAULT_ALLOWED_AUTHORS,
    require_no_findings=True,
    require_checks=True,
):
    """Return (eligible: bool, reason: str).

    READ-ONLY: runs ``gh pr view`` / ``gh pr checks`` and nothing else.
    ``findings_count`` MUST come from ``measure_report_findings`` — the
    CLI enforces this by making the report file mandatory.
    """
    code, out, err = _run([
        "gh", "pr", "view", str(pr_number),
        "--json",
        "author,isDraft,mergeable,files,reviews,reviewDecision,headRefName",
    ])
    if code != 0:
        return False, "cannot fetch PR: " + err[:200]

    try:
        pr = json.loads(out)
    except json.JSONDecodeError:
        return False, "invalid PR JSON from gh"

    if pr.get("isDraft"):
        return False, "PR is a draft"

    author = (pr.get("author") or {}).get("login", "")
    if author not in allowed_authors:
        return False, "author '" + author + "' not in allowed list"

    if pr.get("mergeable") != "MERGEABLE":
        return False, "PR not mergeable: " + str(pr.get("mergeable"))

    if require_no_findings and findings_count > 0:
        return False, "MIZAN found " + str(findings_count) + " vulnerabilities"

    for f in pr.get("files", []):
        path = f.get("path", "")
        if _path_is_excluded(path, exclude_paths):
            return False, "excluded path: " + path

    if require_checks:
        code, _, _ = _run(["gh", "pr", "checks", str(pr_number)])
        if code != 0:
            return False, "one or more checks are failing"

    for r in pr.get("reviews", []):
        if r.get("state") == "APPROVED":
            return False, "PR already approved"
        if r.get("state") == "CHANGES_REQUESTED":
            return False, "changes requested by reviewer"

    return True, "eligible"


__all__ = [
    "DEFAULT_EXCLUDE_PATHS",
    "DEFAULT_ALLOWED_AUTHORS",
    "is_pr_eligible",
    "measure_report_findings",
]
