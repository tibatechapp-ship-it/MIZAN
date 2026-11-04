"""Safe PR auto-approval and merge with strict guardrails."""

import json
import subprocess


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


def is_pr_eligible(
    pr_number,
    findings_count=0,
    exclude_paths=DEFAULT_EXCLUDE_PATHS,
    allowed_authors=DEFAULT_ALLOWED_AUTHORS,
    require_no_findings=True,
    require_checks=True,
):
    """Return (eligible: bool, reason: str)."""
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


def approve_pr(pr_number, comment=None):
    """Approve a PR. Returns (success, message)."""
    cmd = ["gh", "pr", "review", str(pr_number), "--approve"]
    if comment:
        cmd.extend(["--body", comment])
    code, out, err = _run(cmd)
    if code == 0:
        return True, (out.strip() or "approved")
    return False, (err.strip() or out.strip() or "approve failed")


def merge_pr(pr_number, method="squash", auto=True):
    """Merge a PR. Returns (success, message)."""
    cmd = ["gh", "pr", "merge", str(pr_number), "--" + method]
    if auto:
        cmd.append("--auto")
    code, out, err = _run(cmd)
    if code == 0:
        return True, (out.strip() or "merged")
    return False, (err.strip() or out.strip() or "merge failed")
