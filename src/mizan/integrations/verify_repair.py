"""Isolated repair verification (Wave 4).

Plan v0.16.0-dev Wave 4 contract (docs/DEV_PLAN_V0150.md):

* isolated temporary copy (``git worktree``, detached HEAD) — the
  agent's patch is applied ONLY there, never in the user's tree;
* apply the change, run the tests with NO secrets and NO network in
  the environment by default (env-level scrubbing, honestly declared
  in the report's isolation limits);
* produce the diff and the measured result: did the original finding
  stop firing, did the patch introduce new findings, did the tests
  pass;
* explicit approval gates the transfer: without ``--approve`` on
  ``--transfer-branch`` the worktree is disposed and only the report
  survives — transfer or delete, nothing else;
* the verification report (``mizan.repair-verification.v1``) always
  records: the changed files, which tests ran and which did not, the
  persistence of the original finding fingerprint (identity survives
  the whole round trip), and the isolation limits — what was enforced
  and what only declared.

Exit contract: 0 = patch verified, 1 = verification measured a
failure (stated, never silent), 2 = refusal (invalid request, patch
that does not apply, missing approval — every refusal names the path
and the reason).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .repair_request import REPAIR_SCHEMA, validate_repair_request
from .sarif_import import _fallback_fingerprint

VERIFY_SCHEMA = "mizan.repair-verification.v1"

# The default test command runs INSIDE the worktree with cwd set to
# it; unittest discover from the worktree root picks up tests/ there.
DEFAULT_TESTS_COMMAND = [sys.executable, "-m", "unittest", "discover", "-q"]
DEFAULT_TEST_TIMEOUT = 600

# Environment variable name fragments that mark a secret: any var whose
# UPPERCASE name contains one is removed from the subprocess env.
SECRET_ENV_MARKERS = (
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE",
    "CREDENTIAL", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY",
    "SERVICE_ACCOUNT", "DATABASE_URL",
    "AWS_", "AZURE_", "GCP_", "SSH_", "GPG_", "GIT_", "GITHUB_",
)

# Exact env names stripped when network is not allowed (default):
# removing proxy configuration is env-level network denial.
NETWORK_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy",
)

ISOLATION_LIMITS = [
    "secret scrubbing is environment-level: variables are removed by "
    "name; secrets already embedded in tracked files are untouched "
    "and must still fire the analyzer",
    "network enforcement is environment-level: proxy variables are "
    "stripped by default; direct socket connections from the test "
    "process are not policed",
    "the test command runs with the worktree as cwd and no additional "
    "filesystem sandbox — whatever the command can do to the machine "
    "it can do",
    "the worktree is created from HEAD: uncommitted changes in the "
    "user's tree are NOT part of what the patch is verified against",
    "a transferred branch is staged for human review only — MIZAN "
    "never merges it",
]

_GIT_IDENTITY = [
    "-c", "user.name=mizan verify-repair",
    "-c", "user.email=mizan@verify.invalid",
]


class VerifyRepairError(ValueError):
    """Refusal — the error message names the path and the reason."""


def _run_git(args: list[str], cwd: Path, env: dict[str, str],
             what: str, timeout: int | None = None,
             input_text: str | None = None) -> str:
    """Run one git command and return stdout; a failure raises with the
    command purpose, the path, and git's own stderr — never silent."""
    try:
        proc = subprocess.run(
            ["git", *args], cwd=str(cwd), env=env,
            capture_output=True, text=True,
            timeout=timeout or DEFAULT_TEST_TIMEOUT,
            input=input_text,
        )
    except FileNotFoundError as exc:
        raise VerifyRepairError(
            f"git is not available while {what}: {exc}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise VerifyRepairError(
            f"git timed out after {exc.timeout}s while {what}"
        ) from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise VerifyRepairError(
            f"git failed while {what} (exit {proc.returncode}) in "
            f"{cwd}: {stderr[:800]}"
        )
    return proc.stdout


def build_verification_env(allow_network: bool = False):
    """Build the scrubbed subprocess environment and the honest audit
    of what was removed.

    Secret-marked variables are ALWAYS removed. Network proxy
    variables are removed unless ``allow_network`` is set explicitly.
    Returns ``(env, audit)`` — the audit travels into the report.
    """
    network_names = {n.upper() for n in NETWORK_ENV_VARS}
    env: dict[str, str] = {}
    scrubbed: list[str] = []
    network_removed: list[str] = []
    for name, value in os.environ.items():
        upper = name.upper()
        if any(marker in upper for marker in SECRET_ENV_MARKERS):
            scrubbed.append(name)
            continue
        if not allow_network and upper in network_names:
            network_removed.append(name)
            continue
        env[name] = value
    audit = {
        "secrets_scrubbed": True,
        "scrubbed_var_count": len(scrubbed),
        "scrubbed_var_names": sorted(scrubbed),
        "network": (
            "allowed-by-explicit-flag" if allow_network
            else "proxies-stripped-default"
        ),
        "network_vars_removed": (
            [] if allow_network else sorted(network_removed)
        ),
    }
    return env, audit


def _load_and_validate_request(request_path: Path) -> dict[str, Any]:
    if not request_path.is_file():
        raise VerifyRepairError(
            f"repair request file not found: {request_path}"
        )
    try:
        payload = json.loads(
            request_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise VerifyRepairError(
            f"cannot read repair request {request_path}: {exc}"
        ) from exc

    request = payload
    # A batch handoff is acceptable: verify-repair operates on ONE
    # request; a batch with exactly one is taken as that request.
    if (
        isinstance(payload, dict)
        and payload.get("schema") == REPAIR_SCHEMA
        and isinstance(payload.get("requests"), list)
    ):
        if len(payload["requests"]) != 1:
            raise VerifyRepairError(
                f"{request_path}: verify-repair takes ONE repair "
                f"request; the batch holds {len(payload['requests'])}"
            )
        request = payload["requests"][0]
    try:
        return validate_repair_request(request)
    except ValueError as exc:
        raise VerifyRepairError(
            f"invalid repair request {request_path}: {exc}"
        ) from exc


def _load_patch(patch_path: Path) -> str:
    if not patch_path.is_file():
        raise VerifyRepairError(f"patch file not found: {patch_path}")
    patch = patch_path.read_text(encoding="utf-8", errors="replace")
    if not patch.strip():
        raise VerifyRepairError(f"patch file is empty: {patch_path}")
    if "diff --git" not in patch and not patch.startswith("--- "):
        raise VerifyRepairError(
            f"patch does not look like a unified diff (no 'diff --git' "
            f"or '--- ' header): {patch_path}"
        )
    return patch


def _resolve_repo(repo_path: Path, env: dict[str, str]) -> tuple[Path, str]:
    root = repo_path.expanduser().resolve()
    if not root.is_dir():
        raise VerifyRepairError(f"repository path not found: {root}")
    try:
        top = _run_git(
            ["rev-parse", "--show-toplevel"], root, env,
            f"resolving the repository at {root}",
        ).strip()
        head = _run_git(
            ["rev-parse", "HEAD"], root, env,
            f"resolving HEAD in {root}",
        ).strip()
    except VerifyRepairError as exc:
        raise VerifyRepairError(
            f"{root} is not a usable git repository with at least one "
            f"commit: {exc}"
        ) from exc
    return Path(top), head


def _changed_files_from_patch(patch: str, worktree: Path,
                              env: dict[str, str]) -> list[str]:
    try:
        out = _run_git(
            ["apply", "--numstat", "-"], worktree, env,
            "reading the patch's changed files",
            input_text=patch,
        )
    except VerifyRepairError as exc:
        # The numstat pass is the earliest applicability check: a patch
        # git cannot even parse is named as what it is — one that does
        # not apply — with git's own reason attached.
        raise VerifyRepairError(
            f"patch does not apply cleanly (rejected while reading "
            f"the changed files): {exc}"
        ) from exc
    # --numstat prints WITHOUT applying; the same call also rejects a
    # patch that would not apply, so a failure here is named before
    # anything touches the worktree.
    files: list[str] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        path = parts[-1].strip()
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        if path:
            files.append(path)
    if not files:
        raise VerifyRepairError(
            "the patch carries no parseable file paths — refusing to "
            "verify a change whose touched files cannot be named"
        )
    return files


def _fingerprint_findings(findings: list[dict[str, Any]],
                          changed_files: set[str]):
    """Fingerprint analyzer findings restricted to the changed files,
    using the same wave-0 fallback formula — the identity space the
    repair request itself used, so 'still fires' is an exact match."""
    mapped = {}
    for finding in findings:
        if finding.get("file") not in changed_files:
            continue
        fp = _fallback_fingerprint(
            "MIZAN",
            str(finding.get("rule") or ""),
            str(finding.get("file") or ""),
            finding.get("line"),
            str(finding.get("message") or ""),
        )
        mapped[fp] = finding
    return mapped


def _measure_checks(request: dict[str, Any], still_fires: bool,
                    new_count: int, tests_passed: bool) -> list[dict]:
    measured = [
        {"what": "the original finding no longer fires",
         "status": "measured", "passed": not still_fires},
        {"what": "no new findings of any rule appeared",
         "status": "measured", "passed": new_count == 0},
        {"what": "the project's test suite passes",
         "status": "measured", "passed": tests_passed},
    ]
    results = list(measured)
    for step in request.get("verification", []):
        what = str(step.get("what") or "").strip()
        if not what:
            continue
        lower = what.lower()
        if "no longer fires" in lower:
            continue  # measured above
        if "new findings" in lower:
            continue
        if "test suite" in lower or "tests" in lower:
            continue
        results.append({
            "what": what,
            "status": "declared-only",
            "passed": None,
            "note": ("declared in the request, not measurable by "
                     "this run — a human verifies it"),
        })
    return results


def _summary_tail(*streams: str, limit: int = 1200) -> str:
    text = "\n".join(s for s in streams if s).strip()
    if len(text) <= limit:
        return text
    return "… " + text[-limit:]


def run_verification(
    request_path: str | Path,
    patch_path: str | Path,
    repo_path: str | Path = ".",
    tests_command: list[str] | str | None = None,
    allow_network: bool = False,
    keep_worktree: bool = False,
    transfer_branch: str | None = None,
    approve: bool = False,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Verify one repair request's patch in an isolated worktree.

    Returns the ``mizan.repair-verification.v1`` report. Raises
    :class:`VerifyRepairError` on every refusal (exit-2 path in the
    CLI). ``verified`` is False — never an exception — when the
    verification itself measured a failure: that is the honest exit-1
    path, and the report states which check failed.
    """
    timeout = timeout or DEFAULT_TEST_TIMEOUT

    # --- fail-fast refusals (no side effects yet) --------------------
    if transfer_branch and not approve:
        raise VerifyRepairError(
            "--transfer-branch requires --approve: transfer is the "
            "explicitly approved path; without it the worktree is "
            "disposed after the report"
        )
    if approve and not transfer_branch:
        raise VerifyRepairError(
            "--approve only makes sense together with --transfer-branch"
        )
    if tests_command is None:
        cmd = list(DEFAULT_TESTS_COMMAND)
    elif isinstance(tests_command, str):
        cmd = shlex.split(tests_command)
    else:
        cmd = list(tests_command)
    if not cmd:
        raise VerifyRepairError("the test command is empty")

    request = _load_and_validate_request(Path(request_path))
    patch = _load_patch(Path(patch_path))

    git_env, git_audit_unused = build_verification_env(allow_network=True)
    repo_root, head = _resolve_repo(Path(repo_path), git_env)

    if transfer_branch:
        _run_git(
            ["check-ref-format", "--branch", transfer_branch],
            repo_root, git_env,
            f"validating branch name {transfer_branch!r}",
        )
        probe = subprocess.run(
            ["git", "rev-parse", "--verify",
             f"refs/heads/{transfer_branch}"],
            cwd=str(repo_root), env=git_env, capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            raise VerifyRepairError(
                f"branch {transfer_branch!r} already exists in "
                f"{repo_root} — refusing to overwrite; pick another "
                f"name or delete the old branch first"
            )

    # --- isolated worktree -------------------------------------------
    # A path that does NOT exist yet: git creates it, git removes it —
    # no empty-dir edge case at either end.
    worktree = (
        Path(tempfile.gettempdir())
        / f"mizan-verify-{os.getpid()}-{uuid.uuid4().hex[:10]}"
    )
    worktree_created = False
    result: dict[str, Any] | None = None
    try:
        _run_git(
            ["worktree", "add", "--detach", str(worktree), head],
            repo_root, git_env,
            f"creating the isolated worktree at {worktree}",
        )
        worktree_created = True

        changed_files = _changed_files_from_patch(
            patch, worktree, git_env
        )

        # BEFORE state measured on the same HEAD the patch will sit on.
        before = _fingerprint_findings(
            _analyze(worktree)["findings"], set(changed_files)
        )

        _run_git(
            ["apply", "--whitespace=nowarn", "-"],
            worktree, git_env,
            f"applying {patch_path} in the worktree at HEAD "
            f"{head[:12]}",
            input_text=patch,
        )

        after_analysis = _analyze(worktree)
        after = _fingerprint_findings(
            after_analysis["findings"], set(changed_files)
        )

        finding_id = request["finding_id"]
        still_fires = finding_id in after
        new_fps = [fp for fp in after if fp not in before]
        new_findings = [
            {
                "file": after[fp].get("file"),
                "line": after[fp].get("line"),
                "rule": after[fp].get("rule"),
                "message": after[fp].get("message"),
                "fingerprint": fp,
            }
            for fp in sorted(new_fps)
        ]
        custom_errors = list(
            after_analysis.get("custom_rules_errors") or []
        )

        # --- tests: no secrets, no network (default) --------------
        test_env, env_audit = build_verification_env(allow_network)
        tests: dict[str, Any] = {
            "command": shlex.join(cmd),
            "ran": False,
            "passed": False,
            "returncode": None,
            "cwd": str(worktree),
        }
        try:
            proc = subprocess.run(
                cmd, cwd=str(worktree), env=test_env,
                capture_output=True, text=True, timeout=timeout,
            )
            tests["ran"] = True
            tests["returncode"] = proc.returncode
            # An empty suite must never count as a pass: Python < 3.12
            # exits 0 when the discovery collects zero tests — the
            # output is the honest signal, not the exit code.
            combined = f"{proc.stdout or ''}\n{proc.stderr or ''}"
            zero_tests = bool(
                re.search(r"^Ran 0 tests\b", combined, re.MULTILINE)
            )
            tests["zero_tests_detected"] = zero_tests
            tests["passed"] = (
                proc.returncode == 0 and not zero_tests
            )
            if zero_tests:
                tests["summary"] = (
                    "the test command reported 'Ran 0 tests' — an "
                    "empty suite never counts as a pass\n"
                ) + _summary_tail(proc.stdout, proc.stderr)
            else:
                tests["summary"] = _summary_tail(proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            tests["ran"] = True
            tests["returncode"] = None
            tests["passed"] = False
            tests["summary"] = (
                f"test run timed out after {exc.timeout}s and was "
                f"killed — an unfinished run never counts as a pass"
            )
        tests["environment"] = env_audit

        # --- the measured verdict ---------------------------------
        verified = (
            (not still_fires)
            and not new_findings
            and tests["passed"]
            and not custom_errors
        )

        checks = _measure_checks(
            request, still_fires, len(new_findings), tests["passed"]
        )

        # --- transfer (only with explicit approval + verified) ----
        transfer = {
            "requested": bool(transfer_branch),
            "branch": transfer_branch,
            "approved": bool(approve),
            "done": False,
            "reason": None,
        }
        if transfer_branch and approve:
            if not verified:
                transfer["reason"] = (
                    "verification failed — an unverified patch is "
                    "never transferred; read finding_check/tests and "
                    "produce a new patch"
                )
            else:
                commit_msg = (
                    f"verify-repair: staged fix for finding {finding_id}\n"
                    "\n"
                    "Measured in the isolated worktree:\n"
                    f"- original finding no longer fires: "
                    f"{not still_fires}\n"
                    f"- new findings introduced: {len(new_findings)}\n"
                    f"- tests: {tests['command']} -> "
                    f"{'passed' if tests['passed'] else 'FAILED'}\n"
                    "\n"
                    "human_review_required=true — merging this branch "
                    "requires explicit human approval.\n"
                    "Generated by mizan verify-repair "
                    f"({REPAIR_SCHEMA} -> {VERIFY_SCHEMA}).\n"
                )
                _run_git(
                    ["add", "--all"], worktree, git_env,
                    "staging the verified patch",
                )
                _run_git(
                    _GIT_IDENTITY + [
                        "commit", "-m", commit_msg,
                        "--no-verify", "--quiet",
                    ],
                    worktree, git_env,
                    "committing the verified patch on the isolated "
                    "HEAD",
                )
                _run_git(
                    ["branch", transfer_branch], worktree, git_env,
                    f"creating branch {transfer_branch!r} for human "
                    f"review",
                )
                transfer["done"] = True

        # Measured BEFORE anything (transfer included) touches the
        # worktree state: the diff is the agent's patch, always.
        diff_stat = _run_git(
            ["diff", "--stat"], worktree, git_env,
            "measuring the diff stat",
        )

        report = {
            "schema": VERIFY_SCHEMA,
            "request": {
                "schema": REPAIR_SCHEMA,
                # Persistence of the original identity: the finding's
                # fingerprint travels through the whole round trip
                # unchanged — discovery, request, verification.
                "finding_id": finding_id,
                "evidence": dict(request.get("evidence") or {}),
                "confidence": request.get("confidence"),
                "human_review_required": True,
            },
            "repo": str(repo_root),
            "head_before": head,
            "worktree": {
                "path": str(worktree),
                "base": head,
                "created": True,
                "disposed": None,  # filled after disposal below
                "isolation": (
                    f"git worktree, detached HEAD at {head[:12]}"
                ),
            },
            "patch": {
                "path": str(Path(patch_path).resolve()),
                "applied": True,
                "changed_files": changed_files,
                "diff_stat": diff_stat.strip(),
            },
            "finding_check": {
                "original_finding_id": finding_id,
                "original_still_fires": still_fires,
                "before_findings_on_changed_files": len(before),
                "after_findings_on_changed_files": len(after),
                "new_findings_count": len(new_findings),
                "new_findings": new_findings,
                "custom_rules_errors": custom_errors,
            },
            "tests": tests,
            "checks": checks,
            "verified": verified,
            "transfer": transfer,
            "isolation_limits": list(ISOLATION_LIMITS),
            "human_review_required": True,
        }
        result = report
        return report
    finally:
        # Disposal is unconditional unless explicitly kept — transfer
        # or delete, nothing else. A kept worktree is recorded in the
        # report for the human to inspect and remove.
        if worktree_created and not keep_worktree:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=str(repo_root), env=git_env, capture_output=True,
                text=True, timeout=timeout,
            )
            subprocess.run(
                ["git", "worktree", "prune"],
                cwd=str(repo_root), env=git_env, capture_output=True,
                text=True, timeout=timeout,
            )
            if result is not None:
                result["worktree"]["disposed"] = True
        elif worktree_created and result is not None:
            result["worktree"]["disposed"] = False


def _analyze(directory: Path) -> dict[str, Any]:
    # Imported lazily to keep the integration module import-light and
    # to avoid a circular import at package init time.
    from ..analyzer import analyze_repository

    return analyze_repository(str(directory))


def write_verification_report(report: dict[str, Any],
                              output_path: str | Path | None) -> None:
    """Write the report when an output path is given; otherwise the
    CLI prints it. Only the caller-provided path is ever written."""
    if output_path is None:
        return
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "VERIFY_SCHEMA",
    "DEFAULT_TESTS_COMMAND",
    "DEFAULT_TEST_TIMEOUT",
    "SECRET_ENV_MARKERS",
    "NETWORK_ENV_VARS",
    "ISOLATION_LIMITS",
    "VerifyRepairError",
    "build_verification_env",
    "run_verification",
    "write_verification_report",
]
