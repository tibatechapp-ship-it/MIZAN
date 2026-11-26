# MIZAN GitHub Action

Scan dependencies for vulnerabilities, upload SARIF, optionally auto-fix.

## Usage

Add to `.github/workflows/mizan.yml`:

```yaml
name: MIZAN Security Scan
on: [push, pull_request]

# Least privilege (RW-207): the default example below grants ONLY what a
# plain scan + SARIF upload needs. Extra permissions are opt-in — see
# "Permission matrix" — never grant them "just in case".
permissions:
  contents: read
  security-events: write

jobs:
  mizan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Pin to a released tag. For security-sensitive repositories, pin to
      # the full commit SHA instead so the code you run can never change
      # under your feet:
      #   uses: tibatechapp-ship-it/MIZAN/action@<full-commit-sha>
      - uses: tibatechapp-ship-it/MIZAN/action@v0.16.0
        with:
          fail-on-findings: "true"
```

## Permission matrix

The composite action runs with the permissions of YOUR workflow — it cannot
elevate them. Grant only what the features you enable actually need:

| Feature | Required permissions |
|---|---|
| Scan + fail on findings | `contents: read` |
| Upload SARIF to Code Scanning | + `security-events: write` |
| `create-pr: true` (push fix branch, open PR, label it) | + `contents: write` and `pull-requests: write` |

F-01 (2026-11-26 live audit): the Action has **no** approve/merge
capability and never will — the merge decision always belongs to a
human. The former `approve-prs` / `merge-prs` inputs were deleted with
their workflow step; a guard test keeps every executable surface free
of `gh pr merge` / `gh pr review` calls.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| path | . | Repository path |
| auto-fix | false | Apply safe upgrades with test validation |
| create-pr | false | Commit fixes and open a PR |
| fail-on-findings | true | Exit 1 on findings |
| sarif-output | mizan-results.sarif | SARIF path |
| python-version | 3.11 | Python version |
| fail-on-fix-error | false | Exit 1 when `mizan fix` errors — the failure is **always** surfaced as an `::error` and the `fix-status` output reports it; this input only decides whether it also fails the workflow |
| fail-on-pr-error | false | Exit 1 when creating the fix PR errors — the failure is **always** surfaced as an `::error` and the `pr-status` output reports it; this input only decides whether it also fails the workflow |

## Outputs

| Output | Description |
|-------|-------------|
| findings-count | Number of vulnerabilities found |
| sarif-file | Absolute path to the SARIF file |
| fix-status | `skipped` \| `no-changes` \| `applied` \| `failed` |
| pr-status | `skipped` \| `no-changes` \| `created` \| `failed` |
| pr-url | URL of the created PR (empty unless `pr-status` is `created`) |

Gate downstream steps on `fix-status` / `pr-status` instead of guessing:
never assume a green workflow means the fix was applied or the PR exists.

## Failure semantics (RW-205)

The scan step distinguishes **"scan completed"** from **"scan produced a
report"**:

| Exit code from `mizan vuln-scan` | Meaning | Action step behaviour |
|---|---|---|
| 0 | completed, no findings | `findings-count=0`, workflow continues |
| 1 | completed, findings present | `findings-count=N`, `fail-on-findings` decides |
| ≥ 2 | scan FAILURE (bad path, OSV outage) | step FAILS — never reported as "0 vulnerabilities" |

A missing or malformed SARIF file also fails the step instead of counting
as zero findings.

## Fix and PR failure semantics (E-01, 2026-11-17 review)

The optional fix/PR paths follow the same "explicit, never silent" rule:

| Situation | Always happens | `fail-on-*-error: false` | `fail-on-*-error: true` |
|---|---|---|---|
| `mizan fix` exits non-zero | `::error` + `fix-status=failed` | workflow continues | workflow fails |
| `git commit` / `git push` / `gh pr create` fails | `::error` + `pr-status=failed` | workflow continues | workflow fails |

There is no code path where a failed fix or a missing PR looks like an
unqualified success — the status outputs and `::error` annotations are
emitted in every case; the inputs only control hard failure.

## Security

- No code leaves the runner
- OSV.dev queries are metadata-only
- Rollback on test failure
- All action inputs reach the shell only via environment variables and
  literal argument arrays — never interpolated into command strings
