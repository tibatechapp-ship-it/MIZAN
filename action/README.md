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
      - uses: tibatechapp-ship-it/MIZAN/action@v0.9.0
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
| `create-pr: true` (push fix branch, open PR) | + `contents: write` |
| Comment/approve/merge PRs (`approve-prs` / `merge-prs`) | + `pull-requests: write` |

`approve-prs` and `merge-prs` are **off by default** and are refused for
PRs authored by anyone outside `approve-allowed-authors` or touching
`approve-exclude-paths`. Review both lists before enabling them.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| path | . | Repository path |
| auto-fix | false | Apply safe upgrades with test validation |
| create-pr | false | Commit fixes and open a PR |
| fail-on-findings | true | Exit 1 on findings |
| sarif-output | mizan-results.sarif | SARIF path |
| python-version | 3.11 | Python version |
| approve-prs | false | Auto-approve eligible PRs (off by default) |
| merge-prs | false | Auto-merge after approval (implies approve-prs) |
| approve-exclude-paths | .github/,Dockerfile,.env,... | Paths that block auto-approval |
| approve-allowed-authors | dependabot[bot],renovate[bot],... | Bot authors eligible for auto-approval |

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

## Security

- No code leaves the runner
- OSV.dev queries are metadata-only
- Rollback on test failure
- All action inputs reach the shell only via environment variables and
  literal argument arrays — never interpolated into command strings
