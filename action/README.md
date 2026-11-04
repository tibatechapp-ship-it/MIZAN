# MIZAN GitHub Action

Scan dependencies for vulnerabilities, upload SARIF, optionally auto-fix.

## Usage

Add to `.github/workflows/mizan.yml`:

```yaml
name: MIZAN Security Scan
on: [push, pull_request]
permissions:
  contents: write
  security-events: write
  pull-requests: write
jobs:
  mizan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tibatechapp-ship-it/MIZAN/action@main
        with:
          fail-on-findings: "true"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| path | . | Repository path |
| auto-fix | false | Apply safe upgrades with test validation |
| create-pr | false | Commit fixes and open a PR |
| fail-on-findings | true | Exit 1 on findings |
| sarif-output | mizan-results.sarif | SARIF path |
| python-version | 3.11 | Python version |

## Security

- No code leaves the runner
- OSV.dev queries are metadata-only
- Rollback on test failure
