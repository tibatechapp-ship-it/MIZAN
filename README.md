<div align="center">

# ⚖️ MIZAN Security

**The read-only security engine that fits one command.**

Code · Secrets · Dependencies · CI · Documentation — inspected in a single
pass, explained in plain language, never executed.

[![MIZAN CI](https://github.com/tibatechapp-ship-it/MIZAN/actions/workflows/tests.yml/badge.svg)](https://github.com/tibatechapp-ship-it/MIZAN/actions/workflows/tests.yml)
[![MIZAN Security Scan](https://github.com/tibatechapp-ship-it/MIZAN/actions/workflows/mizan.yml/badge.svg)](https://github.com/tibatechapp-ship-it/MIZAN/actions/workflows/mizan.yml)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)](https://github.com/tibatechapp-ship-it/MIZAN/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/tibatechapp-ship-it/MIZAN)](https://github.com/tibatechapp-ship-it/MIZAN/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Self-scan](https://img.shields.io/badge/self--scan-0%20actionable%20findings-brightgreen)](CHANGELOG.md)

[Quickstart](#quickstart) · [The engine](#the-engine-one-pass-eight-scanners) · [Measured](#measured-not-marketed) · [The gate](#the-gate-honest-exit-codes) · [Policies](#custom-policies) · [GitHub Action](#github-action) · [Docs](#documentation)

</div>

## Why MIZAN

Security tooling usually forces a trade: heavyweight platforms that own your
workflow, or noisy linters that teach your team to ignore alerts. MIZAN is the
third option — a precision-first engine you run locally, in your pipeline, on
your terms.

- **One command, the whole surface** — `mizan full-scan .` covers static
  analysis, secret patterns, dependency manifests, vulnerability feeds, CI
  configuration, change risk and documentation health in a single report.
- **Read-only by design** — MIZAN never executes the code it inspects. Every
  scanner is read-only; any repair goes through a dry-run-first, isolated,
  test-verified gate.
- **Precision is a feature, not a hope** — a measured **−93.6% false-positive
  reduction** across 20 real repositories (v0.9.0); on the latest field wave,
  **20/20 sampled findings verified true positives, zero security false
  positives** (v0.12.0).
- **Fail loud, never fake green** — MIZAN distinguishes *clean* (exit 0),
  *blocking findings* (exit 1) and *could not verify* (exit 2). A scan that
  could not load its policies never certifies a pass.
- **SARIF-native** — SARIF 2.1.0 output wired directly into GitHub code
  scanning, plus JSON and self-contained HTML reports.
- **Works offline** — dependency vulnerability checks run against OSV.dev
  with batched queries and a local cache. No cloud account, no data leaves
  your machine.
- **Your policies, declaratively** — custom rules in `.mizan/rules.json`
  (plain regex per line, no new query language). Invalid rules are rejected
  loudly, not silently dropped.
- **Accountable** — an engineering ledger records every decision, and the
  severity gate only fails builds on what you told it to fail on.

## The engine: one pass, eight scanners

| Scanner | Command | What it inspects |
|---|---|---|
| Static Analyzer | `mizan analyze` | AST-based source analysis — injection vectors, unsafe calls, dangerous patterns |
| Secrets & Patterns | `mizan scan` | curated detection rules for keys, tokens and credentials, plus code-quality checks |
| Git Hygiene | `mizan git-scan` | repository-level risk in history and configuration — read-only |
| CI Auditor | `mizan ci-scan` | workflow hardening gaps in your CI/CD configuration |
| Dependency Scanner | `mizan dependency-scan` | manifests per ecosystem — npm, crates.io, Go, Packagist, PyPI |
| Vulnerability Feed | `mizan vuln-scan` | known vulnerabilities via OSV.dev — batched, cached, offline-capable |
| Change Risk | `mizan risk-scan` | risk assessment of pending changes without modifying files |
| Doc Intelligence | `mizan doc-scan` | do the docs still match reality? broken links, stale references, undocumented endpoints, README command validity |

Run everything at once — eight read-only scanners in parallel, wall time is
the slowest pass, not the sum:

```bash
mizan full-scan . --jobs 4
```

## Measured, not marketed

Every number below is reproducible from the project's own changelog and CI —
not aspirational marketing.

| Metric | Result | Where it was measured |
|---|---|---|
| Full-scan wall time — requests, axios, cobra, fd, chalk | **0.5–1.6 s** per repository | v0.12.0 field notes |
| False-positive reduction vs prior wave, 20 real repositories | **−93.6%** | v0.9.0 precision wave |
| Sampled findings verified true positives | **20/20**, zero security FPs | v0.12.0 field notes |
| MIZAN scanning its own repository | **0 actionable findings** across all scanners | v0.12.1+, strict `--gate` |
| Field benchmark — 100 real open-source repos (zai-org first, Nov 2026) | **median 1.04 s / repo**, 0 crashes, 0 timeouts | v0.12.2 field wave |
| Test suite | **410 tests green**, Python 3.10–3.14 | CI, every push |
| Trusted CI steps that can hide a failure | **0** (`continue-on-error` removed) | v0.12.1 |

## Quickstart

```bash
python -m pip install -e .
```

```bash
# Look around — project structure, technologies, entry points
mizan inspect .
mizan detect .

# Static analysis with a JSON report
mizan analyze . --output reports/analysis.json

# Unified scan with the severity gate — exit 1 only on critical/high
mizan scan . --gate critical,high

# The whole surface, one report, one gate
mizan full-scan . --gate critical,high

# Do the docs still match the code?
mizan doc-scan . --format text
```

## The gate: honest exit codes

The difference between *clean* and *could not verify* is the difference
between a green build and a false one:

| Exit code | Meaning |
|---|---|
| `0` | complete scan — no blocking findings |
| `1` | complete scan — blocking findings present |
| `2` | **incomplete** — a scanner failed, or OSV verification was impossible; never a silent clean pass |

### Baseline (delta) scanning — kill alert fatigue, not signal

```bash
mizan baseline . --save .mizan/baseline.json
mizan scan . --gate --baseline .mizan/baseline.json
```

Known findings are absorbed; the gate alerts on what is *new*. Regressions
are never hidden — they are the whole point.

## Custom policies

Write rules in plain JSON — no new query language to learn:

```json
{
  "version": 1,
  "rules": [
    {"id": "custom-no-eval", "severity": "high",
     "languages": ["python"], "pattern": "\\beval\\s*\\(",
     "message": "eval() is forbidden by policy"}
  ]
}
```

Custom findings flow through the same gate and baseline pipeline as built-in
ones. A broken rules file makes the gate return exit 2 (incomplete) — a scan
that could not load its policies never certifies a clean pass.

## GitHub Action

Drop MIZAN into any workflow — SARIF lands in GitHub code scanning
automatically:

```yaml
- uses: tibatechapp-ship-it/MIZAN/action@main
  with:
    fail-on-findings: 'true'
    sarif-output: mizan-results.sarif
```

Optional inputs: `auto-fix` (apply safe dependency upgrades that pass your
tests) and `create-pr` (open a PR with the fixes). See
[`action/README.md`](action/README.md) for the full reference.

## Portfolio: one report for many repositories

```bash
mizan portfolio ./repos/* --output portfolio.html
```

Aggregates full-scan results for multiple repositories into **one
self-contained HTML report** with gate-fingerprint deduplication — a local
display layer for governance visibility, explicitly not a GRC platform.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | how the engine is built |
| [`docs/features.md`](docs/features.md) | full capability reference (عربي) |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | honest gap analysis and the P2 plan |
| [`docs/AI_COLLABORATION.md`](docs/AI_COLLABORATION.md) | how AI agents contribute to this repo |
| [`SECURITY.md`](SECURITY.md) | disclosure policy |
| [`CHANGELOG.md`](CHANGELOG.md) | every release, measured and documented |

## Project status

**Current release: Version 0.12.2** — calibrated in the field on 100 real
open-source repositories (zai-org first, then the newest November 2026
projects): median scan time 1.04 s, zero crashes, zero timeouts — and the
wave exposed two real defects that are now fixed: OSV batch queries are
chunked (a 1024-dependency monorepo used to fail deterministically on HTTP
400) and the 0/1/2 exit contract now holds without `--gate` too. 410 tests
green, zero actionable self-scan findings, and the README you are reading
passes MIZAN's own Documentation Intelligence.

## Evolution

- **v0.12.2** — Field calibration on 100 real repositories (zai-org first):
  median 1.04 s per scan, zero crashes. Fixed: OSV `querybatch` now chunks
  (≤100 queries), retries transient errors, and degrades per-chunk — a
  1024-dependency monorepo used to fail the whole dependency scan with HTTP
  400; and the 0/1/2 exit contract holds without `--gate` (an incomplete
  scan can no longer exit 0).
- **v0.12.1** — Fail-loud CI: the three trusted-workflow steps no longer
  swallow real failures (`continue-on-error` removed; the email reporter
  exits 1 on a real send failure). Self-scan reports zero actionable
  findings across every scanner.
- **v0.12.0** — Portfolio: one local, self-contained HTML report across many
  repositories with gate-fingerprint deduplication. Plus OSV cache-key
  hardening (`usedforsecurity=False`) found by MIZAN's own self-scan.
- **v0.11.0** — Dependency precision & custom policies: correct OSV
  ecosystems per manifest, honest dev-dependency severity cap, shallow
  reachability metadata, and `.mizan/rules.json` declarative custom rules
  with the fail-loud contract.
- **v0.10.0** — Documentation Intelligence: MIZAN audits the docs that
  explain the code, not just the code itself.
- **v0.9.0** — Precision wave: −93.6% false positives on 20 real
  repositories, 5 new detection rules with positive/negative tests.
- **v0.8.x** — Severity gate, baseline delta scanning, parallel full-scan.
- **v0.7.0** — Security hardening wave: safe scan/publish CI pipeline,
  verified isolated repair gate, disclosure policy.
- **v0.2.0** — Verified-fix engine, OSV vulnerability feeds, SARIF output,
  accountability ledger.

## License

[MIT](LICENSE) — free and open source, forever. See
[`docs/FREE_AND_OPEN_SOURCE_POLICY.md`](docs/FREE_AND_OPEN_SOURCE_POLICY.md)
for the full policy.
