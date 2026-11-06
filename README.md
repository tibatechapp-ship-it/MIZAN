# ⚖️ MIZAN Security

One lightweight, fast engine for code, secrets, dependencies and CI hardening.

MIZAN Security is an open-source security engine that inspects repositories
read-only, explains every finding in plain language, and gives your team full
control over what should fail a build and what should stay quiet.

## What it does for you

- **Start in one command** — `mizan full-scan .` covers code analysis,
  secrets patterns, dependency manifests, CI configuration and change risk
  in a single report.
- **Stay focused** — the severity gate fails builds on critical/high
  findings only; everything else is reported, not shouted.
- **Move fast without noise** — baseline delta scanning absorbs known
  findings and alerts you on what is new.
- **Fast by design** — scanners run in parallel by default; wall time is
  the slowest pass, not the sum.
- **No surprises** — read-only by default: MIZAN never executes the code
  it inspects, and any repair goes through a verified, isolated gate.
- **Fits your pipeline** — SARIF 2.1.0 for GitHub code scanning, JSON and
  HTML reports, CI-friendly exit codes, automatic PR comments.
- **Works offline** — dependency vulnerability checks run against OSV.dev
  with a local cache; no cloud account required.
- **Your own policies** — declarative custom rules in `.mizan/rules.json`
  (regex per line, no new query language): invalid rules are rejected
  loudly and an unloadable policies file never certifies a clean pass.
- **Honest dependency precision** — correct OSV ecosystem per manifest
  (npm / crates.io / Go / Packagist, not just PyPI), dev-dependency
  findings capped below the default gate with the original severity
  preserved, and shallow import-based reachability metadata that
  informs triage without ever downgrading a severity.
- **Accountable** — a ledger log records every engineering decision.

## Capabilities

- Repository structure inspection & static source analysis (AST-based).
- **Documentation Intelligence** — `mizan doc-scan` verifies the docs that
  explain the code still match reality: broken links and anchors, stale
  references, undocumented API endpoints, docstring coverage, README
  command validity, and git-aware change-impact review — read-only.
- Unified severity gate — `mizan scan --gate critical,high` fails the build
  on blocking findings only.
- Baseline (delta) scanning — gate ONLY on *new* findings versus
  `.mizan/baseline.json`; kill alert fatigue without hiding regressions.
- Parallel full-scan — 8 read-only scanners run concurrently (`--jobs N`),
  wall time becomes the slowest pass instead of the sum.
- OSV.dev dependency vulnerability feeds with batched queries, caching and
  offline mode; SARIF 2.1.0 output for GitHub code scanning.
- Verifiable safe-repair gate (dry-run by default, isolated worktree apply),
  engineering ledger, PR approval policy engine.

## Safety

MIZAN performs read-only source inspection.
It does not execute inspected repository code.

## Installation

```bash
python -m pip install -e .
```

## Usage

```bash
mizan inspect .
mizan analyze . --output reports/analysis.json

# Severity gate — exit 1 only on critical/high findings
mizan scan . --gate critical,high

# Your own policies — .mizan/rules.json (v1 schema):
# {
#   "version": 1,
#   "rules": [
#     {"id": "custom-no-eval", "severity": "high",
#      "languages": ["python"], "pattern": "\\beval\\s*\\(",
#      "message": "eval() is forbidden by policy"}
#   ]
# }
# Custom findings flow through the same gate/baseline pipeline; a broken
# rules file makes the gate return exit 2 (incomplete) — a scan that
# could not load its policies never certifies a clean pass.

# Delta scanning — absorb known findings, gate on new ones only
mizan baseline . --save .mizan/baseline.json
mizan scan . --gate --baseline .mizan/baseline.json

# Parallel full-scan (8 scanners, one JSON report)
mizan full-scan . --jobs 4

# Documentation Intelligence — do the docs still match reality?
mizan doc-scan . --format text
mizan doc-scan . --format json --output reports/docs.json

# Gate the WHOLE scan (code + CI + git + dependencies) with one threshold
mizan full-scan . --gate critical,high --baseline .mizan/baseline.json

# Gate exit codes — the difference between "clean" and "could not verify"
#   0 = complete scan, no blocking findings
#   1 = complete scan, blocking findings present
#   2 = INCOMPLETE scan (a scanner failed, or OSV verification was
#       impossible / offline with no cache) — never a silent clean pass
mizan --version
mizan ledger "Initial project setup" --actor human
```

## Evolution

- **v0.12.0** — Portfolio: one local, self-contained HTML report across
  many repositories (`mizan portfolio <dirs…>`) with gate-fingerprint
  deduplication — a display layer, explicitly not a GRC platform. Plus
  OSV cache-key hardening (`usedforsecurity=False`) found by MIZAN's
  own self-scan.
- **v0.11.0** — Dependency precision & custom policies: correct OSV
  ecosystems per manifest, honest dev-dependency severity cap,
  shallow reachability metadata, and `.mizan/rules.json` declarative
  custom rules with the fail-loud contract (see `docs/ROADMAP.md` for
  the full competitive-gap plan).
- **v0.10.0** — Documentation Intelligence: MIZAN audits the docs that
  explain the code, not just the code itself.
- **v0.9.0** — Precision wave: ‑93.6% false positives on 20 real
  repositories, 5 new detection rules with positive/negative tests.
- **v0.8.x** — Severity gate, baseline delta scanning, parallel full-scan,
  smoother gate UX.
- **v0.7.0** — Security hardening wave: safe scan/publish CI pipeline,
  verified isolated repair gate, disclosure policy.
- **v0.2.0** — Verified-fix engine, OSV vulnerability feeds, SARIF output,
  accountability ledger.

## Project status

Version 0.12.0 — Portfolio aggregation: `mizan portfolio <dirs…>` folds full-scan results for multiple repositories into ONE self-contained HTML report (inline CSS, zero scripts, zero external requests) with gate-fingerprint deduplication so the report's numbers are exactly the gate's numbers — a local display layer for governance visibility, explicitly not a GRC platform and not a compliance certification (see `docs/ROADMAP.md`). Field-measured on five real open-source projects (requests, axios, cobra, fd, chalk): 0.5–1.6s per full scan, 20/20 sampled findings verified true positives, zero security false positives in the sample. Plus a self-scan-driven fix: the OSV cache key documents its non-security intent with `usedforsecurity=False`. On top of v0.11.0 dependency precision (correct OSV ecosystem per manifest — npm, crates.io, Go, Packagist — where previously every manifest was queried against PyPI, so real npm/Rust/Go vulnerabilities read as "clean"), the honest dev-dependency severity cap, shallow import-based reachability metadata that never changes a severity, and `.mizan/rules.json` declarative custom rules with the fail-loud contract; and v0.10.0 Documentation Intelligence (github-slugger-accurate anchors, stale references, docstring coverage — the first build's 75 "broken links" on a real repository were proven false positives and corrected to 0) and the v0.9.0 precision wave (‑93.6% false positives on 20 real repositories, 5 new detection rules).
