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
- **Accountable** — a ledger log records every engineering decision.

## Capabilities

- Repository structure inspection & static source analysis (AST-based).
- Unified severity gate — `mizan scan --gate critical,high` fails the build
  on blocking findings only.
- Baseline (delta) scanning — gate ONLY on *new* findings versus
  `.mizan/baseline.json`; kill alert fatigue without hiding regressions.
- Parallel full-scan — 7 read-only scanners run concurrently (`--jobs N`),
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

# Delta scanning — absorb known findings, gate on new ones only
mizan baseline . --save .mizan/baseline.json
mizan scan . --gate --baseline .mizan/baseline.json

# Parallel full-scan (7 scanners, one JSON report)
mizan full-scan . --jobs 4

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

- **v0.8.x** — Severity gate, baseline delta scanning, parallel full-scan,
  smoother gate UX.
- **v0.7.0** — Security hardening wave: safe scan/publish CI pipeline,
  verified isolated repair gate, disclosure policy.
- **v0.2.0** — Verified-fix engine, OSV vulnerability feeds, SARIF output,
  accountability ledger.

## Project status

Version 0.9.0 — Precision wave: measured on 20 real repositories (456 findings, ~85% false positives) and rebuilt to 29 (‑93.6%) — test fixtures, vendored bundles and i18n trees are no longer your attack surface, dictionary-value secrets and RegExp `.exec()` no longer fire, and `os.system` no longer confuses itself with `Message.system()` — while FIVE missing detection rules land (unsafe-deserialization, yaml-unsafe-load, sql-injection with value-position precision, path-traversal, weak-crypto), each with positive and negative acceptance tests; the new rules immediately caught real issues the old engine was blind to (a pickle.load deserialization sink, dynamic SQL SET-clause builders) — on top of the v0.8.3 hardening: symlink-proof repair, the `incomplete` (exit 2) gate, OSV error honesty, and the 0/1/2 Action exit-code contract.
