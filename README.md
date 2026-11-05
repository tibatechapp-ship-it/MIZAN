# ⚖️ MIZAN Security

One lightweight, fast engine for code, secrets, dependencies and CI hardening.

MIZAN Security exists because strong teams run **5+ separate security tools**
while 97% of them plan to consolidate. Instead of repeating that sprawl,
MIZAN reverse-engineers the strongest systems — CodeQL's baseline discipline,
Semgrep's speed philosophy, Snyk's dependency reach — and rebuilds their best
ideas in a single zero-dependency, read-only engine. See
[docs/competitive-analysis.md](docs/competitive-analysis.md) for the full
reverse-engineering study.

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

# Q2: severity gate — exit 1 only on critical/high findings
mizan scan . --gate critical,high

# Q2: delta scanning — absorb known findings, gate on new ones only
mizan baseline . --save .mizan/baseline.json
mizan scan . --gate --baseline .mizan/baseline.json

# Q2: parallel full-scan (7 scanners, one JSON report)
mizan full-scan . --jobs 4

mizan ledger "Initial project setup" --actor human
```

## Project status

Version 0.8.1 — Severity gate (bare `--gate` fix), baseline delta scanning, parallel full-scan engine, verified-fix engine, OSV vulnerability feeds, SARIF output, Ledger accountability log, safe-repair gate.
