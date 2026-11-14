# MIZAN Architecture — measured at 0.15.0-dev (2026-11-10)

This file describes what IS implemented and where it lives. Plans, gaps and
deferrals live in `docs/ROADMAP.md` (single source for future work); CLI
scope lives in `docs/CLI.md`. Everything below is checkable against the named
module. The v0.1-era draft this file replaces listed five components; the
engine now ships 30 modules under `src/mizan/` (measured by directory
listing).

## Layout

- `src/mizan/` — engine + CLI. Minimal measured runtime dependencies
  (`PyYAML>=6.0`, `tomli` only on Python < 3.11 — see `pyproject.toml`); no
  analyzer/network frameworks. Tree-sitter-style additions still require an
  explicit recorded decision, see ROADMAP.
- `action/` — composite GitHub Action (dependency-vulnerability scan +
  SARIF upload + optional safe fix flow).
- `tests/` — full suite, including the golden rule-accuracy suite in
  `tests/rules/`. The suite size published in README is enforced against
  runtime reality by `tests/test_docs_consistency.py`.
- `docs/` + `website/` — documentation and the project site.

## Components (measured roles)

| Group | Modules | Measured role |
|---|---|---|
| CLI & gate | `cli.py`, `gate.py` | 24 subcommands (measured via `--help`, see `docs/CLI.md`); honest exit contract — 0 clean, 1 blocking findings, 2 incomplete |
| Discovery | `inspector.py`, `detector.py` | repository structure discovery and technology detection |
| Static analysis | `analyzer.py`, `scan.py`, `scanner.py`, `code_quality.py`, `semgrep_scanner.py` | read-only source scanning; the Python path is AST-based, other languages use line-level patterns (measured gap, tracked as ROADMAP P1 — multi-language accuracy gate) |
| Dataflow (PoC) | `taint.py`, `reachability.py` | single-file Python taint with documented PoC limits in the module docstring (no function-boundary isolation, no cross-module flow, no aliasing); shallow informational reachability |
| Supply chain | `dependency_scanner.py`, `vulnerabilities.py` | offline manifest inspection per ecosystem; OSV.dev client — batched queries, local cache, retries, failure isolation (`osv_errors` surfaced, never faked clean) |
| Repos & CI | `git_scanner.py`, `ci_scanner.py`, `risk_scanner.py`, `doc_intel.py` | git hygiene, workflow hardening gaps, change risk, docs-vs-reality checks |
| Governance | `ledger.py`, `approval.py`, `repair.py`, `fix.py`, `ai_fixer.py`, `custom_rules.py`, `plugins.py`, `secret_remover.py` | engineering ledger, safe fix/PR flows with test validation, declarative `.mizan/rules.json`, plugin registry |
| Reporting | `sarif.py`, `portfolio.py`, `email_reporter.py` | SARIF 2.1.0 (tool version derives from `_version.py`), self-contained multi-repo HTML, mail notification helper |
| Remote | `remote_scan.py` | GitHub tarball scan with strict safe-extraction filters; the extracted tree is deleted immediately after the scan (`docs/REMOTE_SCAN.md`) |

## Execution flow (measured)

CLI command → one or more read-only scanners → findings → severity gate
(exit 0 / 1 / 2, enforced in `cli.py` — the return-2 paths for
could-not-verify scans are documented in-code) → renderers: JSON, SARIF,
self-contained HTML. `full-scan` runs the eight scanners of the README table
in parallel; wall time is the slowest pass, not the sum.

## Safety boundary (held since v0.1, still enforced)

The engine reads inspected repositories; it never imports, executes,
installs, or runs their code. The only network-facing paths are `vuln-scan`
(OSV.dev) and `scan-remote` (GitHub tarball API with a user-supplied token) —
measured by import audit: `urllib` appears only in `vulnerabilities.py` and
`remote_scan.py`.

## Deliberately not here (see ROADMAP)

- Tree-sitter / multi-language AST — first external dependency; requires an
  explicit decision gate, not a silent addition.
- Cross-file taint — P3 research item with a declared time budget.
- Central GRC platform — explicitly out of scope; integration is via SARIF
  and JSON.
