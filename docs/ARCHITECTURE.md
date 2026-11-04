# MIZAN Architecture — v0.1

## Components

- CLI: user-facing command interface.
- Inspector: repository structure discovery.
- Analyzer: read-only static source analysis.
- Ledger: engineering collaboration records.
- Tests: automated verification.

## Initial execution flow

CLI -> Inspector or Analyzer -> Structured Result -> JSON output

## Safety boundary

The initial analyzer reads source files only.
It does not import, execute, install, or run code from inspected repositories.

## Planned evolution

1. Rule engine and severity model.
2. Language-specific analyzers.
3. Test discovery and coverage integration.
4. Verification workflows.
5. AI-assisted analysis with human approval.
