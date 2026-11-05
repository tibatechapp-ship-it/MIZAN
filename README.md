# MIZAN

AI-powered Software Analysis and Verification Engine.

MIZAN is an open-source project designed to inspect software repositories,
identify potential code risks, organize findings, and support verifiable
software quality workflows.

## Initial capabilities

- Repository structure inspection.
- Static source analysis.
- Basic risk pattern detection.
- JSON report generation.
- Engineering collaboration ledger.
- Automated tests.

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
mizan analyze .
mizan analyze . --output reports/analysis.json
mizan ledger "Initial project setup" --actor human
```

## Project status

Version 0.7.0 — Verified-fix engine, OSV vulnerability feeds, SARIF output, Ledger accountability log, safe-repair gate.
