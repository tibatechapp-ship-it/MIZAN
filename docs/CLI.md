# CLI surface — measured, not claimed

Snapshot of `mizan --help` at 0.15.0-dev (2026-11-10), 19 subcommands.
Purpose strings are verbatim from each command's own `--help` output (or from
the README table where a command exposes no one-liner). The Network/Token
columns come from an import audit of the implementing modules: `urllib`
appears only in `vulnerabilities.py` (OSV.dev client) and `remote_scan.py`
(GitHub tarball API). The writes column reflects the read-only scanning
contract; write-capable flows are explicit, user-driven commands.

| Command | Purpose (verbatim from --help / README) | Network | Token | Writes |
|---|---|---|---|---|
| `inspect` | repository structure discovery (README table) | no | no | no |
| `analyze` | read-only static source analysis, optional JSON output (README) | no | no | no |
| `detect` | Detect project technologies | no | no | no |
| `plugins` | Manage built-in scanner plugins (`list`, `info`) | no | no | plugin config |
| `scan` | Run unified read-only repository scanning | no | no | no |
| `scan-remote` | Scan a GitHub repository via the Tarball API with strict safe-extraction filters (see docs/REMOTE_SCAN.md); the extracted tree is deleted immediately after the scan | yes | yes — user-supplied | no (temp tree deleted) |
| `report` | Local disclosure-report toolkit (docs/REPORT_SECURITY.md): triage-gated draft generation, local view, 90-day overdue tracking, SARIF export. No network; no publish command. | no | no | report files |
| `git-scan` | Inspect Git repository without modifying it | no | no | no |
| `ci-scan` | Inspect CI/CD configuration files | no | no | no |
| `full-scan` | Run all MIZAN repository scanners | via vuln-scan pass (OSV.dev) | no | no |
| `dependency-scan` | Inspect dependency manifests offline | no | no | no |
| `risk-scan` | Assess Git change risk without modifying files | no | no | no |
| `doc-scan` | Documentation Intelligence: verify docs match reality (links, stale references, coverage, endpoints, README) | no | no | no |
| `ledger` | engineering ledger record — `mizan ledger --actor {human,chatgpt,joint} "message"` | no | no | ledger file |
| `vuln-scan` | Scan dependencies for known vulnerabilities via OSV.dev | yes — OSV.dev, batched + cached | no | cache dir |
| `approve` | Safely auto-approve and optionally merge eligible PRs | no (local git) | no | git state (explicit) |
| `fix` | Apply safe dependency upgrades with test-based validation | no — runs your tests locally | no | yes (explicit) |
| `baseline` | Save current findings as a gate baseline (delta scanning) | no | no | `.mizan/baseline.json` |
| `portfolio` | Aggregate full-scan results for MULTIPLE repositories into one self-contained HTML report (display layer) | no | no | HTML output |

## Exit contract (enforced, documented in README §The gate)

- **0** — clean, verified.
- **1** — blocking findings under the configured `--gate`.
- **2** — incomplete: a scan that could not load its policies or lost a
  scanner never certifies a clean pass (the return-2 paths are enforced in
  `cli.py` and commented in-code).

MIZAN does not honor `# nosec`; accepted findings go through versioned
baselines (`mizan baseline`), per README §Suppression policy.
