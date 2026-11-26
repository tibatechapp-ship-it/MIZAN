# CLI surface — measured, not claimed

Snapshot of `mizan --help` at 0.16.0 (2026-11-14), 24 subcommands.
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
| `approve` | Report PR eligibility measured from a scan report — report-only: MIZAN never approves or merges PRs (F-01); findings are counted from a mandatory report file, never from a flag (F-02) | no (local git, read-only gh) | no | no |
| `fix` | Apply safe dependency upgrades with test-based validation | no — runs your tests locally | no | yes (explicit) |
| `baseline` | Save current findings as a gate baseline (delta scanning) | no | no | `.mizan/baseline.json` |
| `import-sarif` | Import an external SARIF 2.1.0 report (Semgrep, Gitleaks, Trivy, Bandit, ...) into MIZAN's normalized finding schema — read-only, provenance preserved, failures are loud | no | no | no (output file only if `--output`) |
| `merge-findings` | Merge several SARIF reports into grouped findings — link, never erase: every occurrence keeps its tool and evidence | no | no | no (output file only if `--output`) |
| `triage` | Apply documented review decisions to imported findings — decisions referencing unknown fingerprints are rejected | no | no | no (output file only if `--output`) |
| `repair-request` | Build a structured `repair-request.v1` handoff for a coding agent — evidence first, no guessing, human review always required | no | no | no (output file only if `--output`) |
| `verify-repair` | Verify one repair request's patch inside an isolated git worktree — apply, test with no secrets and no network by default, measure the diff and the result; transfer with explicit approval (`--approve`) or delete — the user's tree is never written | no (local git + test subprocess) | no | git worktree under the system temp dir (disposed unless `--keep`), review branch only with explicit approval |
| `portfolio` | Aggregate full-scan results for MULTIPLE repositories into one self-contained HTML report (display layer) | no | no | HTML output |

### `repair-request` — structured handoff to a coding agent (wave 3)

```bash
mizan analyze src/ --output findings.json
mizan repair-request findings.json --output requests.json
```

Builds a `repair-request.v1` batch: for every finding, `finding_id`
(the stable fingerprint), the evidence (tool, rule, file, line, message,
`tool_level` verbatim), a review suggestion per rule family,
constraints, verification steps, `confidence`, and
`human_review_required=true` — always. MIZAN never writes into the
user's tree in this wave: the agent works in an isolated branch or
worktree, presents the diff plus test results, and a human approves the
merge. `auto_appliable` is always `false`.

Insufficient evidence is refused with exit **2** naming exactly what
must be measured ("don't guess; explain what is needed to verify") — a
finding without a usable location, rule identity, or evidence message
never becomes a request. Inputs: a `mizan.finding.v1` list, an
`mizan.import.v1` summary, an `mizan.merged.v1` summary, or MIZAN's raw
analyzer findings (1:1 field adapter, documented). The published JSON
Schema lives at `docs/schemas/repair-request.v1.json`; a consistency
test keeps schema and validator from drifting.

### `merge-findings` and `triage` — link, never erase (wave 1)

```bash
mizan merge-findings semgrep.sarif gitleaks.sarif trivy.sarif --output merged.json
mizan triage merged.json --decisions review.json --output triaged.json
```

`merge-findings` imports every report (same contract as `import-sarif`)
and groups the findings by their stable fingerprint into
`mizan.merged.v1`. Groups keep every occurrence verbatim with its own
tool, rule, and evidence — a finding is never dropped because another
tool disagreed, and removing one report from the merge can never erase
another tool's findings.

`triage` applies documented review decisions from a JSON object
(`{fingerprint: accepted|false_positive}`). Decisions referencing
fingerprints absent from the findings fail loudly with exit **2** —
suppression is only possible against a documented, imported finding
(MIZAN does not honor blind `# nosec`-style suppression). Every applied
decision stamps `triage_source: review-file` for auditability.

`mizan.external_gate.v1` (module `mizan.integrations.merge`) gates the
merged findings on the verbatim severity carried from the source tool:
`unknown` never blocks, triaged findings never block, and blocking is an
exact match — no case-folding, no silent severity-ladder normalization.

### `import-sarif` — unified external-report contract (wave 0)

```bash
mizan import-sarif semgrep.sarif                # normalized findings to stdout
mizan import-sarif trivy.sarif --output out.json
```

Reads a SARIF 2.1.0 report produced by any external scanner and emits
`mizan.import.v1`: every finding keeps its originating tool
(`tool.driver.name`), rule id, location, original SARIF `tool_level`, and a
stable fingerprint (SARIF `partialFingerprints` win; otherwise a
deterministic SHA-256). SARIF levels are deliberately NOT mapped to MIZAN
severities — that judgment belongs to documented triage. No tool is
executed and no dependency is required; MIZAN only parses the report.

No-silent-clean: a missing, unreadable, or structurally invalid report
fails with the path in the message and exits **2** (incomplete) — a failed
import is never certified as an empty result set. Strictness is
intentional: a malformed result entry fails the import instead of being
silently skipped.

### `verify-repair` — isolated repair verification (wave 4)

```bash
mizan verify-repair request.json \
  --patch agent-fix.diff --repo . \
  [--tests "python -m unittest discover -q"] \
  [--output verification.json]
```

Takes ONE `repair-request.v1` (or a one-request batch) plus the coding
agent's unified diff, and verifies the patch in an isolated `git
worktree` (detached HEAD) — the user's tree is never written. The test
run gets an environment with NO secrets (every variable whose name
carries a secret marker — `TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`,
`AWS_`, `GIT_`, ... — is removed) and NO network by default (proxy
variables stripped; `--allow-network` keeps them). The report
(`mizan.repair-verification.v1`, schema at
`docs/schemas/repair-verification.v1.json`) records: the changed files,
whether the original finding's fingerprint still fires, findings the
patch introduced, the tests that ran and their output tail, the
scrubbed variables by name, and the declared isolation limits — what
is enforced and what only declared, never oversold.

**Isolation is NOT a sandbox (E-05, 2026-11-17 review).** `verify-repair`
gives you a temporary git worktree plus an environment scrub — that is
its whole isolation surface, and the module says so itself. The code
under test still executes on your machine as your user: with
`--allow-network` it can open arbitrary network connections, and even
without it it can reach local files, sockets, and resources available
to the runner user. Never present `verify-repair` as "sandboxed" or
"fully isolated". For hard isolation, run the whole command inside a
container with explicit network, CPU, memory, and time limits — for
example:

```bash
docker run --rm --network none --cpus 2 --memory 1g \
  --pids-limit 128 --read-only --tmpfs /tmp \
  -v "$PWD:/src:rw" -w /src \
  mizan-image mizan verify-repair request.json
```

Exit contract: **0** = the patch verified (finding gone, no new
findings, tests passed); **1** = verification measured a failure —
stated in the report, never silent (a timed-out or empty test run
never counts as a pass); **2** = refusal naming the path and the
reason (invalid request, patch that does not apply,
`--transfer-branch` without `--approve`, existing branch). An
unverified patch is never transferred; without `--keep` the worktree
is disposed after the report — transfer or delete, nothing else. A
transferred branch carries `human_review_required=true` in its commit
message; MIZAN never merges it.

### `approve` — eligibility report, nothing else (F-01/F-02, 2026-11-26 live audit)

```bash
mizan vuln-scan . --format sarif -o report.sarif
mizan approve --pr 42 --report report.sarif
```

The 2026-11-26 live audit (F-01, high) demonstrated that the old
`--approve` / `--merge` executive path could emit `gh` review/merge
calls — contradicting the project's own "final merge is human" policy.
The capability is **deleted**: `approve` is now a READ-ONLY eligibility
report (gh `view`/`checks` only), and the human decides.

Findings are **measured, never trusted** (F-02): the old `--findings N`
flag — whose default of 0 let any caller claim a clean scan — is gone.
The report file is mandatory:

| Report input | Behaviour |
|---|---|
| SARIF (`runs[].results[]`) | measured count = sum of `results[]` lengths |
| MIZAN JSON (`findings[]`) | measured count = `len(findings[])`; a stale declared `findings_count` is reported as a mismatch |
| missing / unreadable / malformed / unrecognized | **exit 2 refusal** — never counted as "0 findings" (RW-205 doctrine) |

Exit contract: **0** = ELIGIBLE (report-only — no action taken, the
measured basis is printed); **1** = BLOCKED (reason stated); **2** =
refusal (report cannot be measured). Every finding in the measured
report blocks eligibility (conservative by design).

## Exit contract (enforced, documented in README §The gate)

- **0** — clean, verified.
- **1** — blocking findings under the configured `--gate`.
- **2** — incomplete: a scan that could not load its policies or lost a
  scanner never certifies a clean pass (the return-2 paths are enforced in
  `cli.py` and commented in-code).

MIZAN does not honor `# nosec`; accepted findings go through versioned
baselines (`mizan baseline`), per README §Suppression policy.
