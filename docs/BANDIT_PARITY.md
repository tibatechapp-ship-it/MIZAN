# Bandit Parity Tracker — MIZAN

Status: waves 1+2+3 shipped · Last reviewed: 2026-11-11 · Wave 1 released in MIZAN v0.13.0 · Waves 2+3 in v0.15.0-dev

> Governing rule (protocol): every row below is a **documented decision**, not
> a claim. "adopted" rows are implemented in MIZAN's own engine and covered by
> positive+negative tests; anything not measured is labeled as such.

## Governing principle — "Bandit-compatible subset"

MIZAN does not depend on Bandit at runtime and does not copy its code. For
every Bandit check, exactly one documented decision is made:

| Decision | Criterion |
|---|---|
| **adopted** | high-signal CWE, verifiable semantics, low structural false-positive rate |
| **rejected** | structural noise (asserts, exception-style handlers, non-crypto randomness, partial paths) |
| **deferred** | plausible candidate — pending the FP gate (20-repo sample) or scope work |

The result: MIZAN covers what matters, without the noise, with full control —
and the gap to Bandit is documented publicly, not denied.

## Provenance & license

- Bandit is **Apache-2.0** (PyCQA); MIZAN is **MIT**.
- **Reimplementation, not copying.** Every adopted rule is implemented inside
  MIZAN's own AST engine (`src/mizan/analyzer.py`,
  `PythonSecurityVisitor`). No Bandit source code is included in this
  repository, and no Apache-2.0 attribution notice is therefore required.
- Attribution (ethical): rule semantics informed by the Bandit project —
  https://github.com/PyCQA/bandit (Apache-2.0).
- Bandit per-check Severity/Confidence values were **not** independently
  re-verified in this wave. The Severity column below is MIZAN's binding
  classification. Each future adoption session re-verifies severity from
  the per-check pages at https://bandit.readthedocs.io before recording the
  decision (step 1 of the update cycle).

## Wave 1 — status table (2026-11-08)

| Bandit | MIZAN rule | Severity | Status | Rationale | Updated |
|---|---|---|---|---|---|
| B501 (`requests` with `verify=False`) | `tls-verification-disabled` | high | **adopted** (new) | CWE-295 — the `verify=False` keyword itself is the signal, regardless of client library | 2026-11 |
| B323 (`ssl._create_unverified_context`) | `ssl-unverified-context` | high | **adopted** (new) | CWE-295 — process-wide certificate validation off | 2026-11 |
| B113 (`requests` without `timeout`) | `request-without-timeout` | low | **adopted** (new) | CWE-400 — severity parity with Bandit LOW; scope narrowed, see deviations | 2026-11 |
| B614 (`torch.load`) | `torch-unsafe-load` | high | **adopted** (new) | CWE-502 — same family as `unsafe-deserialization` (MIZAN HIGH by design); `weights_only=True` exempt | 2026-11 |
| B615 (HF `trust_remote_code=True`) | `hf-trust-remote-code` | high | **adopted** (new) | CWE-94 — hand-confirmed in field repos (10 sites in CogAgent) | 2026-11 |
| B701 (Jinja2 `autoescape=False`) | `jinja2-autoescape-false` | high | **adopted** (new) | CWE-79 — explicit opt-out is the dangerous configuration | 2026-11 |
| B703 (Django `mark_safe`) | `django-mark-safe` | medium | **adopted** (new) | CWE-79 — `mark_safe` is a policy decision, not always an injection | 2026-11 |
| B202 (`tarfile` extractall) | `tarfile-extractall` | high | **adopted** (new) | CWE-22 — PEP 706 `filter=` exemptions; zipfile carve-out, see deviations | 2026-11 |
| B108 (hardcoded `/tmp` path) | `hardcoded-tmp-path` | low | **adopted** (new) | CWE-377 — value positions only, see deviations | 2026-11 |
| B506 (`yaml.load`) | `yaml-unsafe-load` | medium | **adopted** (pre-existing, v0.9.0) | parity verified this wave: missing or non-safe `Loader` fires; SafeLoader variants pass | 2026-11 |
| B301 (`pickle`) | `unsafe-deserialization` | high | **adopted** (pre-existing, v0.9.0) | CWE-502 — MIZAN HIGH is intentional (differs from Bandit MEDIUM; documented decision) | 2026-11 |
| B602 (`shell=True`) | `shell-true` | high | **adopted** (pre-existing, v0.9.0) | CWE-78 | 2026-11 |
| B608 (SQL built by string ops) | `sql-injection` | high | **adopted** (pre-existing, v0.9.0) | CWE-89 — value-position interpolation only | 2026-11 |
| B324 (`hashlib` weak hashes) | `weak-crypto` | medium | **adopted** (pre-existing, v0.9.0) | CWE-327 — `usedforsecurity=False` exempt | 2026-11 |
| B101 (`assert` used) | — | — | **rejected** | assert is structural noise, not a vulnerability signal | 2026-11 |
| B110 (`try/except/pass`) | — | — | **rejected** | structural noise | 2026-11 |
| B112 (`try/except/continue`) | — | — | **rejected** | structural noise | 2026-11 |
| B311 (`random`) | — | — | **rejected** | non-crypto randomness is rarely a real exposure; high-noise | 2026-11 |
| B607 (partial path in processes) | — | — | **rejected** | partial path = noise | 2026-11 |

"new" = implemented in this wave · "pre-existing" = verified equivalent rule
that already existed in MIZAN (measured in `src/mizan/analyzer.py`, covered by
`tests/test_detection_suite.py`).

## Documented deviations from Bandit recall (precision over recall)

Each deviation below is asserted as a NEGATIVE test in
`tests/test_bandit_parity.py` so it cannot regress silently:

1. **B113 scope**: only literal `requests.*` receivers fire
   (`session.get(...)` and from-imported bare `get(...)` are out of scope).
   Rationale: receiver-type inference without taint analysis is the top FP
   source for this rule class.
2. **B614 mitigation**: explicit `weights_only=True` (PyTorch 2.x safe
   unpickling) exempts the call.
3. **B202 mitigation**: `filter="data"` / `filter="tar"` (PEP 706) exempts
   the call.
4. **B202 scope**: `zipfile` receivers are NOT flagged — direct
   (`zipfile.ZipFile(...)` call chains), variables assigned from
   `zipfile.*` constructors, AND with-bindings
   (`with zipfile.ZipFile(...) as zf:`); tar symlink traversal does not
   apply to the zip format.
5. **B108 positions**: `/tmp` and `/var/tmp` literals fire in call-argument
   and assignment-value positions only (segment-boundary safe: `/tmpfile`
   does not fire). Docstrings and bare expression strings do not fire.
6. **Kwarg-only signals**: `verify=False`, `autoescape=False`,
   `trust_remote_code=True` are detected as keyword arguments of calls;
   dict values like `{"verify": False}` are not.

## Wave 2 — status table (2026-11-10)

Per the update cycle: severity/confidence re-verified per-check from
bandit.readthedocs.io (and the plugin source for B104) before each
recorded decision.

| Bandit | MIZAN rule | Severity | Status | Rationale | Updated |
|---|---|---|---|---|---|
| B104 (`0.0.0.0` literal) | `hardcoded-bind-all-interfaces` | medium | **adopted** (new) | M/M verified from source — the exact literal `"0.0.0.0"` ONLY; the `"::"` IPv6 extension was measured and REJECTED by the wave-2 FP gate (4 FPs in one IPv6 validator: string-manipulation args, not bind hosts) | 2026-11 |
| B201 (`run(debug=True)`) | `flask-debug-enabled` | high | **adopted** (new) | H/H verified; receiver-agnostic attribute-call form per Bandit semantics | 2026-11 |
| B601 (`exec_command`) | `paramiko-exec-command` | medium | **adopted** (new) | M/M verified; `.exec_command(` attribute calls | 2026-11 |
| B401 (`import telnetlib`) | `telnetlib-import` | high | **adopted** (new) | Bandit blacklist parity (import level, high) | 2026-11 |
| B402 (`import ftplib`) | `ftplib-import` | high | **adopted** (new) | Bandit blacklist parity; `FTP_TLS` NOT exempted — import-level signal, documented | 2026-11 |
| B502/B503 (weak SSL/TLS versions) | `ssl-insecure-version` | high | **adopted** (new) | H/H + M/M verified; any qualified `ssl.PROTOCOL_SSLv2/SSLv3/TLSv1/TLSv1_1` reference | 2026-11 |
| B504 (`wrap_socket` without `ssl_version`) | — | — | **rejected** | Bandit LOW; modern `ssl` defaults are sane — flagging the default idiom is noise | 2026-11 |
| B615 expansion (HF downloads without pinned `revision`) | `hf-unpinned-download` | medium | **adopted** (new — gate-promoted) | M/H verified; the wave-1 deferred candidate adopted THROUGH the measured FP gate (see field measurement below) | 2026-11 |
| B102/B307 (`exec`/`eval`) | `dynamic-execution` | high | **adopted** (pre-existing) | bare-call boundary (v0.12.3 measured) | 2026-11 |
| B605 (`os.system`/`os.popen`) | `process-execution` | medium | **adopted** (pre-existing) | qualified-os boundary (v0.9.0 measured) | 2026-11 |
| B602 (`shell=True`) | `shell-true` | high | **adopted** (pre-existing) | subprocess-rooted launchers (golden-set wave) | 2026-11 |
| B105/B106/B107 (hardcoded passwords) | — | — | **rejected** | name-only literals are structural noise — MIZAN's `hardcoded-secret-candidate` was deliberately narrowed in the v0.14.0 measured campaign (`password = 'hardcoded'` no longer fires; prefix/entropy signals do) | 2026-11 |
| B603/B606 (subprocess without shell) | — | — | **rejected** | every subprocess call is not a finding; receiver-blind noise | 2026-11 |
| B604 (`shell=True` on any function) | — | — | **rejected** | `obj.run(shell=True)` on arbitrary objects is not a shell — MIZAN's `shell-true` is subprocess-rooted (documented deviation, negative-tested) | 2026-11 |
| B609 (linux wildcard) | — | — | **rejected** | same noise family as B607 (wave-1 rejection) | 2026-11 |
| B313–B320 (XML/XXE family) | — | — | **deferred** | fires on ALL XML parsing regardless of input trust — needs the v0.15 taint engine for precision; revisit when taint covers file paths | 2026-11 |
| B505 (weak key sizes) | `weak-crypto-key-size` | high/medium | **adopted** (wave 3, 2026-11-11) | the wave-2 deferred candidate adopted through the measured wave-3 pipeline — see the Wave 3 sections | 2026-11 |
| B508/B509 (SNMP) | — | — | **deferred** | niche protocol surface; revisit if field demand measured | 2026-11 |
| B610/B611 (Django ORM raw) | — | — | **deferred** | receiver-based `.extra(`/`.raw(` — needs receiver-type tracking; wave-3 candidate with taint | 2026-11 |
| B612 (logging listen) | — | — | **deferred** | niche; low field presence | 2026-11 |
| B613 (trojansource) | `bidi-override-chars` | high | **adopted** (wave 3, 2026-11-11) | the wave-2 deferred candidate adopted through the measured wave-3 pipeline — see the Wave 3 sections | 2026-11 |
| B702 (Mako) / B704 (Markup XSS) | — | — | **deferred** | template XSS needs taint for precision (B704 same family as adopted B703 `django-mark-safe`) | 2026-11 |

"new" = implemented in wave 2 · "pre-existing" = verified equivalent rule
already in MIZAN (measured in `src/mizan/analyzer.py`).

## Wave 2 — documented deviations (negative-tested)

1. **B104 exact literal**: `"0.0.0.0"` only — verified against the Bandit
   plugin source (`context.string_val == "0.0.0.0"`). The `"::"` extension
   was implemented, measured (4 FPs in `TheAlgorithms__Python` IPv6
   validator: `split("::", 1)`, `startswith("::")` args), and removed.
2. **B201/B601 call form**: attribute calls only — bare `run(debug=True)`
   / `exec_command(...)` Name-calls are quiet (documented deviation).
3. **B502/B503 qualified refs only**: `ssl.PROTOCOL_SSLv3` fires;
   from-imported bare `PROTOCOL_SSLv3` does not (B113 deviation family:
   import tracking out of scope); module aliasing unresolved.
4. **B402 no FTP_TLS carve-out**: `import ftplib` fires regardless —
   Bandit's blacklist signal is import-level; TLS-secured usage is a
   review outcome, not a static proof.
5. **B615 pinned semantics**: `revision=` present as a non-constant is
   treated as pinned (cannot statically prove mutable); the mutable refs
   `None`/`"main"` and a MISSING revision fire; bare Name-call form fires
   for function-style entry points (`load_dataset`, `hf_hub_download`,
   `snapshot_download` — the measured dominant idiom) while bare
   `from_pretrained(...)` stays quiet (method call in real usage).
6. **B615 measured carve-outs** (wave-2 FP gate): `sns`/`seaborn`
   receivers are out of scope (seaborn's `load_dataset` is a local CSV
   loader — 2 measured FPs); a constant offline-builder name as the first
   argument (`"json"`, `"csv"`, `"text"`, `"parquet"`) is quiet (2
   measured sites, both local `data_files=` calls).

## Wave 2 — field measurement (2026-11-10)

Same protocol as wave 1: read-only scans, every hit hand-checked against
its source line. Sample: 23 `fp_gate_repos` local copies + `tawteen` +
MIZAN self-scan = **25 targets / 3,997 files**.

- **Round 1 (71 raw hits)** — hand-check found 6 false positives and 2
  refined cases: 4× `"::"` in an IPv6 validator (B104 extension), 2×
  `sns.load_dataset` (B615), 2× offline `load_dataset("json",
  data_files=...)`. **Semantics were corrected BEFORE adoption** — each
  case became a negative test.
- **Round 2 (final gate run: 62 hits, 0 false positives)**: 58 real
  unpinned HF Hub downloads (56 `hiyouga__LlamaFactory` scripts incl.
  `AutoConfig.from_pretrained(...)`, `trust_remote_code=True` sites; 2
  `Alishahryar1__free-claude-code` model loads) + 3 real server bind-all
  defaults (`os.getenv("API_HOST", "0.0.0.0")`, `Field(default="0.0.0.0")`)
  + 1 self-scan hit (the rule's own `BIND_ALL_INTERFACES` literal in
  `analyzer.py` — classified context-dependent like wave 1's `/tmp`
  self-hits, severity medium, non-blocking).
- No `flask-debug`/`telnetlib`/`ftplib`/`ssl-insecure-version`/
  `paramiko-exec-command` hits appeared in the sample — their positive
  coverage is the acceptance suite, and their FP status on the sample is
  measured-zero by absence.

Gate artifacts: `fp_gate_wave2_v0150dev/gate_rows.json` (workspace).
Test suite at time of writing: **596 tests green** (same CI command).

## Wave 3 — status table (2026-11-11)

Per the update cycle: severity/confidence and exact semantics
re-verified from the per-check pages AND the plugin sources verbatim
(`bandit/plugins/weak_cryptographic_key.py`, `trojansource.py`) before
each recorded decision.

| Bandit | MIZAN rule | Severity | Status | Rationale | Updated |
|---|---|---|---|---|---|
| B505 (`weak_cryptographic_key`) | `weak-crypto-key-size` | high/medium (per band) | **adopted** (new) | CWE-326 — thresholds verified verbatim from the plugin config: RSA/DSA high<1024 / medium<2048, EC high<160 / medium<224 via the Bandit curve registry; constant-integer sizes only | 2026-11 |
| B613 (`trojansource`) | `bidi-override-chars` | high | **adopted** (new) | CWE-838 — Trojan Source bidi control chars (CVE-2021-42574); the `BIDI_CHARACTERS` tuple verified verbatim (U+202A-E, U+2066-2069, U+200F); text-level BY DESIGN (the attack lives in strings and comments, invisible to an AST) | 2026-11 |

"new" = implemented in wave 3. The wave-2 deferred rows for B505/B613
are flipped to "adopted (wave 3)" in the table above — the deferral
record is preserved in git history and in the row text, not erased.

## Wave 3 — documented deviations (negative-tested)

1. **B505 scope**: pycrypto/pycryptodome fires on
   `<Crypto\|Cryptodome>.PublicKey.<RSA\|DSA>.generate(...)` AND the
   bare from-import alias form `RSA.generate(...)` / `DSA.generate(...)`
   (the measured dominant idiom — B615 bare-form precedent). A FOREIGN
   root with a PublicKey segment (`mylib.PublicKey.RSA.generate`) stays
   quiet — caught by the acceptance suite before the field gate ran,
   corrected, re-measured.
2. **B505 arg discipline**: `bits=` / `key_size=` kwargs or exact
   positional positions (pycrypto: 0; cryptography RSA: 1 — the
   public exponent comes first; DSA: 0). Dynamic, string-valued,
   boolean and MISSING sizes stay quiet (Bandit: strings "can't be
   processed"; missing defaults to a safe 2048). MIZAN additionally
   excludes bool literals (Bandit would classify `True < 1024` — a
   nonsensical size; documented MIZAN deviation).
3. **B505 EC curves**: resolved through the Bandit curve registry
   (verbatim); qualified `ec.SECP192R1()` and bare from-import
   `SECT163K1()` call forms fire (the curve name itself is the
   unambiguous signal); unknown/dynamic curves default to 224 bits
   (Bandit behavior) and classify quiet. Only SECP192R1 (192) and
   SECT163K1/SECT163R2 (163) can fire — all MEDIUM by the verified
   thresholds.
4. **B505 receiver tail matching**: `rsa\|dsa\|ec.generate_private_key`
   fires for full dotted chains AND from-import alias receivers —
   receiver-agnostic like B201/B601 (MIZAN resolves no imports;
   documented deviation family).
5. **B613 language scope**: Bandit scans Python files only; MIZAN's
   per-line loop covers every scannable language (documented
   extension). Measured consequence below: the 6 non-Python gate hits
   exist only through this extension.
6. **B613 reporting**: Bandit returns after the FIRST issue per file;
   MIZAN reports EVERY affected line (more actionable; measured gate
   impact: 2 sites in one guard file instead of 1).
7. **B613 U+200F kept**: full Bandit parity (10 chars). The plausible
   Arabic-UI FP class (RLM inside legitimate RTL display strings) did
   NOT occur in the gate sample (`tawteen`: 0 hits); residual risk
   documented — revisit on field evidence, not speculation.

## Wave 3 — field measurement (2026-11-11)

Same protocol as wave 2: read-only scans, every hit hand-checked
against its source line — with raw-codepoint dumps (bidi characters
are invisible; the hand-check must see the bytes). Sample: the same
local repo copies + `tawteen` + MIZAN self-scan = **25 targets**.

- **8 hits, 8/8 hand-checked — 0 structural false positives, 8
  context-dependent**: 6× invisible-char-stripping regexes in
  `ai-job-search` TypeScript CLIs (`.agents/skills/*/cli/src/helpers.ts`
  — an `INVISIBLE_CHARS` sanitizer; the source comments describe the
  intent) + `BIDI`/`BIDI_TAMPER` constants in the same repo's
  `tools/posting_guard.py` (an explicit bidi-tamper guard). All eight
  are DEFENSIVE definitions of the same character set — the legitimate
  mirror of the rule; classified like the wave-1 self-scan hits
  (context-dependent, review lead, non-blocking). Bandit itself would
  flag the two Python sites (file-level, Python-only).
- `weak-crypto-key-size`: **0 hits** in the sample — measured-zero by
  absence (the wave-2 method for flask-debug/telnetlib/ftplib/
  ssl-insecure-version/paramiko-exec-command).
- `tawteen` (Arabic package): 0 hits — the RLM-in-Arabic-strings FP
  class did not occur in the sample.

Gate artifacts: `fp_gate_wave3_v0150dev/gate_rows.json` (workspace).
Test suite at time of writing: **603 tests green** (same CI command:
`python -m unittest discover -s tests`).

## Suppression policy — `# nosec` is not honored (fail-loud)

Measured 2026-11-08: no `nosec` handling exists anywhere under
`src/mizan/` (package-wide grep: 0 matches). A finding can therefore never
be silently buried by a comment next to the flagged line.

The supported alternative is **delta scanning** (baseline), which exists in
MIZAN since earlier versions (`src/mizan/gate.py`, CLI `baseline` command):

```
mizan baseline [path] --save .mizan/baseline.json --note "accepted set"
mizan full-scan [path] --baseline .mizan/baseline.json
```

Known findings are recorded with fingerprints; only NEW findings reach the
gate. Suppression is explicit, versioned, and reviewable — not a magic
comment beside the dangerous line.

## Continuous update cycle (every new Bandit release)

1. Review the Bandit CHANGELOG / release notes and the per-check docs
   (severity + confidence re-verification happens here).
2. For every new/changed check: measure the false-positive rate on a
   20-repository sample before any adoption decision.
3. Decision: `adopt` / `reject` / `defer` + reason — recorded in the table
   above with the decision date.
4. Add positive + negative sample tests (a rule without both is not
   adopted).
5. Update this file and `CHANGELOG.md`.

Batch cap: **at most 10 rules per release wave** (maintenance burden
control).

## Wave 1 — field measurement (2026-11-08)

Four local repositories, read-only scans, every hit hand-checked against
its source line (method: per-hit line inspection, static only):

| Target | Files scanned | Wave-1 hits | Hand-check result |
|---|---|---|---|
| MIZAN (self-scan) | 32 | 2 | 0 false positives — both hits are the rule's own implementation literals (`analyzer.py:490-491`); classified context-dependent, severity low, non-blocking |
| zai-org/CogAgent (local copy) | 7 | 14 | 0 false positives — 2× `verify=False` (`app/openai_demo.py:298`, `app/vllm_openai_server.py:247`), 2× request-without-timeout (same lines), 10× `trust_remote_code=True` (`openai_demo.py:390,394`; `vllm_openai_server.py:299`; `finetune/finetune.py:409,413,422`; `inference/cli_demo.py:94,95`; `inference/web_demo.py:197,198`) |
| Crosstalk-Solutions/project-nomad (local copy) | 455 | 0 | — (TypeScript-heavy; wave-1 rules are Python AST rules) |
| tawteen (local package) | 10 | 0 | — |

Totals: **16 hits, 16/16 hand-checked, 0 false positives** (rule-level
matches structurally valid; exploitability NOT dynamically tested —
read-only static tool).

Pre-release review pass (same day): two internal inconsistencies found by
self-review and corrected with new negative tests — with-bindings
(`with zipfile.ZipFile(...) as zf:`) added to the B202 zipfile carve-out,
and B108 extended to list/tuple ARGUMENT elements (previously only
assignment collections) so call- and assignment-position semantics match.
Field totals re-measured after the fixes: unchanged (16 hits, 0 FP).

Test suite at time of writing: **420 tests green** (414 pre-existing + 6 new
in `tests/test_bandit_parity.py`), same CI command
(`python -m unittest discover -s tests`).

## Applying the same pattern to other upstream tools

This tracker is the template for every tool MIZAN draws detection semantics
from: `docs/<TOOL>_PARITY.md` with the same adopt/reject/defer contract, a
precision filter, documented deviations, and a dated review session per
upstream release. Dependence on others becomes documented benefit — without
losing sovereignty over MIZAN's own rule set.

## Limitations

- Wave-1 rules run on the Python AST path only; non-Python sources are not
  covered by these nine rules (Bandit is Python-only as well).
- Repository-level exclusions (`tests/`, `vendor/`, `i18n/`, minified
  bundles, …) apply by design — findings inside excluded trees are out of
  scope, not "proven absent".
- Detection is per-file, per-syntax-tree: no cross-module import
  resolution, no taint analysis, no dynamic testing. A structural match is
  a lead for review, not proof of exploitability.
- Bandit per-check Severity/Confidence values were **re-verified in wave
  2** (2026-11-10) from the per-check pages / plugin source before each
  decision; the wave-1 severities were not re-verified that wave (see
  Provenance & license).
- **Measured drift alert (2026-11-08, see `COMPARISON.md`): Bandit 1.9.4
  expanded B615** — it now fires on HF downloads without a pinned
  `revision=` (`snapshot_download`/`from_pretrained`/`load_dataset`), which
  is a different signal from the `trust_remote_code=True` check MIZAN
  adopted. 9 such sites were measured in the field run. Candidate rule
  `hf-unpinned-download` was deferred pending the repo-sample FP gate —
  **resolved in wave 2 (2026-11-10): adopted through the measured gate**,
  see the Wave 2 table and field measurement. This is exactly why every
  parity session re-verifies per-check semantics.
- This document records what was measured and decided; it does not certify
  MIZAN as equivalent to Bandit in coverage.
