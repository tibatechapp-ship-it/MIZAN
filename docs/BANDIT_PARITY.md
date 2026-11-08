# Bandit Parity Tracker — MIZAN

Status: wave 1 shipped · Last reviewed: 2026-11-08 · Released in: MIZAN v0.13.0

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
- Bandit per-check Severity/Confidence values were not re-verified this
  wave (see Provenance & license).
- **Measured drift alert (2026-11-08, see `COMPARISON.md`): Bandit 1.9.4
  expanded B615** — it now fires on HF downloads without a pinned
  `revision=` (`snapshot_download`/`from_pretrained`/`load_dataset`), which
  is a different signal from the `trust_remote_code=True` check MIZAN
  adopted. 9 such sites were measured in the field run. Candidate rule
  `hf-unpinned-download` is deferred pending the 20-repo FP gate; this is
  exactly why every parity session re-verifies per-check semantics.
- This document records what was measured and decided; it does not certify
  MIZAN as equivalent to Bandit in coverage.
