# MIZAN vs Bandit — honest comparison (measured, not marketed)

Status: measured 2026-11-08 · MIZAN 0.13.0 · Bandit 1.9.4 · 10 local repository snapshots

> Protocol: every number in this document was produced by actually running both
> scanners on the same local snapshots and reading the results back from their
> JSON outputs. Nothing here is projected, estimated, or copied from marketing
> pages. Where a claim could not be measured, it says so.

## Why this document exists

MIZAN is a good scanner, but as of v0.13.0 it has **not yet proven it is
necessary**: on the Python code-security surface that Bandit covers, this
measurement found **no high-signal site that Bandit missed**. The one
MIZAN-only Python site in this run is a `trust_remote_code=True` keyword
passed through a `dict(...)` kwargs-construction (see below). MIZAN's real
measured differences today are: severity policy, non-Python surfaces, and the
categories Bandit does not scan at all (docs, CI, dependencies). The gaps are
listed, not hidden, and each one is fed into the parity cycle in
[`BANDIT_PARITY.md`](BANDIT_PARITY.md).

## Method (reproducible)

Local read-only snapshots; same trees for both scanners. MIZAN 0.13.0
(installed from source, `mizan --version` verified), Bandit 1.9.4
(`python3 -m bandit --version`).

```bash
# MIZAN — security category, JSON findings
mizan scan <repo> --category security --format json --output mizan_<repo>.json

# Bandit — default checks, exclusions aligned to MIZAN's documented
# repo-level exclusions (tests/, vendor/, i18n/)
python3 -m bandit -r <repo> -x tests,vendor,i18n -f json -o bandit_<repo>.json
```

Site-level matching: same relative file, line window ±3, mapped rule families
(e.g. `tls-verification-disabled`↔B501, `unsafe-deserialization`↔B301).
Matching was then **hand-checked** at the contested sites (source lines read,
not assumed) — the hand-check changed three first-pass classifications; the
corrected ones are what you see here.

Snapshots: MIZAN self-repo, tawteen, zai-org/CogAgent,
Crosstalk-Solutions/project-nomad, DayuanJiang/next-ai-draw-io, hypit-ai/hypit,
iamkun/dayjs, mobxjs/mobx, tashfeenahmed/freellmapi, QwenLM/Qwen3.
Four are TypeScript/JavaScript projects (Bandit is Python-only by design).

## Per-repo totals (as measured)

| Repository | .py files | MIZAN findings (H/M/L) | Bandit findings (H/M/L) |
|---|---:|---|---:|
| MIZAN (self-scan) | 30 | 2 (0/0/2) | 30 (0/5/25) |
| tawteen | 10 | 0 | 6 (0/1/5) |
| zai-org/CogAgent | 7 | 15 (12/1/2) | 17 (3/14/0) |
| project-nomad | 6 | 1 (1/0/0) | 7 (2/3/2) |
| next-ai-draw-io | 0 | 0 | 0 |
| hypit | 15 | 63 (63/0/0) | 7 (0/3/4) |
| dayjs | 0 | 0 | 0 |
| mobx | 0 | 3 (3/0/0) | 0 |
| freellmapi | 0 | 31 (31/0/0) | 0 |
| QwenLM/Qwen3 | 10 | 7 (5/2/0) | 22 (0/11/11) |
| **Total** | **78** | **122** | **89** |

MIZAN's 122 findings split: **25 on .py files**, **97 on .ts/.tsx/.js files**
(Bandit cannot parse these — see "MIZAN-only surface" below).

## Bandit findings, classified (all 89, no cherry-picking)

| Disposition | Count | Meaning |
|---|---:|---|
| covered — same site | **26** | An equivalent MIZAN rule flagged the same code (±3 lines) |
| covered — rule elsewhere | **7** | The equivalent rule fired in the repo, different site (B615 unpinned variant, see below) |
| family scope deviation | **14** | A MIZAN rule for the family exists but deliberately does not fire there (11× B607 partial-path — documented rejection rationale, incl. 2× in Qwen3; 2× B615 in hypit = unpinned-download variant; 1× B108 in a `test_*.py` fixture — excluded tree by design) |
| rejected as noise | **8** | Checks on MIZAN's documented rejection list (B101 `assert`) |
| **not covered** | **34** | No equivalent MIZAN rule exists — see gap table |

## The measured gaps — Bandit checks with no MIZAN rule

These 34 sites are the honest coverage debt. Disposition is proposed for the
next parity session (each needs the 20-repo FP gate before adoption):

| Bandit check | Sites | Assessment | Proposed disposition |
|---|---:|---|---|
| B310 `urllib.request.urlopen` unvalidated schemes | 3 (MIZAN self, project-nomad ×2) | real signal (CWE-22 class) | **defer** → candidate rule, FP-gate first |
| B104 hardcoded `0.0.0.0` bind | 3 (CogAgent ×2, project-nomad) | real signal (CWE-605), context-dependent | **defer** → candidate rule |
| B103 permissive file permissions (`chmod 0o777` family) | 1 | real signal (CWE-732) | **defer** → candidate rule |
| B314/B405 `xml.etree` parse of untrusted data (+import) | 2 (tawteen/deps.py:186 + import) | real signal (CWE-20 XXE family) — hits our sibling project tawteen | **defer** → candidate rule |
| B603 subprocess without shell | 14 | fires on essentially every subprocess usage | **likely reject** (same rationale as the documented B607 rejection); confirm with FP measurement |
| B404 `import subprocess` | 11 | import-level blacklist noise | **likely reject** |
| B615 — **semantics expanded in Bandit 1.9.x**: "HF download without revision pinning" (`snapshot_download`/`from_pretrained`/`load_dataset` without `revision=`) | 9 (Qwen3 ×6, CogAgent ×1, hypit ×2) | real signal, distinct from `trust_remote_code=True` | **defer** → candidate rule `hf-unpinned-download`; re-verify per-check severity per the parity cycle |

The B615 expansion is exactly why the parity tracker re-verifies Bandit
per-check semantics **every release cycle**: an adopted row silently drifted —
B615 in 1.9.4 is no longer the check MIZAN adopted in wave 1.

## MIZAN-only surface (measured, with its caveats)

1. **Python site Bandit missed: 1.** Qwen3 `examples/speed-benchmark/speed_benchmark_vllm.py:56`
   — `trust_remote_code=True` passed through a `dict(...)` kwargs
   construction (later splatted into the LLM call). MIZAN flags the keyword;
   Bandit's B615 fires on the loader call lines only. One site is a data
   point, not a trend.
2. **97 findings on non-Python files** (Bandit cannot scan them):
   - 83 `hardcoded-secret-candidate` on .ts/.tsx/.js (hypit 55, freellmapi 27, mobx 1) — **heuristic candidates**, each needs human confirmation; a secret pattern in a string literal is a lead, not a confirmed credential.
   - 14 `dynamic-execution` on .ts/.js (hypit 8, freellmapi 4, mobx 2) — `eval`/bare-`exec` shapes in TypeScript/JavaScript.
3. **Categories Bandit does not have**: documentation intelligence, CI
   workflow hardening, offline dependency/OSV checking, git-history scanning.
   These are MIZAN products, not parity items; they are listed here without
   using them to inflate the Python comparison.
4. **Severity policy (deliberate divergence)**: deserialization is HIGH in
   MIZAN (`unsafe-deserialization`, `torch-unsafe-load`) where Bandit rates
   B301 MEDIUM. This is a documented design decision, not an oversight.
5. **`# nosec` is not honored** (fail-loud, measured: no `nosec` handling
   exists in `src/mizan/`). The supported suppression mechanism is
   `mizan baseline` (delta scanning). See
   [`BANDIT_PARITY.md`](BANDIT_PARITY.md) § Suppression policy.

## Verdict (the hard truth, with numbers)

- On Python code-security sites, MIZAN 0.13.0 behaves as a **precision-first
  subset** of Bandit: 26/89 same-site coverage, 8 rejected as documented
  noise, 14 documented scope deviations, 34 uncovered sites across 7 check
  families.
- Differential value on Python today: **1 unique site** + a stricter severity
  policy. That is not enough to justify adoption over Bandit on Python
  coverage alone, and this document will not pretend otherwise.
- Where MIZAN measurably differs: non-Python surfaces (97 findings Bandit
  structurally cannot produce) and the categories outside Bandit's scope.
- The path forward is not "more rules" — it is (a) closing/deciding the 34
  measured gaps through the FP-gated parity cycle, (b) taint analysis to cut
  noise, (c) widening the field sample (100 repos) to measure whether the
  unique-value count grows beyond noise.

## Limitations of this comparison

- 10 local snapshots, not a random sample; 4 are non-Python (bandit columns
  are structurally zero there). The Python-bearing sample is 6 repos, 78
  .py files — small; the 100-repo wave will widen it.
- Site matching uses a ±3 line window with hand-checks at every contested
  site; multi-line calls can still shift reported lines between the tools.
- MIZAN's secrets scanner output is heuristic by design (candidates, not
  confirmed secrets) and was counted as-is on both sides of the ledger.
- Exploitability was not dynamically tested by either tool; a site match
  means "the same pattern was flagged", not "the same risk was proven".
- Bandit per-check Severity/Confidence values were not re-verified line by
  line; the semantics drift that matters (B615) was caught and documented.
