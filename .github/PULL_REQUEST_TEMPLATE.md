# Summary

<!-- one line: what changes and why -->

## Measured numbers

<!-- State the counters this PR adds or changes (tests, findings, precision/recall,
     CLI subcommands). The docs gate enforces README/doc numbers against the
     measured counters; describe the command that produced them. -->

- Tests before: ___ → after: ___ (`python -m unittest discover -s tests`)
- Self-scan: ___ (`python run_mizan.py`)

## Contract checklist

- [ ] Full test suite green locally (`python -m unittest discover -s tests`)
- [ ] Docs gate green (README/doc numbers = measured counters)
- [ ] No silent failures: every exception carries a path and a reason;
      unverifiable results are reported `incomplete`, never clean
- [ ] Golden negatives: any new detection rule distinguishes every golden
      negative (zero false positives on the golden set)
- [ ] Test fixtures use synthetic secrets only — no provider-shaped real keys
- [ ] No tokens or credentials in the diff, the logs, or remote URLs
- [ ] Exit-code contract preserved (`0` clean / `1` measured failure /
      `2` refusal) — or the change is documented explicitly
- [ ] CHANGELOG entry added for user-visible changes

## Linked issues

<!-- Fixes #… -->
