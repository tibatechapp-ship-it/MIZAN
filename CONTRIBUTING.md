# Contributing to MIZAN Security

Thank you for considering a contribution. MIZAN is a read-only security
engine: it inspects code, secrets, dependencies, CI configuration and
documentation in a single pass, explains findings in plain language, and
never executes user code. Every change to this repository must keep those
promises true.

## Ground rules (non-negotiable)

1. **Measured, not marketed.** Every number that appears in the README,
   CHANGELOG or docs must equal the counter actually measured at merge
   time. The docs gate enforces this automatically.
2. **No silent failures.** Any exception must surface with the file path
   and the reason. Anything that could not be verified is reported as
   `incomplete`, never as clean.
3. **Golden negatives come first.** A detection rule that cannot
   distinguish a golden negative (a benign construct it must ignore) is
   postponed, not shipped. Zero false positives on the golden set is the
   bar.
4. **Synthetic secrets only.** Test fixtures must never contain
   provider-shaped real secrets (`sk_live_…`, real keys). Use obviously
   synthetic strings that still trigger the intended rule.
5. **Tokens never touch the tree.** Credentials stay out of tracked
   files, remote URLs, and logs. See `SECURITY.md`.
6. **Exit-code contract.** `0` verified clean, `1` measured failure with
   named evidence, `2` refusal (path/argument contract). A change that
   alters this contract must say so explicitly.

## Development setup

```bash
git clone https://github.com/tibatechapp-ship-it/MIZAN.git
cd MIZAN
python -m pip install -e .
python -m unittest discover -s tests   # full suite must stay green
python run_mizan.py                    # self-scan; quality + security
```

Python 3.11–3.15 are supported; CI runs the matrix. The docs gate
(`tests/test_version_consistency.py` and friends) fails the build if
README/doc numbers drift from the measured counters.

## Pull requests

- Branch from `main`; keep one logical change per PR.
- Run the full test suite and the self-scan before pushing.
- Fill the PR template; state the measured numbers you are adding or
  changing.
- A reviewer may ask for the exact command and output that produced any
  number in your description.
- Security-relevant changes require a corresponding golden negative or
  regression test.

## Reporting bugs and proposing features

Open a GitHub issue using the templates (`.github/ISSUE_TEMPLATE/`).
For vulnerabilities, follow `SECURITY.md` — do not open a public issue.

## Commit style

Conventional and measured: `feat(rules): …`, `fix(sarif): …`,
`docs(plan): …`, `release: v0.X.Y — …`. The message should let a reader
reproduce the measurement.

## License

By contributing you agree that your contributions are licensed under
the MIT License that covers this repository.
