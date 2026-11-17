#!/usr/bin/env python3
"""verify_all_tags.py — verify every local tag matches its remote target.

Release tooling referenced by docs/DEV_PLAN_V0150.md. Compares each local
tag against the remote tag with the SAME annotated-tag peeling git does
(``^{}`` target for annotated tags, object name for lightweight tags), so
a re-pointed or half-pushed tag cannot pass unnoticed.

Usage:
    MIZAN_GH_TOKEN=... python scripts/verify_all_tags.py [REMOTE]

- REMOTE defaults to ``origin``.
- The token is read from MIZAN_GH_TOKEN (or `gh auth token` as fallback)
  and is used ONLY for a temporary push URL — never written to disk,
  never stored in the remote config, never printed. Masking rules from
  the 2026-11-15 lesson: use the FULL ``%(refname)`` and strip the
  ``refs/tags/`` prefix manually; ``%(refname:short)`` is ambiguous when
  a tag shares a name with a remote-tracking branch.

Exit codes: 0 = all tags match, 1 = mismatch/missing found,
2 = could not collect remote refs.
"""
import subprocess
import sys
import os
import re

TOKEN_RE = re.compile(r"(ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|gho_[A-Za-z0-9]+)")


def mask(text):
    return TOKEN_RE.sub("<TOKEN>", str(text))


def sh(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{cmd} failed: {mask(result.stderr)}")
    return result.stdout


def local_tags():
    tags = {}
    for line in sh(["git", "for-each-ref", "--format=%(refname) %(objectname) %(*objectname)",
                    "refs/tags"]).splitlines():
        parts = line.split()
        refname = parts[0]          # full refname — never refname:short
        name = refname[len("refs/tags/"):]
        obj, peeled = parts[1], (parts[2] if len(parts) > 2 else "")
        tags[name] = peeled if peeled else obj
    return tags


def remote_tags(remote):
    out = sh(["git", "ls-remote", "--tags", remote])
    refs = {}
    for line in out.splitlines():
        obj, ref = line.split(maxsplit=1)
        ref = ref.strip()
        if ref.endswith("^{}"):
            refs[ref[:-3]] = obj    # peeled target wins for annotated tags
        elif ref not in refs:
            refs[ref] = obj
    return {r[len("refs/tags/"):]: o for r, o in refs.items()}


def main():
    remote = sys.argv[1] if len(sys.argv) > 1 else "origin"
    local = local_tags()
    token = os.environ.get("MIZAN_GH_TOKEN") or sh(["gh", "auth", "token"]).strip()
    if not token:
        print("ERROR: no token (set MIZAN_GH_TOKEN or run `gh auth login`)")
        return 2
    # Temporary authenticated URL for read-only ls-remote; restored after.
    original = sh(["git", "remote", "get-url", remote]).strip()
    authed = re.sub(r"^https://", f"https://x-access-token:{token}@", original)
    try:
        sh(["git", "remote", "set-url", remote, authed])
        try:
            remote_refs = remote_tags(remote)
        finally:
            sh(["git", "remote", "set-url", remote, original])
    except RuntimeError as exc:
        print("ERROR:", exc)
        return 2

    ok = missing = mismatched = 0
    for name, target in sorted(local.items()):
        if name not in remote_refs:
            print(f"MISSING  {name} (not on remote)")
            missing += 1
        elif remote_refs[name] != target:
            print(f"MISMATCH {name} local={target[:12]} remote={remote_refs[name][:12]}")
            mismatched += 1
        else:
            print(f"OK       {name} -> {target[:12]}")
            ok += 1

    head = sh(["git", "rev-parse", "HEAD"]).strip()[:12]
    print(f"\nsummary: {ok} OK, {mismatched} mismatched, {missing} missing; HEAD={head}")
    return 0 if (missing == 0 and mismatched == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
