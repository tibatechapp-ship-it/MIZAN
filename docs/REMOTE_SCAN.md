# Remote scanning — `mizan scan-remote`

`mizan scan-remote OWNER/REPO [--ref REF] [--category {all,security,quality}]
[--format {json,html}] [--output PATH]`

Downloads a repository through the **GitHub Tarball API**
(`https://api.github.com/repos/OWNER/REPO/tarball[/REF]`), extracts it under
strict safe-extraction filters, runs the **unchanged** local
`scan_repository` pipeline on the extracted tree, and deletes the extracted
tree immediately afterwards.

> Field-measurement policy (P1.3): the 100-repo field measurement MUST use
> `scan-remote` — **not** `git clone`. A tarball carries no `.git` directory,
> no hooks, and a strictly bounded extraction surface.

## The five extraction filters

Any member violating a filter aborts the whole extraction (fail-loud),
with two field-measured refinements (v0.14.0 — 2026-11-08, 50-repo
campaign: 15/50 pre-fix aborts, all in MIZAN's own code, 0 after):

| # | Filter | Behavior |
|---|--------|----------|
| 1 | **Linked members only INSIDE the tree** — a symlink/hardlink whose target resolves strictly inside the extraction tree is materialized (same link kind); absolute, drive-prefixed, or `..`-escaping targets are rejected | inside: materialized · outside: `RemoteScanError`; extraction aborted |
| 2 | **No `..` path components** — e.g. `pkg/../../etc/passwd` | `RemoteScanError`; extraction aborted |
| 3 | **No absolute paths** — `/etc/passwd`, `\…`, `C:\…` | `RemoteScanError`; extraction aborted |
| 4 | **Max 10 MB per file** — declared member size, re-enforced while reading. Oversize members are SKIPPED (never written, never scanned) and recorded in `remote.skipped_oversize` — the scan continues | skip + record (v0.14.0) |
| 5 | **Immediate deletion** — the extracted tree lives in a private temp directory removed in a `finally` block | deleted on success, rejection, and scanner failure |

## Defense-in-depth (beyond the five filters)

- **Tarbomb guards**: the download itself is capped (200 MB) and the total
  uncompressed size is capped (512 MB).
- **Never `extractall`**: members are written individually through
  `tar.extractfile` after passing every filter; `tarfile.extractall` is not
  called anywhere in MIZAN.
- **Containment double-check**: after normalization, every written path is
  verified to stay inside the destination directory.
- **Strict `owner/repo` shape**: the CLI argument must match GitHub's own
  name rules — segments of `[A-Za-z0-9._-]`, no segment may be `.` or
  `..`, leading `-`/`.` accepted (field-measured: `lxc248/-interestseed`,
  the `.github` convention) — rejected
  before any network call.
- **No special members**: devices and FIFOs are rejected.

## Exit contract

| Exit | Meaning |
|------|---------|
| `0`  | Scan completed (findings or not) |
| `2`  | Fetch failed or a filter rejected the tarball (real error, fail-loud message on stderr) |

## Authentication and rate limits

- Token is read from the `MIZAN_GH_TOKEN` or `GH_TOKEN` environment
  variable. It is used **only** in the `Authorization` header — it is never
  printed, logged, or written to disk by MIZAN.
- Unauthenticated requests are limited to 60/hour per IP; authenticated
  requests to 5,000/hour. The 100-repo field measurement requires a token.
- If GitHub refuses the request (HTTP 403/429), `scan-remote` fails loud
  with an explicit rate-limit message.

## Result shape

The scan JSON is the normal `mizan scan` result (same rules, same severities,
same engine version) augmented with a `remote` block:

```json
"remote": {
  "repo": "owner/repo",
  "ref": null,
  "tarball_bytes": 1234567,
  "extracted_files": 42,
  "extracted_bytes": 987654,
  "linked_members": 3,
  "skipped_oversize": [
    {"name": "assets/demo.mp4", "size": 44813108}
  ],
  "extracted_tree_deleted": true
}
```

`mizan scan` (local paths) is deliberately unchanged by this feature.
