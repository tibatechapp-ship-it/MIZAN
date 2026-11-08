"""Remote repository scanning via the GitHub Tarball API (v0.14.0-dev).

ROADMAP action (P1.3 field measurement): the 100-repo field measurement MUST
run through ``mizan scan-remote`` — never ``git clone``. A tarball has no
``.git`` directory, no hooks, and a strictly bounded extraction surface.

Security model (documented in docs/REMOTE_SCAN.md — the five filters):

  1. No linked members      — symlink OR hardlink members are rejected.
  2. No ``..`` components   — any path containing a ``..`` segment is rejected.
  3. No absolute paths      — member names starting with ``/`` (or a Windows
                              drive prefix) are rejected.
  4. Max 10 MB per file     — a member whose declared size exceeds the cap
                              is rejected; the read loop re-enforces the cap.
  5. Immediate deletion     — the extracted tree lives in a private temp
                              directory that is removed in a ``finally``
                              block, on success AND on rejection.

Defense-in-depth (documented, beyond the five filters):

  6. Tarbomb guard          — total uncompressed bytes capped; the download
                              itself is capped as well.
  7. Never ``extractall``   — members are written individually through
                              ``extractfile`` after passing every filter;
                              ``tarfile.extractall`` is not called anywhere.
  8. Strict owner/repo shape — the CLI argument must match
                              ``owner/repo`` or it is rejected before any
                              network call.

Rejection is fail-loud: a violating member aborts the whole extraction
(partial tree deleted), ``RemoteScanError`` carries the reason, and the CLI
exits 2 (real error) — consistent with MIZAN's fail-loud philosophy.

This module MUST NOT modify ``mizan scan``: local scanning behavior is
unchanged; ``scan-remote`` reuses ``scan_repository`` on the extracted tree.
"""

import io
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request

__all__ = [
    "RemoteScanError",
    "MAX_FILE_BYTES",
    "MAX_TARBALL_BYTES",
    "MAX_TOTAL_BYTES",
    "fetch_tarball",
    "extract_tarball",
    "scan_remote",
    "validate_owner_repo",
]

# --- documented limits -------------------------------------------------
MAX_FILE_BYTES = 10 * 1024 * 1024        # filter 4: 10 MB per file
MAX_TARBALL_BYTES = 200 * 1024 * 1024    # guard 6a: download cap
MAX_TOTAL_BYTES = 512 * 1024 * 1024      # guard 6b: total uncompressed cap

_CHUNK = 1024 * 1024

_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")


class RemoteScanError(Exception):
    """A remote-scan input violated a documented filter or failed to fetch."""


def validate_owner_repo(owner_repo: str) -> str:
    """Strict ``owner/repo`` shape check (guard 8) — reject before network."""
    if not _OWNER_REPO_RE.match(owner_repo or ""):
        raise RemoteScanError(
            f"invalid owner/repo {owner_repo!r}: expected 'owner/repo' "
            "with [A-Za-z0-9_.-] segments only"
        )
    return owner_repo


def _member_name_safe(name: str) -> bool:
    """Filters 2 and 3: no ``..`` components, no absolute paths."""
    if not name or "\x00" in name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    if re.match(r"^[A-Za-z]:", name):  # Windows drive prefix
        return False
    parts = name.split("/")
    return ".." not in parts


def _reject(reason: str):
    raise RemoteScanError(reason)


def extract_tarball(fileobj, dest_dir: str) -> dict:
    """Extract a tarball fileobj into dest_dir under the strict filters.

    Returns stats: {"files": int, "bytes": int}. Any filter violation raises
    :class:`RemoteScanError` (fail-loud; the caller deletes dest_dir).
    """
    files = 0
    total = 0
    dest_real = os.path.realpath(dest_dir)
    with tarfile.open(fileobj=fileobj, mode="r:*") as tar:
        for member in tar:
            name = member.name
            # filter 1: no linked members (symlink or hardlink)
            if member.issym():
                _reject(f"rejected: symlink member {name!r} -> "
                        f"{member.linkname!r}")
            if member.islnk():
                _reject(f"rejected: hardlink member {name!r} -> "
                        f"{member.linkname!r}")
            # defense-in-depth: no devices/fifos
            if member.isdev() or member.isfifo():
                _reject(f"rejected: special member {name!r}")
            # filters 2+3: no .., no absolute path
            if not _member_name_safe(name):
                _reject(f"rejected: unsafe member path {name!r}")
            # filter 4: per-file cap (declared size)
            if member.size > MAX_FILE_BYTES:
                _reject(
                    f"rejected: member {name!r} is {member.size} bytes "
                    f"(limit {MAX_FILE_BYTES})"
                )
            if member.isdir():
                os.makedirs(os.path.join(dest_dir, name), exist_ok=True)
                continue
            if not member.isfile():
                _reject(f"rejected: unsupported member type {name!r}")
            src = tar.extractfile(member)
            if src is None:
                _reject(f"rejected: unreadable member {name!r}")
            out_path = os.path.join(dest_dir, name)
            parent = os.path.dirname(out_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            # containment double-check after normalisation
            real = os.path.realpath(out_path)
            if real != dest_real and not real.startswith(dest_real + os.sep):
                _reject(f"rejected: member escapes destination {name!r}")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                _reject(
                    f"rejected: total uncompressed {total} bytes exceeds "
                    f"{MAX_TOTAL_BYTES} (tarbomb guard)"
                )
            written = 0
            with open(out_path, "wb") as out:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_FILE_BYTES:  # re-enforce filter 4
                        _reject(
                            f"rejected: member {name!r} exceeded "
                            f"{MAX_FILE_BYTES} bytes while reading"
                        )
                    out.write(chunk)
            files += 1
    return {"files": files, "bytes": total}


def fetch_tarball(owner_repo: str, ref: str = None,
                  token: str = None) -> bytes:
    """Download the GitHub tarball for owner/repo (optionally at ref).

    The token (if any) is read from the MIZAN_GH_TOKEN or GH_TOKEN
    environment variable by the caller and is only ever placed in the
    Authorization header — it is never printed, logged, or stored.
    """
    validate_owner_repo(owner_repo)
    url = f"https://api.github.com/repos/{owner_repo}/tarball"
    if ref:
        url += f"/{ref}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "mizan-remote-scan")
    req.add_header("Accept", "application/vnd.github+json")
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read(MAX_TARBALL_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise RemoteScanError(
                f"GitHub API refused the tarball request (HTTP {exc.code}) — "
                "rate limit likely; set MIZAN_GH_TOKEN/GH_TOKEN to raise it"
            ) from exc
        if exc.code == 404:
            raise RemoteScanError(
                f"repository or ref not found: {owner_repo}"
                + (f"@{ref}" if ref else "")
            ) from exc
        raise RemoteScanError(
            f"GitHub API returned HTTP {exc.code} for {owner_repo}"
        ) from exc
    if len(data) > MAX_TARBALL_BYTES:
        _reject(f"rejected: tarball exceeds {MAX_TARBALL_BYTES} bytes")
    return data


def scan_remote(owner_repo: str, ref: str = None, category: str = "all",
                token: str = None) -> dict:
    """Fetch, safely extract, scan, and immediately delete (filter 5).

    Reuses the untouched ``scan_repository`` pipeline on the extracted tree;
    the returned result is the normal scan JSON augmented with a
    ``remote`` metadata block. The temp tree is removed in ``finally`` —
    on success, on rejection, and on scanner failure.
    """
    # imported here (and in cli) so the module stays import-light
    from .scanner import scan_repository

    validate_owner_repo(owner_repo)
    data = fetch_tarball(owner_repo, ref=ref, token=token)
    tmp = tempfile.mkdtemp(prefix="mizan-remote-")
    try:
        stats = extract_tarball(io.BytesIO(data), tmp)
        result = scan_repository(tmp, category=category)
        result["remote"] = {
            "repo": owner_repo,
            "ref": ref,
            "tarball_bytes": len(data),
            "extracted_files": stats["files"],
            "extracted_bytes": stats["bytes"],
            "extracted_tree_deleted": True,
        }
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
