"""Remote repository scanning via the GitHub Tarball API (v0.14.0-dev).

ROADMAP action (P1.3 field measurement): the 100-repo field measurement MUST
run through ``mizan scan-remote`` — never ``git clone``. A tarball has no
``.git`` directory, no hooks, and a strictly bounded extraction surface.

Security model (documented in docs/REMOTE_SCAN.md — the five filters,
v0.14.0 field-measurement revision, 2026-11-08 campaign, 50 repos):

  1. Linked members only INSIDE the tree — a symlink/hardlink whose target
                              resolves strictly inside the extraction tree
                              is materialized (recreated as the same link
                              kind); any absolute, drive-prefixed, or
                              ``..``-escaping target is rejected.
  2. No ``..`` components   — any path containing a ``..`` segment is rejected.
  3. No absolute paths      — member names starting with ``/`` (or a Windows
                              drive prefix) are rejected.
  4. Max 10 MB per file     — a member whose declared size exceeds the cap
                              is SKIPPED (not written, not scanned) and
                              recorded in ``remote.skipped_oversize`` —
                              the scan continues; the read loop still
                              re-enforces the cap for written files.
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
                              ``owner/repo`` with GitHub-valid name
                              characters (``[A-Za-z0-9._-]``, segments may
                              not be ``.`` or ``..``) or it is rejected
                              before any network call. Field measurement
                              2026-11-08: repo names CAN start with ``-``
                              (e.g. ``lxc248/-interestseed``) — the shape
                              check now accepts exactly what GitHub does.

Rejection is fail-loud: a violating member aborts the whole extraction
(partial tree deleted), ``RemoteScanError`` carries the reason, and the CLI
exits 2 (real error) — consistent with MIZAN's fail-loud philosophy.

This module MUST NOT modify ``mizan scan``: local scanning behavior is
unchanged; ``scan-remote`` reuses ``scan_repository`` on the extracted tree.
"""

import io
import http.client
import ssl
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
from urllib.parse import quote, urlsplit

__all__ = [
    "RemoteScanError",
    "MAX_FILE_BYTES",
    "MAX_TARBALL_BYTES",
    "MAX_TOTAL_BYTES",
    "fetch_tarball",
    "extract_tarball",
    "scan_remote",
    "validate_owner_repo",
    "validate_ref",
    "link_resolves_inside",
]

# --- documented limits -------------------------------------------------
MAX_FILE_BYTES = 10 * 1024 * 1024        # filter 4: 10 MB per file
MAX_TARBALL_BYTES = 200 * 1024 * 1024    # guard 6a: download cap
MAX_TOTAL_BYTES = 512 * 1024 * 1024      # guard 6b: total uncompressed cap

_CHUNK = 1024 * 1024

# GitHub-valid name characters; a segment may not BE "." or ".." (path
# safety — checked against both "/" and end-of-string), but MAY start with
# "-" or "." — real repos exist with such names (field-measured:
# lxc248/-interestseed, the .github convention).
_OWNER_REPO_RE = re.compile(
    r"^(?!\.(/|$))(?!\.\.(/|$))[A-Za-z0-9._-]+"
    r"/(?!\.(/|$))(?!\.\.(/|$))[A-Za-z0-9._-]+$"
)


_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


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


def validate_ref(ref: str = None):
    """Validate a Git ref before placing it in the fixed GitHub API URL."""
    if ref is None:
        return None
    if not isinstance(ref, str) or not _REF_RE.fullmatch(ref):
        raise RemoteScanError(
            "invalid ref: use 1-255 ASCII letters, digits, '.', '_', '-', or '/'"
        )
    parts = ref.split("/")
    if (ref.startswith("/") or ref.endswith("/") or "//" in ref
            or any(part in {"", ".", ".."} or part.endswith(".")
                   or part.endswith(".lock") for part in parts)
            or "@{" in ref):
        raise RemoteScanError("invalid ref: unsafe Git ref path")
    return ref


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


def link_resolves_inside(member) -> bool:
    """Filter 1 (v0.14.0): True when a linked member's target resolves
    strictly INSIDE the extraction tree.

    Pure path algebra on tar member names (no filesystem access): the
    target is joined onto the member's directory and normalized; any
    result that escapes the root (leading ``..``), or an absolute /
    drive-prefixed target, is out-of-tree. Out-of-tree targets stay
    fail-loud rejections — the escape property is preserved.
    """
    target = member.linkname or ""
    if not target or "\x00" in target:
        return False
    if target.startswith("/") or target.startswith("\\"):
        return False
    if re.match(r"^[A-Za-z]:", target):  # Windows drive prefix
        return False
    base = posixpath.dirname(member.name.rstrip("/"))
    resolved = posixpath.normpath(posixpath.join(base, target))
    if resolved == ".." or resolved.startswith("../"):
        return False
    if posixpath.isabs(resolved):
        return False
    return True


def _reject(reason: str):
    raise RemoteScanError(reason)


def extract_tarball(fileobj, dest_dir: str) -> dict:
    """Extract a tarball fileobj into dest_dir under the strict filters.

    Returns stats: {"files": int, "bytes": int, "skipped_oversize": list,
    "links": int}. Any filter violation raises :class:`RemoteScanError`
    (fail-loud; the caller deletes dest_dir). Oversize members (filter 4)
    are skipped and recorded instead of aborting — v0.14.0 field change.
    """
    files = 0
    total = 0
    links = 0
    skipped = []
    dest_real = os.path.realpath(dest_dir)
    with tarfile.open(fileobj=fileobj, mode="r:*") as tar:
        for member in tar:
            name = member.name
            # filter 1: linked members materialize ONLY when the target
            # resolves inside the tree; out-of-tree targets stay rejected
            if member.issym() or member.islnk():
                kind = "symlink" if member.issym() else "hardlink"
                if not link_resolves_inside(member):
                    _reject(
                        f"rejected: {kind} member {name!r} -> "
                        f"{member.linkname!r} (target resolves outside "
                        "the extraction tree)"
                    )
                out_path = os.path.join(dest_dir, name)
                parent = os.path.dirname(out_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                # containment double-check through the future link path
                real = os.path.realpath(out_path)
                if real != dest_real and not real.startswith(dest_real + os.sep):
                    _reject(f"rejected: member escapes destination {name!r}")
                try:
                    if member.issym():
                        os.symlink(member.linkname, out_path)
                    else:
                        target_fs = os.path.normpath(os.path.join(
                            dest_dir,
                            posixpath.normpath(posixpath.join(
                                posixpath.dirname(name), member.linkname))))
                        target_real = os.path.realpath(target_fs)
                        if (target_real != dest_real
                                and not target_real.startswith(
                                    dest_real + os.sep)):
                            _reject(
                                f"rejected: hardlink member {name!r} -> "
                                f"{member.linkname!r} (target outside tree)"
                            )
                        if not os.path.exists(target_real):
                            _reject(
                                f"rejected: hardlink member {name!r} -> "
                                f"{member.linkname!r} (target not yet "
                                "extracted)"
                            )
                        os.link(target_real, out_path)
                except OSError as exc:
                    _reject(f"rejected: cannot materialize {kind} member "
                            f"{name!r}: {exc}")
                # belt-and-suspenders: the created link must stay inside
                real = os.path.realpath(out_path)
                if real != dest_real and not real.startswith(dest_real + os.sep):
                    try:
                        os.unlink(out_path)
                    except OSError:
                        pass
                    _reject(f"rejected: {kind} member {name!r} escapes "
                            "destination after materialization")
                links += 1
                continue
            # defense-in-depth: no devices/fifos
            if member.isdev() or member.isfifo():
                _reject(f"rejected: special member {name!r}")
            # filters 2+3: no .., no absolute path
            if not _member_name_safe(name):
                _reject(f"rejected: unsafe member path {name!r}")
            if member.isdir():
                os.makedirs(os.path.join(dest_dir, name), exist_ok=True)
                continue
            if not member.isfile():
                _reject(f"rejected: unsupported member type {name!r}")
            # filter 4: per-file cap (declared size) — SKIP + record, do
            # not abort (v0.14.0: 3/50 campaign repos aborted on >10MB
            # media/data assets; assets are outside the scan surface)
            if member.size > MAX_FILE_BYTES:
                skipped.append({"name": name, "size": member.size})
                continue
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
    return {"files": files, "bytes": total, "skipped_oversize": skipped,
            "links": links}


def _https_get(host: str, path: str, headers: dict[str, str], timeout: int):
    """GET a path from a hard-coded HTTPS host using http.client."""
    connection = http.client.HTTPSConnection(host, timeout=timeout, context=ssl.create_default_context())
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        location = response.getheader("Location")
        # Redirect/error bodies are bounded separately; only the final
        # successful tarball receives the full download-size allowance.
        limit = MAX_TARBALL_BYTES + 1 if response.status == 200 else 64 * 1024
        data = response.read(limit)
        return response.status, location, data
    finally:
        connection.close()


def fetch_tarball(owner_repo: str, ref: str = None,
                  token: str = None) -> bytes:
    """Download a GitHub tarball using fixed HTTPS API/CDN hosts.

    GitHub's API redirects tarball requests to codeload.github.com. Redirects
    are followed manually and only to that exact HTTPS host; credentials are
    never forwarded to the CDN.
    """
    validate_owner_repo(owner_repo)
    ref = validate_ref(ref)
    path = f"/repos/{owner_repo}/tarball"
    if ref:
        path += "/" + quote(ref, safe="/")
    headers = {
        "User-Agent": "mizan-remote-scan",
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        status, location, data = _https_get("api.github.com", path, headers, 120)
        if status in (301, 302, 303, 307, 308):
            parsed = urlsplit(location or "")
            prefix = f"/{owner_repo}/"
            if (
                parsed.scheme != "https"
                or parsed.hostname != "codeload.github.com"
                or parsed.port is not None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or not parsed.path.startswith(prefix)
                or ".." in parsed.path.split("/")
                or "//" in parsed.path
            ):
                raise RemoteScanError("GitHub tarball redirect is not an approved HTTPS CDN URL")
            status, _location, data = _https_get(
                "codeload.github.com", parsed.path,
                {"User-Agent": "mizan-remote-scan"}, 120,
            )
        if status in (403, 429):
            raise RemoteScanError(
                f"GitHub API refused the tarball request (HTTP {status}) — "
                "rate limit likely; set MIZAN_GH_TOKEN/GH_TOKEN to raise it"
            )
        if status == 404:
            raise RemoteScanError(
                f"repository or ref not found: {owner_repo}"
                + (f"@{ref}" if ref else "")
            )
        if status != 200:
            raise RemoteScanError(
                f"GitHub API returned HTTP {status} for {owner_repo}"
            )
    except (OSError, http.client.HTTPException) as exc:
        raise RemoteScanError(f"GitHub tarball request failed for {owner_repo}: {exc}") from exc

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
            "linked_members": stats["links"],
            "skipped_oversize": stats["skipped_oversize"],
            "extracted_tree_deleted": True,
        }
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
