"""Remote-scan safe-extraction suite (v0.14.0, docs/REMOTE_SCAN.md).

Contract under test (the five documented filters, field-measurement
revision 2026-11-08 — 50-repo campaign, 15/50 aborts diagnosed):
  1. linked members (symlink/hardlink) are materialized ONLY when the
     target resolves strictly inside the extraction tree; out-of-tree
     targets (absolute, drive-prefixed, ``..``-escaping) are rejected;
  2. ``..`` path components are rejected (``../../etc/passwd``);
  3. absolute member paths are rejected;
  4. members over 10 MB are SKIPPED + recorded (``skipped_oversize``) —
     the scan continues; written files still re-enforce the cap;
  5. the extracted tree is deleted immediately — on success AND rejection.

Plus the strict owner/repo shape check (rejected before any network call),
now accepting exactly GitHub's own name rules (leading ``-``/``.``).

Tarballs are built in-memory (io.BytesIO); no test touches the network —
``fetch_tarball`` is monkeypatched for the end-to-end cases.
"""

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from mizan import remote_scan
from mizan.remote_scan import (
    RemoteScanError,
    extract_tarball,
    scan_remote,
    validate_owner_repo,
)

SMALL_PY = (
    b"import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n"
)


def make_tar(members):
    """Build a gzipped tarball in memory.

    members: list of dicts {name, data=b'..'} for regular files,
    {name, link='...'} for symlinks, {name, hard='...'} for hardlinks,
    {name, size=N, data=b'..'} to lie about/oversize payloads.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for spec in members:
            name = spec["name"]
            info = tarfile.TarInfo(name=name)
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                info.name = name  # directory member
                tar.addfile(info)
                continue
            if "link" in spec:
                info.type = tarfile.SYMTYPE
                info.linkname = spec["link"]
                tar.addfile(info)
                continue
            if "hard" in spec:
                info.type = tarfile.LNKTYPE
                info.linkname = spec["hard"]
                tar.addfile(info)
                continue
            data = spec.get("data", b"")
            info.size = spec.get("size", len(data))
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf.getvalue()


def clean_repo_tar():
    """A well-formed mini repo: pkg/evil.py with a real finding."""
    return make_tar([
        {"name": "pkg/", "data": b""},  # directory member
        {"name": "pkg/evil.py", "data": SMALL_PY},
        {"name": "README.md", "data": b"# tiny\n"},
    ])


class ExtractFilterTests(unittest.TestCase):
    def setUp(self):
        self.dest = tempfile.mkdtemp(prefix="mizan-remote-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dest, ignore_errors=True)

    def test_out_of_tree_symlink_rejected(self):
        tarball = make_tar([
            {"name": "ok.py", "data": b"x = 1\n"},
            {"name": "escape", "link": "/etc"},
        ])
        with self.assertRaises(RemoteScanError) as ctx:
            extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertIn("symlink", str(ctx.exception))
        self.assertIn("outside", str(ctx.exception))

    def test_parent_escape_symlink_rejected(self):
        # the field-measured attack shape: a benign-looking relative link
        # whose .. chain climbs out of the tree
        tarball = make_tar([
            {"name": "ok.py", "data": b"x = 1\n"},
            {"name": "sub/escape", "link": "../../outside"},
        ])
        with self.assertRaises(RemoteScanError) as ctx:
            extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertIn("symlink", str(ctx.exception))

    def test_internal_symlink_materialized(self):
        # the field-measured benign shapes (9/50 campaign aborts):
        #   CLAUDE.md -> AGENTS.md        (sibling file link)
        #   .claude/skills -> ../.agents/skills   (.. INSIDE the tree)
        tarball = make_tar([
            {"name": "AGENTS.md", "data": b"# agents\n"},
            {"name": "CLAUDE.md", "link": "AGENTS.md"},
            {"name": ".agents/skills/x.md", "data": b"skill\n"},
            {"name": ".claude/skills", "link": "../.agents/skills"},
        ])
        stats = extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertEqual(stats["links"], 2)
        root = Path(self.dest)
        self.assertTrue((root / "CLAUDE.md").is_symlink())
        self.assertEqual(
            (root / "CLAUDE.md").read_text(), "# agents\n")
        self.assertTrue((root / ".claude" / "skills").is_symlink())
        # reading THROUGH the internal link stays inside and correct
        self.assertEqual(
            (root / ".claude" / "skills" / "x.md").read_text(), "skill\n")

    def test_internal_hardlink_materialized(self):
        tarball = make_tar([
            {"name": "a.py", "data": b"x = 1\n"},
            {"name": "b.py", "hard": "a.py"},
        ])
        stats = extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertEqual(stats["files"], 1)  # hardlink is not a new file
        self.assertEqual(stats["links"], 1)
        self.assertEqual(
            (Path(self.dest) / "b.py").read_text(), "x = 1\n")

    def test_dangling_out_of_tree_hardlink_rejected(self):
        tarball = make_tar([
            {"name": "a.py", "data": b"x = 1\n"},
            {"name": "b.py", "hard": "../outside.txt"},
        ])
        with self.assertRaises(RemoteScanError) as ctx:
            extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertIn("hardlink", str(ctx.exception))

    def test_parent_traversal_member_rejected(self):
        tarball = make_tar([
            {"name": "pkg/../../etc/passwd", "data": b"root:x:0:0\n"},
        ])
        with self.assertRaises(RemoteScanError) as ctx:
            extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertIn("unsafe member path", str(ctx.exception))
        # nothing was written anywhere inside the destination
        self.assertEqual(list(Path(self.dest).rglob("*")), [])

    def test_absolute_path_member_rejected(self):
        tarball = make_tar([
            {"name": "/etc/passwd", "data": b"root:x:0:0\n"},
        ])
        with self.assertRaises(RemoteScanError) as ctx:
            extract_tarball(io.BytesIO(tarball), self.dest)
        self.assertIn("unsafe member path", str(ctx.exception))

    def test_oversize_member_skipped_and_recorded(self):
        big = b"\x00" * (remote_scan.MAX_FILE_BYTES + 1)
        tarball = make_tar([
            {"name": "assets/demo.mp4", "data": big},
            {"name": "pkg/evil.py", "data": SMALL_PY},
        ])
        stats = extract_tarball(io.BytesIO(tarball), self.dest)
        # the scan surface continues: the code file IS extracted
        self.assertTrue(
            (Path(self.dest) / "pkg" / "evil.py").is_file())
        self.assertEqual(stats["files"], 1)
        self.assertEqual(len(stats["skipped_oversize"]), 1)
        skip = stats["skipped_oversize"][0]
        self.assertEqual(skip["name"], "assets/demo.mp4")
        self.assertEqual(skip["size"], remote_scan.MAX_FILE_BYTES + 1)
        self.assertFalse((Path(self.dest) / "assets" / "demo.mp4").exists())

    def test_clean_tarball_extracts(self):
        stats = extract_tarball(io.BytesIO(clean_repo_tar()), self.dest)
        self.assertEqual(stats["files"], 2)  # dir member is not a file
        self.assertTrue(
            (Path(self.dest) / "pkg" / "evil.py").is_file()
        )
        self.assertTrue((Path(self.dest) / "README.md").is_file())


class OwnerRepoValidationTests(unittest.TestCase):
    def test_shapes(self):
        for ok in ("owner/repo", "zai-org/GLM-5", "a.b-c_d/e.f-g_h",
                   "lxc248/-interestseed",   # field-measured 2026-11-08
                   ".github/.github",         # metadata-repo convention
                   "a..b/x_y.z"):
            validate_owner_repo(ok)  # must not raise
        for bad in ("", "nodir", "a/b/c", "/abs", "own er/rep o",
                    "../etc/passwd", "../x", "a/..", "a/.", "./x",
                    "a/../../x", "a/b ", None):
            with self.assertRaises(RemoteScanError):
                validate_owner_repo(bad)


class ScanRemoteEndToEndTests(unittest.TestCase):
    def setUp(self):
        self._orig_fetch = remote_scan.fetch_tarball

    def tearDown(self):
        remote_scan.fetch_tarball = self._orig_fetch
        self.assert_no_temp_trees()

    def assert_no_temp_trees(self):
        """Filter 5: no mizan-remote-* tree survives any outcome."""
        leftovers = [
            p for p in Path(tempfile.gettempdir()).glob("mizan-remote-*")
        ]
        self.assertEqual(leftovers, [])

    def test_success_scans_then_deletes(self):
        remote_scan.fetch_tarball = (
            lambda owner_repo, ref=None, token=None: clean_repo_tar()
        )
        result = scan_remote("owner/repo")
        self.assertEqual(result["remote"]["repo"], "owner/repo")
        self.assertEqual(result["remote"]["extracted_files"], 2)
        self.assertEqual(result["remote"]["linked_members"], 0)
        self.assertEqual(result["remote"]["skipped_oversize"], [])
        self.assertTrue(result["remote"]["extracted_tree_deleted"])
        rules = {f["rule"] for f in result.get("findings", [])}
        self.assertIn("unsafe-deserialization", rules)

    def test_success_with_internal_symlinks_and_oversize(self):
        # end-to-end over the exact field-measured shapes: internal links
        # materialize, oversize assets skip + record, the scan completes
        tarball = make_tar([
            {"name": "AGENTS.md", "data": b"# agents\n"},
            {"name": "CLAUDE.md", "link": "AGENTS.md"},
            {"name": "assets/demo.mp4",
             "data": b"\x00" * (remote_scan.MAX_FILE_BYTES + 1)},
            {"name": "pkg/evil.py", "data": SMALL_PY},
        ])
        remote_scan.fetch_tarball = (
            lambda owner_repo, ref=None, token=None: tarball
        )
        result = scan_remote("owner/repo")
        self.assertEqual(result["remote"]["linked_members"], 1)
        self.assertEqual(len(result["remote"]["skipped_oversize"]), 1)
        self.assertEqual(result["remote"]["extracted_files"], 2)
        self.assertTrue(result["remote"]["extracted_tree_deleted"])
        rules = {f["rule"] for f in result.get("findings", [])}
        self.assertIn("unsafe-deserialization", rules)

    def test_rejection_still_deletes(self):
        malicious = make_tar([
            {"name": "escape", "link": "/etc"},
        ])
        remote_scan.fetch_tarball = (
            lambda owner_repo, ref=None, token=None: malicious
        )
        with self.assertRaises(RemoteScanError):
            scan_remote("owner/repo")
        self.assert_no_temp_trees()


if __name__ == "__main__":
    unittest.main()
