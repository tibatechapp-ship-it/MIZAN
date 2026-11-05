import subprocess
import tempfile
import unittest

import mizan
from pathlib import Path

from mizan import __version__
from mizan.cli import full_scan_repository


class MasterEngineTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        subprocess.run(
            ["git", "init", "-q", str(self.root)],
            check=True
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_all_engines_are_present(self):
        result = full_scan_repository(self.root)

        expected = {
            "analysis",
            "detection",
            "scanner",
            "git",
            "ci",
            "dependencies",
            "change_risk",
        }

        self.assertTrue(expected.issubset(result.keys()))

    def test_master_version_is_consistent(self):
        result = full_scan_repository(self.root)

        self.assertEqual(result["version"], __version__)
        self.assertEqual(result["version"], mizan.__version__)

    def test_master_engine_is_read_only(self):
        result = full_scan_repository(self.root)

        self.assertEqual(result["mode"], "read-only")
        self.assertFalse(result["execution_performed"])

    def test_all_engines_report_results(self):
        result = full_scan_repository(self.root)

        for engine in (
            "analysis",
            "detection",
            "scanner",
            "git",
            "ci",
            "dependencies",
            "change_risk",
        ):
            with self.subTest(engine=engine):
                self.assertIsInstance(result[engine], dict)

    def test_invalid_directory(self):
        with self.assertRaises(ValueError):
            full_scan_repository(
                self.root / "does-not-exist"
            )


if __name__ == "__main__":
    unittest.main()
