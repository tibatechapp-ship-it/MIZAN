import subprocess
import tempfile
import unittest
from pathlib import Path

from mizan.risk_scanner import scan_change_risk


class RiskScannerTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        subprocess.run(
            ["git", "init", "-q", str(self.root)],
            check=True
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_repository_has_low_risk(self):
        result = scan_change_risk(self.root)

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["changed_files_count"], 0)

    def test_detects_changed_file(self):
        (self.root / "README.md").write_text(
            "MIZAN test",
            encoding="utf-8"
        )

        result = scan_change_risk(self.root)

        self.assertEqual(result["changed_files_count"], 1)
        self.assertGreater(result["risk_score"], 0)

    def test_read_only_metadata(self):
        result = scan_change_risk(self.root)

        self.assertEqual(result["mode"], "read-only")
        self.assertFalse(result["execution_performed"])

    def test_invalid_directory(self):
        with self.assertRaises(ValueError):
            scan_change_risk("/invalid/mizan/path")

    def test_rejects_non_git_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                scan_change_risk(directory)


if __name__ == "__main__":
    unittest.main()
