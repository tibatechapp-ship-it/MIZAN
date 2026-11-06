import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mizan.dependency_scanner import scan_dependencies


def _offline_env(testcase):
    """Hermetic OSV: the RW-204 batch check resolves offline (deterministic
    offline-miss) instead of hitting the network inside unit tests."""
    old = os.environ.get("MIZAN_OFFLINE")
    os.environ["MIZAN_OFFLINE"] = "1"
    testcase.addCleanup(
        lambda: os.environ.pop("MIZAN_OFFLINE", None) if old is None
        else os.environ.__setitem__("MIZAN_OFFLINE", old)
    )


class DependencyScannerTests(unittest.TestCase):

    def setUp(self):
        _offline_env(self)

    def test_detects_requirements(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "requirements.txt").write_text(
                "requests>=2.0\nPyYAML==6.0\n",
                encoding="utf-8"
            )

            result = scan_dependencies(root)

            self.assertEqual(result["dependencies_count"], 2)

    def test_detects_package_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "package.json").write_text(
                json.dumps({
                    "dependencies": {"react": "^18.0.0"}
                }),
                encoding="utf-8"
            )

            result = scan_dependencies(root)

            self.assertEqual(result["dependencies_count"], 1)

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "package.json").write_text(
                "{invalid json",
                encoding="utf-8"
            )

            result = scan_dependencies(root)

            self.assertEqual(result["findings_count"], 1)

    def test_read_only_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            result = scan_dependencies(temp)

            self.assertEqual(result["mode"], "read-only")
            self.assertFalse(result["execution_performed"])

    def test_invalid_directory(self):
        with self.assertRaises(ValueError):
            scan_dependencies("/invalid/mizan/path")


if __name__ == "__main__":
    unittest.main()
