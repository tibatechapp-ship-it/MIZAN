import tempfile
import unittest
from pathlib import Path

from mizan.detector import detect_project


class DetectorTests(unittest.TestCase):

    def test_detects_python(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pyproject.toml").write_text(
                "[project]\nname='demo'\n",
                encoding="utf-8"
            )
            (root / "main.py").write_text(
                "print('hello')\n",
                encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertIn("Python", result["languages"])
            self.assertIn("Ruff", result["suggested_tools"])

    def test_detects_react(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text(
                '{"dependencies":{"react":"^19.0.0"}}',
                encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertIn("JavaScript", result["languages"])
            self.assertIn("React", result["frameworks"])

    def test_ignores_virtual_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ignored = root / ".venv"
            ignored.mkdir()
            (ignored / "hidden.py").write_text(
                "pass", encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertNotIn("Python", result["languages"])
            self.assertEqual(result["files_discovered"], 0)

    def test_invalid_path(self):
        with self.assertRaises(ValueError):
            detect_project("/mizan/path/that/does/not/exist")


if __name__ == "__main__":
    unittest.main()
