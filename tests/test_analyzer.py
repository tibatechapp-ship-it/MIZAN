import tempfile
import unittest
from pathlib import Path

from mizan.analyzer import analyze_repository


class AnalyzerTests(unittest.TestCase):

    def test_detects_eval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.py").write_text(
                "result = eval(user_input)\n",
                encoding="utf-8",
            )

            result = analyze_repository(str(root))

            self.assertEqual(result["files_scanned"], 1)
            self.assertTrue(
                any(
                    item["rule"] == "dynamic-execution"
                    for item in result["findings"]
                )
            )

    def test_ignores_non_source_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "notes.txt").write_text(
                "eval(x)", encoding="utf-8"
            )

            result = analyze_repository(str(root))
            self.assertEqual(result["files_scanned"], 0)

    def test_ignores_git_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            git_dir = root / ".git"
            git_dir.mkdir()

            (git_dir / "hidden.py").write_text(
                "eval(x)", encoding="utf-8"
            )

            result = analyze_repository(str(root))
            self.assertEqual(result["files_scanned"], 0)

    def test_detects_real_todo_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "sample.py").write_text(
                "# TODO: implement validation\n",
                encoding="utf-8",
            )

            result = analyze_repository(str(root))

            self.assertTrue(
                any(
                    item["rule"] == "todo"
                    for item in result["findings"]
                )
            )

    def test_ignores_todo_pattern_definition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / "analyzer.py").write_text(
                'TODO_PATTERN = re.compile(r"\\b(TODO|FIXME|XXX)\\b")\n',
                encoding="utf-8",
            )

            result = analyze_repository(str(root))

            self.assertFalse(
                any(
                    item["rule"] == "todo"
                    for item in result["findings"]
                )
            )


if __name__ == "__main__":
    unittest.main()
