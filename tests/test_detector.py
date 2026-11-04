import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch
from mizan.detector import collect_files, detect_project, _read_python_dependencies


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

    def test_detects_fastapi_from_requirements(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text(
                "fastapi>=0.100.0\nuvicorn\n",
                encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertIn("FastAPI", result["frameworks"])

    def test_ignores_unrelated_next_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text(
                "The next step is to improve the project.\n",
                encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertNotIn("Next.js", result["frameworks"])

    def test_detects_trivy_for_dockerfile(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text(
                "FROM python:3.12-slim\n",
                encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertIn("Trivy", result["suggested_tools"])

    def test_invalid_package_json_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text(
                "{invalid json",
                encoding="utf-8"
            )

            result = detect_project(str(root))

            self.assertIsInstance(result, dict)
            self.assertEqual(result["frameworks"], [])


    def test_reads_poetry_dependencies_and_dev_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "pyproject.toml"
            manifest.write_text(
                "[tool.poetry.dependencies]\n"
                "python = '^3.12'\n"
                "fastapi = '^0.110'\n"
                "[tool.poetry.group.dev.dependencies]\n"
                "pytest = '^8.0'\n",
                encoding="utf-8",
            )

            names = _read_python_dependencies(manifest)

            self.assertIn("fastapi", names)
            self.assertIn("pytest", names)
            self.assertNotIn("python", names)

    def test_reads_pep508_extras_and_environment_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "requirements.txt"
            manifest.write_text(
                "fastapi[all]>=0.100; python_version >= '3.10'\n"
                "uvicorn[standard]==0.29\n"
                "httpx @ https://example.invalid/httpx.whl\n",
                encoding="utf-8",
            )

            names = _read_python_dependencies(manifest)

            self.assertEqual(names, {"fastapi", "uvicorn", "httpx"})

    def test_ignores_requirements_options_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "requirements.txt"
            manifest.write_text(
                "\n"
                "# project dependencies\n"
                "-r base.txt\n"
                "--index-url https://packages.example.invalid/simple\n"
                "-e .\n"
                "fastapi>=0.100  # web framework\n",
                encoding="utf-8",
            )

            names = _read_python_dependencies(manifest)

            self.assertEqual(names, {"fastapi"})

    def test_reads_pep621_optional_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "pyproject.toml"
            manifest.write_text(
                "[project]\n"
                "name = 'demo'\n"
                "dependencies = ['fastapi>=0.100']\n"
                "[project.optional-dependencies]\n"
                "test = ['httpx>=0.27', 'pytest>=8']\n",
                encoding="utf-8",
            )

            names = _read_python_dependencies(manifest)

            self.assertEqual(names, {"fastapi", "httpx", "pytest"})

    def test_invalid_pyproject_toml_returns_empty_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "pyproject.toml"
            manifest.write_text(
                "[project\nname = 'broken'\n",
                encoding="utf-8",
            )

            self.assertEqual(
                _read_python_dependencies(manifest),
                set(),
            )




    def test_does_not_detect_php_framework_from_package_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text(
                '{"dependencies":{"laravel/framework":"^11.0"}}',
                encoding="utf-8",
            )

            result = detect_project(str(root))

            self.assertNotIn("Laravel", result["frameworks"])

    def test_does_not_detect_javascript_framework_from_composer_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "composer.json").write_text(
                '{"require":{"react":"^19.0"}}',
                encoding="utf-8",
            )

            result = detect_project(str(root))

            self.assertNotIn("React", result["frameworks"])


    def test_suggests_tools_for_dart(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pubspec.yaml").write_text(
                "name: demo\\n",
                encoding="utf-8",
            )

            result = detect_project(str(root))

            self.assertIn("Dart", result["languages"])
            self.assertIn("dart analyze", result["suggested_tools"])
            self.assertIn("dart test", result["suggested_tools"])

    def test_suggests_tools_for_csharp(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Program.cs").write_text(
                "class Program {}\\n",
                encoding="utf-8",
            )

            result = detect_project(str(root))

            self.assertIn("C#", result["languages"])
            self.assertIn("dotnet format", result["suggested_tools"])
            self.assertIn("dotnet test", result["suggested_tools"])

    def test_suggests_tools_for_cpp(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.cpp").write_text(
                "int main() { return 0; }\\n",
                encoding="utf-8",
            )

            result = detect_project(str(root))

            self.assertIn("C/C++", result["languages"])
            self.assertIn("Clang-Tidy", result["suggested_tools"])
            self.assertIn("CTest", result["suggested_tools"])


    def test_collect_files_ignores_external_file_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "project"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()

            (root / "inside.py").write_text("pass", encoding="utf-8")
            target = outside / "secret.py"
            target.write_text("secret", encoding="utf-8")

            link = root / "external.py"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"File symlinks unavailable: {exc}")

            files, truncated = collect_files(root)

            self.assertIn(root / "inside.py", files)
            self.assertNotIn(link, files)
            self.assertFalse(truncated)

    def test_collect_files_ignores_external_directory_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "project"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()

            (root / "inside.py").write_text("pass", encoding="utf-8")
            (outside / "secret.py").write_text("secret", encoding="utf-8")

            link = root / "external"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Directory symlinks unavailable: {exc}")

            files, truncated = collect_files(root)

            self.assertIn(root / "inside.py", files)
            self.assertNotIn(link / "secret.py", files)
            self.assertFalse(truncated)

    def test_collect_files_respects_max_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            for name in ("a.py", "b.py", "c.py"):
                (root / name).write_text("pass", encoding="utf-8")

            with patch("mizan.detector.MAX_FILES", 2):
                files, truncated = collect_files(root)

            self.assertEqual(len(files), 2)
            self.assertTrue(truncated)

if __name__ == "__main__":
    unittest.main()
