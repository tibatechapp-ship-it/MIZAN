import tempfile
import unittest
from pathlib import Path

from mizan.ci_scanner import scan_ci_repository


class CIScannerTests(unittest.TestCase):

    def test_detects_github_workflow(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / ".github/workflows"
            workflow.mkdir(parents=True)

            (workflow / "ci.yml").write_text(
                "name: CI\n"
                "on: push\n"
                "permissions: write-all\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n",
                encoding="utf-8"
            )

            result = scan_ci_repository(root)

            self.assertEqual(result["files_scanned"], 1)
            self.assertTrue(any(
                f["rule"] == "excessive-permissions"
                for f in result["findings"]
            ))

    def test_detects_gitlab(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            (root / ".gitlab-ci.yml").write_text(
                "job:\n"
                "  script:\n"
                "    - echo test\n",
                encoding="utf-8"
            )

            result = scan_ci_repository(root)
            self.assertEqual(result["files_scanned"], 1)

    def test_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / ".github/workflows"
            workflow.mkdir(parents=True)

            (workflow / "broken.yml").write_text(
                "jobs:\n  test: [invalid\n",
                encoding="utf-8"
            )

            result = scan_ci_repository(root)

            self.assertTrue(any(
                f["rule"] == "invalid-yaml"
                for f in result["findings"]
            ))

    def test_ignores_unrelated_yaml(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "config.yml").write_text(
                "name: example\n",
                encoding="utf-8"
            )

            result = scan_ci_repository(root)
            self.assertEqual(result["files_scanned"], 0)

    def test_invalid_directory(self):
        with self.assertRaises(ValueError):
            scan_ci_repository("/path/that/does/not/exist")

    def test_read_only_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            result = scan_ci_repository(temp)

            self.assertEqual(result["mode"], "read-only")
            self.assertFalse(result["execution_performed"])


if __name__ == "__main__":
    unittest.main()
