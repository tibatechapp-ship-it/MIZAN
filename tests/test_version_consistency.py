"""SEC-06 enforcement: every version surface must agree with _version.py."""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mizan import __version__  # noqa: E402
from mizan.sarif import TOOL_VERSION  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class VersionConsistencyTests(unittest.TestCase):
    def test_sarif_derives_from_single_source(self):
        self.assertEqual(TOOL_VERSION, __version__)

    def test_pyproject_agrees(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dynamic = [\"version\"]", text,
                      "pyproject must derive the version dynamically")
        self.assertIn('attr = "mizan._version.__version__"', text)

    def test_package_json_agrees(self):
        pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(pkg["version"], __version__)

    def test_website_badge_agrees(self):
        html = (ROOT / "website" / "index.html").read_text(encoding="utf-8")
        self.assertIn(f"v{__version__}", html)

    def test_readme_status_agrees(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(readme, rf"Version {re.escape(__version__)}")

    def test_changelog_has_entry(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"[{__version__}]", changelog)


if __name__ == "__main__":
    unittest.main()
