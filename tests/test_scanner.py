import tempfile
import unittest
from pathlib import Path

from mizan.plugins import list_plugins, get_plugin
from mizan.scanner import scan_repository, render_html


class ScannerTests(unittest.TestCase):

    def create_project(self, root):
        (root / "app.py").write_text(
            "value = eval(user_input)\n"
            "# TODO: review this code\n",
            encoding="utf-8"
        )

    def test_plugin_registry(self):
        plugins = list_plugins()
        names = {plugin["name"] for plugin in plugins}

        self.assertIn("security", names)
        self.assertIn("quality", names)

    def test_plugin_info(self):
        plugin = get_plugin("security")

        self.assertEqual(plugin["category"], "security")
        self.assertTrue(plugin["trusted_builtin"])

    def test_unknown_plugin(self):
        with self.assertRaises(ValueError):
            get_plugin("unknown")

    def test_security_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_project(root)

            result = scan_repository(root, "security")

            self.assertEqual(len(result["plugins"]), 1)
            self.assertEqual(
                result["plugins"][0]["name"], "security"
            )
            self.assertTrue(
                all(
                    item["rule"] != "todo"
                    for item in result["findings"]
                )
            )

    def test_quality_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_project(root)

            result = scan_repository(root, "quality")

            self.assertTrue(
                any(
                    item["rule"] == "todo"
                    for item in result["findings"]
                )
            )

    def test_all_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_project(root)

            result = scan_repository(root)

            self.assertEqual(len(result["plugins"]), 2)
            self.assertGreaterEqual(result["findings_count"], 2)
            self.assertEqual(result["mode"], "read-only")
            self.assertFalse(result["execution_performed"])

    def test_invalid_category(self):
        with self.assertRaises(ValueError):
            scan_repository(".", "unknown")

    def test_html_escapes_untrusted_content(self):
        report = {
            "repository": "<script>alert(1)</script>",
            "files_scanned": 1,
            "findings_count": 1,
            "findings": [{
                "severity": "high",
                "rule": "test",
                "file": "<script>.py",
                "line": 1,
                "message": "<script>alert(1)</script>",
            }],
        }

        rendered = render_html(report)

        self.assertNotIn(
            "<script>alert(1)</script>", rendered
        )
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
