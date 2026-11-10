"""Docs-consistency gate (external review 2026-11-10, P0 adoption).

The review measured README publishing two different test counts (410 and 471)
while the suite was larger, and an unpinned `@main` Action example. This test
makes stale published numbers and unpinned examples fail CI instead of
relying on manual doc sweeps.

Counting rule: the number published in the README metrics table must equal
the size of the suite that verifies it (measured at runtime by discovery),
so the assertion can never drift from reality.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def measured_test_count():
    """Suite size as CI measures it: `unittest discover -s tests`."""
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"))
    return suite.countTestCases()


class DocsConsistencyTests(unittest.TestCase):
    def test_readme_suite_count_is_measured(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        m = re.search(r"\| Test suite \| \*\*(\d+) tests green\*\*", readme)
        self.assertIsNotNone(
            m, "README metrics table must publish the test-suite count")
        self.assertEqual(
            int(m.group(1)), measured_test_count(),
            "README test count is stale — update the metrics table to the "
            "measured suite size (this failure is the automated detector "
            "the 2026-11-10 review asked for)")

    def test_historical_counts_are_marked(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "tests green at the v0.14.0 tag", readme,
            "historical test counts must carry their release tag so "
            "readers cannot mistake them for the current size")

    def test_readme_action_example_is_pinned(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn(
            "tibatechapp-ship-it/MIZAN/action@main", readme,
            "Action examples must be pinned to a release tag, not @main "
            "(action/README.md pinning guidance)")
        self.assertRegex(
            readme, r"tibatechapp-ship-it/MIZAN/action@v\d+\.\d+\.\d+",
            "README must show at least one tag-pinned Action example")


if __name__ == "__main__":
    unittest.main()
