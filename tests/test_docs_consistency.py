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


class ActionDocsTests(unittest.TestCase):
    """E-01/E-04 (2026-11-17 review): the action README pinned an old
    release while the root README pinned the current one, and new inputs
    could ship undocumented. These checks derive the expected stable
    version from the CHANGELOG instead of hardcoding it, so the gate
    itself can never go stale."""

    def _current_stable(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        for m in re.finditer(r"^## \[(\d+\.\d+\.\d+)(-dev)?\]",
                             changelog, re.MULTILINE):
            if not m.group(2):  # skip -dev cycle headings
                return m.group(1)
        self.fail("CHANGELOG has no stable version heading")

    def test_action_readme_pins_current_stable(self):
        stable = self._current_stable()
        doc = (ROOT / "action" / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            f"tibatechapp-ship-it/MIZAN/action@v{stable}", doc,
            "action/README.md usage example pins an outdated release — "
            "update it to the current stable tag (E-04)")

    def test_security_md_lists_current_stable_branch(self):
        stable = self._current_stable()
        branch = stable.rsplit(".", 1)[0] + ".x"
        doc = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        count = doc.count(f"| {branch} |")
        self.assertGreaterEqual(
            count, 2,
            "SECURITY.md supported-versions tables (Arabic + English) "
            "must both list the current stable branch " + branch)

    def test_action_inputs_are_all_documented(self):
        yml = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
        doc = (ROOT / "action" / "README.md").read_text(encoding="utf-8")
        inputs_section = yml.split("inputs:", 1)[1].split("outputs:", 1)[0]
        names = re.findall(r"^  ([a-z][a-z0-9-]*):\s*$",
                           inputs_section, re.MULTILINE)
        self.assertTrue(names, "action.yml must declare inputs")
        for name in names:
            self.assertIn(f"| {name} ", doc,
                          f"input `{name}` exists in action.yml but is "
                          "missing from action/README.md — undocumented "
                          "inputs are exactly the drift E-04 flagged")

    def test_explicit_failure_inputs_exist(self):
        yml = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("fail-on-fix-error", yml)
        self.assertIn("fail-on-pr-error", yml)
        self.assertNotIn(
            '|| echo "::warning::MIZAN fix encountered an issue"',
            yml,
            "silent || echo warning swallow must never return (E-01)")


class AccuracyScopeTests(unittest.TestCase):
    """E-02/E-05 (2026-11-17 review): corpus numbers must stay separated
    from field claims, and repair verification must never be presented
    as a sandbox."""

    def test_readme_keeps_accuracy_scope_separation(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "Not yet measured", readme,
            "README must keep the unmeasured-limits disclosure (E-02)")
        self.assertIn(
            "Do not extrapolate the", readme,
            "README must warn against extrapolating corpus results")

    def test_repair_isolation_is_not_sold_as_a_sandbox(self):
        cli = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")
        self.assertIn(
            "Isolation is NOT a sandbox", cli,
            "docs/CLI.md must keep the explicit not-a-sandbox wording "
            "(E-05)")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "not a container sandbox", readme,
            "README must describe verify-repair isolation precisely")


if __name__ == "__main__":
    unittest.main()
