"""Documentation Intelligence — acceptance tests (v0.10.0).

Every rule gets positive coverage (the defect IS reported) and negative
coverage (clean documentation produces NO finding) — the same precision
contract tests/test_detection_suite.py enforces for the security rules.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mizan.cli import full_scan_repository
from mizan.doc_intel import (
    render_doc_intel_text,
    scan_documentation_repository,
)

README = """# Demo

## Usage

Read the [Guide](docs/guide.md) and the [Self link](README.md#usage).
Broken target: [Missing](nope.md). Bad anchor: [Bad](README.md#no-such-section).

The code lives in `src/app.py` and the ghost `src/gone.py` used to work.
Call `public_helper()` and never `ghost_function()`.

```bash
bash scripts/exists.sh
bash scripts/missing.sh
```

## API

- `GET /items` — list items.
"""

GUIDE = """# Guide

Deep dive into [the app module](../src/app.py).

More details live in `src/app.py` itself.
"""

APP = '''"""Application module used by the documentation tests."""

app = object()


def public_helper():
    """Return a helpful value for all callers."""
    return "help"


def undocumented_public():
    return 42


def _private_thing():
    return 0


@app.get("/items")
def list_items():
    """List items — documented in the README."""
    return []


@app.get("/secret-things")
def secret_things():
    """Hidden endpoint, absent from every document."""
    return []
'''

ORPHAN = '''"""A module no document ever mentions."""


def lonely_function():
    """Nobody links here from any document."""
    return 1
'''

TEST_APP = '''
def test_uncovered_by_docstring_logic():
    """Tests are excluded from coverage — this must not be counted."""
    assert True


def test_undocumented_anyway():
    assert True
'''


def build_repo(root, with_readme=True):
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(exist_ok=True)
    (root / "scripts").mkdir(exist_ok=True)
    (root / "tests").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text(APP, encoding="utf-8")
    (root / "src" / "orphan.py").write_text(ORPHAN, encoding="utf-8")
    (root / "tests" / "test_app.py").write_text(TEST_APP, encoding="utf-8")
    (root / "scripts" / "exists.sh").write_text("echo ok\n", encoding="utf-8")
    (root / "docs" / "guide.md").write_text(GUIDE, encoding="utf-8")
    if with_readme:
        (root / "README.md").write_text(README, encoding="utf-8")


def rules_of(section):
    return {f["rule"] for f in section["findings"]}


def findings_of(section, rule):
    return [f for f in section["findings"] if f["rule"] == rule]


class DocIntelPositiveTests(unittest.TestCase):
    """Each defect IS caught."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        build_repo(cls.root)
        cls.section = scan_documentation_repository(str(cls.root))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_broken_link_target(self):
        targets = [
            f["message"]
            for f in findings_of(self.section, "doc-broken-link")
        ]
        self.assertTrue(
            any("nope.md" in m for m in targets),
            f"missing link target not reported: {targets}",
        )

    def test_broken_anchor(self):
        targets = [
            f["message"]
            for f in findings_of(self.section, "doc-broken-link")
        ]
        self.assertTrue(
            any("#no-such-section" in m for m in targets),
            f"bad anchor not reported: {targets}",
        )

    def test_stale_path_reference(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-stale-reference")
        ]
        self.assertTrue(
            any("src/gone.py" in m for m in messages),
            f"stale path not reported: {messages}",
        )

    def test_stale_symbol_reference(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-stale-reference")
        ]
        self.assertTrue(
            any("ghost_function" in m for m in messages),
            f"stale symbol not reported: {messages}",
        )

    def test_undocumented_endpoint(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-undocumented-endpoint")
        ]
        self.assertTrue(
            any("/secret-things" in m for m in messages),
            f"undocumented endpoint not reported: {messages}",
        )

    def test_missing_docstring(self):
        files = [
            (f["file"], f["message"])
            for f in findings_of(self.section, "doc-missing-docstring")
        ]
        self.assertTrue(
            any(
                f.endswith("app.py") and "undocumented_public" in m
                for f, m in files
            ),
            f"missing docstring not reported: {files}",
        )

    def test_readme_command_missing_file(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-readme-quality")
        ]
        self.assertTrue(
            any("scripts/missing.sh" in m for m in messages),
            f"bad README command not reported: {messages}",
        )

    def test_orphan_code(self):
        files = [
            f["file"] for f in findings_of(self.section, "doc-orphan-code")
        ]
        self.assertIn("src/orphan.py", files)
        self.assertNotIn("src/app.py", files)

    def test_doc_code_map(self):
        mapping = self.section["metrics"]["doc_code_map"]
        self.assertIn("README.md", mapping)
        self.assertIn("src/app.py", mapping["README.md"])
        self.assertIn("docs/guide.md", mapping)
        self.assertIn("src/app.py", mapping["docs/guide.md"])

    def test_metrics(self):
        m = self.section["metrics"]
        self.assertEqual(m["docs_found"], 2)
        self.assertEqual(m["broken_links"], 2)
        self.assertEqual(m["endpoints_total"], 2)
        self.assertEqual(m["endpoints_documented"], 1)
        self.assertEqual(m["public_symbols_python"], 5)
        self.assertEqual(m["documented_symbols"], 4)
        self.assertEqual(m["docstring_coverage_pct"], 80.0)
        self.assertEqual(m["doc_coverage_pct"], 50.0)


class DocIntelNegativeTests(unittest.TestCase):
    """Clean documentation is NOT flagged (precision contract)."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        build_repo(cls.root)
        cls.section = scan_documentation_repository(str(cls.root))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_valid_links_not_flagged(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-broken-link")
        ]
        self.assertFalse(any("docs/guide.md" in m for m in messages))
        self.assertFalse(any("#usage" in m for m in messages))

    def test_valid_path_and_symbol_not_flagged(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-stale-reference")
        ]
        self.assertFalse(any("src/app.py" in m for m in messages))
        self.assertFalse(any("public_helper" in m for m in messages))

    def test_documented_endpoint_not_flagged(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-undocumented-endpoint")
        ]
        self.assertFalse(any("/items" in m for m in messages))

    def test_tests_dir_excluded_from_coverage(self):
        files = [
            f["file"]
            for f in findings_of(self.section, "doc-missing-docstring")
        ]
        self.assertFalse(
            any("test_app" in f for f in files),
            "test fixtures must not count toward docstring coverage",
        )

    def test_private_and_builtin_symbols_skipped(self):
        messages = " ".join(
            f["message"]
            for f in findings_of(self.section, "doc-stale-reference")
        )
        self.assertNotIn("_private_thing", messages)

    def test_existing_script_not_flagged(self):
        messages = [
            f["message"]
            for f in findings_of(self.section, "doc-readme-quality")
        ]
        self.assertFalse(any("scripts/exists.sh" in m for m in messages))

    def test_pattern_vocabulary_symbols_not_flagged(self):
        """Docs quoting rule patterns (`execute()`, `X.system()`) describe
        constructs, not repo symbols — never stale references."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text(
                '"""M."""\n\n\ndef real_one():\n    """D."""\n    return 1\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# R\n\nThe rule fires on `execute()` and on "
                "`platform.system()` and `re.compile()` patterns.\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            messages = " ".join(
                f["message"]
                for f in findings_of(section, "doc-stale-reference")
            )
            self.assertEqual(
                findings_of(section, "doc-stale-reference"), [],
                f"pattern vocabulary flagged as stale: {messages}",
            )

    def test_directory_pattern_mentions_not_flagged(self):
        """Changelog prose naming exclusion trees (`vendor/`, `i18n/`) is
        vocabulary, not a file claim."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# R\n\n## Install\n\nNow skips `tests/`, `vendor/`, "
                "`__tests__/` and `i18n/` trees entirely.\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            self.assertEqual(
                findings_of(section, "doc-stale-reference"), [],
            )

    def test_output_redirection_not_flagged(self):
        """`--output reports/x.json` CREATES the file — never judged."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# R\n\n## Usage\n\n```bash\nmizan analyze . "
                "--output reports/analysis.json\n```\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            messages = [
                f["message"]
                for f in findings_of(section, "doc-readme-quality")
            ]
            self.assertFalse(
                any("reports/analysis.json" in m for m in messages),
                f"output path flagged: {messages}",
            )

    def test_fenced_code_examples_not_judged(self):
        """Illustrative python examples inside fenced blocks are demo
        content, not symbol claims — never stale references."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# R\n\nExample:\n\n```python\n"
                "from mizan import analyze_repository\n"
                "report = analyze_repository('demo_project')\n"
                "print(report)\n```\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            self.assertEqual(
                findings_of(section, "doc-stale-reference"), [],
            )

    def test_external_links_counted_but_never_judged(self):
        """External URLs are counted as skipped; a network failure can
        never be misread as a broken link (no network is contacted)."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# R\n\nSee the [site](https://example.com/does-not-exist) "
                "and [mail](mailto:nobody@nowhere.invalid).\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            self.assertEqual(
                section["metrics"]["external_links_skipped"], 2
            )
            self.assertEqual(
                findings_of(section, "doc-broken-link"), []
            )

    def test_em_dash_heading_and_explicit_html_anchor(self):
        r"""Audited FP: ``#### \`agent/request\` — waterfall`` has GitHub
        slug ``agentrequest--waterfall`` (em-dash removed, spaces NOT
        collapsed), and an explicit ``<a id=...>`` anchor is valid by
        construction. Neither may be reported broken."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "docs").mkdir()
            (root / "docs" / "core.md").write_text(
                "# Core\n\n"
                "<a id=\"agentrequest--waterfall\"></a>\n\n"
                "#### `agent/request` — waterfall\n\n"
                "#### `approval/request` — waterfall\n\n"
                "## Foo - Bar\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# R\n\n"
                "[a](docs/core.md#agentrequest--waterfall) "
                "[b](docs/core.md#approvalrequest--waterfall) "
                "[c](docs/core.md#foo---bar) "
                "[broken](docs/core.md#nope)\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            broken = findings_of(section, "doc-broken-link")
            self.assertEqual(len(broken), 1, str(broken))
            self.assertIn("#nope", broken[0]["message"])

    def test_fenced_markdown_links_and_custom_schemes(self):
        """Audited FP: a markdown-link SYNTAX EXAMPLE inside a ```ts
        fence (`@[label](dsh-session:…)`) is demo material, not a link;
        custom URI schemes (dsh-session:) are not repo paths."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# R\n\n"
                "```ts\n"
                "/** Canonical `@[label](dsh-session:…)` mention. */\n"
                "```\n\n"
                "Mentions look like [label](dsh-session:abc123) in text.\n"
                "[Broken](nope.md) is still judged.\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            broken = [
                f["message"]
                for f in findings_of(section, "doc-broken-link")
            ]
            self.assertEqual(len(broken), 1, str(broken))
            self.assertIn("nope.md", broken[0])
            self.assertEqual(
                findings_of(section, "doc-stale-reference"), []
            )

    def test_local_vs_external_wording(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text(
                "# R\n\n[Broken](nope.md)\n", encoding="utf-8"
            )
            section = scan_documentation_repository(str(root))
            broken = findings_of(section, "doc-broken-link")
            self.assertTrue(
                any("Local link target" in f["message"] for f in broken)
            )

    def test_bash_fence_paths_precision(self):
        """Extension-less dir args in EXAMPLE paths are skipped; a named
        script file that does not exist IS flagged."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            (root / "scripts" / "deploy.sh").write_text(
                "echo ok\n", encoding="utf-8"
            )
            (root / "README.md").write_text(
                "# R\n\n## Usage\n\n```bash\n"
                "mizan scan /path/to/any/project\n"
                "bash scripts/deploy.sh\n"
                "bash scripts/ghost.sh\n"
                "```\n",
                encoding="utf-8",
            )
            section = scan_documentation_repository(str(root))
            messages = [
                f["message"]
                for f in findings_of(section, "doc-readme-quality")
            ]
            self.assertFalse(
                any("/path/to/any/project" in m for m in messages),
                f"example dir path flagged: {messages}",
            )
            self.assertFalse(
                any("scripts/deploy.sh" in m for m in messages)
            )
            self.assertTrue(
                any("scripts/ghost.sh" in m for m in messages),
                f"missing script not flagged: {messages}",
            )

    def test_section_shape_read_only(self):
        section = self.section
        self.assertEqual(section["mode"], "read-only")
        self.assertFalse(section["execution_performed"])
        self.assertEqual(
            section["findings_count"], len(section["findings"])
        )
        self.assertIn("doc_code_map", section["metrics"])


class DocIntelEdgeTests(unittest.TestCase):
    def test_no_readme_medium_finding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            section = scan_documentation_repository(str(root))
            readme = findings_of(section, "doc-readme-quality")
            self.assertTrue(
                any("No README" in f["message"] for f in readme)
            )
            self.assertTrue(
                any(f["severity"] == "medium" for f in readme)
            )

    def test_non_git_repo_change_impact_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build_repo(root)
            section = scan_documentation_repository(str(root))
            self.assertFalse(
                section["metrics"]["git_change_impact_available"]
            )
            self.assertEqual(
                findings_of(section, "doc-needs-review"), []
            )

    def test_stale_reference_cap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            lines = ["# Cap repo", ""]
            for i in range(35):
                lines.append(f"See `ghost/dir{i}/missing.py` here.")
            (root / "README.md").write_text("\n".join(lines), encoding="utf-8")
            section = scan_documentation_repository(str(root))
            self.assertEqual(
                len(findings_of(section, "doc-stale-reference")), 30
            )

    def test_git_change_impact_flags_stale_doc(self):
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                build_repo(root)
                def git(*args):
                    return subprocess.run(
                        ["git", "-C", str(root)] + list(args),
                        capture_output=True, text=True, check=True,
                    )
                git("init", "-q")
                git("-c", "user.email=t@t", "-c", "user.name=t",
                    "add", "-A")
                old_env = {
                    **os.environ,
                    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00",
                    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00",
                }
                subprocess.run(
                    ["git", "-C", str(root), "-c", "user.email=t@t",
                     "-c", "user.name=t", "commit", "-qm", "docs first"],
                    capture_output=True, text=True, check=True, env=old_env,
                )
                # code changes AFTER the docs were written
                (root / "src" / "app.py").write_text(
                    APP + "\n# changed later\n", encoding="utf-8"
                )
                git("-c", "user.email=t@t", "-c", "user.name=t",
                    "add", "-A")
                git("-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "code changed")
                section = scan_documentation_repository(str(root))
                self.assertTrue(
                    section["metrics"]["git_change_impact_available"]
                )
                flagged = findings_of(section, "doc-needs-review")
                self.assertTrue(
                    any(
                        "app.py" in f["message"]
                        and f["file"] == "docs/guide.md"
                        for f in flagged
                    ),
                    f"stale-after-change doc not flagged: {flagged}",
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            self.skipTest("git unavailable")

    def test_invalid_directory_raises(self):
        with self.assertRaises(ValueError):
            scan_documentation_repository("/no/such/dir/anywhere")

    def test_text_renderer(self):
        rendered = render_doc_intel_text(self._section_fixture())
        self.assertIn("Findings by rule:", rendered)
        self.assertIn("MIZAN Documentation Intelligence", rendered)

    @staticmethod
    def _section_fixture():
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build_repo(root)
            return scan_documentation_repository(str(root))


class DocIntelAuditWaveTests(unittest.TestCase):
    """Independent-audit wave: the six pre-approval review points."""

    # -- A2: API discovery (dynamic routes, routers, decorators) --------

    def _endpoint_repo(self, root, app_source, readme):
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "src" / "api.py").write_text(app_source, encoding="utf-8")
        (root / "README.md").write_text(readme, encoding="utf-8")

    def test_dynamic_routes_and_routers_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._endpoint_repo(
                root,
                '''"""API."""\n\napp = object()\nrouter = object()\n\n\n@router.get("/users/{user_id}")\ndef get_user(user_id):\n    """Return one user."""\n    return user_id\n\n\n@app.get("/health", response_model=None)\ndef health():\n    """Health probe."""\n    return "ok"\n\n\n@app.route("/dashboard", methods=["GET", "POST"])\ndef dashboard():\n    """Dashboard view."""\n    return "d"\n\n\n@router.delete("/orders/:order_id/cancel")\ndef cancel(order_id):\n    """Cancel an order."""\n    return order_id\n''',
                "# R\n\n## Usage\n\nThe API exposes /health.\n",
            )
            section = scan_documentation_repository(str(root))
            messages = [
                f["message"]
                for f in findings_of(
                    section, "doc-undocumented-endpoint"
                )
            ]
            # documented via its static prefix "/health" in README
            self.assertFalse(any("/health" in m for m in messages))
            # dynamic routes are discovered with their full path
            self.assertTrue(
                any("/users/{user_id}" in m for m in messages),
                f"dynamic route missed: {messages}",
            )
            self.assertTrue(
                any("/dashboard" in m for m in messages),
                f"Flask route missed: {messages}",
            )
            self.assertTrue(
                any("/orders/:order_id/cancel" in m for m in messages),
                f"express-style route missed: {messages}",
            )
            # Flask @route / Express .all() surface as ANY, not a fake verb
            dashboard = next(
                m for m in messages if "/dashboard" in m
            )
            self.assertIn("ANY", dashboard)

    def test_dynamic_route_counts_unjudgeable_not_undocumented(self):
        """A fully dynamic route ('/{path}') cannot be matched to docs —
        it is counted documented (skipped), never flagged."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._endpoint_repo(
                root,
                '''"""API."""\n\napp = object()\n\n\n@app.get("/{catch_all}")\ndef catch(catch_all):\n    """Catch everything."""\n    return catch_all\n''',
                "# R\n",
            )
            section = scan_documentation_repository(str(root))
            self.assertEqual(
                findings_of(section, "doc-undocumented-endpoint"), []
            )
            self.assertEqual(section["metrics"]["endpoints_total"], 1)
            self.assertEqual(
                section["metrics"]["endpoints_documented"], 1
            )

    # -- A3: docstring QUALITY (not mere presence) ----------------------

    def test_shallow_docstring_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text(
                '"""M."""\n\n\ndef one():\n    """TODO."""\n    return 1\n\n\ndef two():\n    """Do the real work for every caller."""\n    return 2\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text("# R\n\n## Usage\n\nrun it\n",
                                            encoding="utf-8")
            section = scan_documentation_repository(str(root))
            shallow = findings_of(section, "doc-shallow-docstring")
            self.assertTrue(
                any("'one'" in f["message"] for f in shallow),
                f"shallow docstring missed: {shallow}",
            )
            self.assertFalse(
                any("'two'" in f["message"] for f in shallow)
            )
            # coverage stays presence-based, quality is separate
            self.assertEqual(section["metrics"]["shallow_docstrings"], 1)

    def test_docstring_names_not_counted_as_quality(self):
        """A docstring that just repeats the symbol name is shallow."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "x.py").write_text(
                '"""M."""\n\n\ndef helper_thing():\n    """helper_thing."""\n    return 1\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text("# R\n\n## Usage\n\nrun\n",
                                            encoding="utf-8")
            section = scan_documentation_repository(str(root))
            shallow = findings_of(section, "doc-shallow-docstring")
            self.assertTrue(any("'helper_thing'" in f["message"]
                                for f in shallow))

    # -- A4: git change impact robustness -------------------------------

    def test_shallow_clone_degrades_to_safe_noop(self):
        """In a --depth 1 clone the doc's history is absent: doc_time is
        unknown → the doc is skipped, never flagged, never a crash."""
        try:
            with tempfile.TemporaryDirectory() as outer:
                base = Path(outer)
                full = base / "full"
                build_repo(full)

                def git(repo, *args, env=None):
                    return subprocess.run(
                        ["git", "-C", str(repo)] + list(args),
                        capture_output=True, text=True, check=True, env=env,
                    )

                git(full, "init", "-q")
                git(full, "-c", "user.email=t@t", "-c", "user.name=t",
                    "add", "-A")
                git(full, "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "all")
                (full / "src" / "app.py").write_text(
                    APP + "\n# later change\n", encoding="utf-8"
                )
                git(full, "-c", "user.email=t@t", "-c", "user.name=t",
                    "add", "-A")
                git(full, "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "change code")
                shallow_dir = base / "shallow"
                subprocess.run(
                    ["git", "clone", "-q", "--depth", "1",
                     f"file://{full}", str(shallow_dir)],
                    capture_output=True, text=True, check=True,
                )
                # precondition lock: --depth is silently IGNORED in local
                # path clones (git advises file://) — a plain-path clone
                # here yields FULL history, doc_time < commit_time, and
                # the test then flakes whenever its two commits straddle
                # a wall-clock second (CI Python 3.13 run #94 hit that).
                self.assertTrue(
                    (shallow_dir / ".git" / "shallow").exists(),
                    "test precondition: clone must actually be shallow",
                )
                section = scan_documentation_repository(str(shallow_dir))
                self.assertTrue(
                    section["metrics"]["git_change_impact_available"]
                )
                self.assertEqual(
                    findings_of(section, "doc-needs-review"), [],
                    "shallow clone must not guess stale docs",
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            self.skipTest("git unavailable")

    def test_unborn_head_is_safe(self):
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                build_repo(root)
                subprocess.run(
                    ["git", "init", "-q", str(root)],
                    capture_output=True, text=True, check=True,
                )  # git init, zero commits
                section = scan_documentation_repository(str(root))
                self.assertFalse(
                    section["metrics"]["git_change_impact_available"]
                )
                self.assertEqual(
                    findings_of(section, "doc-needs-review"), []
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            self.skipTest("git unavailable")

    # -- A6: parallel-scanner isolation ---------------------------------

    def test_doc_scanner_failure_isolated_in_full_scan(self):
        from unittest.mock import patch
        import mizan.cli as cli_mod

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build_repo(root)
            with patch(
                "mizan.cli.scan_documentation_repository",
                side_effect=RuntimeError("boom"),
            ):
                full = cli_mod.full_scan_repository(str(root), jobs=1)
            self.assertIn("documentation", full["scanners_failed"])
            self.assertIn("boom", full["documentation"]["error"])
            self.assertFalse(
                full["documentation"]["execution_performed"]
            )
            # every other scanner survives
            self.assertIn("analysis", full)
            self.assertIn("detection", full)
            self.assertEqual(
                full["analysis"]["engine"], "MIZAN AST Analyzer"
            )


class DocIntelIntegrationTests(unittest.TestCase):
    def test_full_scan_includes_documentation_section(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build_repo(root)
            full = full_scan_repository(str(root), jobs=1)
            self.assertIn("documentation", full)
            self.assertEqual(
                full["documentation"]["engine"],
                "MIZAN Documentation Intelligence",
            )
            self.assertEqual(full["documentation"]["mode"], "read-only")

    def test_cli_json_and_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build_repo(root)
            for fmt, checker in (
                ("json", self._check_json),
                ("text", self._check_text),
            ):
                result = subprocess.run(
                    [sys.executable, "-m", "mizan.cli", "doc-scan",
                     str(root), "--format", fmt],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                checker(result.stdout)

    @staticmethod
    def _check_json(stdout):
        payload = json.loads(stdout)
        assert payload["engine"] == "MIZAN Documentation Intelligence"
        assert "findings" in payload

    @staticmethod
    def _check_text(stdout):
        assert "Findings by rule:" in stdout
        assert "Docstring coverage" in stdout


if __name__ == "__main__":
    unittest.main()
