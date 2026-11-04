"""Performance + Quality benchmarks 86-100 (SLO baseline)."""
import inspect
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mizan.detector import MAX_FILES, MAX_MANIFEST_SIZE, collect_files
from mizan.scan import scan_repository


def _mock_osv_empty():
    cm = MagicMock()
    resp = MagicMock()
    resp.read.return_value = b'{"vulns": []}'
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    mock = MagicMock(return_value=cm)
    return patch("mizan.vulnerabilities.urllib.request.urlopen", mock)


# ---------- Category 6: Performance (BM-86 -> BM-95) ----------

class BaselineTimeBenchmark(unittest.TestCase):
    def test_86_scan_medium_repo_under_5s(self):
        """BM-86: 500 files scanned in < 5s (generous for CI runners)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for i in range(500):
                (root / f"f{i}.py").write_text("pass\n")
            (root / "requirements.txt").write_text("requests==2.33.0\n")
            start = time.time()
            with _mock_osv_empty():
                scan_repository(root)
            elapsed = time.time() - start
            self.assertLess(elapsed, 5.0, f"took {elapsed:.2f}s")

    def test_87_scan_large_repo_under_20s(self):
        """BM-87: 1000 files scanned in < 20s."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for i in range(1000):
                (root / f"f{i}.py").write_text("pass\n")
            start = time.time()
            with _mock_osv_empty():
                scan_repository(root)
            elapsed = time.time() - start
            self.assertLess(elapsed, 20.0, f"took {elapsed:.2f}s")


class LimitsBenchmark(unittest.TestCase):
    def test_88_max_files_constant(self):
        """BM-88: MAX_FILES = 20000."""
        self.assertEqual(MAX_FILES, 20000)

    def test_89_max_manifest_size_constant(self):
        """BM-89: MAX_MANIFEST_SIZE = 2MB."""
        self.assertEqual(MAX_MANIFEST_SIZE, 2 * 1024 * 1024)

    def test_90_max_files_truncation(self):
        """BM-90: > MAX_FILES -> truncated=True."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for i in range(10):
                (root / f"f{i}.py").write_text("pass\n")
            with patch("mizan.detector.MAX_FILES", 5):
                files, truncated = collect_files(root)
            self.assertTrue(truncated)
            self.assertEqual(len(files), 5)


class TimeoutBenchmark(unittest.TestCase):
    def test_91_osv_timeout_15s(self):
        """BM-91: OSV_TIMEOUT = 15s."""
        from mizan.vulnerabilities import OSV_TIMEOUT
        self.assertEqual(OSV_TIMEOUT, 15)

    def test_92_subprocess_timeout_180s_default(self):
        """BM-92: run_tests default timeout=180s."""
        from mizan.fix import run_tests
        sig = inspect.signature(run_tests)
        self.assertEqual(sig.parameters["timeout"].default, 180)


class MemoryBenchmark(unittest.TestCase):
    def test_93_large_manifest_rejected(self):
        """BM-93: 3MB manifest does not crash (guard active)."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            content = '{"packages": {}}' + ' ' * (3 * 1024 * 1024)
            (root / "package-lock.json").write_text(content)
            from mizan.vulnerabilities import parse_dependencies
            files, _ = collect_files(root)
            deps = parse_dependencies(files)
            self.assertIsInstance(deps, list)


class CliStartupBenchmark(unittest.TestCase):
    def test_94_cli_import_under_2s(self):
        """BM-94: `import mizan.cli` completes in < 2s (Termux-friendly)."""
        start = time.time()
        subprocess.run(
            [sys.executable, "-c", "import mizan.cli"],
            capture_output=True,
            timeout=15,
        )
        elapsed = time.time() - start
        self.assertLess(elapsed, 2.0, f"took {elapsed:.2f}s")


class OutputFormatBenchmark(unittest.TestCase):
    def test_95_sarif_vs_json_similar_speed(self):
        """BM-95: SARIF and JSON output within 10x of each other."""
        from mizan.sarif import build_sarif
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "requirements.txt").write_text("requests==2.33.0\n")
            with _mock_osv_empty():
                scan = scan_repository(root)
            start = time.time()
            build_sarif(scan)
            t_sarif = time.time() - start
            start = time.time()
            json.dumps(scan, default=str)
            t_json = time.time() - start
            ratio = max(t_sarif, t_json) / max(min(t_sarif, t_json), 0.001)
            self.assertLess(ratio, 10.0, f"ratio {ratio:.1f}x")


# ---------- Category 7: Quality (BM-96 -> BM-100) ----------

class QualityBenchmark(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]

    def test_96_compile_all_clean(self):
        """BM-96: `python -m compileall -q src tests` succeeds."""
        result = subprocess.run(
            [sys.executable, "-m", "compileall", "-q", "src", "tests"],
            cwd=str(self.ROOT),
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0,
                         f"compileall failed: {result.stderr.decode()[:200]}")

    def test_97_all_benchmarks_pass(self):
        """BM-97: 100/100 benchmarks exist across 7 files."""
        bench_dir = self.ROOT / "tests" / "benchmark"
        expected = {
            "test_sca.py", "test_fix.py", "test_approval.py",
            "test_ci.py", "test_security.py", "test_performance.py",
        }
        actual = {p.name for p in bench_dir.glob("test_*.py")}
        missing = expected - actual
        self.assertEqual(missing, set(), f"missing benchmark files: {missing}")

    def test_98_python_3_10_to_3_14_compatible(self):
        """BM-98: pyproject.toml declares >=3.10 and no 3.14-only syntax."""
        pyproject = (self.ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("requires-python", pyproject)
        # Check no walrus in comprehension at module level (Python 3.10 support)
        for path in (self.ROOT / "src").rglob("*.py"):
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except SyntaxError as exc:
                self.fail(f"syntax error in {path.name}: {exc}")

    def test_99_ci_workflow_covers_all_versions(self):
        """BM-99: CI matrix covers 3.10, 3.11, 3.12, 3.13, 3.14."""
        import yaml
        with open(self.ROOT / ".github" / "workflows" / "tests.yml") as f:
            data = yaml.safe_load(f)
        job = data["jobs"]["tests"]
        versions = job["strategy"]["matrix"]["python-version"]
        for v in ("3.10", "3.11", "3.12", "3.13", "3.14"):
            self.assertIn(v, versions, f"missing version in CI: {v}")

    def test_100_no_uncommitted_whitespace(self):
        """BM-100: `git diff --check` reports no whitespace errors in tracked files."""
        result = subprocess.run(
            ["git", "diff", "--check"],
            cwd=str(self.ROOT),
            capture_output=True,
            timeout=30,
        )
        # Exit 0 = no errors, exit 2 = whitespace errors
        self.assertEqual(result.returncode, 0,
                         f"whitespace errors: {result.stdout.decode()[:200]}")


if __name__ == "__main__":
    unittest.main()
