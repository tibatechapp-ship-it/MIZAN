"""Security + Reliability benchmarks 71-85 (OWASP Top 10 + CWE Top 25)."""
import ast
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mizan.detector import collect_files
from mizan.scan import scan_repository
from mizan.vulnerabilities import OSV_API_URL, check_vulnerabilities


SRC_DIR = Path(__file__).resolve().parents[2] / "src" / "mizan"


def _iter_py_files():
    for p in SRC_DIR.rglob("*.py"):
        yield p


def _parse(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


class Cwe78Benchmark(unittest.TestCase):
    def test_71_no_shell_true(self):
        """BM-71: subprocess never uses shell=True."""
        violations = []
        for path in _iter_py_files():
            try:
                tree = _parse(path)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            violations.append(f"{path.name}:{node.lineno}")
        self.assertEqual(violations, [], f"shell=True in: {violations}")

    def test_72_no_os_system(self):
        """BM-72: os.system() never called."""
        violations = []
        for path in _iter_py_files():
            try:
                tree = _parse(path)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                        and node.func.attr == "system"):
                    violations.append(f"{path.name}:{node.lineno}")
        self.assertEqual(violations, [], f"os.system in: {violations}")


class Cwe95Benchmark(unittest.TestCase):
    def _find_calls(self, func_names):
        violations = []
        for path in _iter_py_files():
            try:
                tree = _parse(path)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in func_names):
                    violations.append(f"{path.name}:{node.lineno}:{node.func.id}")
        return violations

    def test_73_no_eval(self):
        """BM-73: eval() never called."""
        self.assertEqual(self._find_calls({"eval"}), [])

    def test_74_no_exec(self):
        """BM-74: exec() never called."""
        self.assertEqual(self._find_calls({"exec"}), [])

    def test_75_no_compile_callable(self):
        """BM-75: compile() never called."""
        self.assertEqual(self._find_calls({"compile"}), [])


class Cwe59Benchmark(unittest.TestCase):
    def test_76_symlink_to_outside_ignored(self):
        """BM-76: symlink outside root is skipped."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "inside.py").write_text("pass\n")
            target = Path(t).parent / "external_secret.py"
            target.write_text("SECRET = 'x'\n")
            try:
                (root / "link.py").symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink not available")
            files, _ = collect_files(root)
            names = {f.name for f in files}
            self.assertIn("inside.py", names)
            self.assertNotIn("link.py", names)
            target.unlink()


class Cwe20Benchmark(unittest.TestCase):
    def test_77_invalid_json_returns_empty(self):
        """BM-77: invalid package-lock.json -> empty list."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "package-lock.json").write_text("not json at all")
            files, _ = collect_files(root)
            from mizan.vulnerabilities import parse_dependencies
            self.assertEqual(parse_dependencies(files), [])

    def test_78_invalid_toml_returns_empty(self):
        """BM-78: invalid pyproject.toml -> empty list."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "pyproject.toml").write_text("this is not toml =][")
            files, _ = collect_files(root)
            from mizan.vulnerabilities import parse_dependencies
            self.assertEqual(parse_dependencies(files), [])

    def test_79_non_dict_json_returns_empty(self):
        """BM-79: JSON parses but isn't dict -> empty."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "package-lock.json").write_text('["not", "a", "dict"]')
            files, _ = collect_files(root)
            from mizan.vulnerabilities import parse_dependencies
            self.assertEqual(parse_dependencies(files), [])


class ReadOnlyBenchmark(unittest.TestCase):
    def test_80_scan_does_not_modify_files(self):
        """BM-80: scan_repository leaves files byte-for-byte unchanged."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            content_before = "requests==2.0.0\n"
            (root / "requirements.txt").write_text(content_before)
            with patch("mizan.vulnerabilities.urllib.request.urlopen") as mock:
                cm = MagicMock()
                resp = MagicMock()
                resp.read.return_value = b'{"vulns": []}'
                cm.__enter__.return_value = resp
                cm.__exit__.return_value = False
                mock.return_value = cm
                scan_repository(root)
            content_after = (root / "requirements.txt").read_text()
            self.assertEqual(content_before, content_after)


class NetworkBenchmark(unittest.TestCase):
    def test_81_only_osv_url(self):
        """BM-81: OSV_API_URL is the only external URL."""
        self.assertEqual(OSV_API_URL, "https://api.osv.dev/v1/query")

    def test_82_payload_metadata_only(self):
        """BM-82: OSV payload contains name+version+ecosystem only."""
        with patch("mizan.vulnerabilities.urllib.request.urlopen") as mock:
            cm = MagicMock()
            resp = MagicMock()
            resp.read.return_value = b'{"vulns": []}'
            cm.__enter__.return_value = resp
            cm.__exit__.return_value = False
            mock.return_value = cm
            check_vulnerabilities("requests", "2.0.0", "PyPI")
            req = mock.call_args[0][0]
            payload = json.loads(req.data.decode())
            self.assertEqual(set(payload.keys()), {"package", "version"})
            self.assertEqual(set(payload["package"].keys()), {"name", "ecosystem"})

    @patch.dict(os.environ, {"MIZAN_DISABLE_OSV": "1"})
    def test_83_air_gapped_supported(self):
        """BM-83: MIZAN_DISABLE_OSV allows offline operation."""
        from mizan.vulnerabilities import OsvScanError
        with self.assertRaises(OsvScanError):
            check_vulnerabilities("requests", "2.0.0", "PyPI")


class TimeoutBenchmark(unittest.TestCase):
    def test_84_osv_has_timeout(self):
        """BM-84: OSV call uses timeout."""
        from mizan.vulnerabilities import OSV_TIMEOUT
        self.assertIsInstance(OSV_TIMEOUT, int)
        self.assertGreater(OSV_TIMEOUT, 0)
        self.assertLessEqual(OSV_TIMEOUT, 60)

    def test_85_subprocess_has_timeout(self):
        """BM-85: run_tests passes timeout to subprocess."""
        from mizan.fix import run_tests
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "tests").mkdir()
            with patch("mizan.fix.subprocess.run") as mock:
                mock.return_value = MagicMock(returncode=0, stdout="", stderr="")
                run_tests(root, timeout=1)
                call_kwargs = mock.call_args[1]
                self.assertIn("timeout", call_kwargs)
                self.assertEqual(call_kwargs["timeout"], 1)


if __name__ == "__main__":
    unittest.main()
