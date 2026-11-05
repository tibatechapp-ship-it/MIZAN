"""Tests for the hardened OSV layer: batch queries, cache, offline mode."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mizan import vulnerabilities  # noqa: E402
from mizan.vulnerabilities import (  # noqa: E402
    OsvScanError,
    check_vulnerabilities,
    check_vulnerabilities_batch,
)


VULN_RECORD = {"id": "GHSA-test-1", "summary": "Critical issue"}


def _fake_urlopen(responses):
    """Build a urlopen mock that routes by request URL."""
    calls = []

    class Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def factory(req, timeout=None):
        url = req.get_full_url()
        calls.append(url)
        if url.endswith("querybatch"):
            body = json.loads(req.data.decode())
            out = []
            for q in body["queries"]:
                if q["package"]["name"] == "requests":
                    out.append({"vuln_ids": ["GHSA-test-1"]})
                else:
                    out.append({"vuln_ids": []})
            return Resp({"results": out})
        if url.endswith("query"):
            body = json.loads(req.data.decode())
            if body["package"]["name"] == "requests":
                return Resp({"vulns": [VULN_RECORD]})
            return Resp({"vulns": []})
        raise AssertionError(f"unexpected URL {url}")

    return factory, calls


class _CleanEnv(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        # snapshot the whole env, strip MIZAN_* knobs for determinism
        self._old_env = dict(os.environ)
        for key in list(os.environ):
            if key.startswith("MIZAN_"):
                del os.environ[key]

    def tearDown(self):
        # restore the exact previous environment (prevents MIZAN_OFFLINE=1
        # and friends from leaking into other test modules)
        os.environ.clear()
        os.environ.update(self._old_env)
        os.chdir(self._old_cwd)
        self._tmp.cleanup()


class BatchTests(_CleanEnv):
    def test_all_clean_single_roundtrip(self):
        pkgs = [
            {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI"},
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
        ]
        factory, calls = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = check_vulnerabilities_batch(pkgs, use_cache=False)
        self.assertEqual(len(calls), 1)  # ONE network call
        self.assertTrue(calls[0].endswith("querybatch"))
        self.assertEqual([r["vulns"] for r in results], [[], []])
        self.assertEqual([r["source"] for r in results], ["batch", "batch"])

    def test_vulnful_package_gets_full_record(self):
        pkgs = [
            {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"},
            {"name": "clean-pkg", "version": "1.0.0", "ecosystem": "PyPI"},
        ]
        factory, calls = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = check_vulnerabilities_batch(pkgs, use_cache=False)
        # batch + one detail query for the vulnerable package only
        self.assertEqual(len(calls), 2)
        self.assertEqual(results[0]["source"], "batch+detail")
        self.assertEqual(results[0]["vulns"], [VULN_RECORD])
        self.assertEqual(results[1]["source"], "batch")

    def test_results_align_with_input_order(self):
        pkgs = [
            {"name": "a", "version": "1", "ecosystem": "PyPI"},
            {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"},
            {"name": "b", "version": "2", "ecosystem": "PyPI"},
        ]
        factory, _ = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = check_vulnerabilities_batch(pkgs, use_cache=False)
        self.assertEqual(results[1]["vulns"], [VULN_RECORD])
        self.assertEqual(results[0]["vulns"], [])
        self.assertEqual(results[2]["vulns"], [])


class CacheTests(_CleanEnv):
    def test_second_scan_served_from_cache(self):
        pkgs = [{"name": "clean-pkg", "version": "1.0.0", "ecosystem": "PyPI"}]
        factory, calls = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            first = check_vulnerabilities_batch(pkgs)
        self.assertEqual(len(calls), 1)
        factory2, calls2 = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory2):
            second = check_vulnerabilities_batch(pkgs)
        self.assertEqual(calls2, [])  # zero network on second run
        self.assertEqual(second[0]["source"], "cache")
        self.assertEqual(first[0]["vulns"], second[0]["vulns"])

    def test_cache_file_created(self):
        pkgs = [{"name": "clean-pkg", "version": "1.0.0", "ecosystem": "PyPI"}]
        factory, _ = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            check_vulnerabilities_batch(pkgs)
        cache_path = Path(".mizan/osv-cache.json")
        self.assertTrue(cache_path.exists())
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], 1)
        self.assertTrue(data["entries"])

    def test_ttl_expiry_forces_refetch(self):
        pkgs = [{"name": "clean-pkg", "version": "1.0.0", "ecosystem": "PyPI"}]
        factory, _ = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            check_vulnerabilities_batch(pkgs)
        os.environ["MIZAN_OSV_CACHE_TTL"] = "0"
        factory2, calls2 = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory2):
            result = check_vulnerabilities_batch(pkgs)
        self.assertEqual(len(calls2), 1)
        self.assertEqual(result[0]["source"], "batch")

    def test_single_query_uses_cache_when_enabled(self):
        os.environ["MIZAN_OSV_CACHE"] = "1"
        factory, calls = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            check_vulnerabilities("clean-pkg", "1.0.0", "PyPI")
        self.assertEqual(len(calls), 1)
        factory2, calls2 = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory2):
            again = check_vulnerabilities("clean-pkg", "1.0.0", "PyPI")
        self.assertEqual(calls2, [])
        self.assertEqual(again, [])


class OfflineTests(_CleanEnv):
    def test_offline_miss_reported_not_raised(self):
        pkgs = [{"name": "unknown-pkg", "version": "9.9.9", "ecosystem": "PyPI"}]
        results = check_vulnerabilities_batch(pkgs, offline=True)
        self.assertEqual(results[0]["source"], "offline-miss")
        self.assertEqual(results[0]["vulns"], [])

    def test_offline_serves_cache(self):
        pkgs = [{"name": "clean-pkg", "version": "1.0.0", "ecosystem": "PyPI"}]
        factory, _ = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            check_vulnerabilities_batch(pkgs)
        results = check_vulnerabilities_batch(pkgs, offline=True)
        self.assertEqual(results[0]["source"], "cache")

    def test_offline_env_var_respected(self):
        os.environ["MIZAN_OFFLINE"] = "1"
        pkgs = [{"name": "unknown-pkg", "version": "9.9.9", "ecosystem": "PyPI"}]
        factory, calls = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = check_vulnerabilities_batch(pkgs)
        self.assertEqual(calls, [])
        self.assertEqual(results[0]["source"], "offline-miss")

    def test_single_query_offline_without_cache_raises(self):
        os.environ["MIZAN_OFFLINE"] = "1"
        with self.assertRaises(OsvScanError):
            check_vulnerabilities("nope", "1.0.0", "PyPI")

    def test_corrupt_cache_is_rebuilt(self):
        Path(".mizan").mkdir()
        Path(".mizan/osv-cache.json").write_text("{broken json", encoding="utf-8")
        pkgs = [{"name": "clean-pkg", "version": "1.0.0", "ecosystem": "PyPI"}]
        factory, calls = _fake_urlopen(None)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = check_vulnerabilities_batch(pkgs)
        self.assertEqual(len(calls), 1)  # rebuild via network
        self.assertEqual(results[0]["source"], "batch")


class DisabledOsvTests(_CleanEnv):
    def test_disable_env_still_honoured(self):
        os.environ["MIZAN_DISABLE_OSV"] = "1"
        with self.assertRaises(OsvScanError):
            check_vulnerabilities("requests", "2.0.0", "PyPI")


if __name__ == "__main__":
    unittest.main()
