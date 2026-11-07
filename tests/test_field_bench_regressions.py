"""Field-benchmark regression tests (v0.12.2 wave).

Covers the two weaknesses the 100-repo field benchmark exposed:
  1. OSV querybatch rejects oversized payloads (HTTP 400) — batches must
     be chunked, retried, and degraded per-chunk without failing the scan.
  2. full-scan without --gate exited 0 even when a scanner failed —
     violating the documented 0/1/2 exit contract.
"""
import json
import unittest
from unittest.mock import patch

from mizan import cli
from mizan import vulnerabilities as V


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _pkg(i):
    return {"name": f"pkg-{i}", "version": "1.0.0", "ecosystem": "PyPI"}


class ChunkingTests(unittest.TestCase):
    def setUp(self):
        self._sleep = V._OSV_RETRY_SLEEP
        V._OSV_RETRY_SLEEP = 0

    def tearDown(self):
        V._OSV_RETRY_SLEEP = self._sleep

    def _batch_factory(self, calls, batch_sizes, fail_call=None):
        """Return urlopen factory: answers every querybatch with clean
        results; optionally raises on one specific call index."""
        state = {"n": 0}

        def factory(req, timeout=None):
            state["n"] += 1
            url = req.get_full_url()
            if url.endswith("querybatch"):
                calls.append(url)
                body = json.loads(req.data.decode())
                batch_sizes.append(len(body["queries"]))
                if fail_call is not None and state["n"] == fail_call:
                    raise OSError("simulated transient OSV failure")
                return _Resp({"results": [{"vuln_ids": []}
                                          for _ in body["queries"]]})
            if url.endswith("query"):
                return _Resp({"vulns": []})
            raise AssertionError(f"unexpected URL {url}")

        return factory

    def test_250_packages_chunked_under_100(self):
        pkgs = [_pkg(i) for i in range(250)]
        calls, sizes = [], []
        factory = self._batch_factory(calls, sizes)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = V.check_vulnerabilities_batch(pkgs, use_cache=False)
        self.assertEqual(len(calls), 3)  # 100 + 100 + 50
        self.assertTrue(all(s <= 100 for s in sizes), sizes)
        self.assertEqual(len(results), 250)
        self.assertTrue(all(r["source"] == "batch" for r in results))
        # alignment: every result keeps its own package identity
        self.assertEqual(results[0]["name"], "pkg-0")
        self.assertEqual(results[249]["name"], "pkg-249")

    def test_exactly_1024_packages_three_chunks_fine(self):
        pkgs = [_pkg(i) for i in range(1024)]
        calls, sizes = [], []
        factory = self._batch_factory(calls, sizes)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = V.check_vulnerabilities_batch(pkgs, use_cache=False)
        self.assertEqual(len(calls), 11)
        self.assertEqual(max(sizes), 100)
        self.assertTrue(all(r["source"] == "batch" for r in results))

    def test_transient_failure_is_retried(self):
        pkgs = [_pkg(i) for i in range(10)]
        calls, sizes = [], []
        # fail the very first querybatch call; the retry must succeed
        factory = self._batch_factory(calls, sizes, fail_call=1)
        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = V.check_vulnerabilities_batch(pkgs, use_cache=False)
        self.assertEqual(len(calls), 2)  # 1 failed attempt + 1 retry
        self.assertTrue(all(r["source"] == "batch" for r in results))
        self.assertEqual(len(results), 10)

    def test_chunk_failure_degrades_to_per_item_not_whole_scan(self):
        pkgs = [_pkg(i) for i in range(150)]  # 2 chunks
        calls, sizes = [], []

        def factory(req, timeout=None):
            url = req.get_full_url()
            if url.endswith("querybatch"):
                calls.append(url)
                body = json.loads(req.data.decode())
                sizes.append(len(body["queries"]))
                if len(body["queries"]) == 100:
                    # first chunk always fails (even after retries)
                    raise OSError("chunk down")
                return _Resp({"results": [{"vuln_ids": []}
                                          for _ in body["queries"]]})
            if url.endswith("query"):
                return _Resp({"vulns": []})
            raise AssertionError(f"unexpected URL {url}")

        with patch("mizan.vulnerabilities.urllib.request.urlopen",
                   side_effect=factory):
            results = V.check_vulnerabilities_batch(pkgs, use_cache=False)
        self.assertEqual(len(results), 150)
        first_chunk = [r["source"] for r in results[:100]]
        second_chunk = [r["source"] for r in results[100:]]
        self.assertTrue(all(s == "single-fallback" for s in first_chunk))
        self.assertTrue(all(s == "batch" for s in second_chunk))


class ExitContractTests(unittest.TestCase):
    """full-scan / scan must honour the 0/1/2 contract without --gate."""

    def test_full_scan_exit_2_when_scanner_failed_without_gate(self):
        def fake_full_scan(directory=".", jobs=4):
            return {"scanners_failed": ["dependencies"], "analysis": {},
                    "scanner": {}, "git": {}, "ci": {},
                    "dependencies": {"osv_errors": ["OSV down"]},
                    "change_risk": {}, "documentation": {}}

        with patch.object(cli, "full_scan_repository", fake_full_scan):
            rc = cli.main(["full-scan", "."])
        self.assertEqual(rc, 2)

    def test_full_scan_exit_0_when_complete_without_gate(self):
        def fake_full_scan(directory=".", jobs=4):
            return {"scanners_failed": [], "analysis": {"findings": []},
                    "scanner": {"findings": []}, "git": {"findings": []},
                    "ci": {"findings": []},
                    "dependencies": {"findings": []},
                    "change_risk": {"findings": []},
                    "documentation": {"findings": []}}

        with patch.object(cli, "full_scan_repository", fake_full_scan):
            rc = cli.main(["full-scan", "."])
        self.assertEqual(rc, 0)

    def test_scan_exit_2_when_custom_rules_broken_without_gate(self):
        def fake_scan(path, **kwargs):
            return {"findings": [], "custom_rules_errors": ["bad rules.json"]}

        with patch.object(cli, "scan_repository", fake_scan):
            rc = cli.main(["scan", "."])
        self.assertEqual(rc, 2)

    def test_scan_exit_0_clean_without_gate(self):
        def fake_scan(path, **kwargs):
            return {"findings": [], "custom_rules_errors": []}

        with patch.object(cli, "scan_repository", fake_scan):
            rc = cli.main(["scan", "."])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
