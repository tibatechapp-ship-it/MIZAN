"""Acceptance tests for v0.11.0 dependency precision:

* correct OSV ecosystem per manifest type (npm / crates.io / Go /
  Packagist — previously EVERY manifest was queried against PyPI,
  silently returning "clean" for foreign ecosystems),
* deterministic dev-dependency scope + the documented severity cap
  (CRITICAL/HIGH -> medium, original severity PRESERVED),
* shallow reachability annotation — informational only, it NEVER
  changes a severity,
* gate consequences of the dev cap (and none from reachability).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mizan import dependency_scanner as ds  # noqa: E402
from mizan.dependency_scanner import parse_manifest, scan_dependencies  # noqa: E402
from mizan.gate import apply_gate  # noqa: E402
from mizan.reachability import collect_imports  # noqa: E402

VULN = {
    "id": "GHSA-test-0001",
    "summary": "Remote code execution in the vulnerable path",
    "database_specific": {"severity": "HIGH"},
}


def _fake_batch(sev="HIGH"):
    def fake(packages, **kwargs):
        results = []
        for pkg in packages:
            vuln = dict(VULN)
            vuln["database_specific"] = {"severity": sev}
            results.append({**pkg, "vulns": [vuln], "source": "batch"})
        return results
    return fake


class EcosystemMappingTests(unittest.TestCase):

    def _manifest_repo(self, files):
        temp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, temp, ignore_errors=True)
        root = Path(temp)
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return root

    def test_npm_manifest_maps_to_npm(self):
        root = self._manifest_repo({
            "package.json": json.dumps({
                "dependencies": {"lodash": "^4.0.0"},
                "devDependencies": {"jest": "^29.0.0"},
            })
        })
        deps = {d["name"]: d for d in scan_dependencies(root)["dependencies"]}
        self.assertEqual(deps["lodash"]["ecosystem"], "npm")
        self.assertEqual(deps["jest"]["ecosystem"], "npm")
        self.assertEqual(deps["lodash"]["scope"], "runtime")
        self.assertEqual(deps["jest"]["scope"], "dev")

    def test_cargo_go_composer_ecosystems(self):
        root = self._manifest_repo({
            "Cargo.toml": "[dependencies]\nserde = \"1\"\n[dev-dependencies]\ntempfile = \"3\"\n",
            "go.mod": "module x\n\nrequire github.com/pkg/errors v0.9.1\n",
            "composer.json": json.dumps({
                "require": {"monolog/monolog": "^3.0"},
                "require-dev": {"phpunit/phpunit": "^10.0"},
            }),
        })
        deps = {d["name"]: d for d in scan_dependencies(root)["dependencies"]}
        self.assertEqual(deps["serde"]["ecosystem"], "crates.io")
        self.assertEqual(deps["tempfile"]["scope"], "dev")
        self.assertEqual(deps["github.com/pkg/errors"]["ecosystem"], "Go")
        self.assertEqual(deps["monolog/monolog"]["ecosystem"], "Packagist")
        self.assertEqual(deps["phpunit/phpunit"]["scope"], "dev")

    def test_pypi_manifests_keep_pypi(self):
        root = self._manifest_repo({
            "requirements.txt": "requests==2.25.0\n",
            "pyproject.toml": "[project]\ndependencies = [\"flask>=2.0\"]\n",
        })
        deps = {d["name"]: d for d in scan_dependencies(root)["dependencies"]}
        self.assertEqual(deps["requests"]["ecosystem"], "PyPI")
        self.assertEqual(deps["flask"]["ecosystem"], "PyPI")

    def test_requirements_dev_file_now_scanned_as_dev(self):
        root = self._manifest_repo({
            "requirements-dev.txt": "pytest==8.0.0\n",
        })
        result = scan_dependencies(root)
        deps = {d["name"]: d for d in result["dependencies"]}
        # previously requirements-dev.txt was not scanned at all
        self.assertEqual(deps["pytest"]["scope"], "dev")
        self.assertEqual(deps["pytest"]["ecosystem"], "PyPI")

    def test_parse_manifest_pipfile_dev_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "Pipfile"
            p.write_text(
                "[packages]\nrequests = \"*\"\n[dev-packages]\npytest = \"*\"\n",
                encoding="utf-8",
            )
            records = {r["name"]: r for r in parse_manifest(p)}
            self.assertEqual(records["requests"]["scope"], "runtime")
            self.assertEqual(records["pytest"]["scope"], "dev")


class DevCapTests(unittest.TestCase):

    def _dep_repo(self, root):
        (root / "app.py").write_text("import requests\n", encoding="utf-8")
        (root / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }), encoding="utf-8")

    def test_dev_critical_is_capped_with_original_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._dep_repo(root)
            with patch.object(ds, "check_vulnerabilities_batch", _fake_batch("CRITICAL")):
                result = scan_dependencies(root)
            by_name = {}
            for f in result["findings"]:
                by_name[f["dependency"]["name"]] = f
            self.assertEqual(result["dev_severity_capped"], 1)
            self.assertEqual(by_name["jest"]["severity"], "medium")
            self.assertEqual(by_name["jest"]["original_severity"], "CRITICAL")
            self.assertEqual(by_name["jest"]["scope"], "dev")
            # runtime severity is untouched
            self.assertEqual(by_name["lodash"]["severity"], "CRITICAL")
            self.assertNotIn("original_severity", by_name["lodash"])

    def test_dev_cap_unblocks_default_gate_but_visibility_stays(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._dep_repo(root)
            with patch.object(ds, "check_vulnerabilities_batch", _fake_batch("CRITICAL")):
                result = scan_dependencies(root)
            # default gate (critical,high): runtime lodash still blocks,
            # the capped dev finding does not join the blocking list
            gate = apply_gate(result["findings"], blocking=("critical", "high"))
            self.assertEqual(gate["decision"], "fail")
            blocked_names = {
                f["dependency"]["name"] for f in gate["blocking_findings"]
            }
            self.assertEqual(blocked_names, {"lodash"})
            # explicit "critical,high,medium" blocks on BOTH
            strict = apply_gate(result["findings"],
                                blocking=("critical", "high", "medium"))
            strict_names = {
                f["dependency"]["name"] for f in strict["blocking_findings"]
            }
            self.assertEqual(strict_names, {"lodash", "jest"})

    def test_dev_only_repo_passes_default_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text("import requests\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "devDependencies": {"jest": "^29.0.0"},
            }), encoding="utf-8")
            with patch.object(ds, "check_vulnerabilities_batch", _fake_batch("CRITICAL")):
                result = scan_dependencies(root)
            self.assertEqual(result["dev_severity_capped"], 1)
            # finding stays VISIBLE (capped to medium) but does not block
            self.assertEqual(len(result["findings"]), 1)
            gate = apply_gate(result["findings"], blocking=("critical", "high"))
            self.assertEqual(gate["decision"], "pass")


class ReachabilityTests(unittest.TestCase):

    def _repo(self, root):
        (root / "app.py").write_text(
            "import requests\nfrom PIL import Image\n", encoding="utf-8"
        )
        (root / "index.js").write_text(
            'const _ = require("lodash");\nimport fs from "fs";\n',
            encoding="utf-8",
        )

    def test_imported_vs_not_imported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo(root)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"lodash": "^4.0.0"}
            }), encoding="utf-8")
            (root / "requirements.txt").write_text(
                "requests==2.25.0\nunmatchedpkg==1.0.0\n", encoding="utf-8"
            )
            with patch.object(ds, "check_vulnerabilities_batch", _fake_batch()):
                result = scan_dependencies(root)
            reach = {
                f["dependency"]["name"]: f["reachability"]
                for f in result["findings"]
            }
            self.assertEqual(reach["requests"], "imported")
            self.assertEqual(reach["lodash"], "imported")
            self.assertEqual(reach["unmatchedpkg"], "not-imported")

    def test_pypi_alias_pillow_pil(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo(root)
            (root / "requirements.txt").write_text(
                "Pillow==8.0.0\n", encoding="utf-8"
            )
            with patch.object(ds, "check_vulnerabilities_batch", _fake_batch()):
                result = scan_dependencies(root)
            self.assertEqual(result["findings"][0]["reachability"], "imported")

    def test_not_imported_never_changes_severity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo(root)
            (root / "requirements.txt").write_text(
                "unmatchedpkg==1.0.0\n", encoding="utf-8"
            )
            with patch.object(ds, "check_vulnerabilities_batch", _fake_batch("CRITICAL")):
                result = scan_dependencies(root)
            finding = result["findings"][0]
            self.assertEqual(finding["reachability"], "not-imported")
            self.assertEqual(finding["severity"], "CRITICAL")
            # and the gate still blocks on it — reachability is metadata
            gate = apply_gate(result["findings"], blocking=("critical", "high"))
            self.assertEqual(gate["decision"], "fail")

    def test_collect_imports_families(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._repo(root)
            imports = collect_imports(root)
            self.assertIn("requests", imports["python"])
            self.assertIn("pil", imports["python"])  # Pillow alias root
            self.assertIn("lodash", imports["npm"])


if __name__ == "__main__":
    unittest.main()
