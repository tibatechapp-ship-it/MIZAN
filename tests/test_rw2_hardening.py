"""RW-2xx hardening wave (v0.8.3): closing the externally-audited gaps.

RW-201  symlink escape in repair (resolve_target + worktree write)
RW-202  partial scan must never gate-pass ("incomplete" decision, exit 2)
RW-203  OSV failures are never cached as clean + vuln-scan exit contract
RW-204  full-scan gate actually sees OSV findings / errors (wiring)
RW-205  Action scan step: exit-code contract, SARIF validity, no COUNT=0
RW-206  Action approve step: env + argv-array, no eval, injection-proof

The Action tests (RW-205/206) extract the REAL step scripts from
action/action.yml at runtime — the tests always exercise the shipped
logic, never a drifted copy.
"""

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import yaml  # noqa: E402  (dev/test dependency, ships with CI image)

from mizan.cli import full_scan_repository, main as cli_main  # noqa: E402
from mizan.gate import apply_gate, fingerprint  # noqa: E402
from mizan.repair import Plan, RepairError, apply_repairs, resolve_target  # noqa: E402
from mizan.vulnerabilities import OsvScanError  # noqa: E402


def _git_env():
    return dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")


def _make_git_repo(root, files):
    """git init + commit `files` (dict name -> text; symlink targets allowed)."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=_git_env())
    subprocess.run(["git", "-C", root, "commit", "-qm", "init"],
                   check=True, env=_git_env())
    return root


def _action_step(name):
    """Extract a step's `run:` script from action/action.yml by step name."""
    doc = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "action" / "action.yml")
        .read_text(encoding="utf-8")
    )
    for step in doc["runs"]["steps"]:
        if step.get("name") == name:
            return step["run"], step.get("env") or {}
    raise LookupError(f"step not found in action.yml: {name}")


class TestSymlinkGuard(unittest.TestCase):
    """RW-201: a symlink must never be written through."""

    def test_resolve_target_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                with open("real.py", "w") as fh:
                    fh.write("x = 1\n")
                os.symlink("real.py", "link.py")
                with self.assertRaises(RepairError) as ctx:
                    resolve_target("link.py")
                self.assertIn("symlink", str(ctx.exception))
            finally:
                os.chdir(old)

    def test_apply_repairs_never_writes_through_symlink(self):
        base = tempfile.mkdtemp(prefix="mizan-rw201-")
        victim = os.path.join(base, "victim.py")
        with open(victim, "w") as fh:
            fh.write("SECRET_V0\n")
        repo = os.path.join(base, "repo")
        os.makedirs(repo)
        with open(os.path.join(repo, "normal.py"), "w") as fh:
            fh.write("print('ok')\n")
        os.symlink(victim, os.path.join(repo, "evil.py"))
        _make_git_repo(repo, None)

        old = os.getcwd()
        os.chdir(repo)
        try:
            # The committed symlink is invisible to resolve_target at plan
            # build time on some flows, so Plans may carry it — the worktree
            # write site is the last line of defence (defence in depth).
            plans = [
                Plan(file="normal.py", original="print('ok')\n",
                     modified="print('patched')\n", description="rw-201"),
                Plan(file="evil.py", original="SECRET_V0\n",
                     modified="COMPROMISED = True\n", description="rw-201"),
            ]
            summary = apply_repairs(plans, apply=True)
            with open(victim) as fh:
                after = fh.read()
            self.assertEqual(after, "SECRET_V0\n",
                             "write escaped the worktree through a symlink!")
            self.assertEqual(summary["files"], ["normal.py"])
            self.assertNotIn("evil.py", summary["files"])
        finally:
            os.chdir(old)
            subprocess.run(["git", "worktree", "prune"], cwd=repo,
                           capture_output=True)
            subprocess.run(["git", "branch", "-D",
                            next(b for b in subprocess.run(
                                ["git", "branch", "--list", "mizan/auto-fix-*"],
                                cwd=repo, capture_output=True, text=True)
                                .stdout.split() if "auto-fix" in b)],
                           cwd=repo, capture_output=True)
            subprocess.run(["rm", "-rf", base], check=False)

    def test_apply_repairs_symlink_only_plan_fails_loudly(self):
        base = tempfile.mkdtemp(prefix="mizan-rw201b-")
        victim = os.path.join(base, "victim.py")
        with open(victim, "w") as fh:
            fh.write("SECRET_V0\n")
        repo = os.path.join(base, "repo")
        os.makedirs(repo)
        os.symlink(victim, os.path.join(repo, "evil.py"))
        _make_git_repo(repo, None)

        old = os.getcwd()
        os.chdir(repo)
        try:
            plans = [Plan(file="evil.py", original="SECRET_V0\n",
                          modified="COMPROMISED = True\n", description="rw-201")]
            with self.assertRaises(RepairError):
                apply_repairs(plans, apply=True)
            with open(victim) as fh:
                self.assertEqual(fh.read(), "SECRET_V0\n")
        finally:
            os.chdir(old)
            subprocess.run(["git", "worktree", "prune"], cwd=repo,
                           capture_output=True)
            subprocess.run(["rm", "-rf", base], check=False)


class TestGateCompleteness(unittest.TestCase):
    """RW-202: partial scan must never certify a clean pass."""

    HIGH_FINDING = {"rule": "dynamic-execution", "file": "a.py", "line": 1,
                    "severity": "high", "message": "eval"}

    def test_incomplete_sources_force_incomplete_decision(self):
        decision = apply_gate([], incomplete_sources=["git", "ci"])
        self.assertEqual(decision["decision"], "incomplete")
        self.assertEqual(decision["incomplete_sources"], ["git", "ci"])
        self.assertEqual(decision["blocking_count"], 0)

    def test_blocking_findings_still_fail_despite_incomplete(self):
        decision = apply_gate([self.HIGH_FINDING],
                              incomplete_sources=["git"])
        self.assertEqual(decision["decision"], "fail")
        self.assertEqual(decision["blocking_count"], 1)

    def test_complete_clean_scan_still_passes(self):
        decision = apply_gate([], incomplete_sources=[])
        self.assertEqual(decision["decision"], "pass")
        self.assertEqual(decision["incomplete_sources"], [])

    def test_full_scan_gate_exits_2_on_non_git_directory(self):
        """git + ci scanners cannot run outside a git repo — the gate must
        answer `incomplete` (exit 2), not a clean `pass` (exit 0)."""
        root = tempfile.mkdtemp(prefix="mizan-rw202-nongit-")
        with open(os.path.join(root, "app.py"), "w") as fh:
            fh.write("print('hello')\n")

        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "full-scan", root, "--gate", "critical,high"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 2)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "incomplete")
            self.assertTrue(payload["scanners_failed"])
            self.assertIn("git", payload["gate"]["incomplete_sources"])
        finally:
            sys.argv = old_argv

    def test_full_scan_gate_exits_0_on_clean_complete_scan(self):
        root = tempfile.mkdtemp(prefix="mizan-rw202-clean-")
        with open(os.path.join(root, "app.py"), "w") as fh:
            fh.write("print('hello')\n")
        _make_git_repo(root, None)

        old_argv = sys.argv
        try:
            sys.argv = ["mizan", "full-scan", root, "--gate", "critical,high"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli_main()
            self.assertEqual(code, 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "pass")
            self.assertEqual(payload["gate"]["incomplete_sources"], [])
        finally:
            sys.argv = old_argv


class TestOsvHonesty(unittest.TestCase):
    """RW-203: OSV failures are never cached as clean results."""

    def test_single_fallback_error_recorded_not_cached(self):
        with patch("mizan.vulnerabilities._post_json", return_value={}), \
             patch("mizan.vulnerabilities.check_vulnerabilities",
                   side_effect=OsvScanError("net down")), \
             patch("mizan.vulnerabilities._cache_put") as cache_put:
            from mizan.vulnerabilities import check_vulnerabilities_batch
            results = check_vulnerabilities_batch(
                [{"name": "a", "version": "1.0", "ecosystem": "PyPI"}],
                use_cache=True,
            )
        self.assertEqual(results[0]["source"], "scan-error")
        self.assertEqual(results[0]["vulns"], [])
        self.assertIn("net down", results[0]["error"])
        cache_put.assert_not_called()

    def test_detail_error_keeps_vuln_ids_not_cached(self):
        class Resp:
            def __init__(self, payload):
                self._payload = payload

            def read(self):
                return json.dumps(self._payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_post(url, payload):
            return {"results": [{"vuln_ids": ["GHSA-1"]}]}

        with patch("mizan.vulnerabilities._post_json",
                   side_effect=fake_post), \
             patch("mizan.vulnerabilities.check_vulnerabilities",
                   side_effect=OsvScanError("detail fetch failed")), \
             patch("mizan.vulnerabilities._cache_put") as cache_put:
            from mizan.vulnerabilities import check_vulnerabilities_batch
            results = check_vulnerabilities_batch(
                [{"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"}],
                use_cache=True,
            )
        self.assertEqual(results[0]["source"], "detail-error")
        self.assertEqual(results[0]["vuln_ids"], ["GHSA-1"])
        self.assertEqual(results[0]["vulns"], [])
        cache_put.assert_not_called()

    def test_vuln_scan_exits_2_on_osv_outage(self):
        """The CLI contract (0 clean / 1 findings / 2 failure) must hold
        when OSV is unreachable — never a misleading exit 1."""
        from mizan.scan import main as scan_main
        with patch("mizan.scan.scan_repository",
                   side_effect=OsvScanError("osv down")):
            rc = scan_main(["."])
        self.assertEqual(rc, 2)


class TestFullScanOsvWiring(unittest.TestCase):
    """RW-204: the full-scan gate actually sees dependency/OSV results."""

    def _osv_entry(self, source="batch+detail", vulns=None, **extra):
        entry = {"name": "requests", "version": "2.0.0",
                 "ecosystem": "PyPI", "manifest": "requirements.txt",
                 "source": source, "vulns": vulns or []}
        entry.update(extra)
        return entry

    def test_dependency_section_produces_gateable_osv_findings(self):
        vuln = {"id": "GHSA-abc", "summary": "boom",
                "database_specific": {"severity": "HIGH"}}
        root = tempfile.mkdtemp(prefix="mizan-rw204-")
        with open(os.path.join(root, "requirements.txt"), "w") as fh:
            fh.write("requests==2.0.0\n")

        with patch("mizan.dependency_scanner.check_vulnerabilities_batch",
                   return_value=[self._osv_entry(vulns=[vuln])]):
            from mizan.dependency_scanner import scan_dependencies
            section = scan_dependencies(root)

        self.assertTrue(section["vulnerability_database_checked"])
        osv_findings = [f for f in section["findings"]
                        if f["rule"] == "osv-GHSA-abc"]
        self.assertEqual(len(osv_findings), 1)
        finding = osv_findings[0]
        from mizan.gate import normalize_severity
        self.assertEqual(normalize_severity(finding["severity"]), "high")
        self.assertEqual(finding["dependency"]["name"], "requests")
        self.assertEqual(finding["vuln"]["id"], "GHSA-abc")
        # stable OSV fingerprint + the gate blocks on it
        self.assertEqual(
            fingerprint(finding),
            fingerprint(json.loads(json.dumps(finding))),
        )
        decision = apply_gate([finding], blocking=("critical", "high"))
        self.assertEqual(decision["decision"], "fail")

    def test_full_scan_gate_exits_2_on_osv_errors(self):
        root = tempfile.mkdtemp(prefix="mizan-rw204b-")
        with open(os.path.join(root, "app.py"), "w") as fh:
            fh.write("print('hello')\n")
        _make_git_repo(root, None)

        deps = {"findings": [],
                "osv_errors": [{"name": "x", "source": "scan-error",
                                "error": "down"}],
                "osv_unchecked": []}
        old_argv = sys.argv
        try:
            with patch("mizan.cli.scan_dependencies", return_value=deps):
                sys.argv = ["mizan", "full-scan", root,
                            "--gate", "critical,high"]
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli_main()
            self.assertEqual(code, 2)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["gate"]["decision"], "incomplete")
            self.assertIn("osv", payload["gate"]["incomplete_sources"])
        finally:
            sys.argv = old_argv

    def test_full_scan_gate_exits_2_on_offline_unchecked(self):
        root = tempfile.mkdtemp(prefix="mizan-rw204c-")
        with open(os.path.join(root, "app.py"), "w") as fh:
            fh.write("print('hello')\n")
        _make_git_repo(root, None)

        deps = {"findings": [], "osv_errors": [],
                "osv_unchecked": [{"name": "requests",
                                   "source": "offline-miss"}]}
        old_argv = sys.argv
        try:
            with patch("mizan.cli.scan_dependencies", return_value=deps):
                sys.argv = ["mizan", "full-scan", root,
                            "--gate", "critical,high"]
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli_main()
            self.assertEqual(code, 2)
            payload = json.loads(out.getvalue())
            self.assertIn("osv-offline", payload["gate"]["incomplete_sources"])
        finally:
            sys.argv = old_argv


class _ActionHarness(unittest.TestCase):
    """Shared plumbing: run a real action.yml step script locally with a
    stubbed `mizan` binary and inspect what it received / produced."""

    def _run_step(self, step_name, env_extra=None, stub_script=None):
        run, declared_env = _action_step(step_name)
        bindir = tempfile.mkdtemp(prefix="mizan-stub-bin-")
        stub = os.path.join(bindir, "mizan")
        with open(stub, "w") as fh:
            fh.write(stub_script or (
                '#!/usr/bin/env bash\n'
                'printf \'%s\\0\' "$@" > "$MIZAN_STUB_ARGS"\n'
                'exit "${MIZAN_STUB_EXIT:-0}"\n'
            ))
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)

        workdir = tempfile.mkdtemp(prefix="mizan-stub-wd-")
        github_output = os.path.join(workdir, "github_output.txt")
        env = {
            "PATH": bindir + os.pathsep + os.environ["PATH"],
            "HOME": os.environ.get("HOME", workdir),
            "GITHUB_OUTPUT": github_output,
            "MIZAN_STUB_ARGS": os.path.join(workdir, "stub_args.bin"),
        }
        for key in declared_env:
            # expression values (${{ ... }}) are provided by the runner;
            # supply representative literals for each
            env.setdefault(key, f"literal-{key.lower()}")
        env.update(env_extra or {})

        proc = subprocess.run(
            ["bash", "-c", run], env=env, cwd=workdir,
            capture_output=True, text=True, timeout=60,
        )
        stub_args = []
        args_file = env["MIZAN_STUB_ARGS"]
        if os.path.exists(args_file):
            stub_args = Path(args_file).read_bytes().decode(
                "utf-8", "replace").split("\0")
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "stub_args": stub_args,
            "github_output": (Path(github_output).read_text()
                              if os.path.exists(github_output) else ""),
            "workdir": workdir,
        }


class TestActionScanStep(_ActionHarness):
    """RW-205: scan failure / missing SARIF / malformed SARIF must never
    masquerade as '0 vulnerabilities'."""

    def test_scan_failure_exit_2_fails_the_step(self):
        result = self._run_step(
            "Run MIZAN vuln-scan",
            env_extra={
                "SCAN_PATH": ".",
                "SARIF_OUTPUT": "mizan-results.sarif",
                "MIZAN_STUB_EXIT": "2",
            },
        )
        self.assertEqual(result["rc"], 1)
        self.assertIn("scan failure", result["stdout"] + result["stderr"])
        self.assertNotIn("findings-count", result["github_output"])

    def test_missing_sarif_fails_the_step(self):
        result = self._run_step(
            "Run MIZAN vuln-scan",
            env_extra={
                "SCAN_PATH": ".",
                "SARIF_OUTPUT": "mizan-results.sarif",
                "MIZAN_STUB_EXIT": "0",
            },
        )
        self.assertEqual(result["rc"], 1)
        self.assertIn("no SARIF", result["stdout"] + result["stderr"])
        self.assertNotIn("findings-count", result["github_output"])

    def test_valid_sarif_with_findings_reports_count(self):
        # stub that writes a valid SARIF with 3 results
        workdir_holder = {}
        sarif = {"version": "2.1.0",
                 "runs": [{"results": [{}, {}, {}], "tool": {}}]}
        stub = (
            "#!/usr/bin/env bash\n"
            "printf '%s\\0' \"$@\" > \"$MIZAN_STUB_ARGS\"\n"
            "python -c \"import json,sys; json.dump(json.loads(sys.argv[1]), open(sys.argv[2],'w'))\" "
            f"'{json.dumps(sarif)}' \"$(pwd)/\"$SARIF_OUTPUT\n"
            "exit 1\n"
        )
        result = self._run_step(
            "Run MIZAN vuln-scan",
            env_extra={
                "SCAN_PATH": ".",
                "SARIF_OUTPUT": "mizan-results.sarif",
            },
            stub_script=stub,
        )
        self.assertEqual(result["rc"], 0)
        self.assertIn("findings-count=3", result["github_output"])
        self.assertIn("exit 1", result["stdout"] + result["stderr"])

    def test_malformed_sarif_fails_the_step(self):
        stub = (
            "#!/usr/bin/env bash\n"
            "printf '%s\\0' \"$@\" > \"$MIZAN_STUB_ARGS\"\n"
            "echo 'not json {\"runs\":' > \"$(pwd)/\"$SARIF_OUTPUT\n"
            "exit 0\n"
        )
        result = self._run_step(
            "Run MIZAN vuln-scan",
            env_extra={
                "SCAN_PATH": ".",
                "SARIF_OUTPUT": "mizan-results.sarif",
            },
            stub_script=stub,
        )
        self.assertEqual(result["rc"], 1)
        self.assertIn("malformed", result["stdout"] + result["stderr"])
        self.assertNotIn("findings-count", result["github_output"])

    def test_hostile_input_stays_literal(self):
        marker = "NO_MARKER_EXPECTED"
        result = self._run_step(
            "Run MIZAN vuln-scan",
            env_extra={
                "SCAN_PATH": 'x"; touch marker-pwn; #',
                "SARIF_OUTPUT": "mizan-results.sarif",
                "MIZAN_STUB_EXIT": "0",
            },
        )
        self.assertEqual(result["rc"], 1)  # fails (no SARIF) — but safely
        stub_arg = next((a for a in result["stub_args"]
                         if "marker-pwn" in a), None)
        self.assertIsNotNone(stub_arg,
                             "hostile input never reached the stub")
        self.assertEqual(stub_arg, 'x"; touch marker-pwn; #',
                         "input must arrive as ONE literal argument")
        self.assertFalse(os.path.exists(
            os.path.join(result["workdir"], "marker-pwn")),
            "injection would have created the marker file")


class TestActionApproveStep(_ActionHarness):
    """RW-206: no eval; every input is a literal argv element."""

    def test_values_pass_as_literal_array_arguments(self):
        result = self._run_step(
            "Auto-approve and merge (safe)",
            env_extra={
                "PR_NUMBER": "7",
                "FINDINGS_COUNT": "0",
                "EXCLUDE_PATHS": ".github/,Dockerfile",
                "ALLOWED_AUTHORS": "dependabot[bot]",
                "APPROVE_PRS": "true",
                "MERGE_PRS": "false",
            },
        )
        self.assertEqual(result["rc"], 0)
        args = result["stub_args"]
        self.assertEqual(args[0], "approve")
        self.assertIn("--approve", args)
        self.assertNotIn("--merge", args)
        idx = args.index("--exclude-paths")
        self.assertEqual(args[idx + 1], ".github/,Dockerfile")

    def test_shell_metacharacters_are_never_executed(self):
        hostile = "a'; rm -rf marker-pwn; #"
        result = self._run_step(
            "Auto-approve and merge (safe)",
            env_extra={
                "PR_NUMBER": "7",
                "FINDINGS_COUNT": "0",
                "EXCLUDE_PATHS": hostile,
                "ALLOWED_AUTHORS": "dependabot[bot]",
                "APPROVE_PRS": "false",
                "MERGE_PRS": "false",
            },
        )
        self.assertEqual(result["rc"], 0)
        args = result["stub_args"]
        idx = args.index("--exclude-paths")
        self.assertEqual(args[idx + 1], hostile,
                         "hostile input must arrive as ONE literal argument")
        self.assertFalse(os.path.exists(
            os.path.join(result["workdir"], "marker-pwn")),
            "rm -rf would have created the marker via injection")

    def test_merge_prs_implies_approve(self):
        result = self._run_step(
            "Auto-approve and merge (safe)",
            env_extra={
                "PR_NUMBER": "7",
                "FINDINGS_COUNT": "0",
                "EXCLUDE_PATHS": ".github/",
                "ALLOWED_AUTHORS": "dependabot[bot]",
                "APPROVE_PRS": "false",
                "MERGE_PRS": "true",
            },
        )
        self.assertEqual(result["rc"], 0)
        args = result["stub_args"]
        self.assertEqual(args.count("--approve"), 1)
        self.assertIn("--merge", args)


if __name__ == "__main__":
    unittest.main()
