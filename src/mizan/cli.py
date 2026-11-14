"""MIZAN Security command-line interface."""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .analyzer import analyze_repository
from .inspector import inspect_repository
from .ledger import add_entry
from .detector import detect_project
from .plugins import list_plugins, get_plugin
from .scanner import scan_repository, render_html
from .git_scanner import scan_git_repository
from .ci_scanner import scan_ci_repository
from .risk_scanner import scan_change_risk
from .dependency_scanner import scan_dependencies
from .doc_intel import scan_documentation_repository, render_doc_intel_text


def _run_isolated(name, runner, directory):
    """Run one scanner, turning a crash into a recorded error section.

    One scanner failing (e.g. git scanners outside a Git worktree) must
    NOT destroy the whole full-scan report — the remaining sections stay
    useful, and the failure stays visible instead of silent.
    """
    try:
        return runner(directory)
    except Exception as exc:  # noqa: BLE001 — isolation IS the point
        return {
            "engine": f"MIZAN {name}",
            "error": str(exc),
            "findings": [],
            "mode": "read-only",
            "execution_performed": False,
        }


def full_scan_repository(directory=".", jobs=4):
    """Run all MIZAN Security read-only repository scanners.

    Q2 speed wave: the scanners are independent read-only passes, so by
    default (``jobs >= 2``) they run concurrently in a thread pool —
    wall time becomes the SLOWEST pass instead of the SUM of all passes.
    ``jobs=1`` restores the strictly sequential execution.

    Review wave (v0.8.2): each scanner is isolated — if one of them
    cannot run (for example the Git scanners outside a Git repository)
    its section records ``"error"`` and the rest of the report survives;
    the failing names are listed under ``"scanners_failed"``.
    """
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Invalid repository directory: {root}")

    runners = {
        "analysis": analyze_repository,
        "detection": detect_project,
        "scanner": scan_repository,
        "git": scan_git_repository,
        "ci": scan_ci_repository,
        "dependencies": scan_dependencies,
        "change_risk": scan_change_risk,
        "documentation": scan_documentation_repository,
    }

    started = time.perf_counter()
    if jobs and jobs > 1:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {
                name: pool.submit(_run_isolated, name, runner, directory)
                for name, runner in runners.items()
            }
            results = {
                name: future.result()
                for name, future in futures.items()
            }
    else:
        results = {
            name: _run_isolated(name, runner, directory)
            for name, runner in runners.items()
        }
    wall_seconds = round(time.perf_counter() - started, 3)

    failed = sorted(
        name for name, section in results.items() if "error" in section
    )

    return {
        "engine": "MIZAN Security Master Engine",
        "version": __version__,
        "repository": str(root),
        "mode": "read-only",
        "execution_performed": False,
        "execution": {"jobs": jobs or 1, "wall_seconds": wall_seconds},
        "scanners_failed": failed,
        **results,
    }


def save_or_print(content, output=None):
    """Write the rendered report to a file or print it to stdout."""
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content + "\n", encoding="utf-8")
        print(f"Report saved: {path}")
    else:
        print(content)


def main(argv=None):
    """Parse arguments and dispatch the requested MIZAN subcommand.

    ``argv`` (v0.12.0): injectable for tests and embedders — None keeps
    the historical sys.argv behavior.
    """
    parser = argparse.ArgumentParser(
        prog="mizan",
        description=(
            "MIZAN Security — one lightweight, fast engine for code, "
            "secrets, dependencies and CI hardening"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"MIZAN Security {__version__}",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = commands.add_parser("inspect")
    inspect_cmd.add_argument("path", nargs="?", default=".")

    analyze_cmd = commands.add_parser("analyze")
    analyze_cmd.add_argument("path", nargs="?", default=".")
    analyze_cmd.add_argument("--output", default=None)

    detect_cmd = commands.add_parser(
        "detect",
        help="Detect project technologies"
    )
    detect_cmd.add_argument("path", nargs="?", default=".")
    detect_cmd.add_argument("--output", default=None)

    plugins_cmd = commands.add_parser(
        "plugins",
        help="Manage built-in scanner plugins"
    )
    plugin_commands = plugins_cmd.add_subparsers(
        dest="plugin_command", required=True
    )
    plugin_commands.add_parser("list")
    plugin_info = plugin_commands.add_parser("info")
    plugin_info.add_argument("name")

    scan_cmd = commands.add_parser(
        "scan",
        help="Run unified read-only repository scanning"
    )
    scan_cmd.add_argument("path", nargs="?", default=".")
    scan_cmd.add_argument(
        "--category",
        choices=["all", "security", "quality"],
        default="all"
    )
    scan_cmd.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )
    scan_cmd.add_argument("--output", default=None)
    scan_cmd.add_argument(
        "--gate",
        nargs="?",
        const="critical,high",
        default=None,
        metavar="SEVERITIES",
        help=(
            "Fail (exit 1) when findings at these normalized severities "
            "exist; bare --gate defaults to 'critical,high'"
        ),
    )
    scan_cmd.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help=(
            "Only gate on findings whose fingerprint is NOT in this "
            "baseline (delta scanning — kills alert fatigue)"
        ),
    )

    remote_cmd = commands.add_parser(
        "scan-remote",
        help=("Scan a GitHub repository via the Tarball API with strict "
              "safe-extraction filters (see docs/REMOTE_SCAN.md); the "
              "extracted tree is deleted immediately after the scan")
    )
    remote_cmd.add_argument("owner_repo", metavar="OWNER/REPO")
    remote_cmd.add_argument(
        "--ref", default=None,
        help="branch, tag or commit SHA (default: repository default branch)"
    )
    remote_cmd.add_argument(
        "--category", choices=["all", "security", "quality"], default="all"
    )
    remote_cmd.add_argument(
        "--format", choices=["json", "html"], default="json"
    )
    remote_cmd.add_argument("--output", default=None)

    report_cmd = commands.add_parser(
        "report",
        help=("Local disclosure-report toolkit (docs/REPORT_SECURITY.md): "
              "triage-gated draft generation, local view, 90-day overdue "
              "tracking, SARIF export. No network; no publish command.")
    )
    report_sub = report_cmd.add_subparsers(dest="report_command",
                                           required=True)
    report_gen = report_sub.add_parser(
        "generate",
        help="generate a DRAFT report for ONE finding — triage-gated"
    )
    report_gen.add_argument("scan_json")
    report_gen.add_argument("--finding-id", required=True)
    report_gen.add_argument(
        "--confirm", required=True,
        help="must equal --finding-id (typed by the operator)"
    )
    report_gen.add_argument(
        "--triage", required=True,
        help="path to the completed 10-question triage JSON"
    )
    report_gen.add_argument("--output", required=True)
    report_gen.add_argument(
        "--repo-root", default=".",
        help="repository root for local SECURITY.md discovery"
    )
    report_gen.add_argument("--repo", default=None,
                            help="repository display name")
    report_gen.add_argument(
        "--include-snippet", action="store_true",
        help="include a redacted source snippet (default: none)"
    )
    report_show = report_sub.add_parser(
        "show",
        help="view one finding locally (redacted, never a snippet)"
    )
    report_show.add_argument("scan_json")
    report_show.add_argument("--finding-id", required=True)
    report_sub.add_parser(
        "overdue", help="disclosures past the 90-day deadline"
    )
    report_exp = report_sub.add_parser(
        "export", help="export tracked drafts as SARIF"
    )
    report_exp.add_argument("--output", required=True)

    git_cmd = commands.add_parser(
        "git-scan",
        help="Inspect Git repository without modifying it"
    )
    git_cmd.add_argument("path", nargs="?", default=".")

    ci_cmd = commands.add_parser(
        "ci-scan",
        help="Inspect CI/CD configuration files"
    )
    ci_cmd.add_argument("path", nargs="?", default=".")
    ci_cmd.add_argument("--output", default=None)

    full_cmd = commands.add_parser(
        "full-scan",
        help="Run all MIZAN repository scanners"
    )
    full_cmd.add_argument("path", nargs="?", default=".")
    full_cmd.add_argument("--output", default=None)
    full_cmd.add_argument(
        "--jobs",
        type=int,
        default=4,
        metavar="N",
        help="Parallel scanners (default 4, use 1 for sequential)",
    )
    full_cmd.add_argument(
        "--gate",
        nargs="?",
        const="critical,high",
        default=None,
        metavar="SEVERITIES",
        help=(
            "Fail (exit 1) when findings from ANY scanner (code, CI, "
            "git, dependencies) sit at these normalized severities; "
            "bare --gate defaults to 'critical,high'"
        ),
    )
    full_cmd.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help=(
            "Only gate on findings whose fingerprint is NOT in this "
            "baseline (delta scanning across every scanner)"
        ),
    )

    dependency_cmd = commands.add_parser(
        "dependency-scan",
        help="Inspect dependency manifests offline"
    )
    dependency_cmd.add_argument("path", nargs="?", default=".")
    dependency_cmd.add_argument("--output", default=None)

    risk_cmd = commands.add_parser(
        "risk-scan",
        help="Assess Git change risk without modifying files"
    )
    risk_cmd.add_argument("path", nargs="?", default=".")
    risk_cmd.add_argument("--output", default=None)

    doc_cmd = commands.add_parser(
        "doc-scan",
        help=(
            "Documentation Intelligence: verify docs match reality "
            "(links, stale references, coverage, endpoints, README)"
        ),
    )
    doc_cmd.add_argument("path", nargs="?", default=".")
    doc_cmd.add_argument(
        "--format", choices=["json", "text"], default="json"
    )
    doc_cmd.add_argument("--output", default=None)

    import_cmd = commands.add_parser(
        "import-sarif",
        help=(
            "Import an external SARIF 2.1.0 report (Semgrep, Gitleaks, "
            "Trivy, Bandit, ...) into MIZAN's normalized finding schema "
            "— read-only, provenance preserved, failures are loud"
        ),
    )
    import_cmd.add_argument("report", metavar="REPORT")
    import_cmd.add_argument("--output", default=None)

    merge_cmd = commands.add_parser(
        "merge-findings",
        help=(
            "Merge several SARIF reports into grouped findings — link, "
            "never erase: every occurrence keeps its tool and evidence"
        ),
    )
    merge_cmd.add_argument(
        "reports", nargs="+", metavar="REPORT"
    )
    merge_cmd.add_argument("--output", default=None)

    triage_cmd = commands.add_parser(
        "triage",
        help=(
            "Apply documented review decisions to imported findings — "
            "decisions referencing unknown fingerprints are rejected"
        ),
    )
    triage_cmd.add_argument("findings", metavar="FINDINGS_JSON")
    triage_cmd.add_argument(
        "--decisions", required=True, metavar="JSON"
    )
    triage_cmd.add_argument("--output", default=None)

    ledger_cmd = commands.add_parser("ledger")
    ledger_cmd.add_argument("message")
    ledger_cmd.add_argument(
        "--actor",
        choices=["human", "chatgpt", "joint"],
        required=True
    )

    # NEW: vuln-scan — scans dependencies for known vulnerabilities (OSV.dev)
    vuln_cmd = commands.add_parser(
        "vuln-scan",
        help="Scan dependencies for known vulnerabilities via OSV.dev"
    )
    vuln_cmd.add_argument("path", nargs="?", default=".")
    vuln_cmd.add_argument(
        "--format",
        choices=["sarif", "json"],
        default="sarif"
    )
    vuln_cmd.add_argument("--output", "-o", default=None)

    approve_cmd = commands.add_parser(
        "approve",
        help="Safely auto-approve and optionally merge eligible PRs"
    )
    approve_cmd.add_argument("--pr", type=int, required=True)
    approve_cmd.add_argument("--findings", type=int, default=0)
    approve_cmd.add_argument("--exclude-paths", default="")
    approve_cmd.add_argument(
        "--allowed-authors",
        default="dependabot[bot],renovate[bot],github-actions[bot]",
    )
    approve_cmd.add_argument("--allow-own", action="store_true",
                             help="Allow approving PRs from the current bot (not recommended)")
    approve_cmd.add_argument("--approve", action="store_true")
    approve_cmd.add_argument("--merge", action="store_true")
    approve_cmd.add_argument(
        "--method", choices=["squash", "merge", "rebase"], default="squash"
    )
    approve_cmd.add_argument("--dry-run", action="store_true")

    fix_cmd = commands.add_parser(
        "fix",
        help="Apply safe dependency upgrades with test-based validation"
    )
    fix_cmd.add_argument("path", nargs="?", default=".")
    fix_cmd.add_argument("--plan", action="store_true")
    fix_cmd.add_argument("--apply", action="store_true")
    fix_cmd.add_argument("--no-validate", action="store_true")
    fix_cmd.add_argument("--format", choices=["json", "text"], default="text")

    baseline_cmd = commands.add_parser(
        "baseline",
        help="Save current findings as a gate baseline (delta scanning)",
    )
    baseline_cmd.add_argument("path", nargs="?", default=".")
    baseline_cmd.add_argument(
        "--save",
        default=".mizan/baseline.json",
        metavar="PATH",
    )
    baseline_cmd.add_argument("--note", default="")
    baseline_cmd.add_argument(
        "--jobs",
        type=int,
        default=4,
        metavar="N",
    )

    # NEW: portfolio — aggregate several repositories into ONE
    # self-contained HTML report (display layer; the gate stays
    # full-scan --gate).
    portfolio_cmd = commands.add_parser(
        "portfolio",
        help=(
            "Aggregate full-scan results for MULTIPLE repositories "
            "into one self-contained HTML report (display layer)"
        ),
    )
    portfolio_cmd.add_argument(
        "paths", nargs="+", metavar="DIR",
        help="Two or more repository directories (one or more accepted)",
    )
    portfolio_cmd.add_argument(
        "--output", "-o", default="mizan_portfolio.html",
        metavar="FILE",
        help="Where to write the HTML report (default: mizan_portfolio.html)",
    )
    portfolio_cmd.add_argument(
        "--json", action="store_true",
        help="Print the aggregate JSON instead of writing HTML",
    )
    portfolio_cmd.add_argument(
        "--jobs",
        type=int,
        default=4,
        metavar="N",
        help="Parallel scanners per repository (default 4)",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "import-sarif":
            from .integrations.sarif_import import (
                SarifImportError,
                import_sarif_report,
            )
            try:
                result = import_sarif_report(args.report)
            except SarifImportError as exc:
                # Exit contract: 2 = incomplete. A report that cannot be
                # read or parsed is never certified as a clean import
                # (docs/DEV_PLAN_V0150.md, wave 0).
                parser.error(str(exc))
            rendered = json.dumps(result, indent=2, ensure_ascii=False)
            save_or_print(rendered, args.output)
            return 0

        elif args.command == "merge-findings":
            from .integrations.merge import MergeError, merge_findings
            from .integrations.sarif_import import (
                SarifImportError,
                normalize_sarif,
            )
            lists = []
            try:
                for report_path in args.reports:
                    lists.append(normalize_sarif(report_path))
                result = merge_findings(lists)
            except (SarifImportError, MergeError) as exc:
                # Exit contract: 2 = incomplete — a missing/invalid
                # report never merges into a clean result.
                parser.error(str(exc))
            rendered = json.dumps(result, indent=2, ensure_ascii=False)
            save_or_print(rendered, args.output)
            return 0

        elif args.command == "triage":
            from .integrations.merge import MergeError, apply_triage
            try:
                with open(args.findings, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                parser.error(
                    f"Cannot read findings file {args.findings}: {exc}"
                )
            if isinstance(payload, dict) and isinstance(
                payload.get("findings"), list
            ):
                findings = payload["findings"]
            elif isinstance(payload, dict) and isinstance(
                payload.get("groups"), list
            ):
                # mizan.merged.v1: flatten occurrences — every group's
                # evidence travels into the triage decisions intact.
                findings = [
                    occurrence
                    for group in payload["groups"]
                    for occurrence in group.get("occurrences", [])
                ]
            elif isinstance(payload, list):
                findings = payload
            else:
                parser.error(
                    f"{args.findings} must be a findings list, a "
                    "mizan.import.v1 summary, or a mizan.merged.v1 "
                    "summary"
                )
            try:
                with open(args.decisions, "r", encoding="utf-8") as fh:
                    decisions = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                parser.error(
                    f"Cannot read decisions file {args.decisions}: {exc}"
                )
            try:
                result = apply_triage(findings, decisions)
            except (MergeError, ValueError) as exc:
                # Exit contract: 2 = incomplete — undocumented
                # suppression is never certified as applied.
                parser.error(str(exc))
            rendered = json.dumps(result, indent=2, ensure_ascii=False)
            save_or_print(rendered, args.output)
            return 0

        elif args.command == "inspect":
            result = inspect_repository(args.path)
            print(json.dumps(result, indent=2, ensure_ascii=False))

        elif args.command == "analyze":
            result = analyze_repository(args.path)
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)

        elif args.command == "detect":
            result = detect_project(args.path)
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)

        elif args.command == "plugins":
            if args.plugin_command == "list":
                result = list_plugins()
            else:
                result = get_plugin(args.name)
            print(json.dumps(result, indent=2, ensure_ascii=False))

        elif args.command == "scan":
            result = scan_repository(
                args.path,
                category=args.category
            )
            if args.gate is not None:
                from .gate import apply_gate, validate_blocking
                severities = [
                    s.strip().lower()
                    for s in args.gate.split(",") if s.strip()
                ]
                try:
                    severities = list(validate_blocking(severities))
                except ValueError as exc:
                    parser.error(str(exc))
                # RW-202/203: dependency verification that could not complete
                # (OSV outage or offline cache miss) is not a clean result.
                incomplete = []
                if result.get("osv_errors"):
                    incomplete.append("osv")
                if result.get("osv_unchecked"):
                    incomplete.append("osv-offline")
                # v0.11.0: a policies file that could not be loaded is a
                # partial scan of the repo's own rules — fail loud.
                if result.get("custom_rules_errors"):
                    incomplete.append("custom-rules")
                result["gate"] = apply_gate(
                    result.get("findings", []),
                    blocking=severities,
                    baseline_path=args.baseline,
                    incomplete_sources=incomplete,
                )
            if args.format == "html":
                rendered = render_html(result)
            else:
                rendered = json.dumps(
                    result, indent=2, ensure_ascii=False
                )
            save_or_print(rendered, args.output)
            if "gate" in result:
                decision = result["gate"]["decision"]
                if decision == "fail":
                    return 1
                if decision == "incomplete":
                    return 2
                return 0
            # Exit contract without --gate: unloadable custom policies make
            # the scan incomplete — never a silent clean pass.
            if result.get("custom_rules_errors"):
                return 2
            return 0

        elif args.command == "scan-remote":
            # P1.3 field-measurement path: GitHub Tarball API + strict safe
            # extraction (docs/REMOTE_SCAN.md). Local `scan` is untouched.
            from .remote_scan import RemoteScanError, scan_remote
            token = (
                os.environ.get("MIZAN_GH_TOKEN")
                or os.environ.get("GH_TOKEN")
                or None
            )  # header-only use inside remote_scan; never printed/stored
            try:
                result = scan_remote(
                    args.owner_repo,
                    ref=args.ref,
                    category=args.category,
                    token=token,
                )
            except RemoteScanError as exc:
                print(f"scan-remote: {exc}", file=sys.stderr)
                return 2
            if args.format == "html":
                rendered = render_html(result)
            else:
                rendered = json.dumps(result, indent=2, ensure_ascii=False)
            save_or_print(rendered, args.output)
            return 0

        elif args.command == "report":
            # Local-only disclosure toolkit (docs/REPORT_SECURITY.md).
            from .report import cli as report_cli
            return report_cli.dispatch(args)

        elif args.command == "git-scan":
            result = scan_git_repository(args.path)
            print(json.dumps(
                result, indent=2, ensure_ascii=False
            ))

        elif args.command == "ci-scan":
            result = scan_ci_repository(args.path)
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)

        elif args.command == "portfolio":
            from .portfolio import (
                build_portfolio, portfolio_to_json, render_portfolio_html,
            )
            portfolio = build_portfolio(args.paths, jobs=args.jobs)
            if args.json:
                print(portfolio_to_json(portfolio))
            else:
                save_or_print(render_portfolio_html(portfolio), args.output)
            # Display layer: a report is produced and shown. Exit 2 only
            # when NO repository could be scanned at all — a report nobody
            # can trust is not a report.
            if portfolio.get("scanned_ok", 0) == 0:
                return 2
            return 0

        elif args.command == "full-scan":
            from .gate import apply_gate, collect_findings, validate_blocking
            result = full_scan_repository(args.path, jobs=args.jobs)
            if args.gate is not None:
                severities = [
                    s.strip().lower()
                    for s in args.gate.split(",") if s.strip()
                ]
                try:
                    severities = list(validate_blocking(severities))
                except ValueError as exc:
                    parser.error(str(exc))
                # Gate across EVERY scanner's findings (code, CI, git,
                # dependencies/OSV) — not just the code pass. Deduplication
                # inside apply_gate keeps section overlap from double-counting.
                # RW-202: a PARTIAL scan must never certify a clean pass —
                # failed scanners and unverifiable OSV deps force the
                # "incomplete" decision (exit 2), still overridden by real
                # blocking findings (exit 1).
                incomplete = list(result.get("scanners_failed") or [])
                deps = result.get("dependencies") or {}
                if deps.get("osv_errors"):
                    incomplete.append("osv")
                if deps.get("osv_unchecked"):
                    incomplete.append("osv-offline")
                # v0.11.0: broken .mizan/rules.json = unenforced policies →
                # the gate may not certify a clean pass (same doctrine as
                # osv_errors / scanners_failed).
                analysis = result.get("analysis") or {}
                if analysis.get("custom_rules_errors"):
                    incomplete.append("custom-rules")
                result["gate"] = apply_gate(
                    collect_findings(result),
                    blocking=severities,
                    baseline_path=args.baseline,
                    incomplete_sources=incomplete,
                )
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)
            if "gate" in result:
                decision = result["gate"]["decision"]
                if decision == "fail":
                    return 1
                if decision == "incomplete":
                    return 2
                return 0
            # Documented exit contract (README): exit 2 = INCOMPLETE scan —
            # a scanner failed, OSV verification was impossible, or custom
            # policies could not load. This holds WITHOUT --gate too: a
            # report-only run must never present a happy exit 0 for an
            # incomplete scan ("never a silent clean pass").
            incomplete_sources = list(result.get("scanners_failed") or [])
            deps = result.get("dependencies") or {}
            if deps.get("osv_errors"):
                incomplete_sources.append("osv")
            if deps.get("osv_unchecked"):
                incomplete_sources.append("osv-offline")
            analysis = result.get("analysis") or {}
            if analysis.get("custom_rules_errors"):
                incomplete_sources.append("custom-rules")
            if incomplete_sources:
                return 2
            return 0

        elif args.command == "baseline":
            from .gate import collect_findings, save_baseline
            full = full_scan_repository(args.path, jobs=args.jobs)
            findings = collect_findings(full)
            doc = save_baseline(findings, path=args.save, note=args.note)
            print(json.dumps({
                "tool": "MIZAN Security",
                "baseline": doc["schema"],
                "saved_to": str(Path(args.save)),
                "fingerprints": doc["count"],
                "note": doc["note"],
            }, indent=2, ensure_ascii=False))

        elif args.command == "dependency-scan":
            result = scan_dependencies(args.path)
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)

        elif args.command == "risk-scan":
            result = scan_change_risk(args.path)
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)

        elif args.command == "doc-scan":
            result = scan_documentation_repository(args.path)
            if args.format == "text":
                rendered = render_doc_intel_text(result)
            else:
                rendered = json.dumps(
                    result, indent=2, ensure_ascii=False
                )
            save_or_print(rendered, args.output)

        elif args.command == "ledger":
            entry = add_entry(args.message, args.actor)
            print(json.dumps(entry, indent=2, ensure_ascii=False))

        elif args.command == "vuln-scan":
            from .scan import main as vuln_scan_main
            argv = [args.path, "--format", args.format]
            if args.output:
                argv.extend(["--output", args.output])
            return vuln_scan_main(argv)

        elif args.command == "approve":
            from .approval import (
                is_pr_eligible, approve_pr, merge_pr,
                DEFAULT_EXCLUDE_PATHS, DEFAULT_ALLOWED_AUTHORS,
            )

            excludes = [x.strip() for x in (args.exclude_paths or "").split(",") if x.strip()]
            if not excludes:
                excludes = list(DEFAULT_EXCLUDE_PATHS)

            authors = [x.strip() for x in (args.allowed_authors or "").split(",") if x.strip()]
            if not authors:
                authors = list(DEFAULT_ALLOWED_AUTHORS)
            if args.allow_own:
                authors.append("github-actions[bot]")

            ok, reason = is_pr_eligible(
                args.pr,
                findings_count=args.findings,
                exclude_paths=tuple(excludes),
                allowed_authors=tuple(authors),
            )

            print(f"eligibility: {'ELIGIBLE' if ok else 'BLOCKED'}")
            print(f"reason     : {reason}")

            if not ok:
                return 1

            if args.dry_run:
                print("dry-run: no action taken")
                return 0

            if args.approve:
                success, msg = approve_pr(
                    args.pr,
                    comment="Auto-approved by MIZAN: all checks passed, no findings.",
                )
                print(f"approve    : {'OK' if success else 'FAILED'} ({msg[:100]})")
                if not success:
                    return 1

            if args.merge:
                success, msg = merge_pr(args.pr, method=args.method, auto=True)
                print(f"merge      : {'OK' if success else 'FAILED'} ({msg[:100]})")
                if not success:
                    return 1

            return 0

        elif args.command == "fix":
            from .fix import main as fix_main
            argv = [args.path]
            if args.plan:
                argv.append("--plan")
            if args.apply:
                argv.append("--apply")
            if args.no_validate:
                argv.append("--no-validate")
            argv.extend(["--format", args.format])
            return fix_main(argv)

    except (ValueError, OSError) as exc:
        parser.exit(1, f"MIZAN Security error: {exc}\n")


if __name__ == "__main__":
    import sys
    sys.exit(main())
