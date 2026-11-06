"""MIZAN Security command-line interface."""

import argparse
import json
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
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content + "\n", encoding="utf-8")
        print(f"Report saved: {path}")
    else:
        print(content)


def main():
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

    args = parser.parse_args()

    try:
        if args.command == "inspect":
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
                result["gate"] = apply_gate(
                    result.get("findings", []),
                    blocking=severities,
                    baseline_path=args.baseline,
                )
            if args.format == "html":
                rendered = render_html(result)
            else:
                rendered = json.dumps(
                    result, indent=2, ensure_ascii=False
                )
            save_or_print(rendered, args.output)
            if "gate" in result:
                return 1 if result["gate"]["decision"] == "fail" else 0

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
                result["gate"] = apply_gate(
                    collect_findings(result),
                    blocking=severities,
                    baseline_path=args.baseline,
                )
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)
            if "gate" in result:
                return 1 if result["gate"]["decision"] == "fail" else 0

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
