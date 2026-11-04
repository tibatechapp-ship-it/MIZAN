"""MIZAN command-line interface."""

import argparse
import json
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


def full_scan_repository(directory="."):
    """Run all MIZAN read-only repository scanners."""
    return {
        "engine": "MIZAN Master Engine",
        "version": __version__,
        "repository": str(Path(directory).expanduser().resolve()),
        "mode": "read-only",
        "execution_performed": False,
        "analysis": analyze_repository(directory),
        "detection": detect_project(directory),
        "scanner": scan_repository(directory),
        "git": scan_git_repository(directory),
        "ci": scan_ci_repository(directory),
        "dependencies": scan_dependencies(directory),
        "change_risk": scan_change_risk(directory),
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
        description="MIZAN Software Analysis and Verification Engine"
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
            if args.format == "html":
                rendered = render_html(result)
            else:
                rendered = json.dumps(
                    result, indent=2, ensure_ascii=False
                )
            save_or_print(rendered, args.output)

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
            result = full_scan_repository(args.path)
            rendered = json.dumps(
                result, indent=2, ensure_ascii=False
            )
            save_or_print(rendered, args.output)

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

    except (ValueError, OSError) as exc:
        parser.exit(1, f"MIZAN error: {exc}\n")


if __name__ == "__main__":
    import sys
    sys.exit(main())
