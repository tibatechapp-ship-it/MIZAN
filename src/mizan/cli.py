"""MIZAN command-line interface."""

import argparse
import json
from pathlib import Path

from .analyzer import analyze_repository
from .inspector import inspect_repository
from .ledger import add_entry


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

    ledger_cmd = commands.add_parser("ledger")
    ledger_cmd.add_argument("message")
    ledger_cmd.add_argument(
        "--actor",
        choices=["human", "chatgpt", "joint"],
        required=True
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

            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered + "\n", encoding="utf-8")
                print(f"Report saved: {output}")
            else:
                print(rendered)

        elif args.command == "ledger":
            entry = add_entry(args.message, args.actor)
            print(json.dumps(entry, indent=2, ensure_ascii=False))

    except (ValueError, OSError) as exc:
        parser.exit(1, f"MIZAN error: {exc}\n")


if __name__ == "__main__":
    main()
