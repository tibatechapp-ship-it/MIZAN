"""Scan orchestration and CLI for `mizan scan`."""

import argparse
import json
import os
import sys
from pathlib import Path

from mizan.detector import collect_files
from mizan.sarif import build_sarif
from mizan.vulnerabilities import (
    check_vulnerabilities_batch,
    parse_dependencies,
)


def scan_repository(root):
    """Scan `root` and return a dict of findings.

    Uses ONE batched OSV round-trip for all dependencies instead of one
    query per package. Local caching is opt-in via MIZAN_OSV_CACHE=1.
    """
    files, truncated = collect_files(root)
    dependencies = parse_dependencies(files)

    use_cache = os.environ.get("MIZAN_OSV_CACHE") == "1"
    checked = check_vulnerabilities_batch(dependencies, use_cache=use_cache)

    findings = []
    for result in checked:
        for vuln in result.get("vulns", []):
            dep = {k: v for k, v in result.items()
                   if k in ("name", "version", "ecosystem", "manifest")}
            findings.append({"dependency": dep, "vuln": vuln})

    return {
        "root": str(root),
        "files_scanned": len(files),
        "truncated": truncated,
        "dependencies_checked": len(dependencies),
        "findings": findings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mizan scan")
    parser.add_argument("path", nargs="?", default=".", help="Repository root")
    parser.add_argument("--format", choices=["sarif", "json"], default="sarif")
    parser.add_argument("--output", "-o", help="Write to file instead of stdout")
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: invalid path: {root}", file=sys.stderr)
        return 2

    result = scan_repository(root)

    if args.format == "sarif":
        content = build_sarif(result)
    else:
        content = json.dumps(result, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)

    return 1 if result["findings"] else 0
