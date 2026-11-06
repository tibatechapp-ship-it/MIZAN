"""Scan orchestration and CLI for `mizan scan`."""

import argparse
import json
import os
import sys
from pathlib import Path

from mizan.detector import collect_files
from mizan.sarif import build_sarif
from mizan.vulnerabilities import (
    OsvScanError,
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
    osv_errors = []
    osv_unchecked = []
    for result in checked:
        source = result.get("source")
        if source in ("scan-error", "detail-error"):
            # RW-203: a failed verification is NOT a clean result — surface
            # it explicitly so CI can distinguish "checked, clean" from
            # "could not verify" instead of hiding behind zero findings.
            osv_errors.append({
                "name": result.get("name", ""),
                "version": result.get("version", ""),
                "ecosystem": result.get("ecosystem", ""),
                "source": source,
                "error": result.get("error", ""),
                "vuln_ids": result.get("vuln_ids", []),
            })
        elif source == "offline-miss":
            osv_unchecked.append({
                "name": result.get("name", ""),
                "version": result.get("version", ""),
                "ecosystem": result.get("ecosystem", ""),
                "source": source,
            })
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
        "osv_errors": osv_errors,
        "osv_unchecked": osv_unchecked,
    }


def main(argv=None):
    """CLI entry point for the vulnerability (OSV) scanner."""
    parser = argparse.ArgumentParser(prog="mizan scan")
    parser.add_argument("path", nargs="?", default=".", help="Repository root")
    parser.add_argument("--format", choices=["sarif", "json"], default="sarif")
    parser.add_argument("--output", "-o", help="Write to file instead of stdout")
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: invalid path: {root}", file=sys.stderr)
        return 2

    try:
        result = scan_repository(root)
    except OsvScanError as exc:
        # RW-203: an OSV outage must NOT masquerade as exit 1 ("findings")
        # or 0 ("clean"). It is a scan FAILURE — exit 2, with the reason.
        print(f"error: OSV vulnerability scan failed: {exc}", file=sys.stderr)
        return 2

    if args.format == "sarif":
        content = build_sarif(result)
    else:
        content = json.dumps(result, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)

    return 1 if result["findings"] else 0
