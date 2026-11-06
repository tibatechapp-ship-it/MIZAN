"""Unified read-only scanner using trusted built-in plugins."""

import html
from pathlib import Path

from ._version import __version__
from .analyzer import analyze_repository
from .plugins import PLUGINS


def scan_repository(directory=".", category="all"):
    """Run the unified repository scan and return the scanner section."""
    if category not in {"all", "security", "quality"}:
        raise ValueError(f"Unsupported scan category: {category}")

    analysis = analyze_repository(directory)
    all_findings = analysis["findings"]

    # v0.11.0: custom-rule findings belong to no built-in plugin — the
    # category filter below would silently drop them. They bypass it
    # (their own severity speaks) and are reported in their own section;
    # the unified gate therefore always sees the repo's own policies.
    custom_findings = [
        finding for finding in all_findings
        if str(finding.get("rule", "")).startswith("custom-")
    ]

    selected_plugins = [
        plugin for plugin in PLUGINS
        if category == "all" or plugin.category == category
    ]

    results = []
    combined = []

    for plugin in selected_plugins:
        findings = [
            finding
            for finding in all_findings
            if finding["rule"] in plugin.rules
        ]

        combined.extend(findings)

        results.append({
            "name": plugin.name,
            "category": plugin.category,
            "version": plugin.version,
            "findings_count": len(findings),
            "findings": findings,
        })

    return {
        "engine": "MIZAN Security Scanner",
        "version": __version__,
        "repository": analysis["repository"],
        "mode": "read-only",
        "execution_performed": False,
        "files_scanned": analysis["files_scanned"],
        "plugins": results,
        "custom_rules_loaded": analysis.get("custom_rules_loaded", 0),
        "custom_rules_errors": analysis.get("custom_rules_errors", []),
        "custom_findings_count": len(custom_findings),
        "findings_count": len(combined) + len(custom_findings),
        "findings": combined + custom_findings,
    }


def render_html(report):
    """Render an HTML report without interpreting finding content as HTML."""
    rows = []

    for finding in report["findings"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding['severity']))}</td>"
            f"<td>{html.escape(str(finding['rule']))}</td>"
            f"<td>{html.escape(str(finding['file']))}</td>"
            f"<td>{html.escape(str(finding['line']))}</td>"
            f"<td>{html.escape(str(finding['message']))}</td>"
            "</tr>"
        )

    table_rows = "\n".join(rows)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MIZAN Security Scan Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; line-height: 1.5; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background: #eee; }}
</style>
</head>
<body>
<h1>MIZAN Security Scan Report</h1>
<p>Repository: {html.escape(str(report['repository']))}</p>
<p>Mode: read-only</p>
<p>Files scanned: {report['files_scanned']}</p>
<p>Findings: {report['findings_count']}</p>
<table>
<thead>
<tr><th>Severity</th><th>Rule</th><th>File</th>
<th>Line</th><th>Message</th></tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
</body>
</html>
"""
