"""Unified read-only scanner using trusted built-in plugins."""

import html
from pathlib import Path

from .analyzer import analyze_repository
from .plugins import PLUGINS


def scan_repository(directory=".", category="all"):
    if category not in {"all", "security", "quality"}:
        raise ValueError(f"Unsupported scan category: {category}")

    analysis = analyze_repository(directory)
    all_findings = analysis["findings"]

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
        "engine": "MIZAN Scanner",
        "version": "0.1.0",
        "repository": analysis["repository"],
        "mode": "read-only",
        "execution_performed": False,
        "files_scanned": analysis["files_scanned"],
        "plugins": results,
        "findings_count": len(combined),
        "findings": combined,
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
<title>MIZAN Scan Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; line-height: 1.5; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background: #eee; }}
</style>
</head>
<body>
<h1>MIZAN Scan Report</h1>
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
