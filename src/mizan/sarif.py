"""SARIF 2.1.0 output for MIZAN scan results."""

import json

from mizan._version import __version__ as TOOL_VERSION  # single source of truth
from mizan.vulnerabilities import severity_of

SARIF_VERSION = "2.1.0"
TOOL_NAME = "MIZAN Security"

_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "warning",
}


def build_sarif(scan_result):
    """Convert scan_repository() output to a SARIF 2.1.0 JSON string."""
    rules = {}
    results = []

    for finding in scan_result["findings"]:
        dep = finding["dependency"]
        vuln = finding["vuln"]
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary") or vuln.get("details") or vuln_id
        rule_id = f"MIZAN-{dep['ecosystem']}-{vuln_id}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": str(summary)[:200]},
                "helpUri": f"https://osv.dev/vulnerability/{vuln_id}",
                "properties": {
                    "ecosystem": dep["ecosystem"],
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(severity_of(vuln), "warning"),
            "message": {
                "text": (
                    f"{dep['name']} {dep['version']} is affected by "
                    f"{vuln_id}: {summary}"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": dep.get("manifest", "unknown")},
                }
            }],
            "properties": {
                "package": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "vuln_id": vuln_id,
                "aliases": vuln.get("aliases", []),
            },
        })

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/tibatechapp-ship-it/MIZAN",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(document, indent=2)
