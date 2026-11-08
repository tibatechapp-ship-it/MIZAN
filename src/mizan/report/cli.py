"""``mizan report`` CLI — four LOCAL-ONLY commands; publish is deliberately
not implemented (the triage gate ships first, docs/REPORT_SECURITY.md).

    generate  — triage-gated DRAFT report for ONE finding (md/html/sarif/json)
    show      — local, redacted, snippet-free view of one finding
    overdue   — disclosures past the 90-day deadline, non-terminal statuses
    export    — tracked drafts as SARIF 2.1.0

Writes: only paths under --output, plus the local timeline DB
(~/.mizan/disclosures.db, or MIZAN_REPORT_DB). Every written file is
re-read and scanned for secrets; a hit deletes the file and exits 2.
"""

import json
import sys
from pathlib import Path

from .contact import find_contact
from .generator import generate
from .ids import fingerprint
from .redact import redact_finding, scan_text_for_secrets
from .timeline import Timeline
from .triage import check as triage_check

__all__ = ["dispatch"]


def _load_findings(scan_json: str) -> list:
    data = json.loads(Path(scan_json).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            return [item for item in data["findings"] if isinstance(item, dict)]
        if isinstance(data.get("plugins"), list):
            flat = []
            for plugin in data["plugins"]:
                if isinstance(plugin, dict) and isinstance(
                        plugin.get("findings"), list):
                    flat.extend(f for f in plugin["findings"]
                                if isinstance(f, dict))
            return flat
    raise ValueError(f"unrecognized scan JSON shape in {scan_json!r}")


def _pick(findings: list, fid: str) -> dict:
    matches = [f for f in findings if fingerprint(f) == fid]
    if not matches:
        print(f"report: no finding with id {fid!r} in the scan JSON",
              file=sys.stderr)
        sys.exit(2)
    return matches[0]


def _verify_written(paths: list) -> int:
    """Third secret-safety layer: re-read from disk and fail loud."""
    leaked = []
    for path in paths:
        hits = scan_text_for_secrets(path.read_text(encoding="utf-8"))
        if hits:
            leaked.append((path, hits))
    if leaked:
        for path, hits in leaked:
            path.unlink(missing_ok=True)
        print("report: SECRET LEAK detected in a written report — "
              "files deleted, nothing disclosed:", file=sys.stderr)
        for path, hits in leaked:
            print(f"  - {path}: {hits}", file=sys.stderr)
        return 2
    return 0


def cmd_generate(args) -> int:
    findings = _load_findings(args.scan_json)
    finding = _pick(findings, args.finding_id)
    fid = args.finding_id

    triage = json.loads(
        Path(args.triage).read_text(encoding="utf-8")) if args.triage else {}
    failures = triage_check(finding, triage, fid, args.confirm)
    if failures:
        print("report: triage gate BLOCKED generation:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 2

    repo_root = Path(args.repo_root).resolve()
    repo = args.repo or repo_root.name
    contact = find_contact(repo_root)
    timeline = Timeline()
    payload = generate(
        finding, repo, contact,
        include_snippet=args.include_snippet,
        snippet=finding.get("snippet"),
        prev_hash=timeline.last_hash(),
    )

    outdir = Path(args.output).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    bodies = {
        "md": payload["markdown"],
        "html": payload["html"],
        "sarif": json.dumps(payload["sarif"], indent=2, ensure_ascii=False),
        "json": json.dumps(payload, indent=2, ensure_ascii=False),
    }
    written = []
    for fmt, body in bodies.items():
        path = outdir / f"report-{fid}.{fmt}"
        path.write_text(body, encoding="utf-8")
        written.append(path)

    leak_exit = _verify_written(written)
    if leak_exit:
        return leak_exit

    stored = dict(finding)
    stored["repo"] = repo
    timeline.record_draft(
        stored, contact, str(outdir),
        payload["cvss"]["score"], payload["cvss"]["severity"], payload["hash"],
    )

    print(f"report: draft {stored['repo']}/{fid} written to {outdir}")
    print(f"  chain: {payload['prev_hash'][:12]} -> {payload['hash'][:12]}")
    print(f"  cvss:  {payload['cvss']['severity']} "
          f"{payload['cvss']['score']:.1f}  ({payload['cvss']['vector']})")
    print(f"  cwe:   {payload['cwe']['id'] or 'Unknown'} "
          f"{payload['cwe']['name']}")
    print(f"  contact: {payload['contact']}")
    return 0


def cmd_show(args) -> int:
    finding = _pick(_load_findings(args.scan_json), args.finding_id)
    shown = {key: value for key, value in finding.items()
             if key != "snippet"}     # snippets are never shown locally
    print(json.dumps(redact_finding(shown), indent=2, ensure_ascii=False))
    return 0


def cmd_overdue(_args) -> int:
    rows = Timeline().overdue()
    if not rows:
        print("report: no overdue disclosures")
        return 0
    print(f"report: {len(rows)} overdue (past 90 days, non-terminal):")
    for row in rows:
        print(f"  {row[0]}  {row[1]}  {row[2]}  "
              f"deadline {row[3]}  [{row[4]}]")
    return 0


def _finding_of_row(row) -> dict:
    """Parse a stored finding. Rows written before the P1 integration fix
    held repr(dict) (single quotes); parse those with a tolerant fallback
    so old local databases still export."""
    raw = row["finding_json"] or "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        import ast
        try:
            parsed = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            parsed = {}
    return parsed if isinstance(parsed, dict) else {}


def cmd_export(args) -> int:
    rows = Timeline().all_entries()
    results = []
    rules = []
    for row in rows:
        finding = _finding_of_row(row)
        rule_id = str(finding.get("rule", "unknown"))
        level = {"Critical": "error", "High": "error",
                 "Medium": "warning"}.get(row["cvss_severity"], "warning")
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{row['repo']}: {rule_id} "
                                f"(cvss {row['cvss_score']:.1f} "
                                f"{row['cvss_severity']})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding.get("file", "unknown"))},
                    "region": {"startLine": int(finding.get("line", 0) or 0)},
                }
            }],
            "properties": {"status": row["status"], "cwe": row["cwe"]},
        })
        if rule_id not in [r.get("id") for r in rules]:
            rules.append({"id": rule_id, "helpUri": (
                f"https://cwe.mitre.org/data/definitions/"
                f"{row['cwe'].split('-')[-1]}.html" if row["cwe"] else None)})
    envelope = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "MIZAN Security",
            "informationUri": "https://github.com/tibatechapp-ship-it/MIZAN",
            "rules": rules,
        }}, "results": results}],
    }
    out = Path(args.output).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(envelope, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    leak_exit = _verify_written([out])
    if leak_exit:
        return leak_exit
    print(f"report: exported {len(results)} tracked finding(s) to {out}")
    return 0


def dispatch(args) -> int:
    handlers = {
        "generate": cmd_generate,
        "show": cmd_show,
        "overdue": cmd_overdue,
        "export": cmd_export,
    }
    return handlers[args.report_command](args)
