"""Portfolio aggregation — one local HTML report across many repositories.

v0.12.0 (P2 gap #5 — governance visibility, honestly scoped):

``mizan portfolio <dir>…`` runs the SAME read-only full-scan machinery
over several repositories and folds the results into ONE self-contained
HTML file (inline CSS, zero JavaScript, zero external requests, zero
server, zero accounts).

Explicitly NOT a GRC platform — the ROADMAP "what we will not do" list
still stands. This is a display layer whose numbers are exactly the
numbers ``full-scan`` produced:

* findings are deduplicated with the SAME fingerprint the gate uses
  (``gate.fingerprint``), so the mirrored ``analysis``/``scanner``
  sections cannot double-count a finding;
* portfolio never gates: exit 0 with a report, exit 2 only when NO
  repository could be scanned at all (a report nobody can trust is not
  a report);
* every string from a scanned repository (name, path, rule, message)
  is HTML-escaped — the report can never execute what it displays.
"""

import html as _html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .gate import fingerprint
from ._version import __version__

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "warning")

# Display heuristic ONLY — the contract is `full-scan --gate`, never
# this score. Documented in the report itself.
SCORE_WEIGHTS = {"critical": 40, "high": 10, "medium": 3,
                 "low": 1, "info": 0, "warning": 0}


def _severity_of(finding):
    """Normalized severity for any finding shape (code/CI or OSV)."""
    sev = finding.get("severity")
    if not sev and isinstance(finding.get("vuln"), dict):
        sev = finding["vuln"].get("severity")
    return str(sev or "unknown").strip().lower()


def _rule_of(finding):
    """Stable label for one finding (rule id, or OSV advisory id)."""
    rule = finding.get("rule")
    if not rule and isinstance(finding.get("vuln"), dict):
        rule = finding["vuln"].get("id")
    return str(rule or "unknown")


def _repo_name(path_str):
    try:
        return Path(path_str).name or path_str
    except (TypeError, ValueError):
        return str(path_str)


def _walk_tagged(result):
    """Yield (section, finding) for every finding in a full-scan result.

    Unlike ``gate.collect_findings`` (which flattens), this keeps the
    top-level section name so the report can show WHERE a finding came
    from. Only top-level dict sections with a findings list are walked —
    the full-scan tree is flat by construction.
    """
    for section_name, section in (result or {}).items():
        if not isinstance(section, dict):
            continue
        findings = section.get("findings")
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict):
                    yield section_name, f


def aggregate_one(result):
    """Fold ONE full-scan result into a portfolio repo summary."""
    if not isinstance(result, dict) or "error" in result and not result.get("repository"):
        error = (result or {}).get("error", "unknown error")
        return {
            "name": _repo_name((result or {}).get("path", "?")),
            "path": str((result or {}).get("path", "?")),
            "error": error,
            "findings_by_severity": {},
            "total": 0,
        }

    seen = set()
    by_severity = Counter()
    rules = Counter()
    top = []
    files_scanned = 0

    for section, finding in _walk_tagged(result):
        fp = fingerprint(finding)
        if fp in seen:
            continue  # analysis/scanner mirror — count once, like the gate
        seen.add(fp)

        sev = _severity_of(finding)
        by_severity[sev] += 1
        rule = _rule_of(finding)
        rules[rule] += 1
        if sev in ("critical", "high"):
            entry = {
                "section": section,
                "severity": sev,
                "rule": rule,
                "file": str(finding.get("file")
                            or (finding.get("dependency") or {}).get("manifest", "")
                            or finding.get("dependency", {}).get("name", "")),
                "line": finding.get("line", 0),
                "message": str(finding.get("message")
                               or finding.get("vuln", {}).get("summary", "")),
            }
            top.append(entry)

    analysis = result.get("analysis") or {}
    if isinstance(analysis, dict):
        files_scanned = int(analysis.get("files_scanned", 0) or 0)

    execution = result.get("execution") or {}
    top.sort(key=lambda e: (
        SEVERITY_ORDER.index(e["severity"]) if e["severity"] in SEVERITY_ORDER
        else len(SEVERITY_ORDER),
        str(e["file"]), int(e["line"] or 0),
    ))

    return {
        "name": _repo_name(result.get("repository", "?")),
        "path": str(result.get("repository", "?")),
        "version": str(result.get("version", "")),
        "wall_seconds": execution.get("wall_seconds"),
        "files_scanned": files_scanned,
        "scanners_failed": list(result.get("scanners_failed") or []),
        "findings_by_severity": dict(by_severity),
        "total": sum(by_severity.values()),
        "top_findings": top,
        "rules": dict(rules),
    }


def _score(repo):
    return sum(
        SCORE_WEIGHTS.get(sev, 0) * count
        for sev, count in repo.get("findings_by_severity", {}).items()
    )


def aggregate_portfolio(results):
    """Fold a list of full-scan results into the portfolio aggregate."""
    repos = [aggregate_one(r) for r in results]

    totals = Counter()
    rules = Counter()
    for repo in repos:
        for sev, count in repo.get("findings_by_severity", {}).items():
            totals[sev] += count
        for rule, count in repo.get("rules", {}).items():
            rules[rule] += count

    scannable = [r for r in repos if "error" not in r]
    ranked = sorted(
        scannable, key=lambda r: (-_score(r), r["name"].lower()),
    )

    return {
        "engine": "MIZAN Portfolio",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
        "repos_count": len(repos),
        "scanned_ok": len(scannable),
        "errored": len(repos) - len(scannable),
        "repos": repos,
        "ranking": [r["name"] for r in ranked],
        "totals": {
            "findings_by_severity": dict(totals),
            "total": sum(totals.values()),
        },
        "top_rules": [
            {"rule": rule, "count": count}
            for rule, count in rules.most_common(15)
        ],
        "score_note": (
            "Ranking is a display heuristic (high×10 + medium×3 + low×1). "
            "The contract is `mizan full-scan --gate`, never this score."
        ),
        "mode": "read-only",
        "execution_performed": False,
    }


def build_portfolio(paths, jobs=4):
    """Run the read-only full scan over each path and aggregate."""
    # Imported here so portfolio does not extend cli's import time for
    # every other subcommand.
    from .cli import full_scan_repository

    results = []
    for raw in paths:
        directory = Path(raw).expanduser()
        if not directory.is_dir():
            results.append({
                "path": str(directory),
                "error": f"invalid repository directory: {directory}",
            })
            continue
        try:
            results.append(full_scan_repository(directory, jobs=jobs))
        except Exception as exc:  # noqa: BLE001 — isolation IS the point
            results.append({
                "path": str(directory),
                "error": str(exc),
            })
    return aggregate_portfolio(results)


def render_portfolio_html(portfolio):
    """Render the aggregate as ONE self-contained HTML document."""
    esc = _html.escape
    totals = portfolio.get("totals", {}).get("findings_by_severity", {})

    sev_chips = "".join(
        f'<span class="chip {esc(sev)}">{esc(sev)}: {totals.get(sev, 0)}</span>'
        for sev in SEVERITY_ORDER if totals.get(sev)
    ) or '<span class="chip none">no findings across all repositories</span>'

    repo_rows = []
    for repo in portfolio.get("repos", []):
        name = esc(repo.get("name", "?"))
        if "error" in repo:
            repo_rows.append(
                f"<tr><td>{name}</td>"
                f'<td colspan="6" class="err">scan error: '
                f"{esc(repo['error'])}</td></tr>"
            )
            continue
        sev = repo.get("findings_by_severity", {})
        cells = "".join(
            f'<td class="num {esc(s)}">{sev.get(s, 0)}</td>'
            for s in ("critical", "high", "medium", "low", "info", "warning")
        )
        failed = ""
        if repo.get("scanners_failed"):
            failed = (
                f'<div class="failed">failed scanners: '
                f"{esc(', '.join(repo['scanners_failed']))}</div>"
            )
        wall = repo.get("wall_seconds")
        wall_s = f"{wall:.2f}s" if isinstance(wall, (int, float)) else "—"
        repo_rows.append(
            f"<tr><td>{name}<div class=\"path\">{esc(repo.get('path', ''))}"
            f"</div>{failed}</td>"
            f"<td class=\"num\">{repo.get('files_scanned', 0)}</td>"
            f"{cells}"
            f"<td class=\"num\">{repo.get('total', 0)}</td>"
            f"<td class=\"num\">{wall_s}</td></tr>"
        )

    top_rows = []
    for repo in portfolio.get("repos", []):
        for f in repo.get("top_findings", []):
            # Pre-3.12 f-strings cannot nest the outer quote inside the
            # expression — build the location string outside the template.
            loc = esc(f["file"])
            if f.get("line"):
                loc += " : " + str(f["line"])
            top_rows.append(
                "<tr>"
                f'<td><span class="chip {esc(f["severity"])}">'
                f"{esc(f['severity'])}</span></td>"
                f"<td>{esc(repo.get('name', ''))}</td>"
                f"<td>{esc(f['section'])}</td>"
                f"<td>{esc(f['rule'])}</td>"
                f"<td>{loc}</td>"
                f"<td>{esc(f['message'])}</td>"
                "</tr>"
            )

    rule_rows = "".join(
        f"<tr><td>{esc(item['rule'])}</td>"
        f"<td class=\"num\">{item['count']}</td></tr>"
        for item in portfolio.get("top_rules", [])
    ) or '<tr><td colspan="2">none</td></tr>'

    errored = portfolio.get("errored", 0)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MIZAN Portfolio — {portfolio.get('repos_count', 0)} repositories</title>
<style>
 body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
        margin: 2rem; color: #1a1a2e; background: #fafafa; }}
 h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
 .meta {{ color: #555; font-size: .85rem; }}
 .chip {{ display: inline-block; padding: .1rem .5rem; margin: 0 .2rem;
          border-radius: 999px; font-size: .78rem; color: #fff; }}
 .chip.critical {{ background: #7f1d1d; }} .chip.high {{ background: #b91c1c; }}
 .chip.medium {{ background: #b45309; }} .chip.low {{ background: #4d7c0f; }}
 .chip.info {{ background: #475569; }} .chip.warning {{ background: #7c6f10; }}
 .chip.none {{ background: #166534; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: .6rem;
          background: #fff; font-size: .85rem; }}
 th, td {{ border: 1px solid #ddd; padding: .35rem .55rem;
           text-align: left; vertical-align: top; }}
 th {{ background: #eef1f5; }}
 td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
 td.high {{ color: #b91c1c; font-weight: 600; }}
 td.critical {{ color: #7f1d1d; font-weight: 700; }}
 td.medium {{ color: #b45309; }}
 .path {{ color: #777; font-size: .72rem; word-break: break-all; }}
 .failed {{ color: #b45309; font-size: .72rem; }}
 .err {{ color: #b91c1c; }}
 .note {{ color: #666; font-size: .78rem; margin-top: 1.2rem;
          max-width: 60rem; }}
</style>
</head>
<body>
<h1>MIZAN Portfolio — {portfolio.get('repos_count', 0)} repositories</h1>
<p class="meta">MIZAN v{esc(portfolio.get('version', ''))} · generated
{esc(portfolio.get('generated_at', ''))} · {portfolio.get('scanned_ok', 0)}
scanned, {errored} errored · read-only, no execution performed</p>

<h2>Totals (deduplicated by the gate fingerprint)</h2>
<p>{sev_chips}</p>

<h2>Repositories</h2>
<table>
<tr><th>Repository</th><th>Files</th>
<th class="num">crit</th><th class="num">high</th><th class="num">medium</th>
<th class="num">low</th><th class="num">info</th><th class="num">warn</th>
<th class="num">Total</th><th>Scan wall</th></tr>
{''.join(repo_rows) or '<tr><td colspan="10">no repositories</td></tr>'}
</table>

<h2>Top findings (critical &amp; high only)</h2>
<table>
<tr><th>Severity</th><th>Repository</th><th>Section</th><th>Rule</th>
<th>Location</th><th>Message</th></tr>
{''.join(top_rows) or '<tr><td colspan="6">none — nothing at critical/high after deduplication</td></tr>'}
</table>

<h2>Most frequent rules (all severities)</h2>
<table>
<tr><th>Rule</th><th class="num">Count</th></tr>
{rule_rows}
</table>

<p class="note">{esc(portfolio.get('score_note', ''))}
Portfolio is a display layer over `mizan full-scan` — not a GRC platform,
not a compliance certification. Each repository was scanned read-only;
this file is fully self-contained (no external requests, no scripts).</p>
</body>
</html>"""


def portfolio_to_json(portfolio):
    return json.dumps(portfolio, indent=2, ensure_ascii=False, default=str)
