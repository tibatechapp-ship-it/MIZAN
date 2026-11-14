#!/usr/bin/env python3
"""Measured Semgrep reference run (plan v0.15.0, Wave 2).

Runs the OPTIONAL Semgrep connector against the frozen golden corpus
with the local offline rule config (tests/benchmark/fixtures/
semgrep_local_rules.yaml), twice, asserts the two runs measure
identically (rerun-stability acceptance gate), and records the run in
tests/benchmark/results/semgrep_reference_run.json.

This is EVIDENCE of a measured pipeline run, not a unit test: it needs
the real Semgrep binary (pinned version recorded in the artifact). CI
does not execute it; the measurement-gate tests instead verify the
artifact stays consistent with the connector contract.

Usage: python scripts/run_semgrep_reference.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mizan.integrations.semgrep_connector import run_semgrep  # noqa: E402

TARGET = ROOT / "tests" / "rules" / "fixtures"
CONFIG = ROOT / "tests" / "benchmark" / "fixtures" / "semgrep_local_rules.yaml"
ARTIFACT = ROOT / "tests" / "benchmark" / "results" / "semgrep_reference_run.json"


def imported_findings(run: dict) -> list[dict]:
    return run["import"]["findings"]


def measured_run(out_dir: Path) -> dict:
    # Semgrep's default ignore rules skip fixture/test-shaped directories
    # inside SCM workspaces, so the frozen corpus is staged byte-identical
    # into a neutral directory and scanned there. Same content, same
    # relative paths, no ignore-rule coupling — documented in
    # docs/MEASUREMENT.md (methodology, staging step).
    stage = out_dir / "corpus"
    shutil.copytree(TARGET, stage,
                    ignore=shutil.ignore_patterns("__pycache__"))
    out = out_dir / "semgrep.sarif"
    run = run_semgrep(
        ".", CONFIG, output_path=out, timeout=600, cwd=stage
    )
    if run["status"] != "complete":
        raise SystemExit(
            f"reference run is {run['status']} ({run.get('reason')}) — "
            f"NOT clean, NOT published: {run.get('detail')}"
        )
    # The SARIF lands in a fresh temp path per run; it is pipeline
    # plumbing, not a measurement. The recorded measurement is the
    # imported finding set + the exact command with the volatile temp
    # path normalized to a stable token (the doc documents the pattern).
    recorded = {k: v for k, v in run.items() if k != "sarif_path"}
    recorded["command"] = [
        {str(out): "<temp-out>", str(stage): "<staged-corpus>"}.get(
            part, part
        )
        for part in recorded["command"]
    ]
    recorded["target_files"] = sorted(
        str(p.relative_to(stage)) for p in stage.rglob("*.py")
    )
    recorded["findings"] = sorted(
        (
            f["source"]["rule_id"],
            f["location"]["file"],
            f["location"]["line"],
            f["tool_level"],
        )
        for f in imported_findings(run)
    )
    return recorded


def main() -> int:
    if shutil.which("semgrep") is None:
        print("semgrep binary not found — reference run skipped, "
              "no artifact written", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="mizan-ref-") as td:
        tdp = Path(td)
        first = measured_run(tdp / "a")
        second = measured_run(tdp / "b")

    if json.dumps(first, sort_keys=True) != json.dumps(second, sort_keys=True):
        print("reference run is NOT rerun-stable — refusing to record",
              file=sys.stderr)
        return 2

    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(
        json.dumps(first, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    per_rule: dict[str, int] = {}
    for rule_id, _file, _line, _lvl in first["findings"]:
        per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
    print(f"recorded {ARTIFACT.relative_to(ROOT)}")
    print(f"status: complete | tool_version: {first['tool_version']} "
          f"| files scanned: {len(first['target_files'])} "
          f"| findings: {len(first['findings'])} {per_rule}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
