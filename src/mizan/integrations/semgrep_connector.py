"""Optional Semgrep run connector — report-only, tool-optional.

Plan v0.15.0 Wave 2 contract (docs/DEV_PLAN_V0150.md):

* An external tool is RUN only when its binary is already present; MIZAN
  never installs it and never requires it (plan rule 4).
* The tool's SARIF output passes through the Wave-0 import contract
  (``import_sarif_report`` → ``mizan.finding.v1``, source preserved
  verbatim in ``tool.driver.name``).
* Every failure mode is explicit: a missing binary, a failing version
  probe, a timeout, a non-zero exit, a missing or malformed report all
  return ``status="incomplete"`` with a stable ``reason`` and a detail
  that carries the path and the cause. None of them is ever reported as
  a clean scan (the measured flaw #1 fixed by Wave 0, kept closed here).
* A version that differs from the measured reference is recorded, not
  hidden: ``version_match`` lets every consumer see which Semgrep
  produced a given run.

The connector writes only to the caller-provided output path (default:
a fresh temporary directory) — never into the scanned user tree.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .sarif_import import SarifImportError, import_sarif_report

TOOL_NAME = "semgrep"

# Measured reference run (docs/MEASUREMENT.md): the Semgrep version the
# 2026-11-14 reference run on the frozen golden corpus was performed
# with. A different version is not rejected — it is recorded, because
# silently normalizing tool versions away would be a silent-failure
# pattern in disguise.
SEMGREP_REFERENCE_VERSION = "1.185.0"

def _run_command(
    cmd: list[str], timeout: int, cwd: str | None = None
) -> tuple[int | None, str | None]:
    """Run one command; return (returncode, stderr_tail) or (None, reason)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
        )
    except FileNotFoundError:
        return None, None
    except subprocess.TimeoutExpired:
        return None, f"command exceeded {timeout}s: {' '.join(cmd)}"
    stderr_tail = (proc.stderr or "").strip()[-400:]
    return proc.returncode, stderr_tail or None


def _probe_version(binary: str, cwd: str | None = None) -> str | None:
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=cwd,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    version = (proc.stdout or "").strip().splitlines()
    return version[0].strip() if version else None


def run_semgrep(
    target: str | Path,
    config: str | Path,
    output_path: str | Path | None = None,
    timeout: int = 180,
    binary: str | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Run Semgrep (if present) and import its SARIF through Wave 0.

    Returns a run dict with ``status``:

    * ``"complete"`` — the tool ran, produced a SARIF report, and the
      report passed the Wave-0 import contract; ``import`` holds the
      ``mizan.finding.v1`` summary (source preserved).
    * ``"incomplete"`` — something failed; ``reason`` names the mode,
      ``detail`` carries the path and cause. Never a silent clean.
    """
    target = Path(target)
    config = Path(config)
    result: dict[str, Any] = {"tool": TOOL_NAME}

    resolved = binary or shutil.which(TOOL_NAME)
    if not resolved:
        return {
            **result,
            "status": "incomplete",
            "reason": "tool-missing",
            "detail": (
                f"no {TOOL_NAME!r} binary on PATH; MIZAN never installs "
                f"external tools — install {TOOL_NAME} yourself or skip "
                f"this optional connector"
            ),
        }

    tool_version = _probe_version(str(resolved), cwd=str(cwd) if cwd else None)
    if tool_version is None:
        return {
            **result,
            "status": "incomplete",
            "reason": "version-check-failed",
            "detail": (
                f"{TOOL_NAME} --version failed or timed out; refusing to "
                f"attribute an unknown tool build to a measured run"
            ),
        }
    result["tool_version"] = tool_version
    result["reference_version"] = SEMGREP_REFERENCE_VERSION
    result["version_match"] = tool_version == SEMGREP_REFERENCE_VERSION

    if output_path is None:
        out_dir = tempfile.mkdtemp(prefix="mizan-semgrep-")
        out_path = Path(out_dir) / "semgrep.sarif"
    else:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(resolved), "scan",
        "--config", str(config),
        "--sarif",
        "--output", str(out_path),
        str(target),
    ]
    result["command"] = command

    returncode, stderr_tail = _run_command(
        command, timeout, cwd=str(cwd) if cwd else None
    )
    if returncode is None and stderr_tail is not None:
        return {
            **result,
            "status": "incomplete",
            "reason": "tool-timeout",
            "detail": stderr_tail,
        }

    if returncode != 0:
        return {
            **result,
            "status": "incomplete",
            "reason": f"tool-exit-{returncode}",
            "detail": (
                f"{TOOL_NAME} exited {returncode} on target "
                f"{target}; stderr tail: {stderr_tail!r}"
            ),
        }

    if not out_path.is_file():
        return {
            **result,
            "status": "incomplete",
            "reason": "report-missing",
            "detail": (
                f"{TOOL_NAME} exited 0 but produced no SARIF report at "
                f"{out_path}"
            ),
        }

    try:
        imported = import_sarif_report(out_path)
    except (SarifImportError, OSError, ValueError) as exc:
        return {
            **result,
            "status": "incomplete",
            "reason": "report-invalid",
            "detail": (
                f"SARIF report {out_path} rejected by the import "
                f"contract: {exc}"
            ),
        }

    try:
        sarif_doc = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            **result,
            "status": "incomplete",
            "reason": "report-invalid",
            "detail": f"SARIF report {out_path} unreadable: {exc}",
        }
    result["sarif_version"] = sarif_doc.get("version")

    result.update(
        {
            "status": "complete",
            "sarif_path": str(out_path),
            "import": imported,
        }
    )
    return result


__all__ = [
    "TOOL_NAME",
    "SEMGREP_REFERENCE_VERSION",
    "run_semgrep",
]
