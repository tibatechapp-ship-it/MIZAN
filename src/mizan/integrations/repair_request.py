"""Structured repair request for an external coding agent (Wave 3).

Plan v0.15.0 Wave 3 contract (docs/DEV_PLAN_V0150.md):

* ``mizan.finding.v1`` → ``repair-request.v1``: finding_id, the
  evidence, a proposed fix, constraints, verification steps,
  ``confidence``, and ``human_review_required=true`` — always true.
* MIZAN does NOT write into the user's tree in this wave. The request
  is a JSON handoff: the agent works in its own branch/worktree,
  presents the diff plus test results, and a human approves the merge.
* Insufficient evidence is REJECTED, not guessed: a finding without a
  usable location, rule identity, or evidence message never becomes a
  request — the error names exactly what must be verified instead
  ("don't guess; explain what is needed to verify").

The proposal is a REVIEW suggestion per rule family — MIZAN is a
measured static analyzer, not an auto-fixer; ``auto_appliable`` is
always ``false``. Candidate rules (``hardcoded-secret-candidate``) get
``confidence: "medium"`` because deciding "is this a real secret" is a
human judgment by design; the measured deterministic rules get
``confidence: "high"``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .sarif_import import _fallback_fingerprint

REPAIR_SCHEMA = "repair-request.v1"

CONFIDENCE_LEVELS = ("high", "medium", "low")

# Rules whose verdict is a candidate judgment, not a deterministic
# measurement: the analyzer surfaces the literal, the human decides.
CANDIDATE_RULES = {"hardcoded-secret-candidate"}

# Review guidance per rule family. These are suggestions for a human
# reviewer / coding agent, never auto-applied edits.
RULE_GUIDANCE: dict[str, str] = {
    "django-mark-safe": (
        "validate/escape the value before marking it safe; prefer "
        "letting the template engine escape"
    ),
    "dynamic-execution": (
        "replace eval/exec with explicit dispatch or ast.literal_eval "
        "for trusted literals"
    ),
    "hardcoded-secret-candidate": (
        "move the literal to environment/secret manager and rotate it "
        "if it is a real credential"
    ),
    "hardcoded-tmp-path": (
        "use tempfile APIs instead of a fixed shared-temp path"
    ),
    "hf-trust-remote-code": (
        "avoid trust_remote_code=True; pin an audited revision if the "
        "repo must be used"
    ),
    "input-to-subprocess": (
        "break the taint chain: validate the input before it reaches "
        "the subprocess call"
    ),
    "jinja2-autoescape-false": (
        "enable autoescape for the environment"
    ),
    "path-traversal": (
        "normalize and confine the path inside the intended root "
        "before use"
    ),
    "process-execution": (
        "invoke with an argument list instead of a shell string where "
        "possible"
    ),
    "request-to-sql": (
        "break the taint chain: parameterize the query instead of "
        "interpolating the request value"
    ),
    "request-without-timeout": (
        "set an explicit timeout on the request call"
    ),
    "shell-true": (
        "use an argument list without shell=True, or validate every "
        "interpolated token"
    ),
    "sql-injection": (
        "parameterize the query; never interpolate values into SQL"
    ),
    "ssl-unverified-context": (
        "use the default verified SSL context"
    ),
    "tarfile-extractall": (
        "validate archive members and extract with a confined "
        "destination; avoid blind extractall"
    ),
    "tls-verification-disabled": (
        "re-enable certificate verification on the client/context"
    ),
    "torch-unsafe-load": (
        "use weights_only=True or a safetensors loader"
    ),
    "unsafe-deserialization": (
        "replace pickle-style loads with a data format that cannot "
        "execute code"
    ),
    "weak-crypto": (
        "move to a modern primitive (SHA-256+, no ECB, no MD5/SHA1)"
    ),
    "yaml-unsafe-load": (
        "use yaml.safe_load instead of yaml.unsafe_load/load"
    ),
}

_FIXED_CONSTRAINTS = [
    "human-approval-required-before-merge",
    "apply-only-in-isolated-branch-or-worktree",
    "no-silent-suppression-no-bare-nosec",
    "verification-tests-must-pass-before-proposal",
]


class RepairRequestError(ValueError):
    """Raised when evidence is insufficient or a request is invalid."""


def _require(condition: bool, missing: list[str], what: str) -> None:
    if not condition:
        missing.append(what)


def finding_id_for(finding: dict[str, Any]) -> str:
    """Return the finding's fingerprint, computing the deterministic
    fallback (same formula as the wave-0 import contract) when absent.
    """
    fingerprint = finding.get("fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        return fingerprint
    source = finding.get("source") or {}
    location = finding.get("location") or {}
    return _fallback_fingerprint(
        str(source.get("tool") or ""),
        str(source.get("rule_id") or ""),
        str(location.get("file") or ""),
        location.get("line"),
        str(finding.get("message") or ""),
    )


def _as_finding_v1(finding: Any) -> dict[str, Any]:
    """Accept mizan.finding.v1 entries OR MIZAN's raw analyzer shape
    (``{file, line, rule, severity, message}`` — the direct output of
    ``mizan analyze``) via a documented 1:1 field adapter. Nothing is
    invented: every evidence field travels from the finding itself, and
    anything else is refused by the evidence check downstream.
    """
    if not isinstance(finding, dict):
        raise RepairRequestError(
            f"expected a finding object; got {type(finding).__name__}"
        )
    if finding.get("schema") == "mizan.finding.v1":
        return finding
    if "rule" in finding or "file" in finding:
        return {
            "schema": "mizan.finding.v1",
            "source": {"tool": "MIZAN", "rule_id": finding.get("rule")},
            "location": {"file": finding.get("file"),
                         "line": finding.get("line")},
            "message": finding.get("message"),
            "tool_level": finding.get("severity"),
        }
    raise RepairRequestError(
        "repair-request accepts mizan.finding.v1 entries or MIZAN "
        "analyzer findings (file/line/rule/severity/message); this "
        "object has neither shape"
    )


def build_repair_request(finding: dict[str, Any]) -> dict[str, Any]:
    """Turn one finding into a repair request.

    Accepts ``mizan.finding.v1`` entries and MIZAN's raw analyzer
    findings (adapted 1:1, see ``_as_finding_v1``). Raises
    :class:`RepairRequestError` when the evidence is insufficient — the
    error lists every missing item, so the caller can go measure it
    instead of guessing.
    """
    finding = _as_finding_v1(finding)
    if not isinstance(finding, dict) or finding.get("schema") != "mizan.finding.v1":
        raise RepairRequestError(
            "repair-request expects mizan.finding.v1 entries; got "
            f"{type(finding).__name__} without the schema marker"
        )

    source = finding.get("source") or {}
    location = finding.get("location") or {}
    message = str(finding.get("message") or "")

    missing: list[str] = []
    tool = source.get("tool")
    rule_id = source.get("rule_id")
    file_path = location.get("file")
    line = location.get("line")
    _require(isinstance(tool, str) and bool(tool.strip()),
             missing, "source.tool (which tool produced the finding)")
    _require(isinstance(rule_id, str) and bool(rule_id.strip()),
             missing, "source.rule_id (which rule fired)")
    _require(isinstance(file_path, str) and bool(file_path.strip()),
             missing, "location.file (where the finding lives)")
    _require(isinstance(line, int) and not isinstance(line, bool) and line >= 1,
             missing, "location.line (integer >= 1)")
    _require(bool(message.strip()),
             missing, "message (the evidence text; empty evidence "
             "cannot support a proposal)")
    if missing:
        raise RepairRequestError(
            "insufficient evidence for a repair request — don't guess; "
            "measure and provide: " + "; ".join(missing)
        )

    rule_key = str(rule_id)
    guidance = RULE_GUIDANCE.get(rule_key)
    if guidance is None:
        # An unknown rule (e.g. an imported external rule id) must not
        # get a fabricated suggestion — the honest proposal is a
        # review request without guidance.
        guidance = ""
        confidence = "low"
    else:
        confidence = (
            "medium" if rule_key in CANDIDATE_RULES else "high"
        )

    return {
        "schema": REPAIR_SCHEMA,
        "finding_id": finding_id_for(finding),
        "evidence": {
            "tool": str(tool),
            "rule_id": rule_key,
            "file": str(file_path),
            "line": line,
            "message": message,
            "tool_level": finding.get("tool_level"),
        },
        "proposed_fix": {
            "kind": "review-suggestion",
            "auto_appliable": False,
            "summary": guidance,
        },
        "constraints": list(_FIXED_CONSTRAINTS),
        "verification": [
            {
                "what": "the original finding no longer fires",
                "how": (
                    f"re-run MIZAN over {file_path} and assert "
                    f"{rule_key} does not report it anymore"
                ),
            },
            {
                "what": "no new findings of any rule appeared",
                "how": (
                    "re-run MIZAN over the changed file and compare "
                    "against the pre-change finding set"
                ),
            },
            {
                "what": "the project's test suite passes",
                "how": "run the project's own tests in the worktree",
            },
        ],
        "confidence": confidence,
        "human_review_required": True,
    }


def validate_repair_request(request: dict[str, Any]) -> dict[str, Any]:
    """Validate one repair request against the contract.

    Returns the request unchanged when valid; raises
    :class:`RepairRequestError` with the offending field otherwise.
    ``human_review_required`` must be exactly ``True`` — the schema has
    no "the agent decided by itself" variant.
    """
    def bad(what: str) -> RepairRequestError:
        return RepairRequestError(f"invalid repair request: {what}")

    if not isinstance(request, dict):
        raise bad("expected an object")
    if request.get("schema") != REPAIR_SCHEMA:
        raise bad(f"schema must be {REPAIR_SCHEMA!r}")

    fid = request.get("finding_id")
    if not isinstance(fid, str) or not fid:
        raise bad("finding_id must be a non-empty string")

    evidence = request.get("evidence")
    if not isinstance(evidence, dict):
        raise bad("evidence must be an object")
    for key in ("tool", "rule_id", "file", "message"):
        value = evidence.get(key)
        if not isinstance(value, str) or not value.strip():
            raise bad(f"evidence.{key} must be a non-empty string")
    line = evidence.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise bad("evidence.line must be an integer >= 1")

    proposed = request.get("proposed_fix")
    if not isinstance(proposed, dict):
        raise bad("proposed_fix must be an object")
    if proposed.get("kind") != "review-suggestion":
        raise bad("proposed_fix.kind must be 'review-suggestion' "
                  "— MIZAN does not emit auto-appliable edits")
    if proposed.get("auto_appliable") is not False:
        raise bad("proposed_fix.auto_appliable must be false")

    constraints = request.get("constraints")
    if not isinstance(constraints, list) or not constraints:
        raise bad("constraints must be a non-empty list")
    if not all(isinstance(c, str) and c for c in constraints):
        raise bad("constraints entries must be non-empty strings")

    verification = request.get("verification")
    if not isinstance(verification, list) or not verification:
        raise bad("verification must be a non-empty list")
    for step in verification:
        if not isinstance(step, dict) or not isinstance(
            step.get("what"), str
        ) or not step["what"].strip():
            raise bad(
                "every verification step needs a non-empty 'what'"
            )

    confidence = request.get("confidence")
    if confidence not in CONFIDENCE_LEVELS:
        raise bad(
            f"confidence must be one of {CONFIDENCE_LEVELS}, "
            f"got {confidence!r}"
        )

    if request.get("human_review_required") is not True:
        raise bad(
            "human_review_required must be exactly true — a repair "
            "request without human review is not a MIZAN request"
        )

    return request


def write_repair_requests(
    findings: list[dict[str, Any]], output_path: str | Path | None
) -> dict[str, Any]:
    """Build, validate, and hand over repair requests as JSON.

    Only the caller-provided ``output_path`` is written; without it the
    summary is returned for printing. Every finding either becomes a
    validated request or raises — no partial silent batches.
    """
    if not isinstance(findings, list) or not findings:
        raise RepairRequestError(
            "repair-request needs at least one mizan.finding.v1 entry"
        )
    requests = []
    for index, finding in enumerate(findings):
        try:
            request = build_repair_request(finding)
            validate_repair_request(request)
        except RepairRequestError as exc:
            raise RepairRequestError(
                f"finding {index} cannot become a repair request: {exc}"
            ) from exc
        requests.append(request)

    batch = {
        "schema": REPAIR_SCHEMA,
        "count": len(requests),
        "requests": requests,
        "human_review_required": True,
    }
    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(batch, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return batch


__all__ = [
    "REPAIR_SCHEMA",
    "CONFIDENCE_LEVELS",
    "CANDIDATE_RULES",
    "RULE_GUIDANCE",
    "RepairRequestError",
    "finding_id_for",
    "build_repair_request",
    "validate_repair_request",
    "write_repair_requests",
]
