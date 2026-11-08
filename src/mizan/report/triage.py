"""The mandatory manual triage gate — the reputation firewall (hole #1).

A static analyzer produces false positives. A flow of
``finding -> auto-report -> auto-publish`` is a false-positive spam
machine that would burn MIZAN's name and its users' names. Therefore:

* only severity high (or critical, defensively) is report-ELIGIBLE;
* the operator must pass ``--confirm <id>`` matching the finding id;
* a triage file must answer ALL TEN questions as booleans, and the five
  BLOCKING answers must match the safe profile;
* ``mizan report show`` (local viewing) stays ungated — viewing is not
  disclosure.

There is no publish command in this iteration at all: the gate ships
first and the network publish path is explicitly unimplemented
(docs/REPORT_SECURITY.md).
"""

__all__ = ["REPORT_ELIGIBLE_SEVERITIES", "QUESTIONS", "BLOCKING", "check"]

REPORT_ELIGIBLE_SEVERITIES = {"high", "critical"}

# (key, question the operator must answer truthfully, in the triage file)
QUESTIONS = [
    ("exploitable_path",
     "Is the vulnerable path actually exploitable? Who controls the input?"),
    ("default_env_safe",
     "Is the vulnerable configuration exploitable in a default deployment?"),
    ("nosec_justified",
     "Is there a justified nosec/suppression comment on this site?"),
    ("test_or_example_only",
     "Is the code only under tests/, examples/, or fixtures?"),
    ("reachable_in_prod",
     "Is the code actually reached from production entry points?"),
    ("external_mitigation",
     "Is there an equivalent external control (WAF, authz, filtering)?"),
    ("affected_version_confirmed",
     "Is the affected branch/version the one actually shipped?"),
    ("local_poc_reproduced",
     "Has the impact been reproduced with a minimal local PoC?"),
    ("authorized_to_disclose",
     "Do you hold the right to disclose this repository's issues?"),
    ("contact_verified",
     "Is the report contact channel verified and correct?"),
]

# Required answers. A finding whose triage violates ANY of these is a
# probable false positive or an improper disclosure -> blocked, loud.
BLOCKING = {
    "exploitable_path": True,
    "nosec_justified": False,
    "test_or_example_only": False,
    "reachable_in_prod": True,
    "authorized_to_disclose": True,
}


def check(finding: dict, triage: dict, expected_id: str,
          confirm: str) -> list:
    """Validate the gate. Returns the list of blocking violations
    (empty list = the report may be generated as a DRAFT)."""
    failures = []

    severity = str(finding.get("severity", "")).lower()
    if severity not in REPORT_ELIGIBLE_SEVERITIES:
        failures.append(
            f"severity {severity!r} is not report-eligible "
            f"(only {sorted(REPORT_ELIGIBLE_SEVERITIES)})"
        )

    if not confirm or confirm != expected_id:
        failures.append(
            f"--confirm {confirm!r} does not match the finding id "
            f"{expected_id!r}"
        )

    triage = triage if isinstance(triage, dict) else {}
    if triage.get("finding_id") != expected_id:
        failures.append("triage file does not reference this finding id")

    answers = triage.get("answers")
    if not isinstance(answers, dict):
        answers = {}
    for key, _question in QUESTIONS:
        if not isinstance(answers.get(key), bool):
            failures.append(f"triage question unanswered: {key}")

    if not failures:  # only meaningful once every answer exists
        for key, required in BLOCKING.items():
            if answers.get(key) is not required:
                failures.append(
                    f"blocking triage answer: {key} must be {required}"
                )
    return failures
