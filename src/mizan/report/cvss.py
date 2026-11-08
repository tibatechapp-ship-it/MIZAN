"""CVSS v3.1 Base Score — pure-Python implementation of the NIST specification.

No network, no dependencies, no API. The arithmetic IS the specification
(CVSS v3.1 docs, including the Appendix A Roundup that is robust against
floating-point representation).

Validation status (stated honestly, per MIZAN protocol — no overclaiming):

* 10 published anchor vectors whose scores are widely quoted in advisories
  (e.g. CVE-2021-44228 = 10.0 for the S:C/C:H/I:H/A:H vector, and the
  ubiquitous 9.8 for AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H);
* a full-space property sweep over ALL 2,592 metric combinations asserting
  the spec's structural guarantees: score in [0,10], one-decimal rounding,
  severity bands (None/Low/Medium/High/Critical), S:C >= S:U, CIA
  monotonicity, the Impact<=0 -> 0.0 special rule, and the max=10.0 /
  min=0.0 bounds of the space.

A differential run against the official NIST calculator script is a
pending follow-up and is recorded as such in docs/REPORT_SECURITY.md —
it is NOT claimed here.
"""

import math

__all__ = ["base_score", "base_score_vector", "severity_band", "roundup"]

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope Unchanged
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},    # Scope Changed
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(x: float) -> float:
    """CVSS v3.1 Appendix A Roundup (official float-robust definition)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_band(score: float) -> str:
    """Official v3.1 qualitative severity bands."""
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(av: str, ac: str, pr: str, ui: str, s: str,
               c: str, i: str, a: str) -> tuple:
    """CVSS v3.1 base score from the eight metric letters.

    Returns (score, severity). Raises ValueError on any unknown metric
    value — fail-loud, never a silent default.
    """
    for label, key, table in (
        ("AV", av, _AV), ("AC", ac, _AC), ("UI", ui, _UI),
        ("S", s, {"U": 0, "C": 1}), ("C", c, _CIA),
        ("I", i, _CIA), ("A", a, _CIA),
    ):
        if key not in table:
            raise ValueError(f"unknown CVSS metric value: {label}:{key}")
    if pr not in ("N", "L", "H"):
        raise ValueError(f"unknown CVSS metric value: PR:{pr}")

    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * _AV[av] * _AC[ac] * _PR[s][pr] * _UI[ui]

    if impact <= 0:
        return 0.0, "None"          # NIST special rule: no impact -> no score
    if s == "U":
        score = roundup(min(impact + exploitability, 10.0))
    else:
        score = roundup(min(1.08 * (impact + exploitability), 10.0))
    return score, severity_band(score)


def base_score_vector(vector: str) -> tuple:
    """Score a vector string like 'CVSS:3.1/AV:N/AC:L/...'."""
    parts = {}
    for chunk in str(vector).split("/"):
        if ":" in chunk:
            key, value = chunk.split(":", 1)
            parts[key] = value
    missing = [k for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
               if k not in parts]
    if missing:
        raise ValueError(f"CVSS vector missing metrics: {missing}")
    return base_score(parts["AV"], parts["AC"], parts["PR"], parts["UI"],
                      parts["S"], parts["C"], parts["I"], parts["A"])
