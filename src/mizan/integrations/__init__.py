"""External scanner integrations (read-only imports with provenance).

Wave 0 of docs/DEV_PLAN_V0150.md: MIZAN unifies external scanner output
(SARIF 2.1.0) into one normalized finding contract without re-implementing
any external engine and without forcing its installation.

Contract highlights:
- Read-only: imports parse a report file; they never execute the scanned
  code and never write into the user's tree.
- Provenance preserved: the originating tool, rule id, and original SARIF
  level travel with every finding.
- No silent clean: a missing or invalid report fails loudly instead of
  masquerading as an empty (clean) result set.
"""

from .merge import (
    EXTERNAL_GATE_SCHEMA,
    MERGED_SCHEMA,
    TRIAGE_SCHEMA,
    MergeError,
    apply_triage,
    gate_external_findings,
    merge_findings,
)
from .sarif_import import (
    FINDING_SCHEMA,
    SARIF_VERSION,
    SarifImportError,
    import_sarif_report,
    normalize_sarif,
)

__all__ = [
    "EXTERNAL_GATE_SCHEMA",
    "FINDING_SCHEMA",
    "MERGED_SCHEMA",
    "SARIF_VERSION",
    "SarifImportError",
    "TRIAGE_SCHEMA",
    "MergeError",
    "apply_triage",
    "gate_external_findings",
    "import_sarif_report",
    "merge_findings",
    "normalize_sarif",
]
