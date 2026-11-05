"""Single source of truth for the MIZAN release version (SEC-06 fix).

Every other surface (pyproject metadata, SARIF tool version, package.json,
README, website badge) must DERIVE from or agree with this value; the
consistency is enforced by tests/test_version_consistency.py.
"""

__version__ = "0.3.0"
