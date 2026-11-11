"""Explicit registry of trusted built-in MIZAN scanners."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Plugin:
    """A built-in scanner plugin registration."""
    name: str
    category: str
    version: str
    description: str
    rules: tuple


PLUGINS = (
    Plugin(
        name="security",
        category="security",
        version="0.1.0",
        description="Static security pattern analysis.",
        rules=(
            "dynamic-execution",
            "process-execution",
            "shell-true",
            "hardcoded-secret-candidate",
            "unsafe-deserialization",
            "yaml-unsafe-load",
            "sql-injection",
            "path-traversal",
            "weak-crypto",
            # v0.13.0 Bandit-parity wave 1 (docs/BANDIT_PARITY.md)
            "tls-verification-disabled",
            "ssl-unverified-context",
            "request-without-timeout",
            "torch-unsafe-load",
            "hf-trust-remote-code",
            "jinja2-autoescape-false",
            "django-mark-safe",
            "tarfile-extractall",
            "hardcoded-tmp-path",
            # v0.15.0-dev Bandit-parity wave 2 (docs/BANDIT_PARITY.md)
            "hardcoded-bind-all-interfaces",
            "flask-debug-enabled",
            "paramiko-exec-command",
            "telnetlib-import",
            "ftplib-import",
            "ssl-insecure-version",
            "hf-unpinned-download",
            # v0.15.0-dev Bandit-parity wave 3 (docs/BANDIT_PARITY.md)
            "weak-crypto-key-size",
            "bidi-override-chars",
            # v0.14.0-dev taint-analysis PoC (docs/ROADMAP.md P1.2):
            # dataflow rules — fire only on a confirmed source->sink path.
            "request-to-sql",
            "input-to-subprocess",
        ),
    ),
    Plugin(
        name="quality",
        category="quality",
        version="0.1.0",
        description="Source code maintenance and quality checks.",
        rules=(
            "todo",
            "python-syntax-error",
            "file-read-error",
        ),
    ),
)


def list_plugins():
    """Return metadata for every registered plugin."""
    return [
        {
            "name": plugin.name,
            "category": plugin.category,
            "version": plugin.version,
            "description": plugin.description,
            "rules": list(plugin.rules),
            "trusted_builtin": True,
        }
        for plugin in PLUGINS
    ]


def get_plugin(name):
    """Return metadata for one plugin by name."""
    for plugin in PLUGINS:
        if plugin.name == name:
            return {
                "name": plugin.name,
                "category": plugin.category,
                "version": plugin.version,
                "description": plugin.description,
                "rules": list(plugin.rules),
                "trusted_builtin": True,
            }

    raise ValueError(f"Unknown MIZAN plugin: {name}")
