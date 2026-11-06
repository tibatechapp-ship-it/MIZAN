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
