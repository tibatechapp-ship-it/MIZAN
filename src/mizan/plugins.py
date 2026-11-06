"""Explicit registry of trusted built-in MIZAN scanners."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Plugin:
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
