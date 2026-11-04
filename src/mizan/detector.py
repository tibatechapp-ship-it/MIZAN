"""Safe, read-only project technology detection."""

import json
import os
import re
from pathlib import Path

IGNORED = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".next",
    ".pytest_cache", ".mypy_cache",
}

MARKERS = {
    "Python": ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"],
    "JavaScript": ["package.json", "package-lock.json"],
    "TypeScript": ["tsconfig.json"],
    "Rust": ["Cargo.toml"],
    "Go": ["go.mod"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "PHP": ["composer.json"],
    "Ruby": ["Gemfile"],
    "Dart": ["pubspec.yaml"],
    "C#": [".csproj", ".sln"],
    "C/C++": ["CMakeLists.txt", "Makefile"],
    "Docker": ["Dockerfile", "docker-compose.yml", "compose.yaml"],
}

FRAMEWORKS = {
    "FastAPI": ["fastapi"],
    "Django": ["django"],
    "Flask": ["flask"],
    "React": ["react"],
    "Next.js": ["next"],
    "Vue": ["vue"],
    "Angular": ["@angular/core"],
    "Svelte": ["svelte"],
    "Express": ["express"],
    "Laravel": ["laravel/framework"],
}


FRAMEWORK_MANIFESTS = {
    "FastAPI": ("pyproject.toml", "requirements.txt"),
    "Django": ("pyproject.toml", "requirements.txt"),
    "Flask": ("pyproject.toml", "requirements.txt"),
    "React": ("package.json",),
    "Next.js": ("package.json",),
    "Vue": ("package.json",),
    "Angular": ("package.json",),
    "Svelte": ("package.json",),
    "Express": ("package.json",),
    "Laravel": ("composer.json",),
}

TOOLS = {
    "Python": ["Ruff", "Mypy", "Bandit", "Pytest"],
    "JavaScript": ["ESLint", "npm audit", "Jest"],
    "TypeScript": ["ESLint", "TypeScript compiler"],
    "Rust": ["Clippy", "Cargo test"],
    "Go": ["go vet", "go test"],
    "Java": ["Checkstyle", "JUnit"],
    "PHP": ["PHPStan", "PHPUnit"],
    "Ruby": ["RuboCop", "RSpec"],
    "Docker": ["Trivy"],
}

EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rs": "Rust",
    ".go": "Go",
    ".java": "Java",
    ".php": "PHP",
    ".rb": "Ruby",
    ".dart": "Dart",
    ".cs": "C#",
    ".c": "C/C++",
    ".cpp": "C/C++",
}

MAX_FILES = 20000


def collect_files(root: Path):
    """Collect regular project files without following symlinks."""
    files = []
    truncated = False

    for current, dirs, names in os.walk(root, followlinks=False):
        current_path = Path(current)

        dirs[:] = sorted(
            name
            for name in dirs
            if name not in IGNORED
            and not (current_path / name).is_symlink()
        )

        for name in sorted(names):
            path = current_path / name

            if path.is_symlink() or not path.is_file():
                continue

            if len(files) >= MAX_FILES:
                truncated = True
                return files, truncated

            files.append(path)

    return files, truncated


def _normalize_package(name):
    return name.strip().lower().replace("_", "-")


def _extract_requirement_name(value):
    """Extract a package name from a requirements-style entry."""
    value = value.strip()

    if not value or value.startswith("#") or value.startswith("-"):
        return None

    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()

    match = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9_.-]*)"
        r"(?:\[[^\]]*\])?"
        r"\s*(?:[<>=!~;@]|$)",
        value,
    )

    if not match:
        return None

    return _normalize_package(match.group(1))


def _read_json_dependencies(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return set()

    if not isinstance(data, dict):
        return set()

    names = set()

    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "require",
        "require-dev",
    ):
        dependencies = data.get(section, {})
        if isinstance(dependencies, dict):
            names.update(
                _normalize_package(name)
                for name in dependencies
                if isinstance(name, str)
            )

    return names


def _read_python_dependencies(path):
    """Read Python dependencies from requirements.txt or pyproject.toml."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return set()

    if path.name == "requirements.txt":
        lines = content.splitlines()
        return {
            name
            for value in lines
            for name in [_extract_requirement_name(value)]
            if name
        }

    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        data = tomllib.loads(content)
    except (ImportError, ValueError):
        return set()

    if not isinstance(data, dict):
        return set()

    names = set()

    project = data.get("project", {})
    if isinstance(project, dict):
        dependencies = project.get("dependencies", [])
        if isinstance(dependencies, list):
            for value in dependencies:
                if isinstance(value, str):
                    name = _extract_requirement_name(value)
                    if name:
                        names.add(name)

        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, str):
                            name = _extract_requirement_name(value)
                            if name:
                                names.add(name)

    tool = data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            sections = [
                poetry.get("dependencies", {}),
                poetry.get("dev-dependencies", {}),
            ]

            groups = poetry.get("group", {})
            if isinstance(groups, dict):
                for group in groups.values():
                    if isinstance(group, dict):
                        sections.append(group.get("dependencies", {}))

            for section in sections:
                if isinstance(section, dict):
                    names.update(
                        _normalize_package(name)
                        for name in section
                        if isinstance(name, str)
                        and name.lower() != "python"
                    )

    return names


def _read_dependencies(path):
    if path.name in {"package.json", "composer.json"}:
        return _read_json_dependencies(path)

    if path.name in {"pyproject.toml", "requirements.txt"}:
        return _read_python_dependencies(path)

    return set()


def detect_project(directory="."):
    """Detect project technologies without executing or modifying files."""
    root = Path(directory).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Invalid project directory: {root}")

    files, truncated = collect_files(root)

    names = {path.name.lower() for path in files}
    suffixes = {path.suffix.lower() for path in files}

    languages = []

    for language, markers in MARKERS.items():
        if any(
            marker.lower() in names
            or (
                marker.startswith(".")
                and marker.lower() in suffixes
            )
            for marker in markers
        ):
            languages.append(language)

    for suffix, language in EXTENSIONS.items():
        if suffix in suffixes and language not in languages:
            languages.append(language)

    dependencies_by_manifest = {}

    supported_manifests = {
        "package.json",
        "composer.json",
        "pyproject.toml",
        "requirements.txt",
    }

    for path in files:
        if path.name in supported_manifests:
            dependencies_by_manifest.setdefault(path.name, set()).update(
                _read_dependencies(path)
            )

    frameworks = sorted(
        framework
        for framework, indicators in FRAMEWORKS.items()
        if any(
            _normalize_package(indicator)
            in dependencies_by_manifest.get(manifest, set())
            for manifest in FRAMEWORK_MANIFESTS.get(framework, ())
            for indicator in indicators
        )
    )

    suggested_tools = {
        tool
        for language in languages
        for tool in TOOLS.get(language, [])
    }

    if "dockerfile" in names:
        suggested_tools.add("Trivy")

    return {
        "engine": "MIZAN Smart Detector",
        "version": "0.1.0",
        "repository": str(root),
        "files_discovered": len(files),
        "scan_limit_reached": truncated,
        "languages": sorted(languages),
        "frameworks": frameworks,
        "suggested_tools": sorted(suggested_tools),
        "execution_performed": False,
        "mode": "read-only",
    }
