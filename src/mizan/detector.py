"""Safe, read-only project technology detection."""

import json
import os
import re
from pathlib import Path

from ._version import __version__

IGNORED = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".next",
    ".pytest_cache", ".mypy_cache",
    ".mizan",  # MIZAN backups and runtime data
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
    "Dart": ["dart analyze", "dart test"],
    "C#": ["dotnet format", "dotnet test"],
    "C/C++": ["Clang-Tidy", "CTest"],
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
MAX_MANIFEST_SIZE = 2 * 1024 * 1024


def _read_manifest_text(path, *, errors="strict"):
    """Read a manifest only when its size does not exceed the limit."""
    try:
        with path.open("rb") as file:
            raw = file.read(MAX_MANIFEST_SIZE + 1)
        if len(raw) > MAX_MANIFEST_SIZE:
            return None
        return raw.decode("utf-8", errors=errors)
    except (OSError, UnicodeError):
        return None


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
    content = _read_manifest_text(path)
    if content is None:
        return set()

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
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
    content = _read_manifest_text(path, errors="ignore")
    if content is None:
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
        "version": __version__,
        "repository": str(root),
        "files_discovered": len(files),
        "scan_limit_reached": truncated,
        "languages": sorted(languages),
        "frameworks": frameworks,
        "suggested_tools": sorted(suggested_tools),
        "execution_performed": False,
        "mode": "read-only",
    }


def _read_package_lock(path):
    """Yield {name, version, ecosystem} from package-lock.json (v2/v3)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    packages = data.get("packages") or {}
    if not isinstance(packages, dict):
        return
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            continue
        name = key.split("node_modules/")[-1]
        version = entry.get("version")
        if name and version:
            yield {
                "name": name,
                "version": version,
                "ecosystem": "npm",
            }


def _read_poetry_lock(path):
    """Yield {name, version, ecosystem} from poetry.lock (TOML)."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            yield {
                "name": name,
                "version": version,
                "ecosystem": "PyPI",
            }


def _read_pipfile_lock(path):
    """Yield {name, version, ecosystem} from Pipfile.lock."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            if isinstance(entry, dict):
                version = entry.get("version")
                if version:
                    yield {
                        "name": name,
                        "version": version.lstrip("="),
                        "ecosystem": "PyPI",
                    }


def iter_locked_packages(files):
    """Yield all exact-version packages from lock files in `files`."""
    for path in files:
        if path.name == "package-lock.json":
            yield from _read_package_lock(path)
        elif path.name == "poetry.lock":
            yield from _read_poetry_lock(path)
        elif path.name == "Pipfile.lock":
            yield from _read_pipfile_lock(path)


def _resolve_installed_version(name):
    """Return installed version of `name`, or None if not installed."""
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ImportError:
        return None
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _read_pyproject_dependencies(path):
    """Yield {name, version, ecosystem} from pyproject.toml.

    Reads:
    - [project] dependencies
    - [project] optional-dependencies (PEP 621)
    - [dependency-groups] (PEP 735)
    - [tool.poetry.dependencies], [tool.poetry.dev-dependencies],
      [tool.poetry.group.*.dependencies] (Poetry)

    Exact `==` pins are used directly. For range specifiers, the currently
    installed version is used as a best-effort resolution.
    """
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return

    import re as _re
    pin = _re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([^\s;#]+)")
    name_re = _re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)")

    def _emit(value):
        if not isinstance(value, str):
            return
        match = pin.match(value)
        if match:
            yield {"name": match.group(1), "version": match.group(2), "ecosystem": "PyPI"}
            return
        m = name_re.match(value)
        if not m:
            return
        resolved = _resolve_installed_version(m.group(1))
        if resolved:
            yield {"name": m.group(1), "version": resolved, "ecosystem": "PyPI"}

    project = data.get("project", {})
    if isinstance(project, dict):
        for value in project.get("dependencies", []):
            yield from _emit(value)
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    for value in group:
                        yield from _emit(value)
        for value in project.get("dev-dependencies", []):
            yield from _emit(value)

    groups = data.get("dependency-groups", {})
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                for value in group:
                    yield from _emit(value)

    tool = data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            sections = [
                poetry.get("dependencies", {}),
                poetry.get("dev-dependencies", {}),
            ]
            pgroups = poetry.get("group", {})
            if isinstance(pgroups, dict):
                for group in pgroups.values():
                    if isinstance(group, dict):
                        sections.append(group.get("dependencies", {}))
            import re as _re2
            _ver_re = _re2.compile(r"(\d+(?:\.\d+)+)")
            for section in sections:
                if not isinstance(section, dict):
                    continue
                for name, spec in section.items():
                    if not isinstance(name, str) or name.lower() == "python":
                        continue
                    raw = None
                    if isinstance(spec, str):
                        raw = spec
                    elif isinstance(spec, dict):
                        v = spec.get("version")
                        if isinstance(v, str):
                            raw = v
                    if raw is None:
                        continue
                    cleaned = raw.lstrip("^~<>=!* ").strip()
                    vmatch = _ver_re.match(cleaned)
                    if vmatch and not any(c in raw for c in "<>*"):
                        # Exact version like "2.0.0"
                        yield {"name": name, "version": vmatch.group(1), "ecosystem": "PyPI"}
                    else:
                        resolved = _resolve_installed_version(name)
                        if resolved:
                            yield {"name": name, "version": resolved, "ecosystem": "PyPI"}
