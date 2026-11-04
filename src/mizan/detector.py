"""Safe, read-only project technology detection."""

from pathlib import Path

IGNORED = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".next",
    ".pytest_cache", ".mypy_cache"
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

TOOLS = {
    "Python": [
        "Ruff", "Mypy", "Bandit", "Pytest"
    ],
    "JavaScript": [
        "ESLint", "npm audit", "Jest"
    ],
    "TypeScript": [
        "ESLint", "TypeScript compiler"
    ],
    "Rust": ["Clippy", "Cargo test"],
    "Go": ["go vet", "go test"],
    "Java": ["Checkstyle", "JUnit"],
    "PHP": ["PHPStan", "PHPUnit"],
    "Ruby": ["RuboCop", "RSpec"],
    "Docker": ["Trivy"],
}

MAX_FILES = 20000


def collect_files(root: Path):
    files = []
    truncated = False

    for current, dirs, names in __import__("os").walk(root):
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORED
        )

        for name in sorted(names):
            path = Path(current) / name

            if path.is_file():
                if len(files) >= MAX_FILES:
                    truncated = True
                    return files, truncated
                files.append(path)

    return files, truncated


def detect_project(directory="."):
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

    # Supplement manifest detection with source extensions.
    extension_map = {
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

    for suffix, language in extension_map.items():
        if suffix in suffixes and language not in languages:
            languages.append(language)

    frameworks = []
    manifests = [
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "composer.json",
    ]

    for path in files:
        if path.name not in manifests:
            continue

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="ignore"
            ).lower()
        except OSError:
            continue

        for framework, indicators in FRAMEWORKS.items():
            if any(indicator in content for indicator in indicators):
                if framework not in frameworks:
                    frameworks.append(framework)

    suggested_tools = sorted({
        tool
        for language in languages
        for tool in TOOLS.get(language, [])
    })

    if "Dockerfile" in names:
        if "Trivy" not in suggested_tools:
            suggested_tools.append("Trivy")

    return {
        "engine": "MIZAN Smart Detector",
        "version": "0.1.0",
        "repository": str(root),
        "files_discovered": len(files),
        "scan_limit_reached": truncated,
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "suggested_tools": sorted(suggested_tools),
        "execution_performed": False,
        "mode": "read-only",
    }
