"""Safe dependency fix engine with test-based validation."""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from mizan.scan import scan_repository


@dataclass
class FixPlan:
    manifest: str
    package: str
    ecosystem: str
    current_version: str
    target_version: str | None
    vuln_ids: list = field(default_factory=list)
    reason: str = "upgrade"


@dataclass
class FixResult:
    applied: list = field(default_factory=list)
    rolled_back: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    test_output: str = ""
    tests_passed: bool | None = None


# ----- version helpers -----

def _parse_version(v):
    """Best-effort version parse into a comparable tuple."""
    try:
        from packaging.version import Version
        return Version(v)
    except ImportError:
        pass
    parts = []
    for p in re.split(r"[.\-+]", v):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(p)
    return tuple(parts)


def _min_fixed_for_vuln(vuln):
    """Return the minimum fixed version for a single OSV record, or None."""
    fixed_versions = []
    for affected in vuln.get("affected", []):
        if not isinstance(affected, dict):
            continue
        for rng in affected.get("ranges", []):
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events", []):
                if isinstance(event, dict) and "fixed" in event:
                    fixed_versions.append(event["fixed"])
    if not fixed_versions:
        return None
    try:
        return max(fixed_versions, key=_parse_version)
    except Exception:
        return fixed_versions[-1]


# ----- planning -----

def plan_fixes(scan_result):
    """Convert vuln-scan findings into FixPlan objects."""
    # group by (manifest, package, ecosystem, current_version)
    grouped = {}
    for finding in scan_result.get("findings", []):
        dep = finding["dependency"]
        vuln = finding["vuln"]
        key = (
            dep.get("manifest", "<unknown>"),
            dep["name"],
            dep.get("ecosystem", "unknown"),
            dep["version"],
        )
        grouped.setdefault(key, []).append(vuln)

    plans = []
    for (manifest, package, ecosystem, current), vulns in grouped.items():
        vuln_ids = [v.get("id", "?") for v in vulns]
        fixed_candidates = []
        unfixed = False
        for v in vulns:
            mf = _min_fixed_for_vuln(v)
            if mf is None:
                unfixed = True
            else:
                fixed_candidates.append(mf)

        if unfixed or not fixed_candidates:
            plans.append(FixPlan(
                manifest=manifest,
                package=package,
                ecosystem=ecosystem,
                current_version=current,
                target_version=None,
                vuln_ids=vuln_ids,
                reason="no_fix_available",
            ))
            continue

        try:
            target = max(fixed_candidates, key=_parse_version)
        except Exception:
            target = fixed_candidates[-1]

        plans.append(FixPlan(
            manifest=manifest,
            package=package,
            ecosystem=ecosystem,
            current_version=current,
            target_version=target,
            vuln_ids=vuln_ids,
            reason="upgrade",
        ))

    return plans


# ----- apply to requirements.txt -----

_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([^\s;#]+)(.*)$")


def _apply_to_requirements_txt(path, plan):
    """Rewrite `name==old` to `name==new` in requirements.txt. Returns bool."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False

    lines = content.splitlines()
    changed = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            new_lines.append(line)
            continue
        match = _REQ_LINE.match(stripped)
        if match:
            name, version, rest = match.groups()
            if name.lower() == plan.package.lower() and version == plan.current_version:
                new_lines.append(f"{name}=={plan.target_version}{rest}")
                changed = True
                continue
        new_lines.append(line)

    if changed:
        trailing = "\n" if content.endswith("\n") else ""
        path.write_text("\n".join(new_lines) + trailing, encoding="utf-8")
    return changed


def _apply_plan(root, plan):
    """Apply a single plan to the appropriate manifest. Returns bool."""
    manifest_path = root / plan.manifest
    if not manifest_path.exists() or plan.target_version is None:
        return False
    if manifest_path.name == "requirements.txt":
        return _apply_to_requirements_txt(manifest_path, plan)
    # future: pyproject.toml, package-lock.json
    return False


# ----- test runner -----

def detect_test_command(root):
    """Return a test command list if one is discoverable, else None."""
    if (root / "pyproject.toml").exists():
        return [sys.executable, "-m", "pytest", "-q"]
    if (root / "pytest.ini").exists() or (root / "tox.ini").exists():
        return [sys.executable, "-m", "pytest", "-q"]
    if (root / "tests").is_dir():
        return [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"]
    if (root / "package.json").exists():
        return ["npm", "test", "--silent"]
    return None


def run_tests(root, timeout=180):
    """Run discovered test command. Returns (passed, output)."""
    cmd = detect_test_command(root)
    if cmd is None:
        return (None, "(no test command detected)")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return (result.returncode == 0, output[-2000:])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (False, f"test runner error: {exc}")


# ----- orchestrator -----

def apply_fixes(root, plans, validate=True):
    """Apply plans with backup + validation + rollback."""
    result = FixResult()
    to_apply = [p for p in plans if p.target_version is not None]
    result.skipped = [asdict(p) for p in plans if p.target_version is None]

    if not to_apply:
        return result

    # backup directory
    backup_dir = root / ".mizan" / "backup" / time.strftime("%Y%m%d-%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)

    # group plans by manifest
    by_manifest = {}
    for plan in to_apply:
        by_manifest.setdefault(plan.manifest, []).append(plan)

    # backup + apply
    applied_manifests = []
    for manifest, mplans in by_manifest.items():
        manifest_path = root / manifest
        if not manifest_path.exists():
            continue
        backup_path = backup_dir / manifest_path.name
        try:
            shutil.copy2(manifest_path, backup_path)
        except OSError:
            continue
        any_changed = False
        for plan in mplans:
            if _apply_plan(root, plan):
                result.applied.append(asdict(plan))
                any_changed = True
        if any_changed:
            applied_manifests.append((manifest_path, backup_path))

    if not applied_manifests:
        return result

    # validate
    if validate:
        passed, output = run_tests(root)
        result.test_output = output
        result.tests_passed = passed
        if passed is False:
            # rollback
            for manifest_path, backup_path in applied_manifests:
                try:
                    shutil.copy2(backup_path, manifest_path)
                    result.rolled_back.append(str(manifest_path.relative_to(root)))
                except OSError:
                    pass
            result.applied = []

    return result


# ----- CLI -----

def main(argv=None):
    parser = argparse.ArgumentParser(prog="mizan fix")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Show planned fixes without modifying files",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply fixes with test-based validation",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Apply fixes without running tests",
    )
    parser.add_argument("--format", choices=["json", "text"], default="text")
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: invalid path: {root}", file=sys.stderr)
        return 2

    if not args.plan and not args.apply:
        print("error: specify --plan or --apply", file=sys.stderr)
        return 2

    scan = scan_repository(root)
    plans = plan_fixes(scan)

    if args.plan:
        if args.format == "json":
            print(json.dumps([asdict(p) for p in plans], indent=2))
        else:
            if not plans:
                print("No fixes needed.")
            for p in plans:
                if p.target_version:
                    print(f"[UPGRADE] {p.package} {p.current_version} -> {p.target_version}")
                    print(f"  manifest: {p.manifest}")
                    print(f"  fixes:    {', '.join(p.vuln_ids)}")
                else:
                    print(f"[SKIP]    {p.package} {p.current_version} (no fix available)")
                    print(f"  vulns:    {', '.join(p.vuln_ids)}")
        return 0

    # --apply
    validate = not args.no_validate
    result = apply_fixes(root, plans, validate=validate)

    if args.format == "json":
        print(json.dumps(asdict(result), indent=2))
    else:
        if result.applied:
            print(f"Applied {len(result.applied)} fix(es):")
            for a in result.applied:
                print(f"  + {a['package']} {a['current_version']} -> {a['target_version']} ({a['manifest']})")
        if result.skipped:
            print(f"Skipped {len(result.skipped)} (no fix available)")
        if result.rolled_back:
            print(f"Rolled back {len(result.rolled_back)} manifest(s) due to test failure:")
            for m in result.rolled_back:
                print(f"  - {m}")
        if result.tests_passed is True:
            print("Tests: PASSED")
        elif result.tests_passed is False:
            print("Tests: FAILED (rolled back)")
            print("Test output (tail):")
            print(result.test_output)
        elif result.tests_passed is None:
            print("Tests: not run (no test command detected)")

    if result.rolled_back:
        return 1
    return 0
