#!/usr/bin/env python3
"""
Sentinel QA Agent

Scans one project or a folder of projects for security risks, likely bugs,
dependency issues, secret leaks, and missing QA basics. It uses built-in
heuristics plus optional ecosystem tools when they are installed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any, Iterable

import qa_test_planner


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "target",
    ".terraform",
    ".cache",
    "coverage",
    "htmlcov",
    "reports",
    "latest-report",
    "latest-web-qa",
    "sentinel-qa-report",
    "sentinel-web-qa-report",
    "report.md",
    "report.json",
    "test_cases.md",
    "test_cases.json",
    "state",
}

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".env",
    ".example",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    project: str
    path: str
    line: int | None
    title: str
    detail: str
    recommendation: str


@dataclasses.dataclass
class ScanBudget:
    root: Path
    started_at: float
    max_files: int = 50_000
    max_depth: int = 40
    max_scan_seconds: int = 300
    files_seen: int = 0

    def check_time(self) -> None:
        if time.time() - self.started_at > self.max_scan_seconds:
            raise ScanLimitExceeded(
                "Scan wall-clock limit exceeded",
                f"The scan exceeded {self.max_scan_seconds} seconds.",
            )

    def check_depth(self, path: Path) -> bool:
        try:
            depth = len(path.relative_to(self.root).parts)
        except ValueError:
            depth = len(path.parts)
        return depth <= self.max_depth

    def count_file(self, path: Path) -> None:
        self.check_time()
        self.files_seen += 1
        if self.files_seen > self.max_files:
            raise ScanLimitExceeded(
                "Scan file-count limit exceeded",
                f"The scan stopped after seeing more than {self.max_files} files.",
            )


class ScanLimitExceeded(RuntimeError):
    def __init__(self, title: str, detail: str) -> None:
        super().__init__(detail)
        self.title = title
        self.detail = detail


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
IGNORE_MARKER = "sentinel-qa: ignore"


SECRET_PATTERNS = [
    ("high", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("high", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("high", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("high", "Stripe secret key", re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b")),
    ("high", "Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("medium", "Likely hard-coded credential", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]")),
]

BUG_PATTERNS = [
    ("medium", "Debug mode enabled", re.compile(r"(?i)\b(debug|dev_mode)\b\s*[:=]\s*(true|1|yes)")),
    ("medium", "Dangerous eval usage", re.compile(r"\beval\s*\(")),
    ("medium", "Shell execution with interpolation", re.compile(r"\b(os\.system|exec)\s*\(|subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True")),
    ("medium", "SQL string construction", re.compile(r"(?i)\b(select\b.+\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b.*(\+|%|\{.*\})")),
    ("low", "TODO/FIXME left in code", re.compile(r"\b(TODO|FIXME|HACK)\b")),
    ("low", "Browser console/debug statement", re.compile(r"\b(console\.log|debugger;)\b")),
]

WEB_RISK_PATTERNS = [
    ("high", "Potential XSS sink", re.compile(r"\b(innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write)\b")),
    ("high", "Insecure random for security-sensitive code", re.compile(r"\b(Math\.random|random\.random)\s*\(")),
    ("medium", "Weak hash algorithm", re.compile(r"\b(md5|sha1)\b", re.IGNORECASE)),
    ("medium", "Permissive CORS", re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]")),
]


def load_config(path: Path | None) -> dict:
    if not path:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    if "scan" in config and isinstance(config["scan"], dict):
        nested = config["scan"]
        return {
            "exclude_dirs": nested.get("exclude_dirs", []),
            "exclude_globs": nested.get("exclude_globs", []),
        }
    return config


def should_skip(path: Path, root: Path, excludes: set[str], globs: list[str]) -> bool:
    rel = path.relative_to(root)
    parts = set(rel.parts)
    if parts & excludes:
        return True
    rel_text = rel.as_posix()
    return any(fnmatch.fnmatch(rel_text, pattern) for pattern in globs)


def limit_finding(project: Path, exc: ScanLimitExceeded) -> Finding:
    return Finding(
        "high",
        "resource-limit",
        project.name or str(project),
        ".",
        None,
        exc.title,
        exc.detail,
        "Narrow the scan target or raise the explicit resource limits only for repositories you trust.",
    )


def is_text_file(path: Path, max_bytes: int = 2_000_000) -> bool:
    try:
        if path.stat().st_size > max_bytes:
            return False
    except OSError:
        return False
    if path.name in {".env", ".env.local", ".env.production", ".env.development"}:
        return True
    if path.suffix.lower() not in TEXT_EXTENSIONS:
        return False
    try:
        with path.open("rb") as handle:
            chunk = handle.read(2048)
        return b"\0" not in chunk
    except OSError:
        return False


def discover_projects(root: Path, excludes: set[str], globs: list[str], budget: ScanBudget) -> list[Path]:
    markers = {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
        "composer.json",
        ".git",
    }
    projects: set[Path] = set()
    if any((root / marker).exists() for marker in markers):
        projects.add(root)
    for dirpath, dirnames, filenames in os.walk(root):
        budget.check_time()
        current = Path(dirpath)
        if not budget.check_depth(current):
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if not should_skip(current / name, root, excludes, globs)
        ]
        for filename in filenames:
            budget.count_file(current / filename)
        if any(marker in filenames or (current / marker).is_dir() for marker in markers):
            projects.add(current)
            dirnames[:] = []
    return sorted(projects)


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def scan_file(project: Path, path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel = path.relative_to(project).as_posix()
    project_name = project.name
    for number, line in enumerate(read_lines(path), start=1):
        if IGNORE_MARKER in line or "re.compile(" in line:
            continue
        for severity, title, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        severity,
                        "secrets",
                        project_name,
                        rel,
                        number,
                        title,
                        "The line matches a credential or secret-like pattern.",
                        "Remove the secret, rotate it if real, and load it from a secret manager or environment variable.",
                    )
                )
        for severity, title, pattern in BUG_PATTERNS + WEB_RISK_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        severity,
                        "code-risk",
                        project_name,
                        rel,
                        number,
                        title,
                        line.strip()[:220],
                        "Review whether this is reachable with untrusted input and add tests around the behavior.",
                    )
                )
    return findings


def sandbox_image_for_command(command: list[str], default_image: str) -> str:
    if not command:
        return default_image
    executable = command[0]
    if executable == "npm":
        return "node:22-alpine"
    if executable == "go":
        return "golang:1.23-alpine"
    if executable == "cargo":
        return "rust:1.83-slim"
    return default_image


def run_command(
    project: Path,
    command: list[str],
    timeout: int,
    *,
    sandbox: bool = True,
    allow_network: bool = False,
    sandbox_image: str = "sentinel-qa-scanner:latest",
    sandbox_cpus: float = 1.0,
    sandbox_memory: str = "1g",
    sandbox_pids_limit: int = 256,
    sandbox_max_output_bytes: int = 1_000_000,
) -> tuple[int, str]:
    if sandbox:
        try:
            import sandbox_runner

            options = sandbox_runner.SandboxOptions(
                image=sandbox_image_for_command(command, sandbox_image),
                allow_network=allow_network,
                cpus=sandbox_cpus,
                memory=sandbox_memory,
                pids_limit=sandbox_pids_limit,
                max_duration=timeout,
                max_output_bytes=sandbox_max_output_bytes,
            )
            result = sandbox_runner.run_repo_command(project, command, options)
            return result.returncode, result.output
        except Exception as exc:
            return 125, f"Sandbox execution failed closed: {exc}"

    try:
        completed = subprocess.run(
            command,
            cwd=project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def optional_tool_findings(
    project: Path,
    timeout: int,
    *,
    sandbox: bool = True,
    allow_network: bool = False,
    sandbox_image: str = "sentinel-qa-scanner:latest",
    sandbox_cpus: float = 1.0,
    sandbox_memory: str = "1g",
    sandbox_pids_limit: int = 256,
    sandbox_max_output_bytes: int = 1_000_000,
    run_optional_tools: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    if not run_optional_tools:
        return findings

    commands: list[tuple[str, list[str], str]] = []

    network_tools_allowed = allow_network or not sandbox

    if (project / "package.json").exists() and (sandbox or tool_exists("npm")):
        if network_tools_allowed:
            commands.append(("npm audit", ["npm", "audit", "--json"], "dependency-risk"))
        commands.append(("npm test", ["npm", "test", "--", "--runInBand"], "test-failure"))
    if (project / "requirements.txt").exists() or (project / "pyproject.toml").exists():
        if network_tools_allowed and (sandbox or tool_exists("pip-audit")):
            commands.append(("pip-audit", ["pip-audit", "--format", "json"], "dependency-risk"))
        if sandbox or tool_exists("bandit"):
            commands.append(("bandit", ["bandit", "-q", "-r", "."], "code-risk"))
    if (project / "go.mod").exists():
        if sandbox or tool_exists("go"):
            commands.append(("go test", ["go", "test", "./..."], "test-failure"))
        if tool_exists("gosec"):
            commands.append(("gosec", ["gosec", "./..."], "code-risk"))
    if (project / "Cargo.toml").exists():
        if sandbox or tool_exists("cargo"):
            commands.append(("cargo test", ["cargo", "test", "--all"], "test-failure"))
        if network_tools_allowed and tool_exists("cargo-audit"):
            commands.append(("cargo audit", ["cargo", "audit"], "dependency-risk"))
    if network_tools_allowed and (sandbox or tool_exists("semgrep")):
        commands.append(("semgrep", ["semgrep", "--config", "auto", "--quiet", "."], "code-risk"))

    for name, command, category in commands:
        code, output = run_command(
            project,
            command,
            timeout,
            sandbox=sandbox,
            allow_network=allow_network,
            sandbox_image=sandbox_image,
            sandbox_cpus=sandbox_cpus,
            sandbox_memory=sandbox_memory,
            sandbox_pids_limit=sandbox_pids_limit,
            sandbox_max_output_bytes=sandbox_max_output_bytes,
        )
        if code != 0:
            severity = "high" if category in {"dependency-risk", "test-failure"} or code == 125 else "medium"
            findings.append(
                Finding(
                    severity,
                    category,
                    project.name,
                    ".",
                    None,
                    f"{name} reported issues",
                    trim_output(output),
                    f"Run {' '.join(command)} in {project} and address the reported items.",
                )
            )
    return findings


def trim_output(output: str, limit: int = 2500) -> str:
    output = re.sub(r"\x1b\[[0-9;]*m", "", output).strip()
    if len(output) <= limit:
        return output
    return output[:limit] + "\n... output truncated ..."


def looks_like_test(path: Path) -> bool:
    return (
        path.name in {"test", "tests", "__tests__"}
        or path.name.startswith("test_")
        or path.name.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    )


def detect_project_profile(project: Path) -> dict[str, Any]:
    """Return lightweight project signals without executing repo code."""
    markers: list[str] = []
    languages: set[str] = set()
    frameworks: set[str] = set()
    package_managers: set[str] = set()
    test_signals: set[str] = set()
    ci: set[str] = set()

    marker_map = {
        "package.json": "node",
        "pyproject.toml": "python",
        "requirements.txt": "python",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "pom.xml": "java",
        "build.gradle": "java",
        "composer.json": "php",
    }
    for marker, language in marker_map.items():
        if (project / marker).exists():
            markers.append(marker)
            languages.add(language)

    lock_files = {
        "package-lock.json": "npm",
        "pnpm-lock.yaml": "pnpm",
        "yarn.lock": "yarn",
        "uv.lock": "uv",
        "poetry.lock": "poetry",
        "Pipfile.lock": "pipenv",
        "Cargo.lock": "cargo",
        "go.sum": "go",
        "composer.lock": "composer",
    }
    for lock_file, manager in lock_files.items():
        if (project / lock_file).exists():
            package_managers.add(manager)

    package_json = read_json_file(project / "package.json")
    if package_json:
        package_managers.add(package_json.get("packageManager", "").split("@", 1)[0] or "npm")
        dependencies = dependency_names(package_json, ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"])
        node_frameworks = {
            "next": "Next.js",
            "react": "React",
            "vue": "Vue",
            "svelte": "Svelte",
            "@angular/core": "Angular",
            "express": "Express",
            "@nestjs/core": "NestJS",
            "vite": "Vite",
        }
        frameworks.update(label for name, label in node_frameworks.items() if name in dependencies)
        scripts = package_json.get("scripts") if isinstance(package_json.get("scripts"), dict) else {}
        for script in ("test", "lint", "typecheck", "e2e"):
            if script in scripts:
                test_signals.add(f"npm script: {script}")

    pyproject = read_toml_file(project / "pyproject.toml")
    requirements_text = read_small_text(project / "requirements.txt")
    python_dependencies = set()
    if pyproject:
        project_section = pyproject.get("project") if isinstance(pyproject.get("project"), dict) else {}
        python_dependencies.update(normalize_dependency_name(item) for item in project_section.get("dependencies", []) if isinstance(item, str))
        optional = project_section.get("optional-dependencies") if isinstance(project_section.get("optional-dependencies"), dict) else {}
        for items in optional.values():
            if isinstance(items, list):
                python_dependencies.update(normalize_dependency_name(item) for item in items if isinstance(item, str))
        tool_section = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
        if "pytest" in tool_section:
            test_signals.add("pytest config")
    if requirements_text:
        python_dependencies.update(
            normalize_dependency_name(line)
            for line in requirements_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    python_frameworks = {"django": "Django", "fastapi": "FastAPI", "flask": "Flask", "pytest": "pytest"}
    frameworks.update(label for name, label in python_frameworks.items() if name in python_dependencies)

    if (project / "go.mod").exists():
        go_mod = read_small_text(project / "go.mod")
        if "github.com/gin-gonic/gin" in go_mod:
            frameworks.add("Gin")
        if "github.com/labstack/echo" in go_mod:
            frameworks.add("Echo")
    if (project / "Cargo.toml").exists():
        cargo = read_small_text(project / "Cargo.toml")
        if "actix-web" in cargo:
            frameworks.add("Actix Web")
        if "axum" in cargo:
            frameworks.add("Axum")

    common_tests = ["tests", "test", "__tests__", "spec", "e2e", "playwright.config.ts", "pytest.ini"]
    for signal in common_tests:
        if (project / signal).exists():
            test_signals.add(signal)

    ci_markers = [".github/workflows", ".gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml"]
    for marker in ci_markers:
        if (project / marker).exists():
            ci.add(marker)

    return {
        "path": str(project),
        "name": project.name or str(project),
        "markers": sorted(markers),
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "package_managers": sorted(package_managers),
        "test_signals": sorted(test_signals),
        "ci": sorted(ci),
    }


def read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def read_toml_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def read_small_text(path: Path, max_bytes: int = 256_000) -> str:
    try:
        if not path.exists() or path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def dependency_names(package_json: dict[str, Any], sections: list[str]) -> set[str]:
    names: set[str] = set()
    for section in sections:
        dependencies = package_json.get(section)
        if isinstance(dependencies, dict):
            names.update(str(name) for name in dependencies)
    return names


def normalize_dependency_name(value: str) -> str:
    return re.split(r"[<>=!~;\[\]\s]", value.strip(), maxsplit=1)[0].lower()


def project_health_findings(project: Path, has_tests: bool) -> list[Finding]:
    findings: list[Finding] = []
    if not has_tests:
        findings.append(
            Finding(
                "medium",
                "qa-coverage",
                project.name,
                ".",
                None,
                "No obvious automated tests found",
                "The scanner did not find a test directory or common test filename.",
                "Add smoke tests for the main workflows, then include them in CI.",
            )
        )
    ci_markers = [".github/workflows", ".gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml"]
    if not any((project / marker).exists() for marker in ci_markers):
        findings.append(
            Finding(
                "low",
                "qa-process",
                project.name,
                ".",
                None,
                "No common CI configuration found",
                "The project may not be running tests and security checks automatically.",
                "Add a CI workflow that runs tests, dependency audit, linting, and this scanner.",
            )
        )
    return findings


def scan_project(
    project: Path,
    root: Path,
    excludes: set[str],
    globs: list[str],
    timeout: int,
    *,
    sandbox: bool = True,
    allow_network: bool = False,
    sandbox_image: str = "sentinel-qa-scanner:latest",
    sandbox_cpus: float = 1.0,
    sandbox_memory: str = "1g",
    sandbox_pids_limit: int = 256,
    sandbox_max_output_bytes: int = 1_000_000,
    run_optional_tools: bool = True,
    max_file_bytes: int = 2_000_000,
    max_files: int = 50_000,
    max_depth: int = 40,
    max_scan_seconds: int = 300,
) -> list[Finding]:
    findings: list[Finding] = []
    budget = ScanBudget(
        root=project,
        started_at=time.time(),
        max_files=max_files,
        max_depth=max_depth,
        max_scan_seconds=max_scan_seconds,
    )
    has_tests = False
    try:
        for dirpath, dirnames, filenames in os.walk(project):
            budget.check_time()
            current = Path(dirpath)
            if not budget.check_depth(current):
                dirnames[:] = []
                continue
            if looks_like_test(current):
                has_tests = True
            dirnames[:] = [
                name
                for name in dirnames
                if not should_skip(current / name, root, excludes, globs)
            ]
            for filename in filenames:
                path = current / filename
                budget.count_file(path)
                if looks_like_test(path):
                    has_tests = True
                if should_skip(path, root, excludes, globs):
                    continue
                if path.is_file() and is_text_file(path, max_bytes=max_file_bytes):
                    findings.extend(scan_file(project, path, root))
    except ScanLimitExceeded as exc:
        findings.append(limit_finding(project, exc))
        return findings
    findings.extend(project_health_findings(project, has_tests))
    findings.extend(
        optional_tool_findings(
            project,
            timeout,
            sandbox=sandbox,
            allow_network=allow_network,
            sandbox_image=sandbox_image,
            sandbox_cpus=sandbox_cpus,
            sandbox_memory=sandbox_memory,
            sandbox_pids_limit=sandbox_pids_limit,
            sandbox_max_output_bytes=sandbox_max_output_bytes,
            run_optional_tools=run_optional_tools,
        )
    )
    return findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def category_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_scan_summary(findings: list[Finding], profiles: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.project, item.path, item.line or 0))
    top_items = ordered[:5]
    all_languages = sorted({language for profile in (profiles or {}).values() for language in profile.get("languages", [])})
    all_frameworks = sorted({framework for profile in (profiles or {}).values() for framework in profile.get("frameworks", [])})
    recommendations: list[str] = []
    counts = severity_counts(findings)
    categories = category_counts(findings)
    if counts.get("critical") or counts.get("high"):
        recommendations.append("Fix critical and high findings before trusting this repository.")
    if categories.get("secrets"):
        recommendations.append("Rotate any real secrets before committing or sharing reports.")
    if categories.get("test-failure") or categories.get("qa-coverage"):
        recommendations.append("Get smoke tests passing so future scans can catch regressions.")
    if not findings:
        recommendations.append("No findings were detected; still run project-specific tests and a human review.")
    elif not recommendations:
        recommendations.append("Review the top findings and decide which ones are real risks in this project context.")
    return {
        "severity_counts": counts,
        "category_counts": categories,
        "languages": all_languages,
        "frameworks": all_frameworks,
        "top_findings": [dataclasses.asdict(item) for item in top_items],
        "recommended_next_steps": recommendations,
    }


def render_markdown(
    root: Path,
    projects: list[Path],
    findings: list[Finding],
    elapsed: float,
    profiles: dict[str, dict[str, Any]] | None = None,
    test_cases: list[qa_test_planner.TestCaseSpec] | None = None,
) -> str:
    counts = severity_counts(findings)
    summary = build_scan_summary(findings, profiles)

    lines = [
        "# Sentinel QA Agent Report",
        "",
        f"- Root scanned: `{root}`",
        f"- Projects scanned: `{len(projects)}`",
        f"- Findings: `{len(findings)}`",
        f"- Runtime: `{elapsed:.1f}s`",
        "",
        "## Severity Summary",
        "",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"- {severity.title()}: {counts[severity]}")
    lines.extend(["", "## What To Do First", ""])
    for step in summary["recommended_next_steps"]:
        lines.append(f"- {step}")
    if summary["top_findings"]:
        lines.append("")
        lines.append("Top risk items:")
        for finding in summary["top_findings"][:3]:
            location = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
            lines.append(f"- [{finding['severity'].upper()}] {finding['title']} (`{finding['project']}/{location}`)")
    lines.extend(["", "## Project Signals", ""])
    if profiles:
        for project in projects:
            profile = profiles.get(str(project), {})
            languages = ", ".join(profile.get("languages") or ["unknown"])
            frameworks = ", ".join(profile.get("frameworks") or ["none detected"])
            tests = ", ".join(profile.get("test_signals") or ["none detected"])
            ci = ", ".join(profile.get("ci") or ["none detected"])
            lines.extend(
                [
                    f"### `{project}`",
                    "",
                    f"- Languages: {languages}",
                    f"- Frameworks: {frameworks}",
                    f"- Tests: {tests}",
                    f"- CI: {ci}",
                    "",
                ]
            )
    else:
        lines.append("No project profile signals were generated.")
    lines.extend(["", "## Generated QA Test Cases", ""])
    if test_cases:
        lines.append(
            "Sentinel generated these test cases from static project signals and findings. Existing project tests are run separately through the sandbox when optional tools are enabled."
        )
        lines.append("")
        for case in test_cases[:12]:
            lines.extend(
                [
                    f"### {case.id}: {case.title}",
                    "",
                    f"- Priority: `{case.priority}`",
                    f"- Type: `{case.kind}`",
                    f"- Project: `{case.project}`",
                    f"- Target: `{case.target}`",
                    f"- Status: `{case.execution_status}`",
                    f"- Why: {case.rationale}",
                    "- Steps:",
                ]
            )
            for step in case.steps:
                lines.append(f"  - {step}")
            lines.extend([f"- Expected result: {case.expected_result}", ""])
    else:
        lines.append("No generated test cases were produced for this scan.")
    lines.extend(["", "## Projects", ""])
    for project in projects:
        lines.append(f"- `{project}`")
    lines.extend(["", "## Findings", ""])

    if not findings:
        lines.append("No findings were detected by this scan. This does not guarantee the projects are vulnerability-free.")
        return "\n".join(lines) + "\n"

    for finding in sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.project, item.path, item.line or 0)):
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.extend(
            [
                f"### [{finding.severity.upper()}] {finding.title}",
                "",
                f"- Project: `{finding.project}`",
                f"- Category: `{finding.category}`",
                f"- Location: `{location}`",
                f"- Detail: {finding.detail or 'No additional output.'}",
                f"- Recommendation: {finding.recommendation}",
                "",
            ]
        )
    return "\n".join(lines)


def write_json(
    path: Path,
    findings: list[Finding],
    projects: list[Path],
    root: Path,
    elapsed: float,
    profiles: dict[str, dict[str, Any]] | None = None,
    test_cases: list[qa_test_planner.TestCaseSpec] | None = None,
) -> None:
    payload = {
        "root": str(root),
        "projects": [str(project) for project in projects],
        "runtime_seconds": elapsed,
        "summary": build_scan_summary(findings, profiles),
        "profiles": profiles or {},
        "test_cases": [dataclasses.asdict(case) for case in (test_cases or [])],
        "findings": [dataclasses.asdict(finding) for finding in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_scan(
    root: Path,
    output_dir: Path,
    config_path: Path | None = None,
    workers: int | None = None,
    timeout: int = 90,
    sandbox: bool = True,
    allow_network: bool = False,
    sandbox_image: str = "sentinel-qa-scanner:latest",
    sandbox_cpus: float = 1.0,
    sandbox_memory: str = "1g",
    sandbox_pids_limit: int = 256,
    sandbox_max_output_bytes: int = 1_000_000,
    run_optional_tools: bool = True,
    max_file_bytes: int = 2_000_000,
    max_files: int = 50_000,
    max_depth: int = 40,
    max_scan_seconds: int = 300,
    generate_test_plan: bool = True,
) -> dict:
    root = root.expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Root does not exist: {root}")

    config = load_config(config_path)
    excludes = set(DEFAULT_EXCLUDES) | set(config.get("exclude_dirs", []))
    globs = list(config.get("exclude_globs", []))

    started = time.time()
    initial_findings: list[Finding] = []
    discovery_budget = ScanBudget(
        root=root,
        started_at=started,
        max_files=max_files,
        max_depth=max_depth,
        max_scan_seconds=max_scan_seconds,
    )
    try:
        projects = discover_projects(root, excludes, globs, discovery_budget)
    except ScanLimitExceeded as exc:
        projects = [root]
        initial_findings.append(limit_finding(root, exc))
    if not projects:
        projects = [root]

    profiles = {str(project): detect_project_profile(project) for project in projects}
    all_findings: list[Finding] = list(initial_findings)
    worker_count = workers or max(2, (os.cpu_count() or 2) // 2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, worker_count)) as executor:
        futures = [
            executor.submit(
                scan_project,
                project,
                root,
                excludes,
                globs,
                timeout,
                sandbox=sandbox,
                allow_network=allow_network,
                sandbox_image=sandbox_image,
                sandbox_cpus=sandbox_cpus,
                sandbox_memory=sandbox_memory,
                sandbox_pids_limit=sandbox_pids_limit,
                sandbox_max_output_bytes=sandbox_max_output_bytes,
                run_optional_tools=run_optional_tools,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
                max_depth=max_depth,
                max_scan_seconds=max_scan_seconds,
            )
            for project in projects
        ]
        for future in concurrent.futures.as_completed(futures):
            all_findings.extend(future.result())

    elapsed = time.time() - started
    test_cases: list[qa_test_planner.TestCaseSpec] = []
    if generate_test_plan:
        for project in projects:
            project_findings = [finding for finding in all_findings if finding.project == project.name]
            test_cases.extend(
                qa_test_planner.generate_test_cases(
                    project,
                    profiles.get(str(project), {}),
                    project_findings,
                )
            )
    output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = output_dir / "report.md"
    json_path = output_dir / "report.json"
    test_cases_md, test_cases_json = qa_test_planner.write_artifacts(output_dir, test_cases)
    markdown_path.write_text(render_markdown(root, projects, all_findings, elapsed, profiles, test_cases), encoding="utf-8")
    write_json(json_path, all_findings, projects, root, elapsed, profiles, test_cases)

    return {
        "root": root,
        "projects": projects,
        "profiles": profiles,
        "test_cases": test_cases,
        "findings": all_findings,
        "elapsed": elapsed,
        "markdown_path": markdown_path.resolve(),
        "json_path": json_path.resolve(),
        "test_cases_md": test_cases_md,
        "test_cases_json": test_cases_json,
    }


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan projects for QA, bug, and vulnerability risks.")
    parser.add_argument("root", type=Path, nargs="?", help="Project folder or parent folder containing many projects.")
    parser.add_argument("--config", type=Path, help="Optional JSON config file.")
    parser.add_argument("--output-dir", type=Path, default=Path("sentinel-qa-report"), help="Directory for reports.")
    parser.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 2) // 2), help="Parallel project scans.")
    parser.add_argument("--timeout", type=int, default=90, help="Timeout in seconds for each optional tool command.")
    parser.add_argument("--skip-optional-tools", action="store_true", help="Skip ecosystem tools and test runners.")
    parser.add_argument("--allow-network", action="store_true", help="Allow sandboxed scanner containers to use the network.")
    parser.add_argument("--no-sandbox", action="store_true", help="Run ecosystem tools directly on the host. Requires --confirm-no-sandbox.")
    parser.add_argument("--confirm-no-sandbox", action="store_true", help="Confirm that you accept running untrusted repo commands on the host.")
    parser.add_argument("--sandbox-image", default="sentinel-qa-scanner:latest", help="Default Docker image for sandboxed Python scanners.")
    parser.add_argument("--sandbox-cpus", type=float, default=1.0, help="CPU limit for sandboxed tool containers.")
    parser.add_argument("--sandbox-memory", default="1g", help="Memory limit for sandboxed tool containers, for example 512m or 1g.")
    parser.add_argument("--sandbox-pids-limit", type=int, default=256, help="Process limit for sandboxed tool containers.")
    parser.add_argument("--sandbox-max-output-bytes", type=int, default=1_000_000, help="Maximum captured output per sandboxed command.")
    parser.add_argument("--max-files", type=int, help="Maximum files to inspect per discovery/scan phase.")
    parser.add_argument("--max-depth", type=int, help="Maximum directory depth to walk.")
    parser.add_argument("--max-file-bytes", type=int, help="Maximum text file size to read.")
    parser.add_argument("--max-scan-seconds", type=int, help="Host-side wall-clock limit for static traversal.")
    parser.add_argument("--skip-test-plan", action="store_true", help="Skip generated QA test-case planning.")
    parser.add_argument("--include-nested", action="store_true", help="Scan nested projects instead of stopping at first marker.")
    parser.add_argument("--ai-review", action="store_true", help="Ask an LLM to triage the findings.")
    parser.add_argument("--ai-provider", choices=["openai", "anthropic"], default=os.getenv("QA_AGENT_PROVIDER"), help="AI provider for --ai-review.")
    parser.add_argument("--model", default=os.getenv("QA_AGENT_MODEL"), help="AI model for --ai-review.")
    parser.add_argument("--history", action="store_true", help="Show recent scan history.")
    parser.add_argument("--doctor", action="store_true", help="Check local setup readiness and exit.")
    parser.add_argument("--doctor-json", action="store_true", help="Print --doctor output as JSON.")
    parser.add_argument("--record", action="store_true", help="Record this scan in local history.")
    parser.add_argument("--web-url", help="Run web QA checks against a running app URL.")
    parser.add_argument("--web-route", action="append", default=[], help="Route or URL to include in web crawl. May be repeated.")
    parser.add_argument("--web-discover-routes", action="store_true", help="Discover common app routes from project files for web crawl.")
    parser.add_argument("--web-click", action="append", default=[], help="CSS selector to click during web QA. May be repeated.")
    parser.add_argument("--web-viewport", choices=["desktop", "mobile"], default="desktop", help="Viewport for web QA.")
    parser.add_argument("--policy", type=Path, help="Optional sentinel.policy.json path.")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.doctor:
        import doctor

        payload = doctor.run_doctor(args.root, scanner_image=args.sandbox_image)
        if args.doctor_json:
            print(json.dumps(payload, indent=2))
        else:
            print(doctor.format_doctor_text(payload))
        return 1 if payload["summary"]["fail"] else 0
    if args.history:
        import agent_state

        for run in agent_state.list_runs(limit=20):
            finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(run["finished_at"]))
            print(
                f"#{run['id']} {finished} {run['status']} "
                f"{run['finding_count']} finding(s) {run['root']}"
            )
        return 0
    if not args.root:
        if args.web_url:
            import web_qa

            routes = args.web_route
            if args.web_discover_routes:
                routes = routes + web_qa.discover_routes(Path.cwd())
            if routes:
                result = web_qa.run_web_crawl(
                    args.web_url,
                    routes,
                    args.output_dir,
                    clicks=args.web_click,
                    viewport=args.web_viewport,
                )
                print(f"Web crawl report: {(args.output_dir / 'web_crawl.md').resolve()}")
                print(f"Routes: {result.get('passed')} passed, {result.get('failed')} failed")
            else:
                result = web_qa.run_web_qa(
                    args.web_url,
                    args.output_dir,
                    clicks=args.web_click,
                    viewport=args.web_viewport,
                )
                print(f"Web QA report: {(args.output_dir / 'web_qa.md').resolve()}")
                print(f"Screenshot: {result.get('screenshot') or 'none'}")
            return 0 if result.get("ok") else 1
        print("Root is required unless --history or --web-url is used.", file=sys.stderr)
        return 2

    if args.no_sandbox:
        if not args.confirm_no_sandbox:
            print("--no-sandbox requires --confirm-no-sandbox.", file=sys.stderr)
            return 2
        print(
            "WARNING: sandbox disabled. Optional tools and project scripts may execute untrusted repo code on this host.",
            file=sys.stderr,
        )

    import sentinel_policy

    policy = sentinel_policy.load_policy(root=args.root, path=args.policy)
    include_ai = args.ai_review or bool(policy["ai"].get("enabled"))
    ai_provider = args.ai_provider or policy["ai"].get("provider") or "openai"
    model = args.model or policy["ai"].get("model")
    web_url = args.web_url or policy["web"].get("base_url")
    web_routes = list(args.web_route or policy["web"].get("routes") or [])
    web_clicks = args.web_click or policy["web"].get("clicks") or []
    web_viewport = args.web_viewport or policy["web"].get("viewport") or "desktop"
    scan_policy = policy.get("scan", {})
    max_file_bytes = args.max_file_bytes or scan_policy.get("max_file_bytes") or 2_000_000
    max_files = args.max_files or scan_policy.get("max_files") or 50_000
    max_depth = args.max_depth or scan_policy.get("max_depth") or 40
    max_scan_seconds = args.max_scan_seconds or scan_policy.get("max_scan_seconds") or 300

    try:
        result = run_scan(
            root=args.root,
            output_dir=args.output_dir,
            config_path=args.policy or args.config,
            workers=args.workers,
            timeout=args.timeout,
            sandbox=not args.no_sandbox,
            allow_network=args.allow_network,
            sandbox_image=args.sandbox_image,
            sandbox_cpus=args.sandbox_cpus,
            sandbox_memory=args.sandbox_memory,
            sandbox_pids_limit=args.sandbox_pids_limit,
            sandbox_max_output_bytes=args.sandbox_max_output_bytes,
            run_optional_tools=not args.skip_optional_tools,
            max_file_bytes=max_file_bytes,
            max_files=max_files,
            max_depth=max_depth,
            max_scan_seconds=max_scan_seconds,
            generate_test_plan=not args.skip_test_plan,
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if include_ai:
        ai_path = None
        ai_error = None
        status = "completed"
        try:
            import qa_ai_agent
            model = model or qa_ai_agent.default_model_for_provider(ai_provider)

            qa_ai_agent.write_ai_review(
                args.output_dir,
                result["root"],
                result["projects"],
                result["findings"],
                model=model,
                provider=ai_provider,
            )
            ai_path = (args.output_dir / "ai_review.md").resolve()
            print(f"AI review: {ai_path}")
        except Exception as exc:
            status = "completed_with_ai_error"
            ai_error = str(exc)
            error_path = args.output_dir / "ai_review_error.txt"
            error_path.write_text(str(exc), encoding="utf-8")
            print(f"AI review failed: {exc}", file=sys.stderr)
            print(f"AI review error: {error_path.resolve()}", file=sys.stderr)
        if args.record:
            import agent_state

            run_id = agent_state.record_scan(
                result,
                output_dir=args.output_dir,
                ai_review_md=ai_path,
                status=status,
                error=ai_error,
            )
            print(f"History run: #{run_id}")
    elif args.record:
        import agent_state

        run_id = agent_state.record_scan(result, output_dir=args.output_dir)
        print(f"History run: #{run_id}")

    if web_url:
        import web_qa

        routes = web_routes
        if args.web_discover_routes or policy["web"].get("discover_routes"):
            routes = routes + web_qa.discover_routes(args.root)
        if routes:
            web_result = web_qa.run_web_crawl(
                web_url,
                routes,
                args.output_dir,
                clicks=web_clicks,
                viewport=web_viewport,
            )
            print(f"Web crawl report: {(args.output_dir / 'web_crawl.md').resolve()}")
        else:
            web_result = web_qa.run_web_qa(
                web_url,
                args.output_dir,
                clicks=web_clicks,
                viewport=web_viewport,
            )
            print(f"Web QA report: {(args.output_dir / 'web_qa.md').resolve()}")
        print(f"Web QA status: {web_result.get('status')}")
        if not web_result.get("ok"):
            return 1

    fail_on = set(policy.get("quality_gate", {}).get("fail_on") or ["critical", "high"])
    critical_or_high = [item for item in result["findings"] if item.severity in fail_on]
    print(f"Scanned {len(result['projects'])} project(s), found {len(result['findings'])} issue(s).")
    print(f"Generated test cases: {len(result['test_cases'])}")
    print(f"Markdown report: {result['markdown_path']}")
    print(f"JSON report: {result['json_path']}")
    print(f"Test cases: {result['test_cases_md']}")
    return 1 if critical_or_high else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
