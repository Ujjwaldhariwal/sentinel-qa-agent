#!/usr/bin/env python3
"""Local readiness checks for Sentinel QA Agent."""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import sandbox_runner
import sentinel_qa
import settings


@dataclasses.dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str
    recommendation: str = ""


def run_doctor(root: Path | None = None, *, scanner_image: str = "sentinel-qa-scanner:latest") -> dict[str, Any]:
    checks = [
        check_python_version(),
        check_state_dir(),
        check_docker_daemon(),
        check_scanner_image(scanner_image),
        check_ai_keys(),
        check_web_qa_tools(),
    ]
    if root:
        checks.append(check_project_root(root))

    serialized = [dataclasses.asdict(check) for check in checks]
    summary = {
        "ok": sum(1 for check in checks if check.status == "ok"),
        "warn": sum(1 for check in checks if check.status == "warn"),
        "fail": sum(1 for check in checks if check.status == "fail"),
    }
    return {
        "ok": summary["fail"] == 0,
        "summary": summary,
        "checks": serialized,
    }


def check_python_version() -> DoctorCheck:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        return DoctorCheck("Python", "ok", f"Python {version} is supported.")
    return DoctorCheck("Python", "fail", f"Python {version} is too old.", "Install Python 3.11 or newer.")


def check_state_dir() -> DoctorCheck:
    try:
        settings.DEFAULT_STATE_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=settings.DEFAULT_STATE_DIR, prefix="doctor-", delete=True):
            pass
    except OSError as exc:
        return DoctorCheck(
            "Local state",
            "fail",
            f"Cannot write Sentinel state directory: {exc}",
            f"Fix permissions or set SENTINEL_QA_STATE_DIR to a writable path.",
        )
    return DoctorCheck("Local state", "ok", f"State directory is writable: {settings.DEFAULT_STATE_DIR}")


def check_docker_daemon() -> DoctorCheck:
    if sandbox_runner.docker_available():
        return DoctorCheck("Docker", "ok", "Docker daemon is reachable.")
    return DoctorCheck(
        "Docker",
        "fail",
        "Docker daemon is not reachable.",
        "Start Docker Desktop. Sentinel fails closed instead of running untrusted repo commands on the host.",
    )


def check_scanner_image(scanner_image: str) -> DoctorCheck:
    if not sandbox_runner.docker_available():
        return DoctorCheck("Scanner image", "fail", "Scanner image cannot be checked until Docker is running.", "Start Docker Desktop, then run make scanner-image.")
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", scanner_image],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env=sandbox_runner.docker_client_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DoctorCheck("Scanner image", "fail", f"Could not inspect scanner image: {exc}", "Run make scanner-image.")
    if completed.returncode == 0:
        return DoctorCheck("Scanner image", "ok", f"Local image exists: {scanner_image}")
    return DoctorCheck("Scanner image", "fail", f"Local image is missing: {scanner_image}", "Run make scanner-image.")


def check_ai_keys() -> DoctorCheck:
    providers = []
    if os.getenv("OPENAI_API_KEY"):
        providers.append("OpenAI")
    if os.getenv("ANTHROPIC_API_KEY"):
        providers.append("Anthropic")
    if providers:
        return DoctorCheck("AI keys", "ok", f"AI review can use: {', '.join(providers)}.")
    return DoctorCheck("AI keys", "warn", "No AI provider key detected. Deterministic scans still work.", "Set OPENAI_API_KEY or ANTHROPIC_API_KEY only when you want AI review.")


def check_web_qa_tools() -> DoctorCheck:
    if shutil.which("npx") or shutil.which("playwright"):
        return DoctorCheck("Web QA", "ok", "Playwright can be launched through local tooling.")
    return DoctorCheck("Web QA", "warn", "Playwright tooling was not found on PATH.", "Install Playwright when you want browser smoke tests.")


def check_project_root(root: Path) -> DoctorCheck:
    project = root.expanduser().resolve()
    if not project.exists():
        return DoctorCheck("Project root", "fail", f"Path does not exist: {project}", "Choose an existing project folder.")
    if not project.is_dir():
        return DoctorCheck("Project root", "fail", f"Path is not a directory: {project}", "Choose a project folder, not a file.")
    profile = sentinel_qa.detect_project_profile(project)
    signals = profile["languages"] or profile["markers"]
    if signals:
        return DoctorCheck("Project root", "ok", f"Detected project signals: {', '.join(signals)}.")
    return DoctorCheck("Project root", "warn", "No common project markers were detected.", "You can still scan it, but results may be mostly generic file checks.")


def format_doctor_text(payload: dict[str, Any]) -> str:
    lines = ["Sentinel QA Doctor", ""]
    for check in payload["checks"]:
        marker = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}.get(check["status"], check["status"].upper())
        lines.append(f"[{marker}] {check['name']}: {check['detail']}")
        if check.get("recommendation"):
            lines.append(f"       Fix: {check['recommendation']}")
    summary = payload["summary"]
    lines.extend(["", f"Summary: {summary['ok']} ok, {summary['warn']} warn, {summary['fail']} fail"])
    return "\n".join(lines)
