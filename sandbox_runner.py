#!/usr/bin/env python3
"""
Docker sandbox runner for commands that touch untrusted repository content.

The scanner itself may read files on the host, but package scripts, ecosystem
scanners, and test runners must not execute directly against a cloned repo.
"""

from __future__ import annotations

import dataclasses
import os
import selectors
import subprocess
import time
import uuid
from pathlib import Path


class SandboxError(RuntimeError):
    """Raised when a sandboxed command cannot be started safely."""


@dataclasses.dataclass(frozen=True)
class SandboxOptions:
    image: str = "sentinel-qa-scanner:latest"
    allow_network: bool = False
    cpus: float = 1.0
    memory: str = "1g"
    pids_limit: int = 256
    max_duration: int = 120
    tmpfs_size: str = "128m"
    max_output_bytes: int = 1_000_000


@dataclasses.dataclass(frozen=True)
class SandboxResult:
    returncode: int
    output: str
    timed_out: bool = False
    output_truncated: bool = False
    docker_command: tuple[str, ...] = ()


def docker_client_env() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "XDG_RUNTIME_DIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def docker_available(timeout: int = 5) -> bool:
    try:
        completed = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=docker_client_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def build_docker_command(
    repo: Path,
    command: list[str],
    options: SandboxOptions,
    output_dir: Path | None = None,
    container_name: str | None = None,
) -> list[str]:
    repo = repo.expanduser().resolve()
    if not repo.is_dir():
        raise SandboxError(f"Sandbox repo path is not a directory: {repo}")

    out = (output_dir or repo / ".sentinel-sandbox-out").expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    name = container_name or f"sentinel-qa-{uuid.uuid4().hex}"
    network_mode = "bridge" if options.allow_network else "none"

    return [
        "docker",
        "run",
        "--pull",
        "never",
        "--name",
        name,
        "--rm",
        "--network",
        network_mode,
        "--cpus",
        str(options.cpus),
        "--memory",
        options.memory,
        "--memory-swap",
        options.memory,
        "--pids-limit",
        str(options.pids_limit),
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={options.tmpfs_size}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65532:65532",
        "--workdir",
        "/workspace/repo",
        "--volume",
        f"{repo}:/workspace/repo:ro",
        "--volume",
        f"{out}:/workspace/out:rw",
        "--env",
        "HOME=/tmp",
        "--env",
        "SENTINEL_SANDBOX=1",
        options.image,
        *command,
    ]


def run_repo_command(
    repo: Path,
    command: list[str],
    options: SandboxOptions,
    output_dir: Path | None = None,
) -> SandboxResult:
    if not docker_available():
        raise SandboxError(
            "Docker sandbox is unavailable. Start Docker Desktop or rerun with "
            "--no-sandbox --confirm-no-sandbox if you explicitly accept host execution."
        )

    container_name = f"sentinel-qa-{uuid.uuid4().hex}"
    docker_command = build_docker_command(
        repo=repo,
        command=command,
        options=options,
        output_dir=output_dir,
        container_name=container_name,
    )

    process = subprocess.Popen(
        docker_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=docker_client_env(),
    )
    output, timed_out, output_truncated = collect_process_output(
        process,
        timeout=options.max_duration,
        max_output_bytes=options.max_output_bytes,
    )
    if timed_out:
        subprocess.run(
            ["docker", "kill", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=docker_client_env(),
        )
        extra, _, extra_truncated = collect_process_output(
            process,
            timeout=10,
            max_output_bytes=max(0, options.max_output_bytes - len(output.encode("utf-8", errors="replace"))),
        )
        output = join_output(output, extra)
        output_truncated = output_truncated or extra_truncated
        return SandboxResult(
            returncode=124,
            output=append_status(output, "Sandbox watchdog killed the container after max duration.", output_truncated),
            timed_out=True,
            output_truncated=output_truncated,
            docker_command=tuple(docker_command),
        )
    return SandboxResult(
        returncode=process.returncode,
        output=append_status(output, "Sandbox output truncated.", output_truncated),
        output_truncated=output_truncated,
        docker_command=tuple(docker_command),
    )


def collect_process_output(
    process: subprocess.Popen,
    *,
    timeout: int,
    max_output_bytes: int,
) -> tuple[str, bool, bool]:
    if process.stdout is None:
        try:
            process.wait(timeout=timeout)
            return "", False, False
        except subprocess.TimeoutExpired:
            return "", True, False

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    chunks: list[str] = []
    captured = 0
    truncated = False

    while True:
        if process.poll() is not None:
            remainder = process.stdout.read()
            if remainder:
                captured, truncated = capture_chunk(remainder, chunks, captured, max_output_bytes, truncated)
            break

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "".join(chunks).strip(), True, truncated

        for key, _ in selector.select(timeout=min(0.2, remaining)):
            raw = os.read(key.fileobj.fileno(), 4096)
            if not raw:
                continue
            chunk = raw.decode("utf-8", errors="replace")
            captured, truncated = capture_chunk(chunk, chunks, captured, max_output_bytes, truncated)

    return "".join(chunks).strip(), False, truncated


def capture_chunk(
    chunk: str,
    chunks: list[str],
    captured: int,
    max_output_bytes: int,
    truncated: bool,
) -> tuple[int, bool]:
    if max_output_bytes <= 0:
        return captured, True
    encoded = chunk.encode("utf-8", errors="replace")
    remaining = max_output_bytes - captured
    if remaining <= 0:
        return captured, True
    if len(encoded) <= remaining:
        chunks.append(chunk)
        return captured + len(encoded), truncated
    chunks.append(encoded[:remaining].decode("utf-8", errors="replace"))
    return max_output_bytes, True


def join_output(first: str, second: str) -> str:
    if first and second:
        return f"{first}\n{second}"
    return first or second


def append_status(output: str, status: str, enabled: bool) -> str:
    if not enabled:
        return (output or "").strip()
    return join_output((output or "").strip(), status).strip()
