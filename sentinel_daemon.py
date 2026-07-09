#!/usr/bin/env python3
"""
Watch-mode runner for Sentinel QA Agent.

This keeps the agent operating independently: it fingerprints a project tree,
runs QA when relevant files change, and stores each scan in local history.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import time
from pathlib import Path

import agent_state
import qa_ai_agent
import sentinel_qa


def project_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    excludes = sentinel_qa.DEFAULT_EXCLUDES
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [name for name in dirnames if name not in excludes]
        for filename in sorted(filenames):
            path = current / filename
            if not path.is_file() or not sentinel_qa.is_text_file(path):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            digest.update(rel.encode("utf-8"))
            digest.update(str(stat.st_mtime_ns).encode("utf-8"))
            digest.update(str(stat.st_size).encode("utf-8"))
    return digest.hexdigest()


def run_once(root: Path, output_dir: Path, ai_review: bool, model: str) -> dict:
    result = sentinel_qa.run_scan(root=root, output_dir=output_dir)
    ai_path = None
    status = "completed"
    error = None
    if ai_review:
        try:
            qa_ai_agent.write_ai_review(
                output_dir,
                result["root"],
                result["projects"],
                result["findings"],
                model=model,
            )
            ai_path = output_dir / "ai_review.md"
        except Exception as exc:
            status = "completed_with_ai_error"
            error = str(exc)
            (output_dir / "ai_review_error.txt").write_text(error, encoding="utf-8")
    run_id = agent_state.record_scan(
        result,
        output_dir=output_dir,
        ai_review_md=ai_path,
        status=status,
        error=error,
    )
    return {"run_id": run_id, "result": result, "status": status, "error": error}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Sentinel QA Agent continuously.")
    parser.add_argument("root", type=Path)
    parser.add_argument("--output-root", type=Path, default=Path("sentinel-qa-runs"))
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--ai-review", action="store_true")
    parser.add_argument("--model", default=qa_ai_agent.DEFAULT_MODEL)
    parser.add_argument("--run-now", action="store_true")
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"Root does not exist: {root}")

    last_fingerprint = None
    print(f"Watching {root}", flush=True)
    while True:
        fingerprint = project_fingerprint(root)
        should_run = args.run_now or fingerprint != last_fingerprint
        if should_run:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            output_dir = (args.output_root / stamp).expanduser().resolve()
            run = run_once(root, output_dir, args.ai_review, args.model)
            print(
                f"Run {run['run_id']} {run['status']}: "
                f"{len(run['result']['findings'])} finding(s), report {run['result']['markdown_path']}",
                flush=True,
            )
            args.run_now = False
            last_fingerprint = fingerprint
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
