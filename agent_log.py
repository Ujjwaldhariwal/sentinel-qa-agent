#!/usr/bin/env python3
"""Structured JSONL logging for Sentinel QA Agent."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import settings


DEFAULT_LOG = settings.state_path("logs", "agent.jsonl")


def log_event(event: str, **fields: Any) -> None:
    payload = {
        "ts": time.time(),
        "event": event,
        **fields,
    }
    path = DEFAULT_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, default=str) + "\n")


def tail_events(limit: int = 100, path: Path = DEFAULT_LOG) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
