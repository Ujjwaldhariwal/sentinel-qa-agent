#!/usr/bin/env python3
"""Project policy support for Sentinel QA Agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


POLICY_FILENAMES = ("sentinel.policy.json", ".sentinel-qa.json")


DEFAULT_POLICY: dict[str, Any] = {
    "scan": {
        "exclude_dirs": [],
        "exclude_globs": [],
        "timeout_seconds": None,
        "workers": None
    },
    "ai": {
        "enabled": None,
        "model": None
    },
    "web": {
        "base_url": None,
        "routes": [],
        "discover_routes": False,
        "clicks": [],
        "viewport": "desktop"
    },
    "quality_gate": {
        "fail_on": ["critical", "high"]
    }
}


def find_policy(root: Path) -> Path | None:
    root = root.expanduser().resolve()
    for name in POLICY_FILENAMES:
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def load_policy(root: Path | None = None, path: Path | None = None) -> dict[str, Any]:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy_path = path.expanduser().resolve() if path else find_policy(root) if root else None
    if not policy_path:
        return policy
    with policy_path.open("r", encoding="utf-8") as handle:
        merge(policy, json.load(handle))
    policy["_path"] = str(policy_path)
    return policy


def merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge(base[key], value)
        else:
            base[key] = value
    return base
