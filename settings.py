#!/usr/bin/env python3
"""Configuration helpers for Sentinel QA Agent."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_DIR = Path(os.getenv("SENTINEL_QA_STATE_DIR", str(APP_DIR / "state"))).expanduser()
DEFAULT_CONFIG_PATH = Path(os.getenv("SENTINEL_QA_CONFIG", str(APP_DIR / "sentinel.config.json"))).expanduser()


DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8765,
    "require_token": True,
    "auth_token": "",
    "default_output_dir": "latest-report",
    "default_web_output_dir": "latest-web-qa",
    "max_workers": None,
    "scan_timeout_seconds": 90,
    "ai_review": False,
    "model": "gpt-5.4-mini",
}


def load_config(path: Path | None = None) -> dict[str, Any]:
    config_path = (path or DEFAULT_CONFIG_PATH).expanduser()
    config = dict(DEFAULT_CONFIG)
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            config.update(json.load(handle))
    apply_env_overrides(config)
    return config


def apply_env_overrides(config: dict[str, Any]) -> None:
    mapping = {
        "SENTINEL_QA_HOST": ("host", str),
        "SENTINEL_QA_PORT": ("port", int),
        "SENTINEL_QA_TOKEN": ("auth_token", str),
        "SENTINEL_QA_MODEL": ("model", str),
    }
    for env_name, (key, caster) in mapping.items():
        value = os.getenv(env_name)
        if value:
            config[key] = caster(value)
    if os.getenv("SENTINEL_QA_REQUIRE_TOKEN"):
        config["require_token"] = os.getenv("SENTINEL_QA_REQUIRE_TOKEN", "").lower() not in {"0", "false", "no"}


def ensure_config(path: Path | None = None) -> Path:
    config_path = (path or DEFAULT_CONFIG_PATH).expanduser()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists():
        return config_path
    config = dict(DEFAULT_CONFIG)
    config["auth_token"] = secrets.token_urlsafe(32)
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def state_path(*parts: str) -> Path:
    path = DEFAULT_STATE_DIR.joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
