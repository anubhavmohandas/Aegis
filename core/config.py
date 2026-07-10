"""
Loads config.yaml + environment variables. API keys are read from env vars
ONLY (never stored in the yaml file) so you don't accidentally commit them.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


@dataclass
class AppConfig:
    ai_provider: str = "anthropic"          # "anthropic" | "openai"
    ai_model: str = "claude-sonnet-5"       # override in config.yaml as needed
    watched_folders: list[str] = field(default_factory=list)
    poll_interval_seconds: int = 3          # used by every polling-based monitor (USB/startup/process fallback)
    notify_on_startup_scan: bool = True     # send a summary notification when the app first starts
    log_path: str = "events.log"
    db_path: str = "aegis_events.db"        # SQLite event history for the timeline UI
    trusted_process_names: list[str] = field(default_factory=list)  # opt-in AI-call skip, see core/rule_engine.py
    trusted_process_hashes: list[str] = field(default_factory=list)  # sha256, harder to spoof than name -- see core/rule_engine.py
    trusted_usb_ids: list[str] = field(default_factory=list)        # opt-in AI-call skip, see core/rule_engine.py

    @property
    def api_key(self) -> str | None:
        if self.ai_provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY")
        if self.ai_provider == "openai":
            return os.environ.get("OPENAI_API_KEY")
        return None


def load_config(path: Path | None = None) -> AppConfig:
    path = path or DEFAULT_CONFIG_PATH
    if not path.exists():
        print(f"[config] no config.yaml found at {path}, using defaults", file=sys.stderr)
        return _with_default_folders(AppConfig())

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    cfg = AppConfig(
        ai_provider=raw.get("ai_provider", "anthropic"),
        ai_model=raw.get("ai_model", "claude-sonnet-5"),
        watched_folders=raw.get("watched_folders") or [],
        poll_interval_seconds=int(raw.get("poll_interval_seconds", 3)),
        notify_on_startup_scan=bool(raw.get("notify_on_startup_scan", True)),
        log_path=raw.get("log_path", "events.log"),
        db_path=raw.get("db_path", "aegis_events.db"),
        trusted_process_names=raw.get("trusted_process_names") or [],
        trusted_process_hashes=raw.get("trusted_process_hashes") or [],
        trusted_usb_ids=raw.get("trusted_usb_ids") or [],
    )
    if not cfg.watched_folders:
        cfg = _with_default_folders(cfg)

    if not cfg.api_key:
        print(
            f"[config] WARNING: no API key found in environment for provider '{cfg.ai_provider}'. "
            f"Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or the AI explainer will fail on first event.",
            file=sys.stderr,
        )
    return cfg


def _with_default_folders(cfg: AppConfig) -> AppConfig:
    home = Path.home()
    for name in ("Desktop", "Downloads", "Documents"):
        candidate = home / name
        if candidate.exists():
            cfg.watched_folders.append(str(candidate))
    if not cfg.watched_folders:
        # None of the three default folders exist under this home directory
        # (unusual account setup, containerized environment, etc). Silently
        # running with zero folder coverage looks identical to "everything's
        # fine, nothing's happened" -- say so explicitly instead.
        print(
            "[config] WARNING: no watched_folders configured and none of "
            "Desktop/Downloads/Documents exist under your home folder -- "
            "folder monitoring is effectively disabled. Set watched_folders "
            "explicitly in config.yaml if this isn't intentional.",
            file=sys.stderr,
        )
    return cfg
