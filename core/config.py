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
ENV_FILE_PATH = Path(__file__).resolve().parent.parent / ".env"


def _load_env_file(path: Path = ENV_FILE_PATH) -> None:
    """Minimal .env loader (KEY=VALUE lines, # comments). Deliberately
    dependency-free -- python-dotenv would be a whole package for these ten
    lines. Variables already set in the real shell environment always win;
    the file only fills gaps, so `NVIDIA_API_KEY=other venv/bin/python main.py`
    still behaves the way anyone would expect."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


@dataclass
class AppConfig:
    # AI layer: any OpenAI-compatible endpoint works (NVIDIA, OpenAI, OpenRouter,
    # Ollama, ...) -- only base_url/model/api_key_env change, never code. Anthropic
    # keeps its own provider value because its API is not OpenAI-shaped.
    ai_provider: str = "openai-compatible"  # "openai-compatible" | "anthropic"
    ai_base_url: str = "https://integrate.api.nvidia.com/v1"  # ignored for anthropic
    ai_api_key_env: str = "NVIDIA_API_KEY"  # NAME of the env var holding the key, never the key itself
    ai_model: str = "nvidia/nemotron-3-ultra-550b-a55b"
    ai_temperature: float = 0.2             # low on purpose: consistent, boring explanations
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
        return os.environ.get(self.ai_api_key_env)


def load_config(path: Path | None = None) -> AppConfig:
    _load_env_file()
    path = path or DEFAULT_CONFIG_PATH
    if not path.exists():
        print(f"[config] no config.yaml found at {path}, using defaults", file=sys.stderr)
        return _with_default_folders(AppConfig())

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    ai = _parse_ai_block(raw)
    cfg = AppConfig(
        ai_provider=ai["provider"],
        ai_base_url=ai["base_url"],
        ai_api_key_env=ai["api_key_env"],
        ai_model=ai["model"],
        ai_temperature=ai["temperature"],
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
            f"[config] WARNING: environment variable '{cfg.ai_api_key_env}' is not set. "
            f"The AI explainer will fall back to raw event summaries until it is.",
            file=sys.stderr,
        )
    return cfg


def _parse_ai_block(raw: dict) -> dict:
    """Resolve the `ai:` config block, falling back to the pre-v0.3 flat
    `ai_provider`/`ai_model` keys so old config files keep working."""
    defaults = AppConfig()
    ai_raw = raw.get("ai")
    if not isinstance(ai_raw, dict):
        # Legacy flat keys. "openai" was OpenAI's own endpoint; it's just the
        # first openai-compatible provider, so map it rather than special-case it.
        legacy_provider = raw.get("ai_provider")
        if legacy_provider == "anthropic":
            ai_raw = {
                "provider": "anthropic",
                "api_key_env": "ANTHROPIC_API_KEY",
                "model": raw.get("ai_model", "claude-sonnet-5"),
            }
        elif legacy_provider == "openai":
            ai_raw = {
                "provider": "openai-compatible",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "OPENAI_API_KEY",
                "model": raw.get("ai_model", "gpt-4.1-mini"),
            }
        else:
            ai_raw = {}

    provider = ai_raw.get("provider", defaults.ai_provider)
    return {
        "provider": provider,
        "base_url": ai_raw.get("base_url", defaults.ai_base_url),
        "api_key_env": ai_raw.get(
            "api_key_env",
            "ANTHROPIC_API_KEY" if provider == "anthropic" else defaults.ai_api_key_env,
        ),
        "model": ai_raw.get("model", defaults.ai_model),
        "temperature": float(ai_raw.get("temperature", defaults.ai_temperature)),
    }


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
