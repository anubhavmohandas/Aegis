"""
Loads config.yaml + environment variables. API keys are never stored in the
yaml file (so you don't accidentally commit them): a real process env var
always wins if set, otherwise the encrypted local store (core/secrets_store.py)
is checked, with a legacy plaintext `.env` value as a last resort for anyone
upgrading from before that store existed.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
ENV_FILE_PATH = Path(__file__).resolve().parent.parent / ".env"


def _is_frozen() -> bool:
    # True when running from a PyInstaller bundle (packaging/aegis.spec).
    return bool(getattr(sys, "frozen", False))


def runtime_data_dir() -> Path:
    """Per-user writable directory for a PACKAGED install. Running from
    source keeps v1 behavior (log/db relative to the checkout) -- but a
    Finder-launched .app has CWD `/` and a Program Files install isn't
    user-writable, so relative runtime paths would silently fail exactly
    when a non-developer is the one running Aegis. Frozen builds anchor
    them here instead; users can also drop a `.env` or a `config.yaml`
    override in this directory (see load_config)."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Aegis"
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "Aegis"
    return Path.home() / ".local" / "share" / "aegis"


def persistent_dir() -> Path:
    """Where anything that must survive a self-update lives: self-update
    (core/updater.py) replaces a packaged app's files wholesale (`rm -rf` the
    old .app, copy in the new one), so state stored inside the app's own
    checkout/bundle path -- like the old plaintext `.env` -- was silently
    wiped on every update. This is the same per-user data dir already used
    for the event database on a packaged build, or the repo root for a
    from-source checkout (matching legacy .env/config.yaml behavior)."""
    return runtime_data_dir() if _is_frozen() else Path(__file__).resolve().parent.parent


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
    notify_enabled: bool = False            # master switch for OS desktop popups. Default OFF: the dashboard
                                            # timeline is already a live view of every event, so popups are an
                                            # opt-in interruption, not the primary way to see activity.
    notify_on_startup_scan: bool = True     # send a summary notification when the app first starts
    notify_min_severity: str = "low"        # popup floor: "low" (everything, v1 behavior) .. "critical".
                                            # Gates ONLY the desktop popup -- events below the floor are
                                            # still AI-explained, logged, and persisted to the timeline.
    log_path: str = "events.log"
    db_path: str = "aegis_events.db"        # SQLite event history for the timeline UI
    trusted_process_names: list[str] = field(default_factory=list)  # opt-in AI-call skip, see core/rule_engine.py
    trusted_process_hashes: list[str] = field(default_factory=list)  # sha256, harder to spoof than name -- see core/rule_engine.py
    trusted_usb_ids: list[str] = field(default_factory=list)        # opt-in AI-call skip, see core/rule_engine.py

    @property
    def api_key(self) -> str | None:
        # A real shell/process env var always wins (lets a developer override
        # with `NVIDIA_API_KEY=other python main.py` regardless of what's
        # stored). Otherwise fall back to the encrypted local store the
        # dashboard's Settings page writes to (see core/secrets_store.py).
        env_value = os.environ.get(self.ai_api_key_env)
        if env_value:
            return env_value
        from core.secrets_store import get_secret  # local import: keeps this module dependency-light
        return get_secret(self.ai_api_key_env)


def load_config(path: Path | None = None) -> AppConfig:
    _load_env_file()
    if _is_frozen():
        # Packaged builds: the checkout-relative .env baked into the bundle
        # doesn't exist, so also read one from the per-user data dir, and
        # prefer a user-edited config.yaml there over the bundled default
        # (editing a yaml inside an installed .app/Program Files is not a
        # reasonable ask).
        _load_env_file(runtime_data_dir() / ".env")
        user_config = runtime_data_dir() / "config.yaml"
        if path is None and user_config.exists():
            path = user_config
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
        notify_enabled=bool(raw.get("notify_enabled", False)),
        notify_on_startup_scan=bool(raw.get("notify_on_startup_scan", True)),
        notify_min_severity=_parse_min_severity(raw.get("notify_min_severity", "low")),
        log_path=raw.get("log_path", "events.log"),
        db_path=raw.get("db_path", "aegis_events.db"),
        trusted_process_names=raw.get("trusted_process_names") or [],
        trusted_process_hashes=raw.get("trusted_process_hashes") or [],
        trusted_usb_ids=raw.get("trusted_usb_ids") or [],
    )
    if not cfg.watched_folders:
        cfg = _with_default_folders(cfg)

    _anchor_runtime_paths(cfg)

    if not cfg.api_key:
        print(
            f"[config] WARNING: environment variable '{cfg.ai_api_key_env}' is not set. "
            f"The AI explainer will fall back to raw event summaries until it is.",
            file=sys.stderr,
        )
    return cfg


def _anchor_runtime_paths(cfg: AppConfig) -> None:
    """Frozen builds only: rewrite relative log/db paths to the per-user
    data dir (see runtime_data_dir). Absolute paths in config.yaml are
    always respected as-is, frozen or not."""
    if not _is_frozen():
        return
    data_dir = runtime_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    for attr in ("log_path", "db_path"):
        p = Path(getattr(cfg, attr))
        if not p.is_absolute():
            setattr(cfg, attr, str(data_dir / p))


def _parse_min_severity(value) -> str:
    """A typo'd severity floor must degrade to 'show everything', never to
    'show nothing' -- silently suppressing all popups because someone wrote
    `notify_min_severity: hgih` would look identical to a healthy, quiet
    system, which is the same failure mode ADR-002/ADR-003 exist to avoid."""
    level = str(value).strip().lower()
    if level in ("low", "medium", "high", "critical"):
        return level
    print(
        f"[config] WARNING: notify_min_severity '{value}' is not one of "
        f"low/medium/high/critical -- falling back to 'low' (notify on everything).",
        file=sys.stderr,
    )
    return "low"


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
