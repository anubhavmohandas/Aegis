"""
Aegis dashboard -- local web UI over the SQLite event store.

Read-only by construction: the SQLite file is opened with mode=ro, so this
process can never write to the event store the monitors are appending to.
Runs completely separately from main.py (same philosophy as ui/timeline_app.py:
a UI bug must never take down monitoring), and binds to 127.0.0.1 only --
this is a personal dashboard, not a network service.

Zero dependencies beyond the stdlib, so it works inside the PyInstaller
bundle and on a bare python install alike.

Access requires signing in -- admin/admin on first run, changeable from the
Settings page (see change_password() below); sessions are HttpOnly cookies
that expire after 12h or on restart. Failed sign-ins escalate exactly like a
failed Stop Monitoring attempt (logged, evidence captured, lockout).

The Settings page needs that password a SECOND time (see unlock_settings): it
can switch tamper protection off entirely, so leaving it behind nothing but a
live session would have made every other gate in the app decorative.

Run with:
    python dashboard/server.py [--db aegis_events.db] [--port 8787]

then open http://127.0.0.1:8787
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import psutil  # already a core Aegis dependency (requirements-common.txt)

STATIC_DIR = Path(__file__).parent / "static"
REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))  # lets the report endpoint lazily `import core.*` -- see _handle_report_pdf
from core.config import persistent_dir, _is_frozen  # noqa: E402 -- needs REPO_ROOT on sys.path first
from core.secrets_store import get_secret, set_secret  # noqa: E402

ASSETS_DIR = REPO_ROOT / "assets"                       # brand logo lives with the app assets
logger_srv = logging.getLogger("aegis.dashboard")

# DATA_DIR is the per-user data dir (see core/config.persistent_dir) for a
# packaged build, or the repo root for a from-source checkout. Everything
# below MUST live there rather than under REPO_ROOT for a frozen build:
# self-update (core/updater.py) does `rm -rf` on the whole old .app bundle
# and copies in a fresh one, so anything written under the bundle's own path
# -- which is what a hardcoded REPO_ROOT-relative path resolves to once
# frozen -- was silently deleted on every update. This was a real, confirmed
# bug: users had to re-enter their AI provider API key after every update
# because it was being written to `.env` next to the (about-to-be-replaced)
# app code instead of here.
DATA_DIR = persistent_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA_DIR / "config.yaml" if _is_frozen() else DATA_DIR / "config" / "config.yaml"
ENV_PATH = DATA_DIR / ".env"             # legacy plaintext key location -- read-only, for migration
MAIN_PY = REPO_ROOT / "main.py"
MONITOR_STATE_FILE = DATA_DIR / ".aegis_monitor.json"  # {"pid": int, "started_at": float}
MONITOR_LOG_PATH = DATA_DIR / "monitor.log" if _is_frozen() else DATA_DIR / "dashboard" / "monitor.log"

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",   # self-hosted webfonts -- see the header of static/style.css
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_SOURCES = {"process", "usb", "startup", "folder", "session", "tamper"}

# --- auth -------------------------------------------------------------------
# A single operator account (this is a localhost-only, one-user console, not
# a multi-tenant service), in-memory sessions (restart logs everyone out),
# HttpOnly SameSite cookie. Credentials are salted+hashed (PBKDF2-HMAC-SHA256)
# and persisted in DATA_DIR/credentials.json -- changeable from the Settings
# page (see change_password() below) instead of the old hardcoded admin/admin.
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"      # only ever used to seed credentials.json on first run
CREDENTIALS_PATH = DATA_DIR / "credentials.json"
PBKDF2_ITERATIONS = 200_000
SESSION_COOKIE = "aegis_session"
SESSION_TTL = 12 * 3600
_sessions: dict[str, float] = {}  # token -> expiry (unix seconds)


def _prune_expired(d: dict) -> None:
    """Drop expired entries from a token -> expiry map.

    Both maps are otherwise only pruned when a token is looked up again, so a
    session that was never reused -- signed in, tab closed, never returned --
    left its entry behind for the life of the process. Called when a new token
    is added, which is the only moment either map grows."""
    now = time.time()
    for token in [t for t, expiry in d.items() if expiry <= now]:
        d.pop(token, None)


def _hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()


def _new_credentials(username: str, password: str, is_default: bool = False) -> dict:
    salt = secrets.token_bytes(16)
    return {
        "username": username,
        "salt": salt.hex(),
        # iterations passed explicitly, not left to _hash_password's default:
        # the default binds at import time, so the recorded count and the count
        # actually used could disagree if PBKDF2_ITERATIONS is ever rebound.
        "hash": _hash_password(password, salt, PBKDF2_ITERATIONS),
        "iterations": PBKDF2_ITERATIONS,
        # Recorded once, at write time, rather than re-derived by verifying
        # the default password on every call -- that's 200k PBKDF2 rounds,
        # and _using_default_credentials() is read on every /api/stats poll.
        "is_default": is_default,
    }


def _load_credentials() -> dict:
    if CREDENTIALS_PATH.is_file():
        try:
            creds = json.loads(CREDENTIALS_PATH.read_text(encoding="utf-8"))
            if {"username", "salt", "hash"} <= creds.keys():
                if "is_default" not in creds:
                    # Credentials file written before the flag existed: resolve
                    # it once (this IS the expensive path) and persist, so the
                    # "you're still on admin/admin" warning is honest for
                    # installs that predate it too.
                    creds["is_default"] = (
                        creds["username"] == DEFAULT_USERNAME
                        and hmac.compare_digest(
                            _hash_password(DEFAULT_PASSWORD, bytes.fromhex(creds["salt"]),
                                           creds.get("iterations", PBKDF2_ITERATIONS)),
                            creds["hash"]))
                    _save_credentials(creds)
                return creds
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    creds = _new_credentials(DEFAULT_USERNAME, DEFAULT_PASSWORD, is_default=True)
    _save_credentials(creds)
    return creds


def _using_default_credentials() -> bool:
    """True while the seeded admin/admin login is still in place. Worth a loud
    banner rather than a footnote: this same password is what the tamper gate
    checks for Stop Monitoring, Quit, and Settings, so an unchanged default
    means every one of those gates is open to anyone who read the README."""
    return bool(_load_credentials().get("is_default"))


def _save_credentials(creds: dict) -> None:
    CREDENTIALS_PATH.write_text(json.dumps(creds), encoding="utf-8")
    try:
        os.chmod(CREDENTIALS_PATH, 0o600)  # no-op-ish on Windows, real on POSIX
    except OSError:
        pass


def _verify_password(username: str, password: str) -> bool:
    creds = _load_credentials()
    salt = bytes.fromhex(creds["salt"])
    candidate = _hash_password(password, salt, creds.get("iterations", PBKDF2_ITERATIONS))
    # Both comparisons always evaluate (single &, not `and`) so a wrong
    # username can't short-circuit before the password hash is even computed
    # -- avoids a timing side-channel that would let an attacker enumerate
    # valid usernames faster than valid passwords.
    # The username is compared as UTF-8 bytes: hmac.compare_digest raises
    # TypeError on a str containing non-ASCII characters, and `username` comes
    # straight from the login form -- a submitted non-ASCII username would
    # otherwise surface as an unhandled HTTP 500 instead of a clean "invalid
    # credentials". candidate/hash are hex digests (always ASCII), so they
    # stay as str.
    return (hmac.compare_digest(username.encode("utf-8"), creds["username"].encode("utf-8"))
            & hmac.compare_digest(candidate, creds["hash"]))


def change_password(current_password: str, new_password: str) -> dict:
    """Throttled like every other password prompt (see _throttle_failed_password).

    This endpoint checks the SAME password that guards Stop Monitoring, Quit and
    Settings, and it used to answer "is this the password?" as fast as the
    request could be made -- no delay, no lockout, no timeline entry. A live
    session could brute-force it silently at ~36 guesses/second while the
    Settings unlock next door locked out after 5. Same secret, same escalation.

    The current-password check is NOT routed through guard_protected_action: that
    returns "allowed" outright when tamper_require_password is off, which would
    let anyone with a session set a new password without knowing the old one."""
    if len(new_password) < 8:
        return {"error": "new password must be at least 8 characters"}
    locked = _lockout_check("change_password")
    if locked:
        return locked
    creds = _load_credentials()
    if not _verify_password(creds["username"], current_password):
        return {**_throttle_failed_password("change_password"),
                "error": "current password is incorrect"}
    _tamper_state.pop("change_password", None)   # clean slate on success
    _save_credentials(_new_credentials(creds["username"], new_password))
    return {"ok": True}

# Static files that must be reachable without a session: the login page and
# the stylesheet it uses. Everything else (index, app.js, the API) is gated.
# The `fonts/` prefix is public for the same reason style.css is -- the login
# page references those woff2 files, and gating them would just redirect the
# font requests to /login and render the sign-in screen in fallback type.
PUBLIC_FILES = {"login.html", "style.css", "favicon.png"}
PUBLIC_PREFIXES = ("assets/", "fonts/")

# Columns exposed to the UI -- everything in the events table. details_json is
# passed through as-is; the frontend parses it (it already carries its own
# _schema version tag, see core/database.py).
EVENT_COLUMNS = ("id", "timestamp", "source", "category", "summary", "details_json",
                 "confidence", "severity", "explanation", "risk_hint", "ai_skipped")


def _connect_ro(db_path: str) -> sqlite3.Connection:
    # One short-lived read-only connection per request. This dashboard serves
    # one user on localhost; connection reuse isn't worth sharing state across
    # ThreadingHTTPServer threads.
    conn = sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _build_event_query(params: dict) -> tuple[str, list]:
    """Translate query-string filters into a WHERE clause. Everything is a
    bound parameter -- no filter value is ever interpolated into SQL."""
    where, args = [], []

    severities = [s for s in params.get("severity", [""])[0].split(",") if s in VALID_SEVERITIES]
    if severities:
        where.append(f"severity IN ({','.join('?' * len(severities))})")
        args.extend(severities)

    sources = [s for s in params.get("source", [""])[0].split(",") if s in VALID_SOURCES]
    if sources:
        where.append(f"source IN ({','.join('?' * len(sources))})")
        args.extend(sources)

    category = params.get("category", [""])[0]
    if category:
        where.append("category = ?")
        args.append(category)

    q = params.get("q", [""])[0].strip()
    if q:
        where.append("(summary LIKE ? OR explanation LIKE ? OR details_json LIKE ?)")
        like = f"%{q}%"
        args.extend([like, like, like])

    # Events the user themselves opted out of seeing via a Trust List entry,
    # plus SIP-protected Apple platform binaries (core/rule_engine.py sets
    # risk_hint to one of these four exact strings), are still fully
    # persisted -- this only affects what THIS query returns, never what's in
    # the DB. Distinct from rate_limited/duplicate_suppressed, which stay
    # visible by default: those reflect unusual burst activity worth seeing,
    # not routine noise already vetted by the user or by SIP (e.g.
    # mdworker_shared launching every second during Spotlight indexing, which
    # otherwise buries everything else in the timeline).
    # IS NULL half is load-bearing: normal AI-explained events persist with
    # risk_hint NULL, and `NULL NOT IN (...)` is NULL (falsy) in SQL -- without
    # it, this filter silently hid every ordinary event, not just trusted ones.
    if params.get("hide_trusted", [""])[0] == "1":
        where.append("(risk_hint IS NULL OR risk_hint NOT IN ('user_trusted_process', "
                     "'user_trusted_process_hash', 'user_trusted_usb', 'os_platform_binary'))")

    for key, op in (("since", ">="), ("until", "<=")):
        raw = params.get(key, [""])[0]
        if raw:
            try:
                args.append(float(raw))
                where.append(f"timestamp {op} ?")
            except ValueError:
                pass

    # after_id: incremental live fetch -- "give me only what's new since my
    # last poll". before_id: older-page fetch for infinite scroll.
    for key, op in (("after_id", ">"), ("before_id", "<")):
        raw = params.get(key, [""])[0]
        if raw.isdigit():
            where.append(f"id {op} ?")
            args.append(int(raw))

    clause = f" WHERE {' AND '.join(where)}" if where else ""
    return clause, args


def query_events(db_path: str, params: dict, limit_cap: int = 1000) -> list[dict]:
    try:
        limit = min(max(int(params.get("limit", ["200"])[0]), 1), limit_cap)
    except ValueError:
        limit = 200
    clause, args = _build_event_query(params)
    conn = _connect_ro(db_path)
    try:
        rows = conn.execute(
            f"SELECT {', '.join(EVENT_COLUMNS)} FROM events{clause} "
            f"ORDER BY timestamp DESC, id DESC LIMIT ?",
            (*args, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# Everything that happened within this many seconds either side of an event
# is "related" for the drawer's investigation view. Pure time proximity, no
# correlation heuristics -- the point is to show the story around an event
# (USB inserted -> shell -> archiver -> upload) and let the human read it.
RELATED_WINDOW_SECONDS = 300
RELATED_LIMIT = 50


def query_related(db_path: str, event_id: int) -> dict:
    conn = _connect_ro(db_path)
    try:
        anchor = conn.execute(
            f"SELECT {', '.join(EVENT_COLUMNS)} FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        if anchor is None:
            return {"error": "event not found"}
        ts = anchor["timestamp"]
        rows = conn.execute(
            f"SELECT {', '.join(EVENT_COLUMNS)} FROM events "
            "WHERE id != ? AND timestamp BETWEEN ? AND ? "
            "ORDER BY timestamp, id LIMIT ?",  # chronological: reads as a story
            (event_id, ts - RELATED_WINDOW_SECONDS, ts + RELATED_WINDOW_SECONDS, RELATED_LIMIT),
        ).fetchall()
        return {"anchor_id": event_id, "anchor_timestamp": ts,
                "window_seconds": RELATED_WINDOW_SECONDS, "events": [dict(r) for r in rows]}
    finally:
        conn.close()


def query_stats(db_path: str) -> dict:
    day_ago = time.time() - 86400
    conn = _connect_ro(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        last_24h = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (day_ago,)).fetchone()[0]
        by_severity = dict(conn.execute(
            "SELECT severity, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY severity", (day_ago,)
        ).fetchall())
        by_source = dict(conn.execute(
            "SELECT source, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY source", (day_ago,)
        ).fetchall())
        categories = [r[0] for r in conn.execute(
            "SELECT DISTINCT category FROM events ORDER BY category").fetchall()]
        latest = conn.execute(
            "SELECT id, timestamp, summary, severity FROM events ORDER BY timestamp DESC, id DESC LIMIT 1"
        ).fetchone()
        return {
            "total": total,
            "last_24h": last_24h,
            "by_severity": by_severity,
            "by_source": by_source,
            "categories": categories,
            "latest": dict(latest) if latest else None,
            "server_time": time.time(),
            "default_credentials": _using_default_credentials(),
        }
    finally:
        conn.close()


# --- daily intelligence brief ------------------------------------------------
# "Good morning -- here's what your computer did." A once-a-day narrative over
# the last 24h: the counts a human actually cares about (USB, installs,
# startup changes, away sessions, tamper attempts) plus an AI overview reusing
# the same period-summary path as the PDF report. Computed on demand, not
# scheduled -- the frontend fetches it; there's no background job to babysit.

def daily_brief(db_path: str) -> dict:
    now = time.time()
    since = now - 86400
    events = query_events(db_path, {"since": [str(since)], "limit": ["100000"]}, limit_cap=100000)
    cat = lambda c: sum(1 for e in events if e["category"] == c)
    counts = {
        "total": len(events),
        "processes": sum(1 for e in events if e["source"] == "process"),
        "usb_connected": cat("usb_connected"),
        "startup_added": cat("startup_item_added"),
        "high_critical": sum(1 for e in events if e["severity"] in ("high", "critical")),
        "away_sessions": cat("session_unlocked"),
        "tamper_attempts": cat("tamper_attempt"),
        "monitoring_gaps": cat("monitoring_gap"),
    }
    top = sorted((e for e in events if e["severity"] in ("high", "critical")),
                 key=lambda e: -e["timestamp"])[:10]
    top_events = [{"id": e["id"], "timestamp": e["timestamp"],
                   "summary": e["summary"], "severity": e["severity"]} for e in top]

    top_lines = [f"- [{e['severity']}] {time.strftime('%H:%M', time.localtime(e['timestamp']))} {e['summary']}"
                 for e in top] or ["- (none)"]
    block = "\n".join([
        "Report period: last 24 hours",
        f"Total events: {counts['total']}",
        f"By severity: high/critical={counts['high_critical']}",
        f"Processes started: {counts['processes']}",
        f"USB devices connected: {counts['usb_connected']}",
        f"New startup items: {counts['startup_added']}",
        f"Away sessions (screen locked then unlocked): {counts['away_sessions']}",
        f"Failed tamper attempts: {counts['tamper_attempts']}",
        f"Monitoring gaps: {counts['monitoring_gaps']}",
        "",
        "Highest-severity events:",
        *top_lines,
    ])
    try:
        from core.ai_explainer import AIExplainer
        from core.config import load_config
        summary = AIExplainer(load_config()).summarize_period(block)
    except Exception as e:
        logger_srv.error("Daily brief AI summary failed: %s", e)
        summary = "[AI summary unavailable] See the counts and highlighted events."
    return {"since": since, "until": now, "counts": counts,
            "top_events": top_events, "summary": summary}


# --- settings ----------------------------------------------------------------
# The dashboard edits the SAME config.yaml/.env that core/config.py loads, so
# the monitors and the UI can never disagree about where settings live. PyYAML
# is already a core Aegis dependency (core/config.py), so importing it here
# doesn't add anything new to the install.

SETTINGS_HEADER = (
    "# Aegis configuration -- managed by the dashboard settings page.\n"
    "# (Your original hand-written file was preserved once as config.yaml.orig.)\n"
    "# API keys are NOT stored here: ai.api_key_env names the provider's env var,\n"
    "# and the key itself lives encrypted at rest (see core/secrets_store.py).\n"
)

VALID_PROVIDERS = {"openai-compatible", "anthropic"}


def _lenient_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _lenient_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _lenient_str_list(value) -> list[str]:
    # Same failure shape core/config.py's _parse_str_list guards against: a
    # YAML scalar (`watched_folders: ~/Desktop`) parses as a plain string, and
    # returning that to the frontend breaks the whole Settings page (app.js
    # calls .join() on it). Anything non-list degrades to [].
    return [str(v) for v in value] if isinstance(value, list) else []


def read_settings() -> dict:
    # Lenient parsing throughout: this config file can be hand-edited (the
    # from-source flow documents exactly that), and a typo like
    # `poll_interval_seconds: "3s"` used to raise out of this function and
    # 500 the settings API -- the Settings page just said "Could not load
    # settings" until the yaml was fixed blind. core/config.py already
    # degrades these same fields to defaults with a warning; mirror that here
    # so the UI stays usable and shows what the monitors would actually use.
    import yaml
    raw = {}
    if CONFIG_PATH.is_file():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except yaml.YAMLError:
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
    ai = raw.get("ai")
    if not isinstance(ai, dict):
        ai = {}
    api_key_env = str(ai.get("api_key_env", "NVIDIA_API_KEY"))
    key = _resolve_api_key(api_key_env)
    return {
        "ai": {
            "provider": str(ai.get("provider", "openai-compatible")),
            "base_url": str(ai.get("base_url", "https://integrate.api.nvidia.com/v1")),
            "api_key_env": api_key_env,
            "model": str(ai.get("model", "nvidia/nemotron-3-ultra-550b-a55b")),
            "temperature": _lenient_float(ai.get("temperature", 0.2), 0.2),
            # the key itself never leaves the server -- only whether one exists
            "api_key_set": bool(key),
            "api_key_hint": f"····{key[-4:]}" if key and len(key) >= 8 else ("set" if key else ""),
        },
        "watched_folders": _lenient_str_list(raw.get("watched_folders")),
        "poll_interval_seconds": _lenient_int(raw.get("poll_interval_seconds", 3), 3),
        "notify_enabled": bool(raw.get("notify_enabled", False)),
        "notify_on_startup_scan": bool(raw.get("notify_on_startup_scan", True)),
        "notify_min_severity": str(raw.get("notify_min_severity", "low")),
        "trusted_process_names": _lenient_str_list(raw.get("trusted_process_names")),
        "trusted_process_hashes": _lenient_str_list(raw.get("trusted_process_hashes")),
        "trusted_usb_ids": _lenient_str_list(raw.get("trusted_usb_ids")),
        "enrich_enabled": bool(raw.get("enrich_enabled", False)),
        "vt_api_key_set": bool(_resolve_api_key("VT_API_KEY")),
        "tamper_require_password": bool(raw.get("tamper_require_password", True)),
        "tamper_attempts_before_capture": _lenient_int(raw.get("tamper_attempts_before_capture", 3), 3),
        "tamper_evidence_screenshot": bool(raw.get("tamper_evidence_screenshot", True)),
        "tamper_evidence_webcam": bool(raw.get("tamper_evidence_webcam", False)),
        "evidence_dir": str(raw.get("evidence_dir", "") or ""),
        "evidence_dir_default": _default_evidence_dir(),
        "config_path": str(CONFIG_PATH),
    }


def _default_evidence_dir() -> str:
    from core.evidence import incidents_dir
    return str(incidents_dir())


def _read_env_value(name: str) -> str | None:
    """Legacy plaintext lookup only -- kept so a key set before the encrypted
    store existed still gets picked up once (see _resolve_api_key), never
    written to again."""
    if not ENV_PATH.is_file():
        return None
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == name:
            return value.strip().strip("'\"")
    return None


def _resolve_api_key(name: str) -> str | None:
    """The encrypted store (core/secrets_store.py) is the source of truth
    going forward. A legacy plaintext `.env` value -- from before that store
    existed -- is read once and migrated in, so nobody has to re-type a key
    that already worked."""
    value = get_secret(name)
    if value:
        return value
    legacy = _read_env_value(name)
    if legacy:
        set_secret(name, legacy)
    return legacy


def _clean_str_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if str(v).strip()]


def write_settings(body: dict) -> dict:
    """Validate + persist. Returns {} on success, {'error': ...} otherwise."""
    import yaml
    ai = body.get("ai") or {}
    provider = str(ai.get("provider", "openai-compatible"))
    if provider not in VALID_PROVIDERS:
        return {"error": f"unknown provider '{provider}'"}
    api_key_env = str(ai.get("api_key_env", "")).strip()
    if not api_key_env.replace("_", "").isalnum():
        return {"error": "api_key_env must be an environment-variable name"}
    severity = str(body.get("notify_min_severity", "low")).lower()
    if severity not in VALID_SEVERITIES:
        return {"error": f"invalid severity floor '{severity}'"}
    try:
        temperature = max(0.0, min(1.0, float(ai.get("temperature", 0.2))))
        poll = max(1, min(3600, int(body.get("poll_interval_seconds", 3))))
    except (TypeError, ValueError):
        return {"error": "temperature/poll interval must be numbers"}

    config = {
        "ai": {
            "provider": provider,
            "base_url": str(ai.get("base_url", "")).strip(),
            "api_key_env": api_key_env,
            "model": str(ai.get("model", "")).strip(),
            "temperature": temperature,
        },
        "watched_folders": _clean_str_list(body.get("watched_folders")),
        "poll_interval_seconds": poll,
        "notify_enabled": bool(body.get("notify_enabled", False)),
        "notify_on_startup_scan": bool(body.get("notify_on_startup_scan", True)),
        "notify_min_severity": severity,
        # runtime paths aren't editable from the UI on purpose -- pass through
        "log_path": str(_passthrough("log_path", "events.log")),
        "db_path": str(_passthrough("db_path", "aegis_events.db")),
        "trusted_process_names": _clean_str_list(body.get("trusted_process_names")),
        "trusted_process_hashes": _clean_str_list(body.get("trusted_process_hashes")),
        "trusted_usb_ids": _clean_str_list(body.get("trusted_usb_ids")),
        # VirusTotal threat enrichment (core/enrichment.py) -- now UI-managed.
        "enrich_enabled": bool(body.get("enrich_enabled", _passthrough("enrich_enabled", False))),
        # Severity floor for enrichment. No UI field yet, so this is pure
        # passthrough -- without it, saving Settings would silently reset a
        # hand-tuned "high" back to the default and quietly multiply VT usage.
        "enrich_min_severity": str(_passthrough("enrich_min_severity", "medium")),
        # Tamper protection (core/evidence.py).
        "tamper_require_password": bool(body.get("tamper_require_password",
                                                 _passthrough("tamper_require_password", True))),
        "tamper_attempts_before_capture": max(1, _lenient_int(
            body.get("tamper_attempts_before_capture",
                     _passthrough("tamper_attempts_before_capture", 3)), 3)),
        "tamper_evidence_screenshot": bool(body.get("tamper_evidence_screenshot",
                                                    _passthrough("tamper_evidence_screenshot", True))),
        "tamper_evidence_webcam": bool(body.get("tamper_evidence_webcam",
                                                _passthrough("tamper_evidence_webcam", False))),
    }

    # Custom evidence folder: must be absolute (a relative path would silently
    # anchor somewhere different frozen vs from-source) and provably writable
    # NOW -- an evidence capture is the worst moment to discover it isn't.
    evidence_dir = str(body.get("evidence_dir", _passthrough("evidence_dir", "")) or "").strip()
    if evidence_dir:
        p = Path(evidence_dir).expanduser()
        if not p.is_absolute():
            example = r"C:\Users\you\Documents\AegisEvidence" if os.name == "nt" else "/Users/you/Documents/AegisEvidence"
            return {"error": f"Evidence folder must be an absolute path (e.g. {example})"}
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".aegis_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as e:
            return {"error": f"Evidence folder is not writable: {e}"}
        evidence_dir = str(p)
    config["evidence_dir"] = evidence_dir

    # one-time backup of the original hand-written config before the first
    # dashboard-managed rewrite (yaml.safe_dump drops comments)
    backup = CONFIG_PATH.with_suffix(".yaml.orig")
    if CONFIG_PATH.is_file() and not backup.exists():
        backup.write_bytes(CONFIG_PATH.read_bytes())

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(SETTINGS_HEADER)
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

    api_key = str(ai.get("api_key", ""))
    if api_key:  # blank means "keep whatever is already there"
        set_secret(api_key_env, api_key)
    vt_key = str(body.get("vt_api_key", ""))
    if vt_key:  # same blank-means-keep contract; fixed env var name (one VirusTotal)
        set_secret("VT_API_KEY", vt_key)
    return {}


def _passthrough(key: str, default):
    """Keep yaml keys the settings UI doesn't manage (log/db paths,
    enrich_enabled, tamper_*) intact across a dashboard-driven rewrite.
    Returns the existing value from config.yaml if present, else `default`."""
    import yaml
    if CONFIG_PATH.is_file():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except yaml.YAMLError:
            raw = {}
        if isinstance(raw, dict) and key in raw and raw[key] is not None:
            return raw[key]
    return default


# --- monitor process control --------------------------------------------------
# The dashboard is a read-only viewer over the event store; main.py is the
# actual thing that watches the system and produces events. These two are
# separate processes by design (a UI bug must never take down monitoring --
# see the module docstring), so "start/stop monitoring" here means spawning
# and signalling that separate process, never importing/running its code
# in-thread. State survives dashboard restarts via a small pidfile-style
# state file instead of an in-memory handle.

def _read_monitor_state() -> dict | None:
    if not MONITOR_STATE_FILE.is_file():
        return None
    try:
        return json.loads(MONITOR_STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _process_alive(pid: int) -> bool:
    try:
        return psutil.pid_exists(pid) and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.Error:
        return False


def _find_external_monitor_pid() -> int | None:
    """Detect a main.py started outside the dashboard (e.g. `python main.py`
    from a terminal, the way README.md itself says to run it), so the status
    shown is honest even when the dashboard didn't launch it -- and so Start
    doesn't spawn a second, duplicate monitor process. Matches by resolving
    each cmdline argument against the process's own cwd, since a relative
    "main.py" argument (the common case) carries no path info by itself."""
    target = MAIN_PY.resolve()
    own_pid = os.getpid()
    try:
        for proc in psutil.process_iter(["pid", "cmdline", "cwd"]):
            # Never match THIS process. The desktop app hosts the dashboard in
            # the same process it runs the monitor in; if this ever returned
            # our own pid, "Stop Monitoring" would terminate() the whole app
            # (window included) instead of just pausing monitoring -- which is
            # exactly the "Aegis quits when I click Stop" symptom.
            if proc.info["pid"] == own_pid:
                continue
            cmdline = proc.info.get("cmdline") or []
            if not any(part.endswith("main.py") for part in cmdline):
                continue
            cwd = proc.info.get("cwd")
            for part in cmdline:
                if not part.endswith("main.py"):
                    continue
                candidate = Path(part)
                if not candidate.is_absolute() and cwd:
                    candidate = Path(cwd) / candidate
                try:
                    if candidate.resolve() == target:
                        return proc.info["pid"]
                except OSError:
                    continue
    except psutil.Error:
        pass
    return None


def _heartbeat_age() -> float | None:
    """Seconds since the dispatcher last stamped its heartbeat, or None if it
    never has / can't be read. The dispatcher writes 'last_heartbeat' every
    HEARTBEAT_INTERVAL (core/dispatcher). A growing age while the process is
    still 'running' means the loop stalled -- process-alive is not loop-alive,
    and only the heartbeat can tell those two apart."""
    try:
        conn = _connect_ro(DashboardHandler.db_path)
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'last_heartbeat'").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    if not row:
        return None
    try:
        return max(0.0, time.time() - float(row[0]))
    except (TypeError, ValueError):
        return None


def monitor_status() -> dict:
    if DashboardHandler.in_process_monitor:
        # The monitor pipeline lives in this same process, but -- unlike the
        # app itself -- it's genuinely start/stop-able via
        # monitor_{start,stop}_callback (see desktop_app.py's
        # MonitorPipeline), so its running state has to be asked for, not
        # assumed true.
        info = DashboardHandler.monitor_status_callback()
        running, started_at = info["running"], info.get("started_at")
        return {
            "running": running,
            "pid": os.getpid() if running else None,
            "started_at": started_at,
            "uptime_seconds": max(0.0, time.time() - started_at) if (running and started_at) else None,
            "heartbeat_age": _heartbeat_age() if running else None,
            "managed": "in_process",
        }
    state = _read_monitor_state()
    if state and _process_alive(state.get("pid", -1)):
        pid = state["pid"]
    else:
        if state:
            MONITOR_STATE_FILE.unlink(missing_ok=True)  # stale -- that process is gone
        pid = _find_external_monitor_pid()
        if pid is not None:
            try:
                state = {"pid": pid, "started_at": psutil.Process(pid).create_time()}
                MONITOR_STATE_FILE.write_text(json.dumps(state))
            except psutil.Error:
                pid = None  # gone between the scan and now -- treat as not running

    if pid is None:
        return {"running": False, "pid": None, "started_at": None, "uptime_seconds": None, "managed": "external"}
    return {
        "running": True,
        "pid": pid,
        "started_at": state["started_at"],
        "uptime_seconds": max(0.0, time.time() - state["started_at"]),
        "heartbeat_age": _heartbeat_age(),
        "managed": "external",
    }


def start_monitor() -> dict:
    if DashboardHandler.in_process_monitor:
        # Actually starts/rebuilds the collector+dispatcher pipeline in THIS
        # process (see desktop_app.py's MonitorPipeline.start) -- NOT the
        # subprocess-spawning path below. That path launching here would, in
        # a frozen build, run `sys.executable str(MAIN_PY)` where
        # sys.executable IS the Aegis binary itself -- a second whole copy of
        # the app, second window included, which is exactly what used to
        # happen and looked like "the app restarts itself."
        #
        # A raise here (bad db_path, a watched folder that vanished) used to
        # escape do_POST, which only catches BrokenPipeError -- the browser got
        # a dropped connection and the user got no idea why monitoring was off.
        # MonitorPipeline.start() now leaves itself cleanly stopped on failure,
        # so reporting the reason is both safe and the whole point.
        try:
            DashboardHandler.monitor_start_callback()
        except Exception as e:
            logger_srv.exception("In-process monitor start failed")
            return {**monitor_status(), "error": f"could not start monitoring: {e}"}
        return monitor_status()
    status = monitor_status()
    if status["running"]:
        return status

    MONITOR_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MONITOR_LOG_PATH, "ab") as log_f:
        log_f.write(f"\n--- launched by dashboard at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n".encode())
        popen_kwargs = {}
        if platform.system() == "Windows":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True  # own session: survives the dashboard's shell
        proc = subprocess.Popen(
            [sys.executable, str(MAIN_PY)],
            cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
            stdout=log_f, stderr=subprocess.STDOUT,
            **popen_kwargs,
        )

    started_at = time.time()
    MONITOR_STATE_FILE.write_text(json.dumps({"pid": proc.pid, "started_at": started_at}))
    return {"running": True, "pid": proc.pid, "started_at": started_at, "uptime_seconds": 0.0}


def stop_monitor() -> dict:
    if DashboardHandler.in_process_monitor:
        # Stops the collector+dispatcher threads (desktop_app.py's
        # MonitorPipeline.stop) but leaves the app/window/dashboard server
        # running -- pausing monitoring is not the same as quitting the app.
        DashboardHandler.monitor_stop_callback()
        return monitor_status()
    state = _read_monitor_state()
    pid = state["pid"] if state and _process_alive(state.get("pid", -1)) else _find_external_monitor_pid()
    if pid == os.getpid():
        # Belt-and-suspenders with _find_external_monitor_pid's own guard: a
        # stale MONITOR_STATE_FILE could still name this very process. Refuse
        # to terminate ourselves -- that would close the app/window, not pause
        # monitoring. Clear the bad state and report stopped.
        logger_srv.warning("stop_monitor resolved to our own pid (%s) -- refusing to self-terminate", pid)
        pid = None
    if pid is not None:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except psutil.TimeoutExpired:
                proc.kill()  # each event is committed individually (core/database.py),
                             # so a hard kill here can't corrupt the event store
        except psutil.Error:
            pass
    MONITOR_STATE_FILE.unlink(missing_ok=True)
    return {"running": False, "pid": None, "started_at": None, "uptime_seconds": None, "managed": "external"}


# --- tamper protection -------------------------------------------------------
# The Stop Monitoring button is a protected action: with tamper_require_password
# on (the default), stopping requires the dashboard password. Wrong passwords
# are logged as timeline events, and once they reach the configured threshold,
# evidence is captured as an Incident (see core/evidence.py). Failed-attempt
# counts are in-memory per action -- a restart resets them, which is fine:
# this is a deterrent + evidence trail, not an account-lockout system.
#
# HONEST SCOPE: this gates the in-app protected actions -- the Stop button, and
# (via desktop_app's window-close/menu/tray gate, action "quit") quitting the
# app. What it CANNOT stop is a SIGKILL / force-quit of the OS process; that
# path is covered instead by heartbeat gap detection (core/dispatcher), which
# records that monitoring went dark. Tamper *evidence*, not tamper *proof*.
#
# State is in-memory per action (a restart resets it): {"fails", "locked_until",
# "captured"}. Two independent escalations on wrong passwords -- evidence
# capture at cfg.tamper_attempts_before_capture, and a hard LOCKOUT after
# LOCKOUT_THRESHOLD that blocks the action for LOCKOUT_SECONDS regardless of a
# correct password. The lockout is enforced HERE (server-side), so it holds
# even if someone bypasses the frontend.
_tamper_state: dict[str, dict] = {}
# Serializes wrong-password handling -- see _register_failed_attempt.
_tamper_lock = threading.Lock()
# occam: fixed 5-attempts / 60s per the product decision; promote to config
# fields (like tamper_attempts_before_capture) only if someone needs to tune it.
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 60


def _writable_store():
    from core.database import EventStore
    return EventStore(DashboardHandler.db_path)


def _safe_config():
    """load_config() that never raises. The tamper gates have to keep working
    when config.yaml is unreadable, and they must fail CLOSED when it is --
    AppConfig()'s defaults have tamper_require_password on, so that's what an
    unreadable config degrades to."""
    from core.config import AppConfig, load_config
    try:
        return load_config()
    except Exception:
        logger_srv.warning("Could not load config -- assuming tamper protection is ON",
                           exc_info=True)
        return AppConfig()


def _lockout_check(action: str) -> dict:
    """Non-empty while `action` is locked out. Checked BEFORE the password, so
    a correct password inside the lockout window still waits it out."""
    st = _tamper_state.get(action)
    if not st:
        return {}
    remaining = st["locked_until"] - time.time()
    if remaining <= 0:
        return {}
    seconds = int(remaining) + 1
    return {"error": f"too many attempts -- locked for {seconds}s",
            "locked": True, "retry_after": seconds}


def _register_failed_attempt(action: str, cfg=None) -> dict:
    """One wrong password on `action`: log it to the timeline, capture evidence
    at the configured threshold, lock out at LOCKOUT_THRESHOLD. Returns the
    error dict to send back.

    Shared by every gated path -- Stop Monitoring, Delete Evidence, Settings,
    AND the sign-in form. Sign-in was the hole: it had a 0.4s sleep and nothing
    else, so someone could sit at the login page guessing the password
    indefinitely, silently, and never trip the gate that the Stop button they
    were ultimately after is protected by. Guessing the password IS the tamper
    attempt; where it's typed doesn't change that."""
    # cfg may legitimately be None (the caller's own load_config() raised, which
    # is exactly why it passed None) -- so re-deriving it here has to go through
    # the never-raises path, or this re-raises the error the caller handled.
    cfg = cfg or _safe_config()
    # The whole body runs under one lock. Without it, a burst of parallel wrong
    # passwords each read st["fails"]/st["captured"] before any of them wrote,
    # so N threads all saw "not captured yet" and all fired capture_incident():
    # 20 concurrent attempts produced 18 incident folders -- 18 screenshots and
    # 18 contending grabs of a single webcam -- and left the fails counter at 0.
    # A brute-force burst is precisely when this path must stay accurate, and
    # serializing wrong-password handling is a feature here, not a cost.
    # occam: one global lock over all actions; per-action locks only if a real
    # workload ever has two different gates being attacked at the same time.
    with _tamper_lock:
        # Re-check the lockout now that we hold the lock. The caller's
        # _lockout_check ran before it, so an entire burst can stream past that
        # check while the first attempt is still being processed, and every one
        # of them would then be counted and escalated. Serialized, 20 parallel
        # guesses used to roll through four full 5-strike cycles and capture
        # evidence four times; re-checking here stops the burst at the first
        # lockout, which is what a lockout is for.
        locked = _lockout_check(action)
        if locked:
            return locked
        st = _tamper_state.setdefault(action, {"fails": 0, "locked_until": 0.0, "captured": False})
        time.sleep(0.4)  # blunt guessing damper
        st["fails"] += 1
        n = st["fails"]
        locked_now = n >= LOCKOUT_THRESHOLD
        store = None
        try:
            store = _writable_store()
            try:
                store.insert(
                    source="tamper", category="tamper_attempt",
                    summary=(f"Failed password on protected action: {action} (attempt {n}"
                             + (f" -- locked out for {LOCKOUT_SECONDS}s)" if locked_now else ")")),
                    details={"action": action, "attempt": n, "locked_out": locked_now},
                    confidence="certain", severity="critical" if locked_now else "high")
            except Exception as e:
                logger_srv.error("Could not log tamper attempt: %s", e)
            result = {"error": "incorrect password", "attempts": n}
            # Evidence capture: once, at the configured threshold.
            if n >= cfg.tamper_attempts_before_capture and not st["captured"]:
                from core.evidence import capture_incident
                inc = capture_incident(reason=f"unauthorized attempt: {action}", attempts=n,
                                       store=store, config=cfg, extra_context={"action": action})
                st["captured"] = True
                result["incident_id"] = inc.get("id")
                result["evidence_captured"] = True
            # Lockout: block the action for a fixed window, then start fresh.
            if locked_now:
                st["locked_until"] = time.time() + LOCKOUT_SECONDS
                st["fails"] = 0
                st["captured"] = False
                result["locked"] = True
                result["retry_after"] = LOCKOUT_SECONDS
                result["error"] = f"too many attempts -- locked for {LOCKOUT_SECONDS}s"
            return result
        finally:
            if store is not None:
                store.close()


def _throttle_failed_password(action: str) -> dict:
    """Record a wrong password typed at a prompt that checks the password
    ITSELF (sign-in, change-password) rather than delegating to
    guard_protected_action. Escalates exactly like a gated action when tamper
    protection is on; falls back to the blunt damper alone when the user has
    turned it off. The caller supplies the user-facing wording."""
    cfg = _safe_config()
    if cfg.tamper_require_password:
        return _register_failed_attempt(action, cfg)
    time.sleep(0.4)   # tamper gate off: damper only, no incident trail
    return {}


def guard_protected_action(action: str, password: str) -> dict:
    """Returns {} when the action may proceed, else an error dict. Wrong
    passwords escalate: evidence capture at the configured threshold, then a
    time-boxed lockout at LOCKOUT_THRESHOLD. Never raises.

    Config comes from _safe_config(), not a bare load_config(): this is the
    primary gate for Stop Monitoring, Quit, Delete Evidence and the Settings
    unlock, and a raise here escaped do_POST (which only catches
    BrokenPipeError) as a dropped connection rather than the honest error the
    fail-closed path is supposed to produce. _settings_open() and
    _throttle_failed_password() already went through the safe loader; this was
    the one gate that didn't."""
    cfg = _safe_config()
    if not cfg.tamper_require_password:
        return {}
    locked = _lockout_check(action)
    if locked:
        return locked
    creds = _load_credentials()
    if _verify_password(creds["username"], password):
        _tamper_state.pop(action, None)   # clean slate on success
        return {}
    return _register_failed_attempt(action, cfg)


# --- settings lock -----------------------------------------------------------
# The Settings page is the master key to every other protection in this app: it
# can switch tamper_require_password OFF (which disables the password gate on
# Stop Monitoring AND on quitting), turn off evidence capture, repoint the
# evidence folder somewhere the attacker controls, and empty the trust lists.
# A live session alone was enough to do all of that -- so anyone who walked up
# to an unlocked machine with the dashboard already signed in could disable the
# tamper protocol in two clicks, without ever tripping it.
#
# Reading and writing settings therefore needs the dashboard password again,
# through the SAME guard as Stop Monitoring: wrong attempts are logged as
# timeline events, evidence is captured at the threshold, and five failures
# lock the action out. The unlock is per-session-token, expires on its own, and
# is dropped on sign-out. Like every other gate here, it's disabled when the
# user has explicitly turned tamper_require_password off.
SETTINGS_UNLOCK_TTL = 10 * 60
_settings_unlock_until: dict[str, float] = {}   # session token -> expiry (unix seconds)


def unlock_settings(token: str, password: str) -> dict:
    guard = guard_protected_action("settings", password)
    if guard.get("error"):
        return guard
    _prune_expired(_settings_unlock_until)
    _settings_unlock_until[token] = time.time() + SETTINGS_UNLOCK_TTL
    return {"ok": True, "expires_in": SETTINGS_UNLOCK_TTL}


def _read_incidents(sql: str, args: tuple = ()) -> list[dict]:
    """Read-only incident query. These two endpoints used to go through
    _writable_store(), i.e. a fresh WRITABLE sqlite connection plus a full
    CREATE-TABLE-IF-NOT-EXISTS schema script -- and the dashboard polls
    /api/incidents every 4 seconds to keep the shield badge current. That's a
    write connection opened, schema-scripted and closed every 4s, forever,
    against the same file the dispatcher is appending events to. Reads belong
    on the read-only connection the rest of this file already uses.

    An OperationalError here means the incidents table doesn't exist yet (a DB
    file created before tamper evidence existed, only migrated when an
    EventStore opens it) -- that's "no incidents", not an error page."""
    try:
        conn = _connect_ro(DashboardHandler.db_path)
    except sqlite3.Error:
        return []
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def list_incidents() -> dict:
    rows = _read_incidents("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 200")
    unreviewed = sum(1 for r in rows if not r["reviewed"])
    return {"incidents": rows, "unreviewed": unreviewed, "total": len(rows)}


def get_incident(incident_id: int) -> dict:
    rows = _read_incidents("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    return rows[0] if rows else {"error": "incident not found"}


def delete_incidents_action(ids: list[int]) -> dict:
    """Delete incident rows and their on-disk evidence folders. The password
    gate happens at the route (same guard as Stop Monitoring); this just does
    the work. Deletion itself leaves a timeline event -- evidence that
    evidence was deleted -- so a wipe is never fully silent."""
    import re
    import shutil
    from core.config import load_config
    from core.evidence import incidents_dir
    inc_root = incidents_dir(load_config())
    store = _writable_store()
    deleted_ids: list[int] = []
    file_errors: list[str] = []
    try:
        for iid in ids:
            row = store.get_incident(iid)
            if row is None:
                continue
            # Evidence folders come from the artifact paths (still correct for
            # incidents captured under an older evidence_dir setting), plus the
            # timestamp-derived folder under the current one. Only a directory
            # literally named incident_YYYYMMDD_HHMMSS is ever removed -- a
            # poisoned artifact path can't point this at anything else.
            folders: set[Path] = set()
            try:
                artifacts = json.loads(row.get("artifacts_json") or "{}") or {}
            except json.JSONDecodeError:
                artifacts = {}
            for art in artifacts.values():
                if isinstance(art, dict) and art.get("path"):
                    folders.add(Path(art["path"]).resolve().parent)
            stamp = time.strftime("incident_%Y%m%d_%H%M%S",
                                  time.localtime(row["timestamp"]))
            folders.add((inc_root / stamp).resolve())
            for folder in folders:
                if re.fullmatch(r"incident_\d{8}_\d{6}", folder.name) and folder.is_dir():
                    try:
                        shutil.rmtree(folder)
                    except OSError as e:
                        file_errors.append(f"{folder.name}: {e}")
            store.delete_incidents([iid])
            deleted_ids.append(iid)
        if deleted_ids:
            try:
                store.insert(
                    source="tamper", category="evidence_deleted",
                    summary=(f"{len(deleted_ids)} tamper incident record(s) deleted "
                             "via dashboard (password confirmed)"),
                    details={"incident_ids": deleted_ids},
                    confidence="certain", severity="medium")
            except Exception as e:
                logger_srv.error("Could not log evidence deletion: %s", e)
    finally:
        store.close()
    result = {"ok": True, "deleted": len(deleted_ids)}
    if file_errors:
        result["file_errors"] = file_errors
    return result


def mark_incident_reviewed(incident_id: int) -> dict:
    store = _writable_store()
    try:
        if store.get_incident(incident_id) is None:
            return {"error": "incident not found"}
        store.set_incident_reviewed(incident_id, True)
    finally:
        store.close()
    return {"ok": True}


def test_enrichment() -> dict:
    """Settings-card 'Test connection': one live VirusTotal lookup of the EICAR
    test file's hash with the configured key. Proves key + network + response
    parsing end-to-end — the terminal-free version of
    `python -m core.enrichment --live`. Uses an in-memory cache db so the test
    never writes to the real event store."""
    from core.config import load_config
    from core.enrichment import ThreatEnricher

    cfg = load_config()
    if not cfg.vt_api_key:
        return {"error": "No VirusTotal API key configured — enter one above and Save first."}

    class _TestCfg:
        db_path = ":memory:"
        vt_api_key = cfg.vt_api_key

    enricher = ThreatEnricher(_TestCfg())
    eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = enricher._vt_fetch(eicar)
    if enricher._auth_failed:
        return {"error": "VirusTotal rejected the API key (401) — check the key and Save again."}
    if result is None:
        return {"error": "Could not reach VirusTotal — network problem or free-tier quota exceeded."}
    if result.get("status") != "known" or not result.get("detections"):
        return {"error": "Unexpected VirusTotal reply — the EICAR test file should always be flagged."}
    return {"ok": True, "detections": result["detections"], "engines_total": result["engines_total"]}


def add_trusted(kind: str, value: str) -> dict:
    """Trust Learning: append an 'always trust this' entry to config.yaml so
    future matching events skip the AI call (see core/rule_engine.py). kind is
    'process_names' | 'process_hashes' | 'usb_ids'."""
    field = {"process_names": "trusted_process_names",
             "process_hashes": "trusted_process_hashes",
             "usb_ids": "trusted_usb_ids"}.get(kind)
    if not field:
        return {"error": f"unknown trust kind '{kind}'"}
    value = str(value).strip()
    if not value:
        return {"error": "empty trust value"}
    current = read_settings()
    existing = list(current.get(field, []))
    if value not in existing:
        existing.append(value)
    # write_settings expects the full body shape; reuse the current settings
    # and swap in the augmented list so nothing else changes.
    body = {
        "ai": {"provider": current["ai"]["provider"], "base_url": current["ai"]["base_url"],
               "api_key_env": current["ai"]["api_key_env"], "model": current["ai"]["model"],
               "temperature": current["ai"]["temperature"]},
        "notify_enabled": current["notify_enabled"],
        "notify_min_severity": current["notify_min_severity"],
        "notify_on_startup_scan": current["notify_on_startup_scan"],
        "watched_folders": current["watched_folders"],
        "poll_interval_seconds": current["poll_interval_seconds"],
        "trusted_process_names": current["trusted_process_names"],
        "trusted_process_hashes": current["trusted_process_hashes"],
        "trusted_usb_ids": current["trusted_usb_ids"],
        "enrich_enabled": current["enrich_enabled"],
    }
    body[field] = existing
    result = write_settings(body)
    if result.get("error"):
        return result
    return {"ok": True, "field": field, "value": value}


def monitor_log_tail(max_lines: int = 200) -> str:
    if not MONITOR_LOG_PATH.is_file():
        return ""
    lines = MONITOR_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def export_csv(events: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EVENT_COLUMNS)
    writer.writeheader()
    writer.writerows(events)
    return buf.getvalue()


# --- self-update -------------------------------------------------------------
# Only meaningful for the desktop app (in_process_monitor=True): a standalone
# `python dashboard/server.py` checkout should `git pull`, there's no bundle
# to replace. See core/updater.py for the actual check/download/install logic
# and its VERIFIED (macOS) vs NOT VERIFIED (Windows) status.

def check_update() -> dict:
    from core.updater import check_for_update, UpdateError
    from core.version import __version__

    if not (DashboardHandler.in_process_monitor and _is_frozen()):
        return {"update_available": False, "current_version": __version__,
                "reason": "not a packaged desktop app install"}
    try:
        info = check_for_update()
    except UpdateError as e:
        # Distinct from "no update" -- a failed check must never read as a
        # verified "you're on the latest version" (see check_for_update's
        # docstring for the bug this used to cause).
        return {"update_available": False, "current_version": __version__,
                "check_failed": True, "error": str(e)}
    if info is None:
        return {"update_available": False, "current_version": __version__}
    return {"update_available": True, "current_version": __version__, **info}


def install_update(download_url: str, asset_name: str) -> dict:
    from core.updater import check_for_update, download_update, install_update as do_install, UpdateError

    if not (DashboardHandler.in_process_monitor and _is_frozen()):
        return {"error": "self-update is only available in the packaged desktop app"}
    if DashboardHandler.quit_callback is None:
        return {"error": "no quit hook wired up -- cannot safely restart"}

    # Confirmed bug: this used to hand the client-supplied download_url/
    # asset_name straight to download_update()/do_install() -- i.e. anything
    # that could send one authenticated POST to this endpoint (malware
    # running as the same OS user, a stolen session cookie, a future
    # auth-bypass elsewhere) could point Aegis's self-updater at an arbitrary
    # URL and have the result downloaded and *executed* as a routine update.
    # Never trust these two values on their own -- re-derive them from a
    # fresh, authoritative GitHub API call right here and require an exact
    # match before downloading or installing anything.
    try:
        info = check_for_update()
    except UpdateError as e:
        return {"error": f"could not verify this update before installing it: {e}"}
    if info is None or info["download_url"] != download_url or info["asset_name"] != asset_name:
        return {"error": "update info is stale or does not match the latest published release -- "
                          "refresh and try again"}

    try:
        installer_path = download_update(download_url, asset_name)
        do_install(installer_path, DashboardHandler.quit_callback)
    except (UpdateError, OSError) as e:
        return {"error": str(e)}
    return {"ok": True}  # process is exiting behind this response


class DashboardHandler(BaseHTTPRequestHandler):
    db_path: str = "aegis_events.db"  # overridden in main()
    bind_host: str = "127.0.0.1"      # set in build_server -- see _host_ok
    # Set True by desktop_app.py: the monitor pipeline there runs in THIS
    # same process, not as a separate main.py subprocess the old start/stop
    # buttons were built to spawn/kill -- see monitor_status()/start_monitor()
    # /stop_monitor() below for why that distinction matters.
    in_process_monitor: bool = False
    # desktop_app.py's MonitorPipeline start/stop/status, set alongside
    # in_process_monitor. () -> {"running": bool, "started_at": float|None},
    # () -> None, () -> None respectively.
    monitor_status_callback = None
    monitor_start_callback = None
    monitor_stop_callback = None
    # desktop_app.py's on_quit -- lets /api/update/install shut the monitor
    # pipeline down cleanly before the installer swaps this process's own
    # files out from under it. None outside the desktop app.
    quit_callback = None

    def log_message(self, fmt, *fmt_args):
        pass  # keep the terminal quiet; errors still surface as HTTP 500s

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload, status: int = 200, extra: dict | None = None):
        self._send(status, json.dumps(payload).encode(), "application/json; charset=utf-8", extra)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # --- sessions ---

    def _session_token(self) -> str | None:
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and value:
                return value
        return None

    def _authed(self) -> bool:
        token = self._session_token()
        expiry = _sessions.get(token) if token else None
        if expiry is None:
            return False
        if expiry < time.time():
            _sessions.pop(token, None)
            return False
        return True

    def _settings_open(self) -> bool:
        """Has this session unlocked Settings (see unlock_settings)?"""
        from core.config import load_config
        try:
            if not load_config().tamper_require_password:
                return True     # user turned the whole tamper gate off
        except Exception:
            logger_srv.warning("Could not read tamper settings -- keeping Settings locked",
                               exc_info=True)
            return False        # fail closed: unreadable config must not open the gate
        token = self._session_token()
        expiry = _settings_unlock_until.get(token) if token else None
        if expiry is None:
            return False
        if expiry < time.time():
            _settings_unlock_until.pop(token, None)
            return False
        return True

    def _unlock_remaining(self):
        """Seconds left on this session's Settings unlock, for the countdown in
        the UI. None means "no countdown": either the tamper gate is off
        entirely, or nothing was unlocked (the caller is already past the gate
        because _settings_open() said so)."""
        expiry = _settings_unlock_until.get(self._session_token() or "")
        return max(0, int(expiry - time.time())) if expiry else None

    def _require_settings_unlock(self) -> bool:
        """True if the caller may touch settings; otherwise sends the 403 that
        tells the frontend to open the unlock prompt."""
        if self._settings_open():
            return True
        self._send_json({"error": "Settings are locked -- enter the dashboard password to unlock.",
                         "settings_locked": True}, status=403)
        return False

    # A browser page on any other origin can be made to resolve its own
    # hostname to 127.0.0.1 (DNS rebinding) and then talk to this server. The
    # session cookie wouldn't come along, but the login endpoint would still be
    # reachable -- and the seeded admin/admin is a guessable first try. This
    # server only ever exists to be reached as localhost, so anything else is
    # refused outright.
    _ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", ""}

    def _host_ok(self) -> bool:
        # Hostnames are case-insensitive, so compare casefolded -- "LOCALHOST:8787"
        # is the same host as "localhost:8787" and was being refused.
        host = (self.headers.get("Host") or "").strip().casefold()
        if host.startswith("["):                      # [::1]:8787
            host = host[1:].partition("]")[0]
        elif host.count(":") == 1:                    # 127.0.0.1:8787
            head, _, port = host.rpartition(":")
            # Only strip a genuine numeric port. Splitting on the colon
            # unconditionally accepted "127.0.0.1:8787.evil.com" as "127.0.0.1".
            if port.isdigit():
                host = head
        # bind_host covers someone who deliberately passed --host <lan-ip>:
        # that address is then a legitimate way to reach this server, and a
        # rebinding attacker still can't make a browser send a different one.
        return host in self._ALLOWED_HOSTS or host == self.bind_host

    # --- request handling ---

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self._host_ok():
            self._send(403, b"forbidden host", "text/plain")
            return
        try:
            if parsed.path == "/api/login":
                self._handle_login()
            elif parsed.path == "/api/settings/unlock":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    body = {}
                result = unlock_settings(self._session_token() or "",
                                         str(body.get("password", "")))
                if result.get("error"):
                    self._send_json({**result, "tamper_blocked": True}, status=403)
                else:
                    self._send_json(result)
            elif parsed.path == "/api/settings/lock":
                # No password needed to re-lock -- locking can only reduce
                # access, and a "Lock now" that itself needs the password is
                # useless to someone stepping away from the machine.
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                _settings_unlock_until.pop(self._session_token() or "", None)
                self._send_json({"ok": True})
            elif parsed.path == "/api/settings":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                if not self._require_settings_unlock():
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    self._send_json({"error": "invalid JSON body"}, status=400)
                    return
                result = write_settings(body)
                if result.get("error"):
                    self._send_json(result, status=400)
                else:
                    self._send_json({"ok": True, "settings": read_settings()})
            elif parsed.path == "/api/settings/password":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    self._send_json({"error": "invalid JSON body"}, status=400)
                    return
                result = change_password(str(body.get("current_password", "")),
                                          str(body.get("new_password", "")))
                if result.get("locked"):
                    status = 429      # lockout, not a malformed request
                else:
                    status = 400 if result.get("error") else 200
                self._send_json(result, status=status)
            elif parsed.path == "/api/monitor/start":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                else:
                    self._send_json(start_monitor())
            elif parsed.path == "/api/monitor/restart":
                # Stop + start so the pipeline is rebuilt against freshly
                # loaded config -- how saved settings take effect without
                # relaunching the app. Not password-gated like stop: it ends
                # with monitoring RUNNING, so it can't be used to disable it.
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                stop_monitor()
                self._send_json(start_monitor())
            elif parsed.path == "/api/monitor/stop":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    body = {}
                # Tamper gate: with tamper_require_password on, a correct
                # password is required to stop. Wrong ones are logged and,
                # past the threshold, trigger evidence capture.
                guard = guard_protected_action("stop_monitoring", str(body.get("password", "")))
                if guard.get("error"):
                    self._send_json({**guard, "tamper_blocked": True}, status=403)
                else:
                    self._send_json(stop_monitor())
            elif parsed.path == "/api/evidence/open-folder":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                # No client-supplied path here on purpose: the server opens the
                # folder it resolved from config, nothing else.
                from core.config import load_config
                from core.evidence import incidents_dir
                folder = incidents_dir(load_config())
                try:
                    folder.mkdir(parents=True, exist_ok=True)
                    if sys.platform == "darwin":
                        r = subprocess.run(["open", str(folder)], capture_output=True,
                                           text=True, timeout=10)
                    elif os.name == "nt":
                        os.startfile(str(folder))  # noqa -- windows only
                        r = None
                    else:
                        r = subprocess.run(["xdg-open", str(folder)], capture_output=True,
                                           text=True, timeout=10)
                    if r is not None and r.returncode != 0:
                        detail = (r.stderr or r.stdout or "").strip()
                        logger_srv.error("open-folder failed (rc=%s): %s", r.returncode, detail)
                        self._send_json({"error": f"could not open folder: {detail or 'opener exited '+str(r.returncode)}"},
                                        status=500)
                    else:
                        self._send_json({"ok": True, "path": str(folder)})
                except (OSError, subprocess.TimeoutExpired) as e:
                    self._send_json({"error": f"could not open folder: {e}"}, status=500)
            elif parsed.path == "/api/incidents/review":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    body = {}
                raw_id = body.get("id")
                if not isinstance(raw_id, int):
                    self._send_json({"error": "id must be an integer"}, status=400)
                else:
                    result = mark_incident_reviewed(raw_id)
                    self._send_json(result, status=404 if result.get("error") else 200)
            elif parsed.path == "/api/incidents/delete":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    body = {}
                raw_ids = body.get("ids")
                ids = ([i for i in raw_ids if isinstance(i, int) and not isinstance(i, bool)]
                       if isinstance(raw_ids, list) else [])
                if not ids or len(ids) != len(raw_ids) or len(ids) > 200:
                    self._send_json({"error": "ids must be a non-empty list of integers (max 200)"},
                                    status=400)
                    return
                # Deleting evidence is itself tamper-sensitive: same password
                # gate, attempt logging, capture threshold, and lockout as
                # Stop Monitoring, tracked as its own action.
                guard = guard_protected_action("delete_incidents", str(body.get("password", "")))
                if guard.get("error"):
                    self._send_json({**guard, "tamper_blocked": True}, status=403)
                else:
                    self._send_json(delete_incidents_action(ids))
            elif parsed.path == "/api/enrich/test":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                elif self._require_settings_unlock():
                    result = test_enrichment()
                    self._send_json(result, status=400 if result.get("error") else 200)
            elif parsed.path == "/api/trust/add":
                # Adding a trust entry rewrites config.yaml (write_settings) and
                # permanently silences a binary or device -- same class of change
                # as the Settings page itself, so the same gate applies.
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                if not self._require_settings_unlock():
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    body = {}
                result = add_trusted(str(body.get("kind", "")), str(body.get("value", "")))
                self._send_json(result, status=400 if result.get("error") else 200)
            elif parsed.path == "/api/update/install":
                # Replaces this application's own files on disk -- gated with
                # the rest of Settings, where the button lives.
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                    return
                if not self._require_settings_unlock():
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    self._send_json({"error": "invalid JSON body"}, status=400)
                    return
                url, name = body.get("download_url"), body.get("asset_name")
                if not url or not name:
                    self._send_json({"error": "download_url and asset_name are required"}, status=400)
                    return
                result = install_update(url, name)
                self._send_json(result, status=400 if result.get("error") else 200)
            elif parsed.path == "/api/logout":
                token = self._session_token()
                if token:
                    _sessions.pop(token, None)
                    _settings_unlock_until.pop(token, None)  # signing out re-locks Settings
                self._send_json({"ok": True},
                                extra={"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0"})
            else:
                self._send(404, b"not found", "text/plain")
        except BrokenPipeError:
            pass

    def _handle_login(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, ValueError):
            body = {}
        # Sign-in is a protected action too: it hands out a session that can
        # stop monitoring, and it was the one password prompt in the app with
        # no lockout and no tamper trail (see _register_failed_attempt).
        locked = _lockout_check("login")
        if locked:
            self._send_json({"ok": False, **locked}, status=429)
            return
        ok = _verify_password(str(body.get("username", "")), str(body.get("password", "")))
        if not ok:
            # never confirm which half was wrong
            result = {**_throttle_failed_password("login"), "error": "invalid credentials"}
            self._send_json({"ok": False, **result}, status=401)
            return
        _tamper_state.pop("login", None)   # clean slate on a successful sign-in
        token = secrets.token_urlsafe(32)
        _prune_expired(_sessions)
        _sessions[token] = time.time() + SESSION_TTL
        self._send_json({"ok": True}, extra={
            "Set-Cookie": f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; "
                          f"Path=/; Max-Age={SESSION_TTL}"})

    def do_GET(self):
        parsed = urlparse(self.path)
        if not self._host_ok():
            self._send(403, b"forbidden host", "text/plain")
            return
        params = parse_qs(parsed.query)
        authed = self._authed()
        try:
            if parsed.path == "/login":
                if authed:
                    self._redirect("/")
                else:
                    self._serve_static("/login.html")
            elif parsed.path.startswith("/api/"):
                if not authed:
                    self._send_json({"error": "authentication required"}, status=401)
                elif parsed.path == "/api/events":
                    self._send_json({"events": query_events(self.db_path, params)})
                elif parsed.path == "/api/events/related":
                    raw_id = params.get("id", [""])[0]
                    if not raw_id.isdigit():
                        self._send_json({"error": "id must be an event id"}, status=400)
                    else:
                        result = query_related(self.db_path, int(raw_id))
                        self._send_json(result, status=404 if result.get("error") else 200)
                elif parsed.path == "/api/stats":
                    self._send_json(query_stats(self.db_path))
                elif parsed.path == "/api/incidents":
                    self._send_json(list_incidents())
                elif parsed.path == "/api/incidents/get":
                    raw_id = params.get("id", [""])[0]
                    if not raw_id.isdigit():
                        self._send_json({"error": "id must be an incident id"}, status=400)
                    else:
                        result = get_incident(int(raw_id))
                        self._send_json(result, status=404 if result.get("error") else 200)
                elif parsed.path == "/api/daily":
                    self._send_json(daily_brief(self.db_path))
                elif parsed.path == "/api/settings":
                    # Reading is gated too, not just writing: this response
                    # carries the trust lists, the evidence folder path and
                    # which API keys exist. The frontend uses the 403 as its
                    # cue to prompt for the password.
                    if self._require_settings_unlock():
                        self._send_json({**read_settings(),
                                         "unlock_expires_in": self._unlock_remaining()})
                elif parsed.path == "/api/monitor/status":
                    self._send_json(monitor_status())
                elif parsed.path == "/api/update/check":
                    self._send_json(check_update())
                elif parsed.path == "/api/monitor/log":
                    try:
                        n = min(max(int(params.get("lines", ["200"])[0]), 1), 2000)
                    except ValueError:
                        n = 200
                    self._send_json({"log": monitor_log_tail(n)})
                elif parsed.path == "/api/export":
                    self._handle_export(params)
                elif parsed.path == "/api/report/pdf":
                    self._handle_report_pdf(params)
                else:
                    self._send_json({"error": "not found"}, status=404)
            elif parsed.path in ("/", "/index.html"):
                if authed:
                    self._serve_static("/index.html")
                else:
                    self._redirect("/login")
            else:
                name = parsed.path.lstrip("/")
                if authed or name in PUBLIC_FILES or name.startswith(PUBLIC_PREFIXES):
                    self._serve_static(parsed.path)
                else:
                    self._redirect("/login")
        except sqlite3.OperationalError as exc:
            self._send_json({"error": f"database unavailable: {exc}"}, status=503)
        except BrokenPipeError:
            pass  # client closed the tab mid-response; nothing to do

    def _handle_export(self, params: dict):
        events = query_events(self.db_path, params, limit_cap=100_000)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if params.get("format", ["json"])[0] == "csv":
            body = export_csv(events).encode()
            self._send(200, body, "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="aegis-events-{stamp}.csv"'})
        else:
            body = json.dumps({"exported_at": time.time(), "events": events}, indent=2).encode()
            self._send(200, body, "application/json; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="aegis-events-{stamp}.json"'})

    def _handle_report_pdf(self, params: dict):
        # Lazy imports: core.ai_explainer pulls in anthropic/openai, which
        # aren't stdlib -- keep the module docstring's "zero dependencies
        # unless you use the AI features" promise intact for requests that
        # never hit this endpoint (same pattern as read_settings' `import yaml`).
        from core.config import load_config
        from core.report_generator import format_range_label, generate_pdf_report

        events = query_events(self.db_path, params, limit_cap=100_000)
        try:
            since = float(params.get("since", ["0"])[0] or 0)
        except ValueError:
            since = 0.0
        try:
            until = float(params.get("until", [str(time.time())])[0] or time.time())
        except ValueError:
            until = time.time()
        label = params.get("label", [""])[0].strip() or format_range_label(since, until)

        try:
            config = load_config()
            pdf_bytes = generate_pdf_report(events, label, since, until, config)
        except Exception as exc:
            self._send_json({"error": f"report generation failed: {exc}"}, status=500)
            return

        stamp = time.strftime("%Y%m%d-%H%M%S")
        self._send(200, pdf_bytes, "application/pdf",
                   {"Content-Disposition": f'attachment; filename="aegis-report-{stamp}.pdf"'})

    def _serve_static(self, path: str):
        name = path.lstrip("/") or "index.html"
        if name.startswith("assets/"):
            root, name = ASSETS_DIR, name[len("assets/"):]
        else:
            root = STATIC_DIR
        target = (root / name).resolve()
        # resolve() then prefix-check defeats ../ traversal
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            self._send(404, b"not found", "text/plain")
            return
        self._send(200, target.read_bytes(), MIME.get(target.suffix, "application/octet-stream"))


def build_server(db_path: str, host: str = "127.0.0.1", port: int = 8787,
                  in_process_monitor: bool = False, quit_callback=None,
                  monitor_status_callback=None, monitor_start_callback=None,
                  monitor_stop_callback=None) -> ThreadingHTTPServer:
    """Factory used both by this file's CLI entry point and by desktop_app.py,
    which runs the dashboard in-process (a background thread) instead of as a
    separate `python dashboard/server.py` subprocess -- see desktop_app.py's
    module docstring for why. Same DashboardHandler either way, so the two
    ways of running Aegis can never drift apart in behavior.

    in_process_monitor=True tells the /api/monitor/* endpoints the monitor
    pipeline is running in THIS process, not a separate main.py subprocess
    they can start/stop -- see monitor_status()/start_monitor()/stop_monitor().
    The three monitor_*_callback args are required when in_process_monitor is
    True (desktop_app.py's MonitorPipeline start/stop/status).
    quit_callback, if given, is what /api/update/install calls to shut the
    monitor pipeline down before an installer replaces this process's files."""
    DashboardHandler.db_path = db_path
    DashboardHandler.bind_host = host
    DashboardHandler.in_process_monitor = in_process_monitor
    DashboardHandler.quit_callback = quit_callback
    DashboardHandler.monitor_status_callback = monitor_status_callback
    DashboardHandler.monitor_start_callback = monitor_start_callback
    DashboardHandler.monitor_stop_callback = monitor_stop_callback
    return ThreadingHTTPServer((host, port), DashboardHandler)


def main():
    parser = argparse.ArgumentParser(description="Aegis dashboard server")
    parser.add_argument("--db", default="aegis_events.db", help="Path to the SQLite event store")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (keep the localhost default -- this is a personal "
                             "console behind a single password, not a network service)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open the dashboard")
    args = parser.parse_args()

    if not Path(args.db).is_file():
        print(f"error: event store not found at {args.db!r} -- run main.py first, "
              f"or pass --db path/to/aegis_events.db", file=sys.stderr)
        sys.exit(1)

    server = build_server(args.db, args.host, args.port)
    url = f"http://{args.host}:{args.port}"
    print(f"Aegis dashboard: {url}  (db: {args.db}, read-only)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
