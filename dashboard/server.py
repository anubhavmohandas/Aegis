"""
Aegis dashboard -- local web UI over the SQLite event store.

Read-only by construction: the SQLite file is opened with mode=ro, so this
process can never write to the event store the monitors are appending to.
Runs completely separately from main.py (same philosophy as ui/timeline_app.py:
a UI bug must never take down monitoring), and binds to 127.0.0.1 only --
this is a personal dashboard, not a network service.

Zero dependencies beyond the stdlib, so it works inside the PyInstaller
bundle and on a bare python install alike.

Access requires signing in (fixed admin/admin for now -- see the auth block
below); sessions are HttpOnly cookies that expire after 12h or on restart.

Run with:
    python dashboard/server.py [--db aegis_events.db] [--port 8787]

then open http://127.0.0.1:8787
"""

from __future__ import annotations

import argparse
import csv
import hmac
import io
import json
import platform
import secrets
import sqlite3
import subprocess
import sys
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
ASSETS_DIR = REPO_ROOT / "assets"                       # brand logo lives with the app assets
CONFIG_PATH = REPO_ROOT / "config" / "config.yaml"      # same file core/config.py loads
ENV_PATH = REPO_ROOT / ".env"                           # API keys live here, never in yaml
MAIN_PY = REPO_ROOT / "main.py"
MONITOR_STATE_FILE = REPO_ROOT / ".aegis_monitor.json"  # {"pid": int, "started_at": float}
MONITOR_LOG_PATH = REPO_ROOT / "dashboard" / "monitor.log"

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_SOURCES = {"process", "usb", "startup", "folder"}

# --- auth -------------------------------------------------------------------
# Deliberately simple for now: a single fixed operator account, in-memory
# sessions (restart logs everyone out), HttpOnly SameSite cookie. When the
# settings UI lands, credentials move into config with a hashed passphrase --
# until then this is a placeholder gate for a localhost-only console.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"
SESSION_COOKIE = "aegis_session"
SESSION_TTL = 12 * 3600
_sessions: dict[str, float] = {}  # token -> expiry (unix seconds)

# Static files that must be reachable without a session: the login page and
# the stylesheet it uses. Everything else (index, app.js, the API) is gated.
PUBLIC_FILES = {"login.html", "style.css", "favicon.png"}

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
        }
    finally:
        conn.close()


# --- settings ----------------------------------------------------------------
# The dashboard edits the SAME config.yaml/.env that core/config.py loads, so
# the monitors and the UI can never disagree about where settings live. PyYAML
# is already a core Aegis dependency (core/config.py), so importing it here
# doesn't add anything new to the install.

SETTINGS_HEADER = (
    "# Aegis configuration -- managed by the dashboard settings page.\n"
    "# (Your original hand-written file was preserved once as config.yaml.orig.)\n"
    "# API keys are NOT stored here: ai.api_key_env names the environment\n"
    "# variable (usually set via .env) that holds the key.\n"
)

VALID_PROVIDERS = {"openai-compatible", "anthropic"}


def read_settings() -> dict:
    import yaml
    raw = {}
    if CONFIG_PATH.is_file():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    ai = raw.get("ai") or {}
    api_key_env = ai.get("api_key_env", "NVIDIA_API_KEY")
    key = _read_env_value(api_key_env)
    return {
        "ai": {
            "provider": ai.get("provider", "openai-compatible"),
            "base_url": ai.get("base_url", "https://integrate.api.nvidia.com/v1"),
            "api_key_env": api_key_env,
            "model": ai.get("model", "nvidia/nemotron-3-ultra-550b-a55b"),
            "temperature": float(ai.get("temperature", 0.2)),
            # the key itself never leaves the server -- only whether one exists
            "api_key_set": bool(key),
            "api_key_hint": f"····{key[-4:]}" if key and len(key) >= 8 else ("set" if key else ""),
        },
        "watched_folders": raw.get("watched_folders") or [],
        "poll_interval_seconds": int(raw.get("poll_interval_seconds", 3)),
        "notify_enabled": bool(raw.get("notify_enabled", False)),
        "notify_on_startup_scan": bool(raw.get("notify_on_startup_scan", True)),
        "notify_min_severity": raw.get("notify_min_severity", "low"),
        "trusted_process_names": raw.get("trusted_process_names") or [],
        "trusted_process_hashes": raw.get("trusted_process_hashes") or [],
        "trusted_usb_ids": raw.get("trusted_usb_ids") or [],
        "config_path": str(CONFIG_PATH),
    }


def _read_env_value(name: str) -> str | None:
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


def _write_env_value(name: str, value: str) -> None:
    """Replace (or append) one KEY=VALUE line, leaving every other line --
    including comments and other keys -- byte-for-byte untouched."""
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.is_file() else []
    replaced = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("#") and stripped.partition("=")[0].strip() == name:
            lines[i] = f"{name}={value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{name}={value}")
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
        "log_path": _passthrough("log_path"),
        "db_path": _passthrough("db_path"),
        "trusted_process_names": _clean_str_list(body.get("trusted_process_names")),
        "trusted_process_hashes": _clean_str_list(body.get("trusted_process_hashes")),
        "trusted_usb_ids": _clean_str_list(body.get("trusted_usb_ids")),
    }

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
        _write_env_value(api_key_env, api_key)
    return {}


def _passthrough(key: str) -> str:
    """Keep yaml keys the settings UI doesn't manage (log/db paths) intact."""
    import yaml
    if CONFIG_PATH.is_file():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        value = raw.get(key)
        if value:
            return str(value)
    return {"log_path": "events.log", "db_path": "aegis_events.db"}[key]


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
    try:
        for proc in psutil.process_iter(["pid", "cmdline", "cwd"]):
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


def monitor_status() -> dict:
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
        return {"running": False, "pid": None, "started_at": None, "uptime_seconds": None}
    return {
        "running": True,
        "pid": pid,
        "started_at": state["started_at"],
        "uptime_seconds": max(0.0, time.time() - state["started_at"]),
    }


def start_monitor() -> dict:
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
    state = _read_monitor_state()
    pid = state["pid"] if state and _process_alive(state.get("pid", -1)) else _find_external_monitor_pid()
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
    return {"running": False, "pid": None, "started_at": None, "uptime_seconds": None}


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


class DashboardHandler(BaseHTTPRequestHandler):
    db_path: str = "aegis_events.db"  # overridden in main()

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

    # --- request handling ---

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/login":
                self._handle_login()
            elif parsed.path == "/api/settings":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
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
            elif parsed.path == "/api/monitor/start":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                else:
                    self._send_json(start_monitor())
            elif parsed.path == "/api/monitor/stop":
                if not self._authed():
                    self._send_json({"error": "authentication required"}, status=401)
                else:
                    self._send_json(stop_monitor())
            elif parsed.path == "/api/logout":
                token = self._session_token()
                if token:
                    _sessions.pop(token, None)
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
        # compare_digest on both fields; single & so both always evaluate
        ok = hmac.compare_digest(str(body.get("username", "")), ADMIN_USERNAME) \
             & hmac.compare_digest(str(body.get("password", "")), ADMIN_PASSWORD)
        if not ok:
            time.sleep(0.4)  # blunt damper on credential guessing
            self._send_json({"ok": False, "error": "invalid credentials"}, status=401)
            return
        token = secrets.token_urlsafe(32)
        _sessions[token] = time.time() + SESSION_TTL
        self._send_json({"ok": True}, extra={
            "Set-Cookie": f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; "
                          f"Path=/; Max-Age={SESSION_TTL}"})

    def do_GET(self):
        parsed = urlparse(self.path)
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
                elif parsed.path == "/api/stats":
                    self._send_json(query_stats(self.db_path))
                elif parsed.path == "/api/settings":
                    self._send_json(read_settings())
                elif parsed.path == "/api/monitor/status":
                    self._send_json(monitor_status())
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
                if authed or name in PUBLIC_FILES or name.startswith("assets/"):
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


def main():
    parser = argparse.ArgumentParser(description="Aegis dashboard server")
    parser.add_argument("--db", default="aegis_events.db", help="Path to the SQLite event store")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (keep the localhost default; the API has no auth)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open the dashboard")
    args = parser.parse_args()

    if not Path(args.db).is_file():
        print(f"error: event store not found at {args.db!r} -- run main.py first, "
              f"or pass --db path/to/aegis_events.db", file=sys.stderr)
        sys.exit(1)

    DashboardHandler.db_path = args.db
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
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
