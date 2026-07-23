"""Runnable self-check for the Settings password gate.

The Settings page can switch tamper protection OFF, so a live session alone
must not be enough to read or write it: the dashboard password is required a
second time, and wrong attempts escalate through the same tamper machinery as
Stop Monitoring (timeline event, then lockout).

Drives the real HTTP server over a loopback socket -- the gate lives in the
request handler, so testing the functions directly would prove nothing about
whether the routes actually call it.

No framework: `python tests/test_settings_lock.py`.
"""
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Point every on-disk artifact (credentials, config.yaml, event db) at a
# throwaway directory BEFORE the server module reads its module-level paths.
_TMP = Path(tempfile.mkdtemp(prefix="aegis-settings-lock-"))
import core.config as core_config  # noqa: E402

core_config.DEFAULT_CONFIG_PATH = _TMP / "config" / "config.yaml"
core_config.ENV_FILE_PATH = _TMP / ".env"
core_config.persistent_dir = lambda: _TMP

import dashboard.server as srv  # noqa: E402

srv.DATA_DIR = _TMP
srv.CONFIG_PATH = _TMP / "config" / "config.yaml"
srv.CREDENTIALS_PATH = _TMP / "credentials.json"
srv.ENV_PATH = _TMP / ".env"
srv.MONITOR_STATE_FILE = _TMP / ".aegis_monitor.json"
srv.PBKDF2_ITERATIONS = 1000          # the gate is what's under test, not PBKDF2's cost
srv._settings_unlock_until.clear()
srv._tamper_state.clear()

DB = _TMP / "events.db"
from core.database import EventStore  # noqa: E402

_store = EventStore(str(DB))          # creates the schema the server reads/writes

server = srv.build_server(str(DB), "127.0.0.1", 0)
PORT = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


def call(path, body=None, cookie=None, host=None):
    """-> (status, parsed json or raw text, response headers)"""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method="POST" if data is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw, status, headers = r.read(), r.status, r.headers
    except urllib.error.HTTPError as e:
        raw, status, headers = e.read(), e.code, e.headers
    try:
        return status, json.loads(raw or b"{}"), headers
    except json.JSONDecodeError:
        return status, raw.decode(errors="replace"), headers


def sign_in():
    status, body, headers = call("/api/login", {"username": "admin", "password": "admin"})
    assert status == 200 and body["ok"], (status, body)
    return headers["Set-Cookie"].split(";")[0]


SETTINGS_BODY = {
    "ai": {"provider": "openai-compatible", "base_url": "", "api_key_env": "X_KEY",
           "model": "m", "temperature": 0.2},
    # the whole reason this endpoint is gated: turning this off disables the
    # password gate on Stop Monitoring and on quitting the app
    "tamper_require_password": False,
}

cookie = sign_in()

# --- signed in is NOT enough --------------------------------------------
status, body, _ = call("/api/settings", cookie=cookie)
assert status == 403 and body["settings_locked"], (status, body)
status, body, _ = call("/api/settings", SETTINGS_BODY, cookie=cookie)
assert status == 403 and body["settings_locked"], (status, body)
assert not srv.CONFIG_PATH.exists(), "a locked write must not touch config.yaml"

# trust entries rewrite the same config file -- same gate
status, body, _ = call("/api/trust/add", {"kind": "process_names", "value": "x"}, cookie=cookie)
assert status == 403 and body["settings_locked"], (status, body)

# --- wrong password: refused, logged, counted ---------------------------
status, body, _ = call("/api/settings/unlock", {"password": "nope"}, cookie=cookie)
assert status == 403 and body["tamper_blocked"] and body["attempts"] == 1, (status, body)
rows = _store.recent(5)
assert rows and rows[0]["category"] == "tamper_attempt" and "settings" in rows[0]["summary"], rows[:1]

# --- correct password unlocks, and the unlock is per-session ------------
status, body, _ = call("/api/settings/unlock", {"password": "admin"}, cookie=cookie)
assert status == 200 and body["ok"], (status, body)

status, body, _ = call("/api/settings", cookie=cookie)
assert status == 200 and body["ai"]["api_key_env"], (status, body)
# --- the read carries the countdown, and "Lock now" re-locks on demand ---
assert 0 < body["unlock_expires_in"] <= srv.SETTINGS_UNLOCK_TTL, body
status, _, _ = call("/api/settings/lock", {}, cookie=cookie)
assert status == 200
status, body, _ = call("/api/settings", cookie=cookie)
assert status == 403 and body["settings_locked"], "Lock now must close the gate at once"
status, body, _ = call("/api/settings/unlock", {"password": "admin"}, cookie=cookie)
assert status == 200 and body["ok"], (status, body)

status, body, _ = call("/api/settings", SETTINGS_BODY, cookie=cookie)
assert status == 200 and body["ok"], (status, body)
assert srv.CONFIG_PATH.exists(), "unlocked write should have persisted config.yaml"

other = sign_in()                     # a second session inherits nothing
status, body, _ = call("/api/settings", cookie=other)
assert status == 200, "tamper_require_password is now false -- the gate is off by the user's own choice"

# ...and with tamper protection back on, the second session is locked again.
# Evidence capture is pushed out of reach here on purpose: this test is about
# the gate, and a real capture would drive the screen/camera (core/evidence.py
# has its own self-check for that).
srv.CONFIG_PATH.write_text("tamper_require_password: true\n"
                           "tamper_attempts_before_capture: 99\n"
                           "tamper_evidence_screenshot: false\n", encoding="utf-8")
status, body, _ = call("/api/settings", cookie=other)
assert status == 403 and body["settings_locked"], (status, body)

# --- signing out drops the unlock ---------------------------------------
status, _, _ = call("/api/logout", {}, cookie=cookie)
assert status == 200
assert cookie.split("=", 1)[1] not in srv._settings_unlock_until

# --- lockout after repeated wrong passwords -----------------------------
srv._tamper_state.clear()
fresh = sign_in()
for i in range(srv.LOCKOUT_THRESHOLD):
    status, body, _ = call("/api/settings/unlock", {"password": "wrong"}, cookie=fresh)
    assert status == 403, (i, status, body)
assert body.get("locked") and body["retry_after"] == srv.LOCKOUT_SECONDS, body
# a CORRECT password during the lockout window still has to wait it out
status, body, _ = call("/api/settings/unlock", {"password": "admin"}, cookie=fresh)
assert status == 403 and body.get("locked"), (status, body)

# --- failed sign-ins escalate too (they used to be a free guessing oracle)
srv._tamper_state.clear()
status, body, _ = call("/api/login", {"username": "admin", "password": "wrong"})
assert status == 401 and body["attempts"] == 1 and body["error"] == "invalid credentials", body
assert _store.recent(1)[0]["category"] == "tamper_attempt"

# --- changing the password escalates like every other password prompt ----
# It checks the SAME secret that guards Stop Monitoring and Settings, but it
# used to answer as fast as you could ask -- no damper, no lockout, no timeline
# entry -- so a live session could brute-force it silently right next to a
# Settings unlock that locks out after five.
srv._tamper_state.clear()
pw_session = sign_in()
before = sum(1 for r in _store.recent(200) if r["category"] == "tamper_attempt")
for i in range(srv.LOCKOUT_THRESHOLD):
    status, body, _ = call("/api/settings/password",
                           {"current_password": f"guess{i}", "new_password": "longenough123"},
                           cookie=pw_session)
    assert body["error"] and not body.get("ok"), (i, status, body)
assert body.get("locked"), f"change-password must lock out at {srv.LOCKOUT_THRESHOLD}: {body}"
logged = sum(1 for r in _store.recent(200) if r["category"] == "tamper_attempt") - before
assert logged == srv.LOCKOUT_THRESHOLD, f"every wrong attempt must hit the timeline, got {logged}"
# the correct password waits out the lockout like everywhere else
status, body, _ = call("/api/settings/password",
                       {"current_password": "admin", "new_password": "longenough123"},
                       cookie=pw_session)
assert status == 429 and body.get("locked"), (status, body)

# --- a parallel burst must not outrun the lockout ------------------------
# The lockout is checked before the password, but that check used to sit
# OUTSIDE the lock: a burst streamed past it while the first attempt was still
# being handled, so 20 concurrent guesses rolled through four full 5-strike
# cycles -- counting 20 attempts and capturing evidence four times (four
# screenshots, four contending grabs of one webcam) instead of once.
srv._tamper_state.clear()
burst_session = sign_in()
before = sum(1 for r in _store.recent(400) if r["category"] == "tamper_attempt")
threads = [threading.Thread(
    target=lambda i=i: call("/api/settings/unlock", {"password": f"x{i}"}, cookie=burst_session))
    for i in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
counted = sum(1 for r in _store.recent(400) if r["category"] == "tamper_attempt") - before
assert counted == srv.LOCKOUT_THRESHOLD, \
    f"a burst must stop at the first lockout, not roll through cycles: {counted} counted"
assert srv._tamper_state["settings"]["locked_until"] > time.time(), "burst must leave it locked"

# --- expired tokens don't accumulate ------------------------------------
# Both maps used to be pruned only when a token was looked up again, so a
# session that was signed in and never returned to sat there for the life of
# the process.
# (not clearing _sessions -- `fresh` is still needed by the host checks below)
srv._sessions["stale-token"] = time.time() - 1     # expired a second ago
sign_in()
assert "stale-token" not in srv._sessions, "a new sign-in must sweep expired sessions"

srv._settings_unlock_until.clear()
srv._settings_unlock_until["stale-token"] = time.time() - 1
srv._tamper_state.clear()
status, _, _ = call("/api/settings/unlock", {"password": "admin"}, cookie=sign_in())
assert status == 200
assert "stale-token" not in srv._settings_unlock_until, "a new unlock must sweep expired ones"

# --- DNS-rebinding guard: only localhost Host headers are served --------
status, body, _ = call("/api/stats", cookie=None, host="evil.example.com")
assert status == 403 and "forbidden host" in str(body), (status, body)
# "127.0.0.1:8787.evil.com" has exactly one colon, so splitting on it blindly
# read the host as "127.0.0.1" and served the request.
status, body, _ = call("/api/stats", cookie=None, host=f"127.0.0.1:{PORT}.evil.com")
assert status == 403, f"port must be numeric to be stripped: {status}"
# ...while a hostname differing only in case is the same host (RFC 4343).
status, _, _ = call("/api/stats", cookie=fresh, host=f"LOCALHOST:{PORT}")
assert status == 200, f"host comparison must be case-insensitive: {status}"

server.shutdown()
_store.close()
print("settings-lock self-check: OK")
