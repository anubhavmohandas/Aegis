"""Runnable self-check for Ask Aegis (natural-language Q&A over the event log).

Covers the two non-trivial parts:
  1. Retrieval -- _ask_context_events must reach the right events: recent
     activity, all-time keyword matches (a week-old "python" run the recent
     window skips), and tamper attempts found via "monitoring".
  2. The /api/ask route -- gated by a session, validates the question, and
     answers without any AI key configured (the offline fallback, no network).

No framework, no API key, no network: `python tests/test_ask_aegis.py`.
"""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = Path(tempfile.mkdtemp(prefix="aegis-ask-"))
# Redirecting the config paths isn't enough isolation: a provider key exported
# in the developer's own shell still reaches load_config(), and the /api/ask
# check below then makes a real network call and times out at random.
for _k in [k for k in os.environ if k.endswith("_API_KEY")]:
    os.environ.pop(_k)
import core.config as core_config  # noqa: E402

core_config.DEFAULT_CONFIG_PATH = _TMP / "config" / "config.yaml"
core_config.ENV_FILE_PATH = _TMP / ".env"
core_config.persistent_dir = lambda: _TMP
# ...and the pop above is not enough on its own either. load_config() calls
# _load_env_file() every time, whose `path` DEFAULT ARGUMENT bound to the real
# repo .env when the function was defined -- so rebinding ENV_FILE_PATH two
# lines up doesn't reach it, and every load_config() put the developer's key
# straight back into os.environ. That made the /api/ask assertion below (whose
# comment promises the offline fallback and no network hit) issue a live 30s AI
# call against the test's own 10s client timeout. Harmless in production, where
# this is only ever called with the module constant.
core_config._load_env_file = lambda path=None: None

import dashboard.server as srv  # noqa: E402

srv.DATA_DIR = _TMP
srv.CONFIG_PATH = _TMP / "config" / "config.yaml"
srv.CREDENTIALS_PATH = _TMP / "credentials.json"
srv.ENV_PATH = _TMP / ".env"
srv.PBKDF2_ITERATIONS = 1000
srv._tamper_state.clear()
# "admin" as a deliberately chosen password, not the shipped default: while the
# seeded admin/admin is in place the server refuses every route but
# change-password (PW_CHANGE_EXEMPT_PATHS), which /api/ask is not. That gate has
# its own coverage in test_first_run_password.py.
srv._save_credentials(srv._new_credentials("admin", "admin", is_default=False))

DB = _TMP / "events.db"
from core.database import EventStore  # noqa: E402

_store = EventStore(str(DB))
_now = time.time()
# A week-old python run (outside the 2-day recent window -- only the keyword
# search reaches it), a recent USB insert, and a tamper attempt.
_store.insert(source="process", category="process_started",
              summary="New process: python3 (PID 4821)", details={"name": "python3"},
              confidence="certain", severity="low", timestamp=_now - 7 * 86400,
              explanation="Ran a Python program. Likely normal.")
_store.insert(source="usb", category="usb_connected",
              summary="USB connected: SanDisk Ultra", details={"name": "SanDisk Ultra"},
              confidence="certain", severity="medium", timestamp=_now - 3600)
_store.insert(source="tamper", category="tamper_attempt",
              summary="Failed password on protected action: stop_monitoring (attempt 1)",
              details={"action": "stop_monitoring"}, confidence="certain",
              severity="high", timestamp=_now - 1800)

server = srv.build_server(str(DB), "127.0.0.1", 0)
PORT = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


def call(path, body=None, cookie=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 method="POST" if data is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    return status, json.loads(raw or b"{}")


# --- 1. retrieval ----------------------------------------------------------
def summaries(events):
    return " || ".join(e["summary"] for e in events)


ev = srv._ask_context_events(str(DB), "When did python last run?")
assert any("python3" in e["summary"] for e in ev), \
    f"keyword search must reach the week-old python run: {summaries(ev)}"

ev = srv._ask_context_events(str(DB), "Did someone try to disable monitoring?")
assert any(e["source"] == "tamper" for e in ev), \
    f"'monitoring' must surface the tamper attempt: {summaries(ev)}"

ev = srv._ask_context_events(str(DB), "Did anyone connect a USB?")
assert any(e["source"] == "usb" for e in ev), f"'usb' must surface the USB event: {summaries(ev)}"

# The formatted block carries time, severity and the stored explanation note.
block = srv._format_ask_events(srv._ask_context_events(str(DB), "python"))
assert "python3" in block and "(low)" in block and "note: Ran a Python program" in block, block

# Sources: a keyword question ranks the matching event first, and the returned
# rows are full event rows (so the UI can open them without another fetch).
ev = srv._ask_context_events(str(DB), "When did python last run?")
sources = srv._rank_ask_sources(ev, "When did python last run?")
assert sources and "python3" in sources[0]["summary"], \
    f"python must be the top source: {summaries(sources)}"
assert {"id", "timestamp", "summary", "severity", "details_json"} <= set(sources[0]), \
    f"sources must be full event rows: {sorted(sources[0])}"
# "show suspicious activity" has no keyword hits -> severity must float the
# high-severity tamper event above low-severity ambient events.
ssrc = srv._rank_ask_sources(srv._ask_context_events(str(DB), "show suspicious activity"),
                             "show suspicious activity")
assert ssrc[0]["severity"] in ("high", "critical"), \
    f"suspicious-activity sources should lead with high/critical: {summaries(ssrc)}"
# Chit-chat gets the reply alone -- no "here are 8 high-severity events" under a
# "thanks". Real questions must keep their sources, including the ones whose
# words are all stopwords ("what happened today").
for greeting in ("hi", "Thanks!", "ok", "Theek hai", "thanks yaar", "ok cool"):
    assert srv._rank_ask_sources(ev, greeting) == [], f"{greeting!r} must return no sources"
assert srv._rank_ask_sources(ev, "what happened today?"), \
    "a real question must still get sources even when every word is a stopword"

# --- 2. the /api/ask route -------------------------------------------------
status, _ = call("/api/ask", {"question": "hi"})           # no session
assert status == 401, f"ask must require auth, got {status}"

status, body = call("/api/login", {"username": "admin", "password": "admin"})
assert status == 200 and body.get("ok"), body
cookie = None
# reuse the login cookie
_login = urllib.request.Request(BASE + "/api/login",
                                data=json.dumps({"username": "admin", "password": "admin"}).encode(),
                                method="POST")
_login.add_header("Content-Type", "application/json")
with urllib.request.urlopen(_login, timeout=10) as r:
    cookie = r.headers["Set-Cookie"].split(";")[0]

status, body = call("/api/ask", {"question": ""}, cookie=cookie)
assert status == 400 and "error" in body, f"empty question must 400: {status} {body}"

status, body = call("/api/ask", {"question": "x" * (srv.ASK_MAX_QUESTION + 1)}, cookie=cookie)
assert status == 400 and "error" in body, f"over-long question must 400: {status} {body}"

# A real question: no AI key configured, so the answer is the offline fallback
# (no network hit), but the route still runs retrieval and returns a count.
status, body = call("/api/ask", {"question": "What happened today?"}, cookie=cookie)
assert status == 200, f"{status} {body}"
assert "answer" in body and isinstance(body.get("events_considered"), int), body
assert body["events_considered"] >= 1, body
assert isinstance(body.get("sources"), list) and body["sources"], f"answer must carry sources: {body}"
assert "summary" in body["sources"][0], body["sources"][0]

print("ask_aegis self-check: OK")
