"""Runnable self-check: the POST router's auth gate is STRUCTURAL.

Why this test exists: every protected POST route used to carry its own copy of

    if not self._authed():
        self._send_json({"error": "authentication required"}, status=401)
        return

-- thirteen hand-copied blocks, i.e. thirteen chances for the next route added
to the file to be the one that forgets, on a server whose endpoints stop
monitoring and delete tamper evidence. The gate is now hoisted to the top of
_handle_post (the shape _handle_get already used), so a new route is
authenticated by construction and anything public has to be lifted above the
gate deliberately.

That is only true as long as nobody re-adds a route above the gate by accident,
which is exactly what this asserts: the list below is every POST path the server
recognises, and each one must 401 without a session. A new endpoint added below
the gate passes for free; one added above it fails here.

Also covers _json_body(), which replaced ten copies of the Content-Length +
json.loads dance: a JSON body that parses to a non-object (`[1,2,3]`) used to
reach `body.get(...)` and raise AttributeError out through do_POST -- which
catches only BrokenPipeError -- so the browser saw a dropped connection instead
of a 400.

No framework: `python tests/test_post_auth_gate.py`.
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

_TMP = Path(tempfile.mkdtemp(prefix="aegis-postgate-"))

import dashboard.server as S  # noqa: E402

# Redirect every writable path at a temp dir BEFORE anything touches the real one.
S.DATA_DIR = _TMP
S.CONFIG_PATH = _TMP / "config.yaml"
S.CREDENTIALS_PATH = _TMP / "credentials.json"
S.ENV_PATH = _TMP / ".env"
S.PBKDF2_ITERATIONS = 1000        # the gate is what's under test, not PBKDF2's cost
S._sessions.clear()
S._settings_unlock_until.clear()
S._tamper_state.clear()

from core.database import EventStore  # noqa: E402

_DB = str(_TMP / "events.db")
EventStore(_DB).close()

# A deliberately-chosen password (is_default=False), so the first-run
# password-change gate doesn't mask the 401s this test is about.
S._save_credentials(S._new_credentials("admin", "hunter2", is_default=False))

_server = S.build_server(_DB, "127.0.0.1", 0)
_PORT = _server.server_address[1]
threading.Thread(target=_server.serve_forever, daemon=True).start()
time.sleep(0.3)
_BASE = f"http://127.0.0.1:{_PORT}"

# Every POST path the router recognises. Keep in sync with _handle_post -- a
# route missing from here isn't covered, so add new ones as you add them there.
PROTECTED_POSTS = [
    "/api/settings",
    "/api/settings/unlock",
    "/api/settings/lock",
    "/api/settings/password",
    "/api/monitor/start",
    "/api/monitor/stop",
    "/api/monitor/restart",
    "/api/incidents/review",
    "/api/incidents/delete",
    "/api/trust/add",
    "/api/enrich/test",
    "/api/update/install",
    "/api/ask",
    "/api/evidence/open-folder",
]


def _post(path, body=None, cookie=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    req = urllib.request.Request(_BASE + path, data=data, method="POST")
    if data:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}"), r
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}"), e


def test_every_protected_post_refuses_without_a_session():
    for path in PROTECTED_POSTS:
        status, body, _ = _post(path, {})
        assert status == 401, f"{path} answered {status}, not 401 -- is it above the auth gate?"
        assert body.get("error") == "authentication required", (path, body)
    # An unrecognised path must hit the gate too, not leak 404-vs-401 as a way
    # to enumerate which endpoints exist before signing in.
    assert _post("/api/does-not-exist", {})[0] == 401


def test_logout_stays_ahead_of_the_gate():
    """Logging out only ever reduces access, so an expired session must still
    be able to clear its own cookie rather than get a 401 on the way out."""
    status, body, resp = _post("/api/logout")
    assert status == 200 and body == {"ok": True}, (status, body)
    assert "Max-Age=0" in resp.headers.get("Set-Cookie", "")


def _sign_in():
    status, body, resp = _post("/api/login", {"username": "admin", "password": "hunter2"})
    assert status == 200 and body.get("ok"), (status, body)
    return resp.headers["Set-Cookie"].split(";")[0]


def test_authenticated_request_passes_the_gate():
    cookie = _sign_in()
    # Past the 401 and onto the SECOND gate (the Settings unlock) -- which is
    # the proof the hoisted check let an authenticated caller through rather
    # than blanket-refusing everything.
    status, body, _ = _post("/api/settings", {}, cookie=cookie)
    assert status == 403 and body.get("settings_locked"), (status, body)


def test_non_object_json_body_is_a_400_not_a_dropped_connection():
    cookie = _sign_in()
    for raw in (b"[1,2,3]", b'"a string"', b"null", b"{not json at all"):
        status, body, _ = _post("/api/settings/password", cookie=cookie, raw=raw)
        assert status == 400, f"{raw!r} answered {status}, not 400"
        assert body.get("error") == "invalid JSON body", (raw, body)


def test_lenient_routes_read_a_bad_body_as_no_fields():
    """The other _json_body style: a malformed body means "no password supplied",
    which the tamper gate then refuses on its own terms (403) -- never a 500."""
    cookie = _sign_in()
    status, _, _ = _post("/api/monitor/stop", cookie=cookie, raw=b"{not json")
    assert status in (200, 403), status


def test_oversized_body_is_capped():
    cookie = _sign_in()
    status, _, _ = _post("/api/ask", cookie=cookie,
                         raw=b'{"question":"' + b"x" * 200_000 + b'"}')
    assert status in (200, 400), status


def test_no_pipeline_mode_refuses_instead_of_pretending():
    """Standalone `python dashboard/server.py` has no MonitorPipeline to drive.
    It must say so rather than report a status it cannot know -- this replaced
    the old subprocess-spawning/pid-hunting branch."""
    assert S.monitor_status()["managed"] == "unmanaged"
    assert S.monitor_status()["running"] is False
    assert "not managed" in S.start_monitor().get("error", "")
    assert "not managed" in S.stop_monitor().get("error", "")


if __name__ == "__main__":
    test_every_protected_post_refuses_without_a_session()
    test_logout_stays_ahead_of_the_gate()
    test_authenticated_request_passes_the_gate()
    test_non_object_json_body_is_a_400_not_a_dropped_connection()
    test_lenient_routes_read_a_bad_body_as_no_fields()
    test_oversized_body_is_capped()
    test_no_pipeline_mode_refuses_instead_of_pretending()
    _server.shutdown()
    print("ok: POST auth gate is structural, bodies validate, no-pipeline mode is honest")
