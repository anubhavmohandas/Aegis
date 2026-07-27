"""Two tamper-gate holes, pinned so they can't reopen.

1. THE SEEDED PASSWORD IS A REAL GATE, NOT A BANNER. Aegis ships admin/admin so
   the first sign-in works, and that same password is what guard_protected_action
   checks for Stop Monitoring, Quit, Settings and Delete Evidence. A console that
   merely *suggests* changing it leaves every one of those open to anyone who
   read the README -- and a "please change your password" modal is decoration,
   because the session cookie still opens /api/events and /api/monitor/stop to
   anything that can make an HTTP request. So the server refuses every route but
   change-password and logout until it's actually changed.

2. /api/monitor/restart USED TO BYPASS THE STOP GATE. It needed only a session,
   on the reasoning that "it ends with monitoring RUNNING." It stops first, and
   start_monitor() reports a failed start as JSON rather than raising -- so a
   caller refused by /api/monitor/stop for a wrong password could call restart
   instead and land on monitoring=False with no password, no lockout, no
   timeline entry and no evidence capture. Reproduced below against a pipeline
   whose start() fails, which is what made the old behaviour observable.

No framework needed: `python tests/test_first_run_password.py`.
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

import dashboard.server as srv  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="aegis-firstrun-"))
# Rebind the module-level paths that bound to the real data dir at import time,
# so this never reads or writes the developer's own credentials/config.
srv.DATA_DIR = _TMP
srv.CREDENTIALS_PATH = _TMP / "credentials.json"
srv.CONFIG_PATH = _TMP / "config.yaml"

from core.database import EventStore  # noqa: E402

DB = str(_TMP / "events.db")
EventStore(DB).close()                       # create the schema

# A pipeline whose start() fails on demand -- see the docstring's point 2.
_pipeline = {"running": True, "can_start": True}


def _status():
    return {"running": _pipeline["running"], "started_at": time.time()}


def _start():
    if not _pipeline["can_start"]:
        raise RuntimeError("watched folder vanished")
    _pipeline["running"] = True


def _stop():
    _pipeline["running"] = False


PORT = 8791
_server = srv.build_server(DB, "127.0.0.1", PORT, in_process_monitor=True,
                           monitor_status_callback=_status,
                           monitor_start_callback=_start,
                           monitor_stop_callback=_stop)
threading.Thread(target=_server.serve_forever, daemon=True).start()
time.sleep(0.3)


def _call(path, body=None, cookie=None):
    """-> (status, parsed body, Set-Cookie). Never raises on an HTTP error."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}", data=data,
        headers={"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {})})
    try:
        res = urllib.request.urlopen(req, timeout=10)
        return res.status, json.loads(res.read() or b"{}"), res.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}"), e.headers.get("Set-Cookie")


def _login(password):
    status, body, set_cookie = _call("/api/login", {"username": "admin", "password": password})
    return status, body, (set_cookie or "").split(";")[0]


def test_default_password_blocks_every_route_but_changing_it():
    status, _, cookie = _login("admin")
    assert status == 200 and cookie, "the seeded login must still work -- it's how you get in to fix it"

    # Reading the timeline, unlocking Settings and -- the one that matters --
    # stopping monitoring are all refused while the default is in place.
    for path, body in (("/api/events", None), ("/api/stats", None),
                       ("/api/monitor/stop", {"password": "admin"}),
                       ("/api/monitor/start", {}),
                       ("/api/settings/unlock", {"password": "admin"})):
        status, payload, _ = _call(path, body, cookie)
        assert status == 403 and payload.get("password_change_required"), \
            f"{path} answered {status} on the default password: {payload}"
    assert _pipeline["running"], "a blocked /api/monitor/stop must not have stopped anything"

    # ...and logout stays reachable, so nobody is trapped in the gate.
    status, _, _ = _call("/api/logout", {}, cookie)
    assert status == 200, "logout must stay open while the password gate is up"


def test_short_password_is_refused_then_a_real_one_opens_the_console():
    _, _, cookie = _login("admin")

    status, payload, _ = _call("/api/settings/password",
                               {"current_password": "admin", "new_password": "short"}, cookie)
    assert status == 400 and "8 characters" in payload.get("error", ""), payload
    status, payload, _ = _call("/api/events", None, cookie)
    assert status == 403, "a rejected change must leave the gate closed"

    status, payload, new_cookie = _call(
        "/api/settings/password",
        {"current_password": "admin", "new_password": "a-real-password"}, cookie)
    assert status == 200 and payload.get("ok"), payload
    assert new_cookie, "a successful change must hand the caller a fresh session cookie"

    # Rotating the password ends every session opened with the OLD one -- the
    # single most likely reason to change it is a cookie you no longer trust.
    status, _, _ = _call("/api/events", None, cookie)
    assert status == 401, "the pre-change session must be dead, not merely re-gated"

    session = new_cookie.split(";")[0]
    status, payload, _ = _call("/api/events", None, session)
    assert status == 200 and "events" in payload, payload

    # The old password is genuinely gone.
    assert _login("admin")[0] == 401
    assert _login("a-real-password")[0] == 200


def test_restart_cannot_be_used_to_stop_monitoring_without_the_password():
    """The bypass itself. Settings are locked (tamper_require_password defaults
    on and this session has never unlocked them), and start() is rigged to fail
    -- exactly the conditions under which restart used to leave monitoring off
    for a caller who had just been refused by /api/monitor/stop."""
    _, _, cookie = _login("a-real-password")
    _pipeline["running"] = True
    _pipeline["can_start"] = False

    status, payload, _ = _call("/api/monitor/stop", {"password": "wrong"}, cookie)
    assert status == 403 and payload.get("error") == "incorrect password", payload
    assert _pipeline["running"], "a wrong password must leave monitoring alone"

    status, payload, _ = _call("/api/monitor/restart", {}, cookie)
    assert status == 403 and payload.get("settings_locked"), \
        f"restart must require the Settings unlock, got {status}: {payload}"
    assert _pipeline["running"], \
        "restart stopped monitoring for a caller who never proved the password"

    # With Settings unlocked -- i.e. the real flow, where the button lives --
    # it goes through, and an honest failure is reported rather than swallowed.
    status, payload, _ = _call("/api/settings/unlock", {"password": "a-real-password"}, cookie)
    assert status == 200 and payload.get("ok"), payload
    _pipeline["can_start"] = True
    status, payload, _ = _call("/api/monitor/restart", {}, cookie)
    assert status == 200 and payload.get("running"), payload


if __name__ == "__main__":
    test_default_password_blocks_every_route_but_changing_it()
    test_short_password_is_refused_then_a_real_one_opens_the_console()
    test_restart_cannot_be_used_to_stop_monitoring_without_the_password()
    _server.shutdown()
    print("ok: the default password gates every route, and restart can't bypass the stop gate")
