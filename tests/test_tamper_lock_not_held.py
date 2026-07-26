"""Runnable self-check: evidence capture must not hold the global tamper lock.

_register_failed_attempt used to run its whole body -- DB write AND
capture_incident() -- inside _tamper_lock. capture_incident shells out to
screencapture, spends up to 8s settling a webcam and 3s fetching the public IP,
so ONE wrong password froze every other gated action (Settings, Delete
Evidence, sign-in) for that whole stretch; on macOS the quit gate runs on the
Cocoa main thread, so the window beachballed with it.

The fix claims the capture under the lock ("this attempt is the one") and
performs it outside. Both halves need pinning, because getting either wrong is
silent: keep the capture inside and it's slow again, drop the claim and a
brute-force burst fires N concurrent captures at one webcam.

No framework: `python tests/test_tamper_lock_not_held.py`.
"""
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.evidence as evidence  # noqa: E402
import dashboard.server as srv  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="aegis-tamper-lock-"))
srv.DashboardHandler.db_path = str(_TMP / "events.db")

from core.database import EventStore  # noqa: E402

_store = EventStore(srv.DashboardHandler.db_path)   # create the schema

CAPTURE_SECONDS = 1.5
captures = []


def _slow_capture(*, reason, attempts, store, config=None, extra_context=None):
    """Stand-in for the real screenshot/webcam/public-IP capture."""
    captures.append(reason)
    time.sleep(CAPTURE_SECONDS)
    return {"id": len(captures)}


evidence.capture_incident = _slow_capture   # server.py imports it inside the function


class _Cfg:
    tamper_require_password = True
    tamper_attempts_before_capture = 3


def _fail(action):
    return srv._register_failed_attempt(action, _Cfg())


def test_a_slow_capture_does_not_block_other_actions():
    srv._tamper_state.clear()
    captures.clear()

    _fail("stop_monitoring")            # attempt 1
    _fail("stop_monitoring")            # attempt 2 -- still under the threshold

    # Attempt 3 crosses tamper_attempts_before_capture, so it captures.
    result = {}
    capturing = threading.Thread(target=lambda: result.update(_fail("stop_monitoring")))
    capturing.start()
    time.sleep(0.6)                     # past the 0.4s damper, well inside the capture

    # A DIFFERENT gated action must get its answer now, not after the capture.
    started = time.time()
    _fail("settings")
    waited = time.time() - started
    capturing.join()

    assert result.get("evidence_captured"), f"attempt 3 should have captured: {result}"
    assert result.get("incident_id") == 1, result
    # 0.4s damper + slack; the old code made this wait out the whole capture.
    assert waited < CAPTURE_SECONDS, \
        f"a second action waited {waited:.2f}s on the capture -- the lock is still held across it"


def test_a_parallel_burst_still_captures_exactly_once():
    # The reason the lock exists at all: 20 threads each reading "not captured
    # yet" before any of them wrote used to fire 18 concurrent captures.
    srv._tamper_state.clear()
    captures.clear()
    threads = [threading.Thread(target=_fail, args=("burst",)) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(captures) == 1, f"a burst must capture exactly once, got {len(captures)}"
    # ...and the burst still stops at the first lockout rather than rolling cycles.
    # Count only THIS action's rows -- the test above left its own behind.
    logged = sum(1 for r in _store.recent(200)
                 if r["category"] == "tamper_attempt" and "burst" in r["summary"])
    assert logged == srv.LOCKOUT_THRESHOLD, f"expected {srv.LOCKOUT_THRESHOLD} attempts, got {logged}"
    assert srv._tamper_state["burst"]["locked_until"] > time.time(), "burst must leave it locked"


if __name__ == "__main__":
    test_a_slow_capture_does_not_block_other_actions()
    test_a_parallel_burst_still_captures_exactly_once()
    _store.close()
    print("ok: capture runs outside the lock, and a burst still captures once")
