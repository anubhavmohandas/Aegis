"""Runnable self-check for the duplicate monitoring-gap fix.

A second startup that races the first (settings restart, or a second instance
on the shared DB) must NOT re-emit the gap, because _check_monitoring_gap now
advances the shared heartbeat before the slow AI-backed _handle.

No framework: `python tests/test_monitoring_gap.py`.
"""
import platform, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.dispatcher import (Dispatcher, HEARTBEAT_KEY, GAP_THRESHOLD_SECONDS,
                             _lid_closed_during)


class FakeStore:
    """Just the meta table the gap check touches, shared across dispatchers."""
    def __init__(self): self.meta = {}
    def set_meta(self, k, v): self.meta[k] = v
    def get_meta(self, k): return self.meta.get(k)


def _dispatcher(store):
    # Bypass __init__ (pulls in AI/rules/enricher); wire only what the gap
    # check and _heartbeat use, and record every _handle instead of running it.
    d = Dispatcher.__new__(Dispatcher)
    d.store = store
    d._last_heartbeat = 0.0
    d.handled = []
    d._handle = lambda event: d.handled.append(event)
    return d


def test_no_duplicate_on_second_startup():
    store = FakeStore()
    # A stale heartbeat from ~16 min ago -> a real gap on first startup.
    store.set_meta(HEARTBEAT_KEY, str(time.time() - (GAP_THRESHOLD_SECONDS + 600)))

    d1 = _dispatcher(store)
    d1._check_monitoring_gap()
    assert len(d1.handled) == 1, "first startup should report the gap once"

    # Second startup races before d1's loop runs -- shares the same DB.
    d2 = _dispatcher(store)
    d2._check_monitoring_gap()
    assert d2.handled == [], "second startup must not re-emit the gap (heartbeat advanced)"


def test_lid_detection_never_raises_and_bounds_window():
    # A window in the far future can't contain any past sleep event -> False,
    # on every platform (non-macOS short-circuits to False too).
    assert _lid_closed_during(time.time() + 86400, time.time() + 90000) is False
    if platform.system() == "Darwin":
        # This Mac has clamshell sleeps in its pmset history; an all-of-time
        # window must find at least one.
        assert _lid_closed_during(0, time.time()) is True


if __name__ == "__main__":
    test_no_duplicate_on_second_startup()
    test_lid_detection_never_raises_and_bounds_window()
    print("ok")
