"""Runnable self-check for the performance instrumentation behind the hidden
diagnostics page.

Three properties matter here, and only one of them is about numbers:

1. The stats are *right*. A p95 that is quietly off by one rank sends someone
   hunting the wrong stage, which is worse than having no diagnostics at all --
   they'd at least know they were guessing. (This is a real regression guard:
   the first cut used `round(pct/100*N + 0.5)`, and Python's round-half-to-even
   made p95 of 1..100 come out as 96.)

2. Instrumentation never breaks the thing it measures. core/metrics.py is
   imported by the dispatcher's queue-draining loop -- the single consumer of
   every collector's queue -- so a metrics bug there stops monitoring.

3. The dashboard and the monitor stay separated. In desktop_app mode both run
   in ONE process and therefore share the METRICS singleton, so the endpoint
   filtering server metrics from monitor metrics is doing real work, not just
   passing data through. That's the case this asserts.

No framework: `python tests/test_diagnostics.py`.
"""
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = Path(tempfile.mkdtemp(prefix="aegis-diagnostics-"))
import core.config as core_config  # noqa: E402

core_config.DEFAULT_CONFIG_PATH = _TMP / "config" / "config.yaml"

from core.metrics import (Metrics, RateCounter, Timer,  # noqa: E402
                          _percentile, record_collectors)


# --- 1. the numbers -----------------------------------------------------------

def test_percentiles_are_nearest_rank():
    values = list(range(1, 101))
    assert _percentile(values, 50) == 50, f"p50 of 1..100 should be 50, got {_percentile(values, 50)}"
    assert _percentile(values, 95) == 95, (
        f"p95 of 1..100 should be 95, got {_percentile(values, 95)} -- "
        "nearest rank is ceil(p/100*N), and round() gets this wrong at .5")
    assert _percentile(values, 100) == 100, "p100 is the max"


def test_percentile_edges():
    assert _percentile([], 50) == 0.0, "empty series must not IndexError"
    assert _percentile([7], 95) == 7, "a single sample is every percentile"
    assert _percentile([1, 2], 95) == 2, "p95 of two samples rounds up to the second"


def test_timer_is_bounded_but_counts_everything():
    t = Timer(window=10)
    for i in range(100):
        t.record(float(i))
    stats = t.stats()
    assert len(t._samples) == 10, "the ring buffer must not grow without bound"
    assert stats["count"] == 100, "lifetime count survives trimming"
    assert stats["samples"] == 10, "percentiles describe the retained window"
    assert stats["last"] == 99.0, "last is the most recent sample, not the largest"
    assert Timer().stats() is None, "an unused timer reports None, not a fake zero"


def test_rate_counter_trims_and_normalises():
    c = RateCounter(window_seconds=1)
    c.mark()
    assert c.stats()["in_window"] == 1
    time.sleep(1.2)
    stats = c.stats()
    assert stats["in_window"] == 0, "marks outside the window stop counting toward the rate"
    assert stats["total"] == 1, "...but the lifetime total is never trimmed"


# --- 2. instrumentation must not break its caller ------------------------------

def test_timing_a_failing_block_records_and_reraises():
    m = Metrics()
    try:
        with m.time("boom"):
            raise ValueError("stage blew up")
    except ValueError:
        pass
    else:
        raise AssertionError("m.time() swallowed the caller's exception")
    assert m.timer("boom").stats()["samples"] == 1, (
        "a stage that fails slowly is exactly the one worth timing")


def test_concurrent_records_are_not_lost():
    m = Metrics()

    def hammer():
        for _ in range(2000):
            m.timer("t").record(1.0)
            m.counter("c").mark()

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.timer("t").stats()["count"] == 16000, "timer lost samples under contention"
    assert m.counter("c").stats()["total"] == 16000, "counter lost marks under contention"


def test_record_collectors_never_raises():
    record_collectors(None)          # not iterable
    record_collectors([object()])    # no useful __name__ path
    # Reaching here at all is the assertion: a bad call site must not take down
    # the pipeline that called it.


def test_snapshot_survives_json():
    """The dispatcher ships this through the meta table as a JSON string."""
    m = Metrics()
    m.timer("dispatch").record(1.5)
    m.counter("events_ingested").mark()
    m.gauge("queue_depth", 3)
    m.gauge("collectors", ["MacProcessMonitor"])
    blob = json.dumps(m.snapshot())
    back = json.loads(blob)
    assert back["gauges"]["queue_depth"] == 3
    assert back["timers"]["dispatch"]["samples"] == 1
    assert back["counters"]["events_ingested"]["total"] == 1


# --- 3. the endpoint ----------------------------------------------------------

def _server(db_path):
    import dashboard.server as S

    S.DATA_DIR = _TMP
    S.CONFIG_PATH = _TMP / "config.yaml"
    S.CREDENTIALS_PATH = _TMP / "credentials.json"
    S.MONITOR_STATE_FILE = _TMP / ".aegis_monitor.json"
    S.DashboardHandler.db_path = db_path
    return S


def test_server_panel_excludes_monitor_timers():
    """The separation that makes desktop_app mode readable.

    There, the dispatcher and the HTTP server are the same process and share one
    METRICS singleton -- so without filtering, 'Dashboard server' would list the
    AI round trip and the diagnostics page would blame the console for a slow
    model."""
    from core.database import EventStore

    db = str(_TMP / "panel.db")
    EventStore(db)
    S = _server(db)

    # Simulate the shared-singleton case: both halves recorded in one process.
    S.METRICS.timer("sqlite_events").record(2.0)
    S.METRICS.timer("http GET /api/stats").record(1.0)
    S.METRICS.timer("ai_explain").record(9000.0)     # monitor-side
    S.METRICS.timer("dispatch").record(3.0)          # monitor-side

    d = S.diagnostics(db)
    server_timers = set(d["server"]["timers"])
    assert "sqlite_events" in server_timers, "server panel lost its own SQLite timing"
    assert "http GET /api/stats" in server_timers, "server panel lost its route timing"
    assert "ai_explain" not in server_timers, "AI latency leaked into the dashboard panel"
    assert "dispatch" not in server_timers, "dispatch time leaked into the dashboard panel"


def test_monitor_snapshot_states():
    from core.database import EventStore

    db = str(_TMP / "states.db")
    store = EventStore(db)
    S = _server(db)

    assert S.diagnostics(db)["monitor"]["available"] is False, (
        "with nothing published, the page must say so rather than show zeros "
        "that look like a healthy idle pipeline")

    store.set_meta("metrics_snapshot", json.dumps({
        "at": time.time(), "timers": {}, "series": {}, "gauges": {}, "counters": {},
        "uptime_seconds": 5}))
    fresh = S.diagnostics(db)["monitor"]
    assert fresh["available"] is True and fresh["stale"] is False, "a just-written snapshot is fresh"

    store.set_meta("metrics_snapshot", json.dumps({
        "at": time.time() - 600, "timers": {}, "series": {}, "gauges": {}, "counters": {},
        "uptime_seconds": 5}))
    stale = S.diagnostics(db)["monitor"]
    assert stale["stale"] is True, "a 10-minute-old snapshot must be flagged, not shown as current"

    store.set_meta("metrics_snapshot", "{ not json")
    broken = S.diagnostics(db)["monitor"]
    assert broken["available"] is False, "corrupt telemetry degrades the panel, never 500s the page"


def test_http_labels_are_bounded():
    """self.path is attacker-controlled; an unbounded label set would turn this
    instrumentation into a memory leak."""
    S = _server(str(_TMP / "labels.db"))
    before = set(S.METRICS.snapshot()["timers"])
    for i in range(50):
        S._record_http("GET", f"/wat/{i}/../%2e%2e/{i}", time.perf_counter())
    added = set(S.METRICS.snapshot()["timers"]) - before
    assert added <= {"http other", "http static", "http all"}, (
        f"unrecognised paths must collapse into a fixed bucket, got {added}")


if __name__ == "__main__":
    test_percentiles_are_nearest_rank()
    test_percentile_edges()
    test_timer_is_bounded_but_counts_everything()
    test_rate_counter_trims_and_normalises()
    test_timing_a_failing_block_records_and_reraises()
    test_concurrent_records_are_not_lost()
    test_record_collectors_never_raises()
    test_snapshot_survives_json()
    test_server_panel_excludes_monitor_timers()
    test_monitor_snapshot_states()
    test_http_labels_are_bounded()
    print("ok")
