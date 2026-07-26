"""Runnable self-check: a slow AI call must not delay the timeline.

The dashboard reads persisted rows, so an event has to reach SQLite the moment
it arrives -- not after the explainer's network round-trip, and not behind the
previous event's round-trip. That regression is invisible in normal use (it
looks like "the dashboard is a bit laggy"), so it gets a test.

No framework: `python tests/test_explain_is_async.py`.
"""
import sys, threading, time
from pathlib import Path
from queue import Queue

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.dispatcher import Dispatcher
from core.events import EventCategory, MonitorEvent

SLOW_SECONDS = 1.0


class FakeStore:
    def __init__(self):
        self.rows = {}
        self._next = 1
        self._lock = threading.Lock()

    def insert(self, **kw):
        with self._lock:
            row_id, self._next = self._next, self._next + 1
            self.rows[row_id] = dict(kw, _inserted_at=time.monotonic())
            return row_id

    def update_explanation(self, event_id, explanation):
        with self._lock:
            self.rows[event_id]["explanation"] = explanation


class SlowExplainer:
    """Stands in for a sluggish endpoint."""
    def explain(self, event, severity="medium"):
        time.sleep(SLOW_SECONDS)
        return f"explained: {event.summary}"


def _dispatcher(store, tmp_log):
    from core.rule_engine import RuleEngine
    from core.severity_engine import SeverityEngine
    from concurrent.futures import ThreadPoolExecutor

    class Cfg:
        notify_enabled = False
        notify_min_severity = "low"
        log_path = str(tmp_log)

    d = Dispatcher.__new__(Dispatcher)
    d.config = Cfg()
    d.store = store
    d.explainer = SlowExplainer()
    d.rules = RuleEngine([], [], [])
    d.severity = SeverityEngine()
    d.enricher = None
    d.in_queue = Queue()
    d._recent_summaries = __import__("collections").deque()
    d._minute_bucket = __import__("collections").deque()
    d._stop = threading.Event()
    d._log_lock = threading.Lock()
    d._last_heartbeat = time.time()
    d._explain_pool = ThreadPoolExecutor(max_workers=3)
    return d


def _event(n):
    return MonitorEvent(category=EventCategory.FILE_CREATED,
                        summary=f"File created: /tmp/aegis-test-{n}.txt",
                        details={"path": f"/tmp/aegis-test-{n}.txt"},
                        source="folder", confidence="certain")


def test_rows_land_before_the_ai_answers():
    tmp_log = Path(__file__).parent / "_explain_async_test.log"
    store = FakeStore()
    d = _dispatcher(store, tmp_log)
    try:
        started = time.monotonic()
        for n in range(3):
            d._handle(_event(n))
        queue_drain = time.monotonic() - started

        # Three events, each costing SLOW_SECONDS at the explainer. If the AI
        # call were still inline, draining them would take 3 * SLOW_SECONDS.
        assert queue_drain < SLOW_SECONDS, (
            f"dispatcher blocked {queue_drain:.2f}s on the AI -- the queue must "
            f"drain without waiting for explanations")
        assert len(store.rows) == 3, f"expected 3 rows persisted immediately, got {len(store.rows)}"
        assert all(r["explanation"] is None for r in store.rows.values()), \
            "rows should be written before the explanation exists"

        # ...and the explanations still arrive, filled into the same rows.
        d._explain_pool.shutdown(wait=True)
        assert len(store.rows) == 3, "explaining must UPDATE rows, never insert duplicates"
        for row in store.rows.values():
            assert row["explanation"] == f"explained: {row['summary']}", row
    finally:
        d._explain_pool.shutdown(wait=False)
        tmp_log.unlink(missing_ok=True)
    print("ok: timeline rows persist immediately; explanations land afterwards")


if __name__ == "__main__":
    test_rows_land_before_the_ai_answers()
