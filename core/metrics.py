"""
Aegis -- process-local performance instrumentation.

Exists to answer one question without guessing: when someone says "Aegis feels
slow", which stage is actually slow? The pipeline crosses four boundaries
(collector -> queue -> dispatcher -> SQLite, plus the AI call off to one side,
plus the HTTP server and the browser), and every one of them is a plausible
culprit. Timing them separately turns that into a reading instead of an
argument.

Design notes:

* **Always on.** There is no enable flag. The moment you need this data is the
  moment someone is already complaining, and a switch you have to flip first
  means the incident is over before instrumentation starts. The cost is a
  bounded deque append per measurement (see Timer.record) against event rates
  measured in single digits per second -- unmeasurable next to the SQLite write
  and the AI call it sits beside.
* **Bounded by construction.** Every series is a fixed-length ring buffer, so
  memory is flat no matter how long the process runs. A metrics system that
  leaks while you are diagnosing a leak would be its own bug.
* **Never raises.** Instrumentation that can break the thing it measures is
  worse than none: this module is imported by the dispatcher's queue-draining
  loop, which is the single consumer of every collector's queue. Recording is
  best-effort throughout.
* **Process-local.** METRICS is a per-process singleton. The dispatcher and the
  dashboard's HTTP server each keep their own; when they are separate processes
  (main.py tray mode) the dispatcher publishes its snapshot through the SQLite
  `meta` table, the same read-only channel the heartbeat already uses. See
  dashboard/server.py monitor_metrics().
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from contextlib import contextmanager

# Samples retained per timer. At the dashboard's 2s diagnostics poll this is a
# few minutes of history -- enough to see a spike develop and decay, small
# enough that the percentile sort below stays trivial.
DEFAULT_WINDOW = 120

# Rolling window for rate counters (events/minute is computed over this, then
# normalised, so a 5-minute window smooths bursts without hiding them).
RATE_WINDOW_SECONDS = 300


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile over a pre-sorted list.

    Deliberately not interpolating: these are latency samples read by a human
    hunting outliers, and an interpolated p95 landing between two real
    measurements is a number no request ever actually took.

    Nearest rank is ceil(pct/100 * N), 1-indexed. Note the ceil -- an earlier
    `round(x + 0.5)` spelling was off by one at exact boundaries, because
    Python rounds halves to even: round(95.5) is 96, not 96-as-intended-ceil,
    so p95 of 1..100 returned 96 instead of 95."""
    if not values:
        return 0.0
    rank = max(1, math.ceil(pct / 100 * len(values)))
    return values[min(rank, len(values)) - 1]


class Timer:
    """A bounded series of durations in milliseconds."""

    def __init__(self, window: int = DEFAULT_WINDOW):
        self._samples: deque[float] = deque(maxlen=window)
        self._lock = threading.Lock()
        self._total = 0

    def record(self, ms: float) -> None:
        with self._lock:
            self._samples.append(ms)
            self._total += 1

    def stats(self) -> dict | None:
        with self._lock:
            if not self._samples:
                return None
            values = sorted(self._samples)
            last = self._samples[-1]
            total = self._total
        return {
            "count": total,
            "samples": len(values),
            "last": round(last, 2),
            "avg": round(sum(values) / len(values), 2),
            "p50": round(_percentile(values, 50), 2),
            "p95": round(_percentile(values, 95), 2),
            "max": round(values[-1], 2),
        }

    def recent(self, n: int = 40) -> list[float]:
        """Newest-last, for the diagnostics page's inline bar strips."""
        with self._lock:
            return [round(v, 2) for v in list(self._samples)[-n:]]


class RateCounter:
    """Timestamps of recent marks, trimmed to a rolling window -- so the rate
    reflects now, not an average since process start that a long-idle process
    would flatten to nothing."""

    def __init__(self, window_seconds: int = RATE_WINDOW_SECONDS):
        self._window = window_seconds
        self._marks: deque[float] = deque()
        self._lock = threading.Lock()
        self._total = 0

    def mark(self, n: int = 1) -> None:
        now = time.time()
        with self._lock:
            for _ in range(n):
                self._marks.append(now)
            self._total += n
            self._trim(now)

    def _trim(self, now: float) -> None:
        cutoff = now - self._window
        while self._marks and self._marks[0] < cutoff:
            self._marks.popleft()

    def stats(self) -> dict:
        now = time.time()
        with self._lock:
            self._trim(now)
            in_window = len(self._marks)
            total = self._total
            oldest = self._marks[0] if self._marks else None
        # Normalise over the elapsed window, not the nominal one: a process up
        # for 20 seconds must not report a per-minute rate a third of the truth.
        elapsed = min(self._window, max(1.0, now - oldest)) if oldest else self._window
        return {
            "total": total,
            "window_seconds": self._window,
            "in_window": in_window,
            "per_minute": round(in_window / elapsed * 60, 2),
        }


class Metrics:
    """Named timers, rate counters and gauges for one process."""

    def __init__(self):
        self._timers: dict[str, Timer] = {}
        self._counters: dict[str, RateCounter] = {}
        self._gauges: dict[str, object] = {}
        self._lock = threading.Lock()
        self.started_at = time.time()

    def timer(self, name: str) -> Timer:
        with self._lock:
            t = self._timers.get(name)
            if t is None:
                t = self._timers[name] = Timer()
            return t

    def counter(self, name: str) -> RateCounter:
        with self._lock:
            c = self._counters.get(name)
            if c is None:
                c = self._counters[name] = RateCounter()
            return c

    def gauge(self, name: str, value) -> None:
        with self._lock:
            self._gauges[name] = value

    @contextmanager
    def time(self, name: str):
        """`with METRICS.time("sqlite.events"): ...`

        Records on the way out even if the body raises, then re-raises: a stage
        that fails slowly is exactly the stage you want timed."""
        start = time.perf_counter()
        try:
            yield
        finally:
            try:
                self.timer(name).record((time.perf_counter() - start) * 1000)
            except Exception:
                pass  # never let instrumentation break the caller

    def snapshot(self) -> dict:
        with self._lock:
            timers = dict(self._timers)
            counters = dict(self._counters)
            gauges = dict(self._gauges)
        return {
            "at": time.time(),
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "timers": {k: v.stats() for k, v in timers.items() if v.stats()},
            "series": {k: v.recent() for k, v in timers.items()},
            "counters": {k: v.stats() for k, v in counters.items()},
            "gauges": gauges,
        }


METRICS = Metrics()


def record_collectors(monitors) -> None:
    """Publish which collectors are actually up, by class name.

    Called from both pipelines (main.py's tray mode and desktop_app's
    MonitorPipeline) with the list that genuinely started -- not the list that
    was meant to. A collector that raised on start and got rolled back must not
    appear here, because "which collectors are running?" is precisely the
    question this answers when a whole source of events has silently gone
    missing."""
    try:
        METRICS.gauge("collectors", sorted(m.__class__.__name__ for m in monitors))
    except Exception:
        pass


def rss_mb() -> float | None:
    """Resident memory of THIS process in MB, or None where psutil isn't
    importable. Imported lazily so core.metrics stays usable (and testable)
    without it -- everything else here is stdlib."""
    try:
        import psutil

        return round(psutil.Process().memory_info().rss / (1024 * 1024), 1)
    except Exception:
        return None
