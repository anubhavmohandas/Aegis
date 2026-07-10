"""
Pulls MonitorEvents off the shared queue, dedupes, classifies severity,
optionally gates through the rule engine, rate-limits what's left, sends
survivors to the AI explainer, notifies the user, and persists everything
(flat log + SQLite) regardless of outcome.

PIPELINE ORDER (and why it's in this order, not the naive Event -> AI):

    Queue -> dedupe -> rule engine -> severity engine -> rate limit -> AI
             -> notify -> persist

Rate limiting sits AFTER severity classification, not before, for one
specific reason: a burst of low-severity noise (an installer spawning
twenty child processes) should hit the cap, but a single high/critical
severity event should not get silently dropped just because it happened to
land inside a noisy 60-second window. High/critical events are exempt from
the rate limit. This is the concrete benefit of computing severity locally
before the AI call, not just a diagram exercise.

RULE ENGINE EXISTS TO CUT COST/LATENCY/EXPOSURE, NOT TO MAKE SECURITY CALLS:
see core/rule_engine.py for why it's a user-configured opt-in allowlist, not
a built-in "known safe" database.

SEVERITY IS A LOCAL HEURISTIC, NOT AN AI JUDGMENT: see core/severity_engine.py
-- it's deliberately conservative (defaults to "medium," never "low," for
anything it doesn't have a specific reason to downgrade or upgrade).

EVERY EVENT IS PERSISTED REGARDLESS OF OUTCOME: deduped, rate-limited, and
rule-skipped events are all still written to the flat log and the SQLite
event store. Only the AI explanation step is ever skipped -- the audit trail
is never skipped.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from queue import Empty, Queue

from .ai_explainer import AIExplainer
from .config import AppConfig
from .database import EventStore
from .events import MonitorEvent
from .notifier import notify
from .rule_engine import RuleEngine
from .severity_engine import SeverityEngine

logger = logging.getLogger("aegis.dispatcher")

# Hard ceiling independent of poll_interval_seconds -- protects against a
# misconfigured or malicious flood regardless of other settings.
MAX_EVENTS_PER_MINUTE = 20
DEDUPE_WINDOW_SECONDS = 30
RATE_LIMIT_EXEMPT_SEVERITIES = {"high", "critical"}


class Dispatcher:
    def __init__(self, in_queue: Queue, config: AppConfig, event_store: EventStore | None = None):
        self.in_queue = in_queue
        self.config = config
        self.explainer = AIExplainer(config)
        self.rules = RuleEngine(config.trusted_process_names, config.trusted_usb_ids)
        self.severity = SeverityEngine()
        self.store = event_store or EventStore(config.db_path)
        self._recent_summaries: deque[tuple[str, float]] = deque()
        self._minute_bucket: deque[float] = deque()
        self._stop = threading.Event()
        self._log_lock = threading.Lock()

    def run_forever(self):
        while not self._stop.is_set():
            try:
                event = self.in_queue.get(timeout=1)
            except Empty:
                continue
            self._handle(event)

    def stop(self):
        self._stop.set()

    def _handle(self, event: MonitorEvent):
        self._log_raw(event)

        if self._is_duplicate(event):
            logger.debug("Suppressed duplicate event: %s", event.summary)
            self._persist(event, severity="low", explanation=None, ai_skipped=True,
                          risk_hint="duplicate_suppressed")
            return

        verdict = self.rules.evaluate(event)
        severity = self.severity.evaluate(event, verdict)

        if verdict.skip_ai:
            logger.info("Rule engine skipped AI call (%s): %s", verdict.reason, event.summary)
            notify(self._title_for(event, severity), verdict.canned_explanation or event.summary)
            self._persist(event, severity=severity, explanation=verdict.canned_explanation,
                          ai_skipped=True, risk_hint=verdict.reason)
            return

        if severity not in RATE_LIMIT_EXEMPT_SEVERITIES and not self._under_rate_limit():
            logger.warning("Rate limit hit (%s/min) -- skipping AI call for: %s",
                            MAX_EVENTS_PER_MINUTE, event.summary)
            notify("Aegis (rate-limited)", event.summary)
            self._persist(event, severity=severity, explanation=None, ai_skipped=True,
                          risk_hint="rate_limited")
            return

        explanation = self.explainer.explain(event, severity)
        notify(self._title_for(event, severity), explanation)
        self._persist(event, severity=severity, explanation=explanation, ai_skipped=False)

    def _title_for(self, event: MonitorEvent, severity: str) -> str:
        base = {
            "process": "New process started",
            "usb": "USB device change",
            "startup": "Startup programs changed",
            "folder": "Watched folder changed",
        }.get(event.source, "System event")
        return f"{base} [{severity.upper()}]"

    def _is_duplicate(self, event: MonitorEvent) -> bool:
        now = time.time()
        # drop expired entries
        while self._recent_summaries and now - self._recent_summaries[0][1] > DEDUPE_WINDOW_SECONDS:
            self._recent_summaries.popleft()
        for summary, ts in self._recent_summaries:
            if summary == event.summary:
                return True
        self._recent_summaries.append((event.summary, now))
        return False

    def _under_rate_limit(self) -> bool:
        now = time.time()
        while self._minute_bucket and now - self._minute_bucket[0] > 60:
            self._minute_bucket.popleft()
        if len(self._minute_bucket) >= MAX_EVENTS_PER_MINUTE:
            return False
        self._minute_bucket.append(now)
        return True

    def _log_raw(self, event: MonitorEvent):
        # Every event is logged regardless of dedupe/rate-limit/AI outcome --
        # the AI layer can fail or be throttled, the audit trail should not be.
        with self._log_lock:
            with open(self.config.log_path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {event.source} | {event.summary}\n")

    def _persist(self, event: MonitorEvent, severity: str, explanation: str | None, ai_skipped: bool,
                 risk_hint: str | None = None):
        try:
            self.store.insert(
                source=event.source,
                category=event.category.value,
                summary=event.summary,
                details=event.details,
                confidence=event.confidence,
                severity=severity,
                explanation=explanation,
                risk_hint=risk_hint,
                ai_skipped=ai_skipped,
                timestamp=event.timestamp,
            )
        except Exception as e:
            # DB failure must never crash the monitor loop -- the flat log
            # (_log_raw, above) already has this event regardless.
            logger.error("Failed to persist event to SQLite: %s", e)
