"""
Pulls MonitorEvents off the shared queue, dedupes, classifies severity,
optionally gates through the rule engine, rate-limits what's left, sends
survivors to the AI explainer, notifies the user, and persists everything
(flat log + SQLite) regardless of outcome.

PIPELINE ORDER (and why it's in this order, not the naive Event -> AI):

    Queue -> dedupe -> rule engine -> severity engine -> rate limit
          -> enrichment -> AI -> notify -> persist

Enrichment (core/enrichment.py, opt-in) sits between rate limiting and the
AI call: it only runs for events that are actually about to be explained
(deduped/trusted/rate-limited events never trigger an off-box lookup), and
its evidence has to exist before the prompt is built. It can only ever add
context -- every enrichment failure mode leaves the event exactly as it was.

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
from .enrichment import ThreatEnricher
from .events import MonitorEvent
from .notifier import notify
from .rule_engine import RuleEngine
from .severity_engine import SEVERITY_ORDER, SeverityEngine

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
        self.rules = RuleEngine(config.trusted_process_names, config.trusted_usb_ids,
                                 config.trusted_process_hashes)
        self.severity = SeverityEngine()
        self.enricher = ThreatEnricher(config) if config.enrich_enabled else None
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
            # One bad event must never kill this thread: it's the single
            # consumer of every collector's queue, it runs as a daemon, and
            # its death has no visible symptom -- the monitors keep queueing
            # into a queue nobody drains while the app looks healthy. That
            # "silently stops monitoring while looking fine" failure mode is
            # the exact thing every collector in this codebase already guards
            # its own threads against; the central loop was the one place
            # still missing the guard.
            try:
                self._handle(event)
            except Exception:
                logger.exception("Unhandled error dispatching event %r -- "
                                 "event skipped, dispatcher still running", event.summary)

    def stop(self):
        self._stop.set()

    # --- pipeline entry point -------------------------------------------
    # Decomposed into one method per stage (v2 cleanup -- this was previously
    # one long _handle() body). Each stage either returns a terminal verdict
    # (persist-and-stop) or hands off to the next stage; the shape of that
    # handoff is deliberately uniform ("_StageResult") so the order documented
    # at the top of this file is enforced by the code, not just the comments.

    def _handle(self, event: MonitorEvent):
        self._log_raw(event)

        if self._stage_dedupe(event):
            return

        verdict, severity = self._stage_classify(event)

        if self._stage_rule_gate(event, verdict, severity):
            return

        if self._stage_rate_limit(event, severity):
            return

        if self.enricher:
            # Non-terminal: attaches details["threat_intel"] when there's
            # evidence, attaches nothing on any failure, never raises.
            self.enricher.annotate(event, severity)

        self._stage_explain_and_notify(event, severity)

    # --- individual stages ------------------------------------------------
    # Each returns True if it fully handled (persisted + stopped) the event,
    # False if the event should continue to the next stage.

    def _stage_dedupe(self, event: MonitorEvent) -> bool:
        if not self._is_duplicate(event):
            return False
        logger.debug("Suppressed duplicate event: %s", event.summary)
        self._persist(event, severity="low", explanation=None, ai_skipped=True,
                      risk_hint="duplicate_suppressed")
        return True

    def _stage_classify(self, event: MonitorEvent) -> tuple:
        """Runs the rule engine and severity engine. Neither stage is
        terminal on its own -- this just computes the verdict/severity pair
        that the later gating stages act on."""
        verdict = self.rules.evaluate(event)
        severity = self.severity.evaluate(event, verdict)
        return verdict, severity

    def _stage_rule_gate(self, event: MonitorEvent, verdict, severity: str) -> bool:
        if not verdict.skip_ai:
            return False
        # Deliberately silent: a user-trusted item is the one case where
        # NOT notifying is correct. The whole point of trusted_process_names/
        # trusted_process_hashes is "stop bugging me about this" -- still
        # logged and persisted to the timeline for the audit trail, just no
        # popup.
        logger.info("Rule engine skipped AI call and notification (%s): %s", verdict.reason, event.summary)
        self._persist(event, severity=severity, explanation=verdict.canned_explanation,
                      ai_skipped=True, risk_hint=verdict.reason)
        return True

    def _stage_rate_limit(self, event: MonitorEvent, severity: str) -> bool:
        if severity in RATE_LIMIT_EXEMPT_SEVERITIES or self._under_rate_limit():
            return False
        # Also deliberately silent -- notifying once per rate-limited event
        # defeated the purpose of rate limiting: a burst of 6 events in
        # 400ms became 6 "rate-limited" popups instead of 6 AI-explained
        # ones, which is worse, not better. Still logged (at WARNING, so
        # it's visible if you're watching the console) and persisted to
        # the timeline -- just no popup for something whose entire
        # premise is "too much is happening to explain individually."
        logger.warning("Rate limit hit (%s/min) -- skipping AI call and notification for: %s",
                        MAX_EVENTS_PER_MINUTE, event.summary)
        self._persist(event, severity=severity, explanation=None, ai_skipped=True,
                      risk_hint="rate_limited")
        return True

    def _stage_explain_and_notify(self, event: MonitorEvent, severity: str) -> None:
        explanation = self.explainer.explain(event, severity)
        if not self.config.notify_enabled:
            logger.debug("notify_enabled=false -- no popup for [%s] %s", severity, event.summary)
        elif self._severity_meets_notify_floor(severity):
            notify(self._title_for(event, severity), explanation)
        else:
            logger.info("Below notify_min_severity=%s -- no popup for [%s] %s",
                        self.config.notify_min_severity, severity, event.summary)
        self._persist(event, severity=severity, explanation=explanation, ai_skipped=False)

    def _severity_meets_notify_floor(self, severity: str) -> bool:
        # Gates ONLY the popup. The AI explanation above still ran and is
        # persisted -- the timeline is where a user who set the floor to
        # "high" goes to review the medium/low events they opted out of
        # being interrupted for. An unknown severity string fails open
        # (notify) for the same reason config.py falls back to "low":
        # a bug here must produce more noise, never silent suppression.
        try:
            return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(self.config.notify_min_severity)
        except ValueError:
            return True

    def _title_for(self, event: MonitorEvent, severity: str) -> str:
        base = {
            "process": "New process started",
            "usb": "USB device change",
            "startup": "Startup programs changed",
            "folder": "Watched folder changed",
        }.get(event.source, "System event")
        return f"{base} [{severity.upper()}]"

    def _dedupe_key(self, event: MonitorEvent) -> str:
        # Prefer (category, pid) over the raw summary string when a pid is
        # present. Found via code review, not guessed: macOS's process
        # monitor has two independent collection paths (NSWorkspace and
        # psutil) that can both report the SAME real process launch with
        # DIFFERENT summary text ("New application launched: Safari" vs
        # "New process: Safari (PID 1234)") -- summary-string dedupe would
        # never catch that, letting one real event through twice. Every
        # collector across all three OSes already puts "pid" in `details`
        # under the same key name, so this generalizes without needing
        # per-platform special-casing. Falls back to the summary string for
        # event types that have no pid (USB, startup, folder).
        pid = event.details.get("pid")
        if pid is not None:
            return f"{event.category.value}:{pid}"
        return event.summary

    def _is_duplicate(self, event: MonitorEvent) -> bool:
        now = time.time()
        key = self._dedupe_key(event)
        # drop expired entries
        while self._recent_summaries and now - self._recent_summaries[0][1] > DEDUPE_WINDOW_SECONDS:
            self._recent_summaries.popleft()
        for seen_key, ts in self._recent_summaries:
            if seen_key == key:
                return True
        self._recent_summaries.append((key, now))
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
        # A failed write (disk full, permissions, log dir deleted) must not
        # abort the rest of the pipeline for this event: SQLite (_persist) is
        # the redundant second trail, same reasoning as _persist's own guard
        # in the other direction.
        try:
            with self._log_lock:
                with open(self.config.log_path, "a", encoding="utf-8") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {event.source} | {event.summary}\n")
        except OSError as e:
            logger.error("Failed to append to the flat event log %s: %s", self.config.log_path, e)

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
