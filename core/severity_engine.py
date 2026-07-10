"""
Local, deterministic severity classification -- runs BEFORE the AI call, not
instead of it. Levels: "low" | "medium" | "high" | "critical".

WHY THIS IS SEPARATE FROM `confidence` (see events.py): confidence answers
"how sure are we we detected this correctly" (real-time vs polled).
Severity answers "how concerning is this event, assuming we detected it
correctly." Conflating the two would mean a real-time detection of something
harmless reads as more alarming than a polled detection of something
dangerous, which is backwards. They're tracked independently and both shown
in the UI.

DESIGN PRINCIPLE: default to "medium," never "low," for anything this engine
doesn't have a specific reason to downgrade. An unrecognized event getting
silently classified as low-severity is exactly the failure mode that made
the rule engine an opt-in allowlist instead of a built-in "safe" list (see
rule_engine.py) -- the same reasoning applies here. Only two things can push
severity down: (1) the user's own trusted-item list, or (2) a startup-item
*removal* event, which is inherently less actionable than an addition.

Only two things push severity up beyond the category baseline, both
well-established, boring heuristics from real EDR products, not guesses:
  - A new process executing from a temp/downloads-style path.
  - A new/modified file in a watched folder with an executable-ish extension.
These are heuristics, not verdicts -- they raise the number in the UI, they
don't block anything or make a decision for the user.
"""

from __future__ import annotations

from core.events import EventCategory, MonitorEvent
from core.rule_engine import RuleVerdict

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

_CATEGORY_BASELINE = {
    EventCategory.PROCESS_STARTED: "medium",
    EventCategory.USB_CONNECTED: "medium",
    EventCategory.USB_REMOVED: "low",
    EventCategory.STARTUP_ITEM_ADDED: "high",       # persistence mechanisms are a classic malware behavior
    EventCategory.STARTUP_ITEM_REMOVED: "medium",   # could be innocuous cleanup, or something disabling security tooling -- not assumed safe
    EventCategory.FILE_CREATED: "low",
    EventCategory.FILE_MODIFIED: "low",
    EventCategory.FILE_DELETED: "low",
    EventCategory.FILE_MOVED: "low",
}

_SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/downloads/", "\\downloads\\",
)

_EXECUTABLE_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dll", ".sh", ".command",
)


def _bump(level: str, steps: int = 1) -> str:
    idx = SEVERITY_ORDER.index(level)
    return SEVERITY_ORDER[min(idx + steps, len(SEVERITY_ORDER) - 1)]


class SeverityEngine:
    def evaluate(self, event: MonitorEvent, rule_verdict: RuleVerdict | None = None) -> str:
        if rule_verdict is not None and rule_verdict.skip_ai:
            # User explicitly told Aegis about this item -- downgrade, but
            # never silently drop it from the timeline (dispatcher still
            # persists + notifies, just with lower urgency).
            return "low"

        level = _CATEGORY_BASELINE.get(event.category, "medium")

        if event.category == EventCategory.PROCESS_STARTED:
            path = str(
                event.details.get("exe")
                or event.details.get("executable_path")
                or event.details.get("image_name")
                or ""
            ).lower()
            if any(frag in path for frag in _SUSPICIOUS_PATH_FRAGMENTS):
                level = _bump(level)

        if event.category in (EventCategory.FILE_CREATED, EventCategory.FILE_MODIFIED):
            path = str(event.details.get("path", "")).lower()
            if any(path.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS):
                level = _bump(level, steps=2)  # low -> high: an executable dropped in a watched folder is worth surfacing

        if event.category == EventCategory.FILE_MOVED:
            # Check the DESTINATION name, not the source. This is the specific
            # evasion on_moved was added to catch: drop "payload.txt" (fires
            # on_created, extension check finds nothing suspicious), then
            # rename it to "payload.exe" (only on_moved fires -- if this checked
            # src_path instead of dest_path, the rename to an executable
            # extension would go completely unclassified).
            dest = str(event.details.get("dest_path", "")).lower()
            if any(dest.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS):
                level = _bump(level, steps=2)

        return level
