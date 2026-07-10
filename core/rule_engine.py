"""
Local pre-filter that decides whether an event needs an AI call at all.

WHY THIS IS AN ALLOWLIST YOU CONFIGURE, NOT A BUILT-IN "KNOWN SAFE" DATABASE:

A hardcoded "these process names are always safe" list is a classic malware
masquerade vector -- e.g. treating "svchost.exe" as automatically safe is
exactly wrong, since svchost.exe impersonation is a real technique. Baking in
a global safe-list would make Aegis *less* trustworthy, not more: it would
create false confidence in exactly the cases an attacker is most likely to
exploit.

Instead, this engine only skips the AI call for items YOU explicitly added to
your own config (trusted_process_names / trusted_usb_ids in config.yaml) --
e.g. your own dev tools that fire constantly. That's an opt-in reduction of
noise for things you already know about, not a security judgment made on
your behalf. Everything else still goes to the AI, and every event -- gated
or not -- is still written to the database and the flat log.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.events import EventCategory, MonitorEvent


@dataclass
class RuleVerdict:
    skip_ai: bool
    canned_explanation: str | None = None
    reason: str = ""


class RuleEngine:
    def __init__(self, trusted_process_names: list[str] | None = None,
                 trusted_usb_ids: list[str] | None = None):
        # Normalize to lowercase for case-insensitive matching (Windows paths
        # especially are inconsistent about casing).
        self.trusted_process_names = {p.lower() for p in (trusted_process_names or [])}
        self.trusted_usb_ids = {u.lower() for u in (trusted_usb_ids or [])}

    def evaluate(self, event: MonitorEvent) -> RuleVerdict:
        if event.category == EventCategory.PROCESS_STARTED:
            name = str(event.details.get("image_name") or event.details.get("name") or "").lower()
            if name and name in self.trusted_process_names:
                return RuleVerdict(
                    skip_ai=True,
                    canned_explanation=f"{name} started. This is on your trusted-process list "
                                        f"(config.yaml), so this wasn't sent to the AI explainer.",
                    reason="user_trusted_process",
                )

        if event.category in (EventCategory.USB_CONNECTED, EventCategory.USB_REMOVED):
            device_id = str(event.details.get("device_id") or event.details.get("serial_num") or "").lower()
            if device_id and device_id in self.trusted_usb_ids:
                return RuleVerdict(
                    skip_ai=True,
                    canned_explanation=f"USB device event for a device on your trusted-device list "
                                        f"(config.yaml). Not sent to the AI explainer.",
                    reason="user_trusted_usb",
                )

        return RuleVerdict(skip_ai=False)
