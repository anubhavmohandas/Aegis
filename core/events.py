"""
Shared event model used by every platform backend (Windows + macOS).

Every monitor (process, USB, startup, folder) produces a MonitorEvent.
The AI explainer and notification layer only ever see this type, so
adding a new monitor later means implementing one function that returns
MonitorEvent objects -- nothing else in the app needs to change.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class EventCategory(str, Enum):
    PROCESS_STARTED = "process_started"
    USB_CONNECTED = "usb_connected"
    USB_REMOVED = "usb_removed"
    STARTUP_ITEM_ADDED = "startup_item_added"
    STARTUP_ITEM_REMOVED = "startup_item_removed"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"


@dataclass
class MonitorEvent:
    category: EventCategory
    summary: str                     # short machine-generated line, e.g. "New process: powershell.exe (PID 4821)"
    details: dict = field(default_factory=dict)   # raw fields for the AI prompt (path, hash, parent proc, etc.)
    source: str = "unknown"          # which monitor produced it: "process", "usb", "startup", "folder"
    timestamp: float = field(default_factory=time.time)
    confidence: str = "certain"      # "certain" | "polled" | "degraded" -- see note below

    def as_prompt_block(self) -> str:
        """Render this event as plain text for the AI explainer prompt."""
        lines = [f"Event type: {self.category.value}", f"Summary: {self.summary}"]
        for k, v in self.details.items():
            lines.append(f"{k}: {v}")
        if self.confidence != "certain":
            lines.append(
                f"NOTE: this event was detected via a {self.confidence} method and may be delayed "
                f"or incomplete -- mention that in your answer if relevant."
            )
        return "\n".join(lines)


# `confidence` exists because Windows ETW-based detection and macOS
# EndpointSecurity-based detection are near-real-time and complete, while
# WMI polling / psutil diffing / NSWorkspace-only detection are not. The AI
# explainer and the UI both surface this so the user never mistakes a
# best-effort polled event for a guaranteed real-time one.
