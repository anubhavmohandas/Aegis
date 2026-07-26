"""
Shared event model used by every platform backend (Windows + macOS).

Every monitor (process, USB, startup, folder) produces a MonitorEvent.
The AI explainer and notification layer only ever see this type, so
adding a new monitor later means implementing one function that returns
MonitorEvent objects -- nothing else in the app needs to change.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TypedDict


class EventCategory(str, Enum):
    PROCESS_STARTED = "process_started"
    USB_CONNECTED = "usb_connected"
    USB_REMOVED = "usb_removed"
    STARTUP_ITEM_ADDED = "startup_item_added"
    STARTUP_ITEM_REMOVED = "startup_item_removed"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_MOVED = "file_moved"        # v2: watchdog's on_moved was previously dropped entirely --
                                       # a rename (e.g. payload.txt -> payload.exe) never fired
                                       # on_created/on_modified, so it was invisible to Aegis.
    SESSION_LOCKED = "session_locked"      # screen locked -- start of an "away session"
    SESSION_UNLOCKED = "session_unlocked"  # screen unlocked -- carries the away-session recap
    MONITORING_GAP = "monitoring_gap"      # Aegis itself was not running for a while (see dispatcher heartbeat)
    TAMPER_ATTEMPT = "tamper_attempt"      # wrong password on a protected action (stop monitoring, settings)
    TAMPER_EVIDENCE = "tamper_evidence"    # repeated failures -> evidence captured as an Incident


# --- Canonical per-category `details` shapes ------------------------------
# These TypedDicts are NOT runtime-enforced (collectors build plain dicts,
# and every one of them is honest about only filling in what it actually
# has -- ETW gives you more than WMI polling does, NSWorkspace gives you
# less than a full EndpointSecurity event would). They exist so a human
# reading dispatcher.py/severity_engine.py/rule_engine.py/the UI code has one
# place to check "what keys can I expect here" instead of grepping collector
# files across three OSes. total=False on every one of these is deliberate --
# treat every key as optional and use `.get()`, never `[...]`, against them.

class ProcessDetails(TypedDict, total=False):
    pid: int
    ppid: int
    image_name: str            # e.g. "powershell.exe" -- Windows/ETW+WMI naming
    name: str                  # e.g. "Safari" -- macOS/NSWorkspace naming
    exe: str                   # full path, when the collector could resolve one
    executable_path: str       # alternate key some collectors use for the same thing
    sha256: str                 # only present if the rule engine's hash check computed one
    cmdline: str
    username: str


class UsbDetails(TypedDict, total=False):
    device_id: str
    serial_num: str
    vendor_id: str
    product_id: str
    name: str
    volume_uuid: str            # macOS SPStorageDataType-sourced events only


class StartupDetails(TypedDict, total=False):
    name: str
    path: str
    location: str                # e.g. "HKCU\\...\\Run", "~/Library/LaunchAgents", "~/.config/autostart"


class FolderDetails(TypedDict, total=False):
    path: str
    dest_path: str               # only present on FILE_MOVED -- the new path after rename/move


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
            if isinstance(v, (dict, list)):
                # Structured values (e.g. the enrichment stage's threat_intel
                # block) go into the prompt as JSON, not Python repr -- the
                # explainer's system prompt tells the model to treat that
                # block's numbers as fetched facts, so they must be unambiguous.
                v = json.dumps(v)
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
