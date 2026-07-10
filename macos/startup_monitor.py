"""
macOS startup-item monitoring. Two distinct mechanisms:

1. LaunchAgents / LaunchDaemons (.plist files) -- the dominant persistence
   mechanism on macOS. Watched via `watchdog` (FSEvents under the hood), so
   this is genuinely real-time, same as the folder monitor. confidence="certain".
   Locations watched: ~/Library/LaunchAgents, /Library/LaunchAgents,
   /Library/LaunchDaemons. (/System/Library/LaunchAgents is Apple's own and
   SIP-protected; not user-writable, so not watched.)

2. "Login Items" (System Settings -> General -> Login Items) -- the
   user-facing list of apps that reopen at login. Modern macOS (Ventura+)
   manages this via a private, undocumented store
   (com.apple.backgroundtaskmanagementagent), there is no public API for it.
   This module polls it indirectly via `osascript` querying System Events'
   login-items list, which reflects the classic (pre-Ventura-era) login items
   API System Events still exposes. CONFIDENCE: this may not fully reflect
   everything Ventura's newer background-task UI shows -- treat this as
   best-effort coverage, not a complete picture, and confirmed UNTESTED
   since I have no Mac to verify against.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from pathlib import Path
from queue import Queue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.macos.startup_monitor")

LAUNCH_AGENT_DIRS = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]

LOGIN_ITEMS_SCRIPT = 'tell application "System Events" to get the name of every login item'


class _PlistHandler(FileSystemEventHandler):
    def __init__(self, out_queue: Queue):
        self.out_queue = out_queue

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".plist"):
            return
        self.out_queue.put(MonitorEvent(
            category=EventCategory.STARTUP_ITEM_ADDED,
            summary=f"LaunchAgent/Daemon added: {event.src_path}",
            details={"path": event.src_path},
            source="startup",
            confidence="certain",
        ))

    def on_deleted(self, event):
        if event.is_directory or not event.src_path.endswith(".plist"):
            return
        self.out_queue.put(MonitorEvent(
            category=EventCategory.STARTUP_ITEM_REMOVED,
            summary=f"LaunchAgent/Daemon removed: {event.src_path}",
            details={"path": event.src_path},
            source="startup",
            confidence="certain",
        ))


class MacStartupMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 5):
        self.out_queue = out_queue
        self.poll_interval_seconds = poll_interval_seconds
        self._stop = threading.Event()
        self._observer = Observer()
        self._login_items_thread: threading.Thread | None = None
        self._last_login_items: set[str] = set()

    def start(self):
        handler = _PlistHandler(self.out_queue)
        for d in LAUNCH_AGENT_DIRS:
            path = Path(d).expanduser()
            if path.exists():
                self._observer.schedule(handler, str(path), recursive=False)
            else:
                logger.debug("LaunchAgent dir does not exist, skipping: %s", path)
        self._observer.start()

        self._login_items_thread = threading.Thread(target=self._poll_login_items, daemon=True)
        self._login_items_thread.start()

    def stop(self):
        self._stop.set()
        self._observer.stop()
        self._observer.join(timeout=5)
        if self._login_items_thread:
            self._login_items_thread.join(timeout=5)

    def _get_login_items(self) -> set[str]:
        try:
            result = subprocess.run(
                ["osascript", "-e", LOGIN_ITEMS_SCRIPT],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.warning("osascript login-items query failed: %s", result.stderr.strip())
                return self._last_login_items
            # osascript returns a comma-space-separated list, e.g. "Dropbox, Zoom"
            raw = result.stdout.strip()
            return {name.strip() for name in raw.split(",") if name.strip()}
        except Exception as e:
            logger.error("Failed to query login items via osascript: %s", e)
            return self._last_login_items

    def _poll_login_items(self):
        self._last_login_items = self._get_login_items()
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval_seconds)
            if self._stop.is_set():
                break
            current = self._get_login_items()
            for name in current - self._last_login_items:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.STARTUP_ITEM_ADDED,
                    summary=f"Login item added: {name}",
                    details={"name": name},
                    source="startup",
                    confidence="polled",
                ))
            for name in self._last_login_items - current:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.STARTUP_ITEM_REMOVED,
                    summary=f"Login item removed: {name}",
                    details={"name": name},
                    source="startup",
                    confidence="polled",
                ))
            self._last_login_items = current
