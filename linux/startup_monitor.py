"""
Linux startup-item monitoring: XDG autostart `.desktop` files.

Watches `~/.config/autostart` and `/etc/xdg/autostart` via `watchdog`
(inotify under the hood) -- real-time, same pattern as the folder monitor
and the Windows/macOS startup-folder watchers. confidence="certain".

Deliberately does NOT attempt to enumerate systemd user/system service
"enable" state (`systemctl list-unit-files --state=enabled`) -- that's a
polling-only signal (systemd has no simple change-notification API for unit
enablement) and was left out of this pass rather than bolted on half-tested.
Worth adding later as a polled signal, same pattern as Windows registry Run
keys or macOS Login Items.
"""

from __future__ import annotations

import logging
from pathlib import Path
from queue import Queue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.linux.startup_monitor")

AUTOSTART_DIRS = [
    "~/.config/autostart",
    "/etc/xdg/autostart",
]


class _AutostartHandler(FileSystemEventHandler):
    def __init__(self, out_queue: Queue):
        self.out_queue = out_queue

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".desktop"):
            return
        self.out_queue.put(MonitorEvent(
            category=EventCategory.STARTUP_ITEM_ADDED,
            summary=f"Autostart entry added: {event.src_path}",
            details={"path": event.src_path},
            source="startup",
            confidence="certain",
        ))

    def on_deleted(self, event):
        if event.is_directory or not event.src_path.endswith(".desktop"):
            return
        self.out_queue.put(MonitorEvent(
            category=EventCategory.STARTUP_ITEM_REMOVED,
            summary=f"Autostart entry removed: {event.src_path}",
            details={"path": event.src_path},
            source="startup",
            confidence="certain",
        ))


class LinuxStartupMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 3):
        self.out_queue = out_queue
        self.poll_interval_seconds = poll_interval_seconds  # unused, kept for constructor-signature parity with other collectors
        self._observer = Observer()

    def start(self):
        handler = _AutostartHandler(self.out_queue)
        for d in AUTOSTART_DIRS:
            path = Path(d).expanduser()
            if path.exists():
                self._observer.schedule(handler, str(path), recursive=False)
            else:
                logger.debug("Autostart dir does not exist, skipping: %s", path)
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=5)
