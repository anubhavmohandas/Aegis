"""
Windows startup program monitoring. Two distinct mechanisms, handled
differently:

1. Startup *folders* (Shell:Startup) -- real .lnk/.exe files dropped into
   %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup (per-user) and
   the equivalent all-users folder. These are plain folders, so we reuse
   `watchdog` (real-time, no compromise -- see core/folder_monitor.py).

2. Registry Run/RunOnce keys (HKCU and HKLM). The registry does not expose a
   simple cross-platform-friendly change notification in pure Python; the
   real-time option is `RegNotifyChangeKeyValue` via ctypes, which is more
   plumbing than fits this MVP. This module POLLS the four Run/RunOnce keys
   every `poll_interval_seconds` and diffs the value list. Confidence: likely
   correct approach (these are the standard, well-documented autorun keys),
   but polling means a program that adds then immediately removes itself
   between polls would be missed -- flagged via confidence="polled".
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from queue import Queue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.windows.startup_monitor")

REGISTRY_RUN_KEYS = [
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


class _StartupFolderHandler(FileSystemEventHandler):
    def __init__(self, out_queue: Queue):
        self.out_queue = out_queue

    def on_created(self, event):
        if event.is_directory:
            return
        self.out_queue.put(MonitorEvent(
            category=EventCategory.STARTUP_ITEM_ADDED,
            summary=f"Startup folder item added: {event.src_path}",
            details={"path": event.src_path},
            source="startup",
            confidence="certain",
        ))

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.out_queue.put(MonitorEvent(
            category=EventCategory.STARTUP_ITEM_REMOVED,
            summary=f"Startup folder item removed: {event.src_path}",
            details={"path": event.src_path},
            source="startup",
            confidence="certain",
        ))


class WindowsStartupMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 3):
        self.out_queue = out_queue
        self.poll_interval_seconds = poll_interval_seconds
        self._stop = threading.Event()
        self._registry_thread: threading.Thread | None = None
        self._observer = Observer()
        self._last_snapshot: dict[str, dict] = {}

    def start(self):
        self._start_folder_watch()
        self._registry_thread = threading.Thread(target=self._poll_registry, daemon=True)
        self._registry_thread.start()

    def stop(self):
        self._stop.set()
        self._observer.stop()
        self._observer.join(timeout=5)
        if self._registry_thread:
            self._registry_thread.join(timeout=5)

    def _start_folder_watch(self):
        import os
        handler = _StartupFolderHandler(self.out_queue)
        candidates = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        ]
        for folder in candidates:
            if folder.exists():
                self._observer.schedule(handler, str(folder), recursive=False)
        self._observer.start()

    def _poll_registry(self):
        try:
            import winreg
        except ImportError:
            logger.error("winreg unavailable (not running on Windows?) -- registry startup monitoring disabled.")
            return

        self._last_snapshot = self._read_all_run_keys(winreg)
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval_seconds)
            if self._stop.is_set():
                break
            current = self._read_all_run_keys(winreg)
            self._diff_and_emit(self._last_snapshot, current)
            self._last_snapshot = current

    def _read_all_run_keys(self, winreg) -> dict[str, dict]:
        values: dict[str, dict] = {}
        for hive_name, subkey in REGISTRY_RUN_KEYS:
            hive = getattr(winreg, hive_name)
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            location = f"{hive_name}\\{subkey}"
                            # v2 fix: this used to emit {"registry_path": key,
                            # "value": value} -- neither key matches
                            # core/events.py's StartupDetails TypedDict
                            # (name/path/location), the same kind of silent
                            # key-name mismatch already fixed for
                            # trusted_process_names/trusted_usb_ids elsewhere.
                            # Nothing reads these yet, but a future
                            # trusted-startup-path feature would have hit the
                            # exact same "silently never matches" bug.
                            values[f"{location}\\{name}"] = {
                                "name": name, "path": str(data), "location": location,
                            }
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.warning("Could not read %s\\%s: %s", hive_name, subkey, e)
        return values

    def _diff_and_emit(self, old: dict[str, dict], new: dict[str, dict]):
        for key, info in new.items():
            if key not in old:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.STARTUP_ITEM_ADDED,
                    summary=f"Startup registry entry added: {key} = {info['path']}",
                    details=info,
                    source="startup",
                    confidence="polled",
                ))
        for key, info in old.items():
            if key not in new:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.STARTUP_ITEM_REMOVED,
                    summary=f"Startup registry entry removed: {key}",
                    details=info,
                    source="startup",
                    confidence="polled",
                ))
