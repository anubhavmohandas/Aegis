"""
Folder watching, shared across Windows and macOS via the `watchdog` library.

This is one of the few pieces of this project that is GENUINELY cross-platform
and near-real-time on both OSes without compromise: watchdog uses
ReadDirectoryChangesW on Windows and FSEvents on macOS under the hood, both
of which are proper OS-level file change notification APIs (not polling).
"""

from __future__ import annotations

import logging
from pathlib import Path
from queue import Queue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.folder_monitor")

_CATEGORY_MAP = {
    "created": EventCategory.FILE_CREATED,
    "modified": EventCategory.FILE_MODIFIED,
    "deleted": EventCategory.FILE_DELETED,
}


class _Handler(FileSystemEventHandler):
    def __init__(self, out_queue: Queue):
        self.out_queue = out_queue

    def _emit(self, event_type: str, path: str, is_directory: bool):
        if is_directory:
            return  # directory-level noise (e.g. temp folders being created) isn't useful here
        category = _CATEGORY_MAP.get(event_type)
        if category is None:
            return
        self.out_queue.put(
            MonitorEvent(
                category=category,
                summary=f"File {event_type}: {path}",
                details={"path": path},
                source="folder",
                confidence="certain",
            )
        )

    def on_created(self, event):
        self._emit("created", event.src_path, event.is_directory)

    def on_modified(self, event):
        self._emit("modified", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._emit("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        # v2 fix: this was previously unhandled entirely, which meant a
        # rename inside a watched folder was invisible to Aegis -- including
        # the exact evasion the severity engine's extension check exists to
        # catch (drop "payload.txt", then rename it to "payload.exe" -- no
        # on_created/on_modified ever fires for the new name, only on_moved).
        if event.is_directory:
            return
        self.out_queue.put(
            MonitorEvent(
                category=EventCategory.FILE_MOVED,
                summary=f"File moved: {event.src_path} -> {event.dest_path}",
                details={"path": event.src_path, "dest_path": event.dest_path},
                source="folder",
                confidence="certain",
            )
        )


class FolderMonitor:
    def __init__(self, folders: list[str], out_queue: Queue):
        self.folders = folders
        self.out_queue = out_queue
        self.observer = Observer()

    def start(self):
        # Confirmed bug: watchdog's Windows backend (ReadDirectoryChangesW)
        # calls CreateFileW synchronously inside Observer.start() itself --
        # if `folder` doesn't exist, that raises straight out of start(),
        # which propagates out of main.py's unguarded startup loop and kills
        # the whole process before the dispatcher/tray ever comes up. macOS's
        # FSEvents backend happens to be lenient about this, so the bug was
        # Windows-only. Every other collector that schedules a watchdog path
        # (macos/windows/linux startup_monitor.py) already guards with
        # `if path.exists()`; this was the one place that guard was missing.
        handler = _Handler(self.out_queue)
        for folder in self.folders:
            if Path(folder).is_dir():
                self.observer.schedule(handler, folder, recursive=False)
            else:
                logger.warning("Watched folder does not exist, skipping: %s", folder)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
