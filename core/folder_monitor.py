"""
Folder watching, shared across Windows and macOS via the `watchdog` library.

This is one of the few pieces of this project that is GENUINELY cross-platform
and near-real-time on both OSes without compromise: watchdog uses
ReadDirectoryChangesW on Windows and FSEvents on macOS under the hood, both
of which are proper OS-level file change notification APIs (not polling).
"""

from __future__ import annotations

from queue import Queue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .events import EventCategory, MonitorEvent

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


class FolderMonitor:
    def __init__(self, folders: list[str], out_queue: Queue):
        self.folders = folders
        self.out_queue = out_queue
        self.observer = Observer()

    def start(self):
        handler = _Handler(self.out_queue)
        for folder in self.folders:
            self.observer.schedule(handler, folder, recursive=False)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
