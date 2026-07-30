"""
Folder watching, shared across Windows and macOS via the `watchdog` library.

This is one of the few pieces of this project that is GENUINELY cross-platform
and near-real-time on both OSes without compromise: watchdog uses
ReadDirectoryChangesW on Windows and FSEvents on macOS under the hood, both
of which are proper OS-level file change notification APIs (not polling).

Watches are RECURSIVE. They were not originally, which quietly made "watch my
Downloads folder" mean "watch the top level of my Downloads folder" -- a drop
into ~/Downloads/installer/ produced no event at all. Recursion is what makes
the setting mean what it reads like, and _DEFAULT_IGNORES below is what keeps
it from burying the dispatcher in .git and node_modules churn.
"""

from __future__ import annotations

import logging
from fnmatch import fnmatch
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

# Deliberately SHORT. Every entry here is a blind spot -- a folder Aegis watches
# recursively but will never report on -- so this list is limited to things that
# are pure churn, and specifically avoids the plausible staging directories.
# Notably absent: build/, dist/, target/, Library/. Those are noisy, but they
# are also exactly where a compiled binary legitimately appears, and a watcher
# that ignores the place executables land is not watching for executables.
#
# The partial-download suffixes are safe to skip for a subtler reason: they are
# the IN-PROGRESS name. When the download completes the file is renamed to its
# real name, which fires on_moved and gets classified on the destination -- so
# skipping the partials drops the noise without dropping the detection.
_DEFAULT_IGNORES = (
    ".git", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".Trash", ".DS_Store",
    "*.swp", "*.swx", "*.tmp", "*.part", "*.crdownload", "~$*",
)


def _ignored(path: str, patterns: tuple[str, ...]) -> bool:
    """True if any COMPONENT of `path` matches an ignore pattern.

    Component-wise rather than against the whole string: "node_modules" has to
    exclude everything beneath it, not just a file literally named that. Uses
    fnmatch (not fnmatchcase) so matching follows the platform's own case rules
    -- macOS and Windows are case-insensitive, and ".GIT" must not slip past a
    ".git" rule there.
    """
    return any(fnmatch(part, pat) for part in Path(path).parts for pat in patterns)


class _Handler(FileSystemEventHandler):
    def __init__(self, out_queue: Queue, ignores: tuple[str, ...] = _DEFAULT_IGNORES):
        self.out_queue = out_queue
        self.ignores = ignores

    def _emit(self, event_type: str, path: str, is_directory: bool):
        if is_directory:
            return  # directory-level noise (e.g. temp folders being created) isn't useful here
        if _ignored(path, self.ignores):
            return
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
        # Only the DESTINATION is tested against the ignore list, matching what
        # severity_engine classifies. A file moving out of node_modules into a
        # watched folder is exactly the case that must still be reported; a file
        # moving around inside node_modules has an ignored dest and is dropped.
        if _ignored(event.dest_path, self.ignores):
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
    def __init__(self, folders: list[str], out_queue: Queue,
                 ignore_patterns: list[str] | None = None):
        self.folders = folders
        self.out_queue = out_queue
        # Config EXTENDS the defaults rather than replacing them: a user adding
        # one noisy directory of their own should not have to re-list .git and
        # node_modules to keep them suppressed.
        self.ignores = _DEFAULT_IGNORES + tuple(ignore_patterns or ())
        self.observer = Observer()

    def start(self):
        # Confirmed bug behind the is_dir() guard below: watchdog's Windows
        # backend (ReadDirectoryChangesW) calls CreateFileW synchronously while
        # the emitter starts -- if `folder` doesn't exist that raises straight
        # out of this method, propagates through the caller's startup
        # loop, and kills the whole process before the dispatcher/tray ever
        # comes up. macOS's FSEvents backend happens to be lenient about this,
        # so the bug was Windows-only. Every other collector that schedules a
        # watchdog path (macos/windows/linux startup_monitor.py) already guards
        # with `if path.exists()`; this was the one place that guard was
        # missing. The try/except below is the second line of defense, for the
        # folders that DO exist and still can't be watched.
        handler = _Handler(self.out_queue, self.ignores)
        # Observer FIRST, watches after. watchdog only starts an emitter inside
        # schedule() once the observer is already alive; scheduled beforehand,
        # every emitter is instead started by observer.start(), so the first
        # folder that fails takes the whole call -- and with it folder
        # monitoring entirely -- down with one exception. Started first, each
        # schedule() raises at its own folder and can be contained to it.
        self.observer.start()
        for folder in self.folders:
            if not Path(folder).is_dir():
                logger.warning("Watched folder does not exist, skipping: %s", folder)
                continue
            try:
                # Recursive: a drop into ~/Downloads/installer/ was previously
                # invisible, which made "watch my Downloads folder" mean
                # something narrower than anyone reading it would assume.
                # _DEFAULT_IGNORES is what keeps this from drowning the
                # dispatcher in .git and node_modules churn.
                self.observer.schedule(handler, folder, recursive=True)
            except OSError as e:
                # Linux, and only since watches became recursive: inotify burns
                # one watch descriptor PER DIRECTORY and
                # fs.inotify.max_user_watches (commonly 8192) is a per-user cap
                # shared with every other watcher on the box, so a deep
                # Documents tree can exhaust it with ENOSPC. Windows can land
                # here too (ReadDirectoryChangesW opens the directory handle
                # synchronously) for a folder that exists but can't be opened.
                # Note folder_ignore_patterns does NOT help: it filters events
                # after the fact, it does not prune the watched tree.
                logger.error(
                    "Could not watch %s (%s) -- continuing without it, remaining folders "
                    "are unaffected. On Linux this is usually the inotify watch limit: "
                    "raise it with `sudo sysctl -w fs.inotify.max_user_watches=524288` "
                    "(persist in /etc/sysctl.d/) or narrow watched_folders in config.yaml.",
                    folder, e)

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
