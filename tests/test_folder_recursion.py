"""Runnable self-check: watched folders are recursive, and ignores are narrow.

TWO FAILURES THIS GUARDS, pulling in opposite directions:

  1. NOT recursive. Watches used to be top-level only, so "watch my Downloads
     folder" silently meant "watch the top level of it" -- a drop into
     ~/Downloads/installer/ produced no event at all. Anyone reading the
     setting would assume otherwise, which makes it a blind spot the user does
     not know they have.

  2. Ignores too broad. Every ignore pattern is a folder Aegis walks past
     without looking, so the default list has to stay short and must never
     include the directories where executables legitimately land (build/,
     dist/, target/, Library/). An ignore list that grows to silence noise
     eventually silences the thing you installed this to catch.

Deliberately exercises the handler and the pattern matcher directly rather than
starting a real Observer: no sleeps, no filesystem races, and it runs the same
on a CI box with no FSEvents. The one thing source-level checking cannot prove
-- that schedule() is actually asked for a recursive watch -- is asserted with a
stub observer instead of by reading the file.

No framework: `python tests/test_folder_recursion.py`.
"""
import sys
from pathlib import Path
from queue import Empty, Queue

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.folder_monitor import _DEFAULT_IGNORES, FolderMonitor, _Handler, _ignored

# --- 1. ignore matching is component-wise ----------------------------------
assert _ignored("/Users/me/proj/node_modules/left-pad/index.js", _DEFAULT_IGNORES), \
    "an ignored directory must exclude everything beneath it, not just itself"
assert _ignored("/Users/me/proj/.git/objects/ab/cdef", _DEFAULT_IGNORES)
assert _ignored("/Users/me/Downloads/installer.dmg.part", _DEFAULT_IGNORES)
assert _ignored("/Users/me/.Trash/old.txt", _DEFAULT_IGNORES)

# ...and must not fire on a substring of a legitimate name.
assert not _ignored("/Users/me/Downloads/payload.exe", _DEFAULT_IGNORES)
assert not _ignored("/Users/me/my-node_modules-notes.txt", _DEFAULT_IGNORES), \
    "a file merely NAMED after an ignored directory must still be watched"
assert not _ignored("/Users/me/git/report.pdf", _DEFAULT_IGNORES), \
    "'git' is not '.git' -- an ordinary folder must not inherit the rule"

# --- 2. the default ignores must not cover where executables land ----------
# These are noisy, and excluding them is exactly the tempting mistake: they are
# also the normal home of a freshly compiled binary.
for never_ignore in ("/Users/me/proj/build/app",
                     "/Users/me/proj/dist/installer.pkg",
                     "/Users/me/proj/target/release/tool",
                     "/Users/me/Library/LaunchAgents/x.plist"):
    assert not _ignored(never_ignore, _DEFAULT_IGNORES), \
        f"{never_ignore} is a plausible drop site and must not be a default blind spot"

# --- 3. the handler actually drops ignored paths ---------------------------
q: Queue = Queue()
h = _Handler(q, _DEFAULT_IGNORES)

h._emit("created", "/Users/me/proj/node_modules/pkg/index.js", False)
h._emit("created", "/Users/me/proj/.git/index", False)
assert q.empty(), "ignored paths must never reach the queue"

h._emit("created", "/Users/me/Downloads/nested/deep/payload.bin", False)
assert q.qsize() == 1, "a nested drop must produce an event"
assert "payload.bin" in q.get_nowait().summary

# A directory event is dropped regardless of the ignore list.
h._emit("created", "/Users/me/Downloads/newfolder", True)
assert q.empty()


# on_moved is tested on the DESTINATION: a file leaving an ignored tree for a
# watched one is precisely the case that must still be reported.
class _Moved:
    def __init__(self, src, dest):
        self.src_path, self.dest_path, self.is_directory = src, dest, False


h.on_moved(_Moved("/Users/me/proj/node_modules/a", "/Users/me/proj/node_modules/b"))
assert q.empty(), "a move entirely inside an ignored tree is still noise"

h.on_moved(_Moved("/Users/me/proj/node_modules/payload", "/Users/me/Downloads/payload"))
assert q.qsize() == 1, "a file moving OUT of an ignored tree must be reported"

# --- 4. config patterns extend the defaults, never replace them ------------
fm = FolderMonitor([], Queue(), ["*.log", "MyNoisyFolder"])
assert "node_modules" in fm.ignores, "a user pattern must not wipe out the defaults"
assert "*.log" in fm.ignores and "MyNoisyFolder" in fm.ignores
assert _ignored("/Users/me/app/MyNoisyFolder/x.txt", fm.ignores)
assert FolderMonitor([], Queue()).ignores == _DEFAULT_IGNORES

# --- 5. the watch is actually scheduled recursively ------------------------
scheduled = []


class _StubObserver:
    def schedule(self, handler, path, recursive=False):
        scheduled.append((path, recursive))

    def start(self):
        pass


here = str(Path(__file__).resolve().parent)
fm = FolderMonitor([here, "/definitely/not/a/real/path"], Queue())
fm.observer = _StubObserver()
fm.start()
assert scheduled == [(here, True)], \
    f"existing folders must be watched recursively and missing ones skipped: {scheduled}"

print("ok: watches recurse, ignores stay narrow, and drop sites are never ignored")
