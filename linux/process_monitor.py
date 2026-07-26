"""
Linux process creation monitoring via psutil polling diff.

CONFIDENCE NOTE: Linux actually has a real kernel-level real-time option here
-- the process events connector (netlink, `CONFIG_PROC_EVENTS`, the same
mechanism tools like `forkstat` use) delivers fork/exec/exit notifications
without polling. It was deliberately NOT implemented here: subscribing to it
requires manually constructing netlink connector protocol messages (there's
no well-maintained Python wrapper), typically needs CAP_NET_ADMIN/root in
practice, and I did not have time to validate the full protocol exchange
against a real target distro (a partially-correct netlink implementation
would be worse than an honest polling fallback). This module uses the same
psutil-diff approach as the macOS collector instead -- consistent,
simple, and actually tested (see below). confidence="polled" throughout.

CONFIDENCE: the diffing logic itself was run against real process spawns in
my sandbox and correctly detected them -- see this project's verification
notes for the live end-to-end run.
"""

from __future__ import annotations

import logging
import threading
from queue import Queue

import psutil

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.linux.process_monitor")


class LinuxProcessMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 2):
        self.out_queue = out_queue
        self.poll_interval_seconds = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _poll(self):
        # Confirmed bug: this initial baseline snapshot ran outside any
        # try/except, unlike the per-iteration psutil call inside the loop
        # below (which already handles failure). If this call raised, the
        # thread died before the loop ever ran -- with zero log output --
        # silently taking down process monitoring entirely.
        try:
            known_pids = {p.pid for p in psutil.process_iter()}
        except Exception as e:
            logger.error("Initial psutil.process_iter baseline failed (%s) -- starting from an "
                         "empty baseline, so the first poll will report every already-running "
                         "process as newly started.", e)
            known_pids = set()
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval_seconds)
            if self._stop.is_set():
                break
            try:
                current = {p.pid: p for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"])}
            except Exception as e:
                logger.error("psutil.process_iter failed: %s", e)
                continue

            new_pids = set(current.keys()) - known_pids
            for pid in new_pids:
                proc = current[pid]
                try:
                    info = proc.info
                    # psutil fills inaccessible attrs with None, not a missing
                    # key -- `or` on all three keeps None out of details/summary.
                    name = info.get("name") or "unknown"
                    exe = info.get("exe") or "unknown"
                    ppid = info.get("ppid") or "unknown"
                except Exception:
                    name, exe, ppid = "unknown", "unknown", "unknown"

                self.out_queue.put(MonitorEvent(
                    category=EventCategory.PROCESS_STARTED,
                    summary=f"New process: {name} (PID {pid})",
                    details={"name": name, "pid": pid, "exe": exe, "parent_pid": ppid},
                    source="process",
                    confidence="polled",
                ))
            known_pids = set(current.keys())
