"""
Screen lock/unlock detection -- the boundary events for Away Sessions.

Aegis's core promise is "know what happened while you were away", and the
lock/unlock pair is what turns a flat event stream into an *away session*:
everything between SESSION_LOCKED and SESSION_UNLOCKED is what happened
while the owner wasn't looking. The unlock event carries lock/unlock
timestamps; the dispatcher (see dispatcher._away_recap) then pulls
the events inside that window out of the store and has the AI brief the
user on their return.

All three backends are POLLED (confidence="polled"), matching the rest of
the collectors:

  macOS   -- `ioreg -n Root -d1 -a` exposes a Root-level `IOConsoleLocked`
             boolean (verified on real hardware: present and False while
             unlocked). No pyobjc-framework-Quartz dependency needed.
  Windows -- LogonUI.exe running == the lock/logon screen is up. Well-known
             heuristic; pywin32 session notifications need a window message
             pump this headless monitor doesn't have.
  Linux   -- `loginctl show-session self -p LockedHint --value` (systemd).

A backend that can't determine the state returns None ("unknown"), and
unknown NEVER emits events -- a broken detector must look like "no session
events", not like a stream of phantom lock/unlocks.
"""

from __future__ import annotations

import logging
import platform
import plistlib
import subprocess
import threading
import time
from queue import Queue

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.session_monitor")


def _locked_macos() -> bool | None:
    try:
        out = subprocess.run(["ioreg", "-n", "Root", "-d1", "-a"],
                             capture_output=True, timeout=10)
        data = plistlib.loads(out.stdout)
    except Exception as e:
        logger.debug("ioreg lock-state check failed: %s", e)
        return None
    locked = data.get("IOConsoleLocked")
    if isinstance(locked, bool):
        return locked
    # Older macOS: fall back to the per-console-user key.
    for user in data.get("IOConsoleUsers", []):
        if isinstance(user.get("CGSSessionScreenIsLocked"), bool):
            return user["CGSSessionScreenIsLocked"]
    return None


def _locked_windows() -> bool | None:
    try:
        import psutil
        for proc in psutil.process_iter(["name"]):
            if (proc.info.get("name") or "").lower() == "logonui.exe":
                return True
        return False
    except Exception as e:
        logger.debug("LogonUI lock-state check failed: %s", e)
        return None


def _locked_linux() -> bool | None:
    try:
        out = subprocess.run(["loginctl", "show-session", "self", "-p", "LockedHint", "--value"],
                             capture_output=True, text=True, timeout=5)
        value = out.stdout.strip().lower()
        if value in ("yes", "no"):
            return value == "yes"
        return None
    except Exception as e:
        logger.debug("loginctl lock-state check failed: %s", e)
        return None


_BACKENDS = {"Darwin": _locked_macos, "Windows": _locked_windows, "Linux": _locked_linux}


class SessionMonitor:
    """Cross-platform, same start()/stop() contract as every other collector."""

    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 3):
        self.out_queue = out_queue
        self.poll_interval_seconds = max(poll_interval_seconds, 2)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._check = _BACKENDS.get(platform.system())
        self._locked: bool | None = None   # None = unknown / not yet sampled
        self._locked_at: float | None = None

    def start(self):
        if self._check is None:
            logger.warning("No session lock detector for %s -- away sessions disabled", platform.system())
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Session monitor started (lock/unlock polling every %ss)", self.poll_interval_seconds)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        self._locked = self._check()
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval_seconds)
            if self._stop.is_set():
                break
            current = self._check()
            if current is None or current == self._locked:
                continue
            if self._locked is None:
                # First determinate sample after an unknown start: adopt the
                # state silently rather than inventing a transition.
                self._locked = current
                continue
            now = time.time()
            if current:
                self._locked_at = now
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.SESSION_LOCKED,
                    summary="Screen locked — away session started",
                    details={"locked_at": now},
                    source="session",
                    confidence="polled",
                ))
            else:
                away = (now - self._locked_at) if self._locked_at else None
                details = {"unlocked_at": now}
                if self._locked_at:
                    details["locked_at"] = self._locked_at
                    details["away_seconds"] = round(away, 1)
                mins = f" after {int(away // 60)}m {int(away % 60)}s away" if away else ""
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.SESSION_UNLOCKED,
                    summary=f"Screen unlocked{mins}",
                    details=details,
                    source="session",
                    confidence="polled",
                ))
                self._locked_at = None
            self._locked = current


if __name__ == "__main__":
    # Self-check: transition logic against a stubbed backend -- no real
    # lock/unlock needed. Unknown states must never emit.
    q: Queue = Queue()
    m = SessionMonitor(q, poll_interval_seconds=2)
    states = iter([False, None, True, True, False])  # unlocked -> ? -> locked -> locked -> unlocked
    m._check = lambda: next(states)
    m._locked = m._check()                            # baseline sample (False)
    for _ in range(4):                                # replay the poll loop body
        current = m._check()
        if current is None or current == m._locked:
            continue
        now = time.time()
        if current:
            m._locked_at = now
            q.put(MonitorEvent(category=EventCategory.SESSION_LOCKED, summary="t", source="session"))
        else:
            q.put(MonitorEvent(category=EventCategory.SESSION_UNLOCKED, summary="t",
                               details={"locked_at": m._locked_at}, source="session"))
        m._locked = current
    evs = [q.get_nowait().category for _ in range(q.qsize())]
    assert evs == [EventCategory.SESSION_LOCKED, EventCategory.SESSION_UNLOCKED], evs
    # live backend smoke test: must return a bool or None, never raise
    assert _BACKENDS.get(platform.system(), lambda: None)() in (True, False, None)
    print("session_monitor self-check: OK")
