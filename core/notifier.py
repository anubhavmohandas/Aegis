"""
Desktop notifications, dispatched per platform.

macOS: `osascript -e 'display notification ...'` is the PRIMARY backend, not
a fallback. History of this decision (v1 -> v2):

  v1 tried plyer first everywhere. CONFIRMED BUG (found on a real macOS run,
  not a guess): plyer's macOS notification backend imports `pyobjus`, a
  separate and much less commonly installed Objective-C bridge library from
  `pyobjc` (which is what requirements-macos.txt actually installs, for the
  process/USB monitors). `pip install -r requirements-macos.txt` does NOT get
  you `pyobjus`, so plyer's notification path fails on a stock macOS install
  every time -- meaning EVERY notification paid a doomed plyer import attempt
  and logged a spurious warning before landing on osascript anyway.

  v2 therefore skips plyer entirely on macOS. osascript ships with every Mac,
  needs nothing extra installed, and `display notification` is a stable,
  long-documented AppleScript feature. The alternative -- a native
  UNUserNotificationCenter backend via pyobjc -- was considered and rejected
  for now: it requires the process to be a signed, bundled .app to register
  for notifications, which is exactly what running `python main.py` from a
  clone is not. Revisit when signed releases exist.

Windows/Linux: plyer remains the backend (it wraps the win32 toast APIs and
libnotify respectively, and works there). Per ADR-008, the Windows path is
not restructured without Windows hardware evidence -- this change only stops
macOS from routing through a backend known-broken on macOS.

The `print` fallback is last resort on every platform: notification backends
are the most environment-fragile part of this app, and a notification
failure must never kill the monitor loop.
"""

from __future__ import annotations

import logging
import platform
import subprocess

logger = logging.getLogger("aegis.notifier")


def notify(title: str, message: str) -> None:
    # Truncate hard -- OS notification systems silently clip long text anyway,
    # better to clip deliberately and point the user at the log file.
    message = (message[:250] + "…") if len(message) > 250 else message
    branded_title = f"Aegis — {title}"

    if platform.system() == "Darwin":
        if _notify_macos(branded_title, message):
            return
    else:
        if _notify_plyer(branded_title, message):
            return

    print(f"[NOTIFY-FALLBACK] {branded_title}: {message}")


def _notify_macos(branded_title: str, message: str) -> bool:
    try:
        # Pass title/message as argv, never interpolated into the script
        # source. An earlier version escaped `"` but not `\`, so a message
        # containing `\"` (e.g. a crafted filename in a watched folder,
        # echoed into the notification text) closed the AppleScript string
        # literal and executed attacker-chosen AppleScript -- including
        # `do shell script`. argv values are plain data to osascript; there
        # is nothing to escape.
        subprocess.run(
            [
                "osascript",
                "-e", "on run argv",
                "-e", "display notification (item 1 of argv) with title (item 2 of argv)",
                "-e", "end run",
                message, branded_title,
            ],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except Exception as e:
        logger.warning("macOS osascript notification failed: %s | %s | %s", e, branded_title, message)
        return False


def _notify_plyer(branded_title: str, message: str) -> bool:
    try:
        from plyer import notification
        notification.notify(title=branded_title, message=message, timeout=10)
        return True
    except Exception as e:
        logger.warning("plyer notification failed (%s): %s | %s", e, branded_title, message)
        return False
