"""
Cross-platform desktop notifications via `plyer`, with a macOS-specific
fallback -- see the note below, found via a real run on real macOS, not
guessed.

plyer wraps win10toast/win32 toast APIs on Windows and NSUserNotification /
UNUserNotificationCenter on macOS. It's the pragmatic choice for a single
codebase; the tradeoff is less control over notification actions/buttons
than writing native code per OS. If you later want clickable notifications
that open a detail window, that's a legitimate reason to replace this with
native APIs per platform -- flagging that now so it's not a surprise later.

CONFIRMED BUG (found on a real macOS run, not a guess): plyer's macOS
notification backend imports `pyobjus`, a separate and much less commonly
installed Objective-C bridge library from `pyobjc` (which is what
requirements-macos.txt actually installs, for the process/USB monitors).
`pip install -r requirements-macos.txt` does NOT get you `pyobjus`, so
plyer's notification path fails on a stock install every time.

Rather than add yet another native dependency, macOS notifications fall
back to calling `osascript -e 'display notification ...'` directly --
ships with every Mac, needs nothing extra installed, and is a stable,
long-documented AppleScript feature. plyer is tried first (works fine on
Windows), osascript is the macOS-specific fallback, print is the last
resort on any platform.
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

    try:
        from plyer import notification
        notification.notify(title=branded_title, message=message, timeout=10)
        return
    except Exception as e:
        logger.warning("plyer notification failed (%s): %s | %s", e, branded_title, message)

    if platform.system() == "Darwin":
        try:
            # Pass title/message as argv, never interpolated into the script
            # source. The previous version escaped `"` but not `\`, so a
            # message containing `\"` (e.g. a crafted filename in a watched
            # folder, echoed into the notification text) closed the
            # AppleScript string literal and executed attacker-chosen
            # AppleScript -- including `do shell script`. argv values are
            # plain data to osascript; there is nothing to escape.
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
            return
        except Exception as e2:
            logger.warning("macOS osascript notification fallback also failed: %s", e2)

    # Notification backends are the most environment-fragile part of this --
    # never let a notification failure kill the monitor loop.
    print(f"[NOTIFY-FALLBACK] {branded_title}: {message}")
