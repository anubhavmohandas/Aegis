"""
Per-OS collector wiring: given a queue, build the monitors for this platform.

Windows: ETW/WMI + registry. macOS: NSWorkspace+psutil / system_profiler /
LaunchAgents. Linux: pyudev/psutil/XDG autostart.

The platform packages are imported INSIDE the branches on purpose -- importing
windows/* on a Mac (or macos/* on Linux) fails on native deps that can't exist
there, and PyInstaller's bytecode scan still finds them for the bundle.

Windows: run from an elevated (Administrator) terminal for the ETW backend to
work; without elevation it silently falls back to WMI polling (see
windows/process_monitor.py).

macOS: on first run, grant Camera / Screen Recording / folder access when macOS
prompts (core/permissions.py raises those at launch), so the login-items check
and evidence capture work.

Linux: not part of the client-requested scope (Windows + macOS), included
because it's the one collector set that could actually be run and verified
end to end during development -- see ARCHITECTURE.md.

This was main.py, back when Aegis had a second, tray-only entry point that ran
the pipeline without a window. desktop_app.py is the entry point now; this is
the only part of main.py anything still called.
"""

from __future__ import annotations

import logging
import sys
from queue import Queue

logger = logging.getLogger("aegis.collectors")


def build_platform_monitors(system: str, event_queue: Queue, poll_interval: int) -> list:
    monitors = []

    if system == "Windows":
        from windows.process_monitor import WindowsProcessMonitor
        from windows.usb_monitor import WindowsUsbMonitor
        from windows.startup_monitor import WindowsStartupMonitor

        monitors.append(WindowsProcessMonitor(event_queue, poll_interval))
        monitors.append(WindowsUsbMonitor(event_queue))
        monitors.append(WindowsStartupMonitor(event_queue, poll_interval))

    elif system == "Darwin":
        from macos.process_monitor import MacProcessMonitor
        from macos.usb_monitor import MacUsbMonitor
        from macos.startup_monitor import MacStartupMonitor

        monitors.append(MacProcessMonitor(event_queue, poll_interval))
        monitors.append(MacUsbMonitor(event_queue, poll_interval))
        monitors.append(MacStartupMonitor(event_queue, poll_interval))

    elif system == "Linux":
        from linux.process_monitor import LinuxProcessMonitor
        from linux.usb_monitor import LinuxUsbMonitor
        from linux.startup_monitor import LinuxStartupMonitor

        monitors.append(LinuxProcessMonitor(event_queue, poll_interval))
        monitors.append(LinuxUsbMonitor(event_queue))
        monitors.append(LinuxStartupMonitor(event_queue, poll_interval))

    else:
        logger.error("Unsupported OS: %s.", system)
        sys.exit(1)

    return monitors
