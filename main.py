"""
Aegis -- entry point.

Detects the OS, wires up the right collector modules (Windows: ETW/WMI/
registry; macOS: NSWorkspace+psutil/system_profiler/LaunchAgents; Linux:
pyudev/psutil/XDG autostart), starts the tray icon, and runs the dispatcher
loop that turns raw events into AI explanations + notifications.

Run with:
    python main.py

Windows: run from an elevated (Administrator) terminal for the ETW backend to
work; without elevation it silently falls back to WMI polling (see
windows/process_monitor.py).

macOS: on first run, grant Terminal/your Python interpreter permission for
Automation (System Events) when macOS prompts, so the login-items check works.

Linux: not part of the client-requested scope (Windows + macOS), included
because it's the one collector set that could actually be run and verified
end to end during development -- see ARCHITECTURE.md.
"""

from __future__ import annotations

import logging
import platform
import sys
import threading
from queue import Queue

from core.config import load_config
from core.dispatcher import Dispatcher
from core.folder_monitor import FolderMonitor
from core.notifier import notify
from core.session_monitor import SessionMonitor
from core.tray_app import TrayApp
from core.version import __version__

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("aegis.main")


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


def main(use_tray: bool = True):
    system = platform.system()
    logger.info("Starting Aegis %s on %s", __version__, system)

    config = load_config()
    event_queue: Queue = Queue()

    platform_monitors = build_platform_monitors(system, event_queue, config.poll_interval_seconds)
    folder_monitor = FolderMonitor(config.watched_folders, event_queue)
    session_monitor = SessionMonitor(event_queue, config.poll_interval_seconds)

    dispatcher = Dispatcher(event_queue, config)

    all_monitors = platform_monitors + [folder_monitor, session_monitor]
    for m in all_monitors:
        m.start()

    dispatcher_thread = threading.Thread(target=dispatcher.run_forever, daemon=True)
    dispatcher_thread.start()

    if config.notify_enabled and config.notify_on_startup_scan:
        notify("Aegis", f"Now monitoring your system ({system}). Watching: "
                         f"{', '.join(config.watched_folders) or 'no folders configured'}")

    def on_quit():
        logger.info("Shutting down...")
        dispatcher.stop()
        dispatcher_thread.join(timeout=5)
        if dispatcher_thread.is_alive():
            logger.warning("Dispatcher thread did not exit within 5s of stop() -- "
                            "it's daemonized so it won't block process exit, but an "
                            "in-flight AI call or DB write may get cut off.")
        for m in all_monitors:
            try:
                m.stop()
            except Exception as e:
                logger.warning("Error stopping %s: %s", m.__class__.__name__, e)

    if not use_tray:
        # Headless mode -- used for the sandboxed live end-to-end verification
        # run, and useful on Linux dev boxes without a desktop tray.
        return dispatcher, all_monitors, on_quit

    def gated_quit():
        # Tray Quit honors the tamper gate exactly like the desktop app's
        # menu-bar Quit (password prompt + lockout + evidence capture) --
        # this was the one quit path in the app that skipped it. Returns
        # False to veto (TrayApp._quit then keeps the icon running).
        # Lazy import: desktop_app imports this module at load time.
        # Ctrl-C below stays ungated on purpose: terminal access already
        # defeats a userland gate (kill -9), and that path is covered
        # after the fact by heartbeat-gap detection, not prevention.
        try:
            from desktop_app import _authorize_action
            allowed = _authorize_action("quit", "Quit Aegis",
                                        "Enter the dashboard password to quit Aegis.")
        except Exception:
            # A tamper gate must fail CLOSED: an import/dialog error means
            # "keep running", never a silent quit bypass.
            logger.warning("Quit gate errored -- refusing to quit (fail closed).", exc_info=True)
            return False
        if not allowed:
            return False
        on_quit()

    tray = TrayApp(on_quit=gated_quit)
    try:
        # macOS requires the tray/run-loop to own the main thread.
        tray.run_blocking()
    except KeyboardInterrupt:
        on_quit()


if __name__ == "__main__":
    main()
