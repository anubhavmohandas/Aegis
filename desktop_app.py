"""
Aegis -- desktop app entry point.

This is the "just give me a real app" entry point: one process, one Dock/
taskbar icon, one window. It starts the same monitor pipeline as main.py
(collectors + dispatcher), runs the dashboard's HTTP server in a background
thread instead of as a separate `python dashboard/server.py` process, and
opens a native window (pywebview -- Cocoa/WebKit on macOS, WebView2 on
Windows, GTK/QtWebEngine on Linux) pointed at it. Closing the window stops
the monitors and exits, the way a normal desktop app behaves -- no invisible
background process left over, unlike main.py's tray-only mode (still
available for anyone who explicitly wants headless/background operation).

Run with:
    python desktop_app.py

First screen is the dashboard's own login (admin/admin on first run, then
whatever you change it to from Settings -- see dashboard/server.py's module
docstring); the session cookie persists for the window's lifetime.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import threading
import time
from pathlib import Path
from queue import Queue

import webview

from core.config import load_config
from core.dispatcher import Dispatcher
from core.folder_monitor import FolderMonitor
from core.session_monitor import SessionMonitor
from dashboard.server import MONITOR_LOG_PATH, build_server
from main import build_platform_monitors

logger = logging.getLogger("aegis.desktop_app")

WINDOW_TITLE = "Aegis"
HOST = "127.0.0.1"
PORT = 8787
APP_ICON = Path(__file__).resolve().parent / "assets" / "tray_icon.png"  # square mark, not the full text lockup


class MonitorPipeline:
    """Same collectors + dispatcher wiring as main.main(), but as a
    start/stop-able object instead of a one-shot function -- the dashboard's
    Start/Stop Monitoring button needs to actually restart this, not just
    fire once at launch. Each start() builds fresh monitor/dispatcher
    objects rather than reusing stopped ones; none of these classes are
    documented as restart-safe, and "always construct new" is the same
    pattern main.py already used across the app's lifetime, just repeated
    on demand instead of once."""

    def __init__(self, config):
        self.config = config
        self.running = False
        self.started_at: float | None = None
        self._dispatcher = None
        self._monitors: list = []
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.running:
            return
        event_queue: Queue = Queue()
        system = platform.system()
        platform_monitors = build_platform_monitors(system, event_queue, self.config.poll_interval_seconds)
        folder_monitor = FolderMonitor(self.config.watched_folders, event_queue)
        session_monitor = SessionMonitor(event_queue, self.config.poll_interval_seconds)
        self._monitors = platform_monitors + [folder_monitor, session_monitor]
        self._dispatcher = Dispatcher(event_queue, self.config)

        for m in self._monitors:
            m.start()
        self._thread = threading.Thread(target=self._dispatcher.run_forever, daemon=True)
        self._thread.start()

        self.running = True
        self.started_at = time.time()
        logger.info("Monitor pipeline started")

    def stop(self) -> None:
        if not self.running:
            return
        self._dispatcher.stop()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            logger.warning("Dispatcher thread did not exit within 5s of stop() -- "
                            "daemonized, won't block process exit, but an in-flight "
                            "AI call or DB write may get cut off.")
        for m in self._monitors:
            try:
                m.stop()
            except Exception as e:
                logger.warning("Error stopping %s: %s", m.__class__.__name__, e)

        self._dispatcher = None
        self._monitors = []
        self._thread = None
        self.running = False
        self.started_at = None
        logger.info("Monitor pipeline stopped")


def _server_already_running(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def _darken_titlebar(window):
    # The dashboard is always dark (obsidian theme default); pywebview's
    # macOS window otherwise gets a plain white titlebar that follows system
    # appearance, not the page -- reads as a browser popup bolted onto a dark
    # app rather than one native window. window.native is only set once the
    # Cocoa window actually exists, hence hooking events.shown, not calling
    # this right after create_window().
    if sys.platform != "darwin":
        return
    try:
        import AppKit
        window.native.setAppearance_(AppKit.NSAppearance.appearanceNamed_("NSAppearanceNameDarkAqua"))
    except Exception:
        logger.debug("Could not force a dark title bar", exc_info=True)


def _wire_monitor_log() -> None:
    """The dashboard's "Log" button reads MONITOR_LOG_PATH (dashboard/server.py's
    monitor_log_tail()). That worked in the old two-process model because
    starting main.py as a subprocess piped its stdout straight into that file
    (see server.py's start_monitor()) -- but in this unified process, nothing
    wrote to it at all: logging.basicConfig below only attaches a console
    StreamHandler, invisible once packaged (no terminal). Confirmed bug: the
    Log modal always showed "(log is empty)" for the desktop app specifically.
    Adding a FileHandler at the same path both processes agree on fixes it.

    Rotating, not plain: this app is designed to sit resident for weeks, the
    root logger writes every INFO line here, and nothing ever truncated the
    file -- unbounded growth, plus monitor_log_tail() reads the WHOLE file
    into memory on every click of the dashboard's Log button. 5MB x 2 backups
    keeps a useful history while capping both costs."""
    from logging.handlers import RotatingFileHandler
    MONITOR_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(MONITOR_LOG_PATH, encoding="utf-8",
                                  maxBytes=5 * 1024 * 1024, backupCount=2)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(handler)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    _wire_monitor_log()
    config = load_config()

    pipeline = MonitorPipeline(config)
    pipeline.start()

    http_server = None
    if _server_already_running(HOST, PORT):
        # Most likely another Aegis instance (source or packaged) already has
        # the dashboard up on this port -- reuse it rather than fail to bind.
        # The monitor pipeline we just started above is still ours; whether
        # that's a second monitor writing to the same DB is on the user, the
        # same tradeoff as running `python main.py` twice today.
        logger.info("Dashboard already reachable on %s:%s -- opening a window onto it, "
                    "not starting a second server", HOST, PORT)
    else:
        def _quit_for_update():
            # Called from /api/update/install (see dashboard/server.py and
            # core/updater.py) on an HTTP worker thread, not the main thread.
            # The exit itself is deliberately delayed half a second and run
            # from a separate thread so the HTTP handler that called us gets
            # to actually flush its {"ok": true} response back to the browser
            # first -- os._exit() is immediate and unconditional, calling it
            # inline here would kill the process before that response ever
            # left the socket. The detached installer script core/updater.py
            # spawned is polling for this exact process to disappear before
            # it swaps files, so the delay only needs to clear one HTTP round
            # trip, not be graceful about anything else.
            def _delayed_exit():
                time.sleep(0.5)
                logger.info("Restarting for update -- shutting down")
                pipeline.stop()
                http_server.shutdown()
                os._exit(0)

            threading.Thread(target=_delayed_exit, daemon=True).start()

        http_server = build_server(
            config.db_path, HOST, PORT,
            in_process_monitor=True,
            quit_callback=_quit_for_update,
            monitor_status_callback=lambda: {"running": pipeline.running, "started_at": pipeline.started_at},
            monitor_start_callback=pipeline.start,
            monitor_stop_callback=pipeline.stop,
        )
        threading.Thread(target=http_server.serve_forever, daemon=True).start()
        logger.info("Dashboard server started on %s:%s (db: %s)", HOST, PORT, config.db_path)

    def _on_closed():
        logger.info("Window closed -- shutting down")
        pipeline.stop()
        if http_server is not None:
            http_server.shutdown()

    # Confirmed bug: create_window()/start() were called with no try/except.
    # All monitor/dispatcher threads are daemonic, so the *process* still
    # exits fine either way -- but if window creation fails (missing
    # WebView2 runtime on Windows, no GTK/QtWebEngine on a headless Linux
    # box), _on_closed() never fires, so pipeline.stop()/http_server.shutdown()
    # were skipped: in-flight AI calls/DB writes got cut off ungracefully,
    # and in the "another instance already has the dashboard" branch above,
    # the second monitor pipeline this process just started (still writing
    # to the shared DB) was never stopped either.
    try:
        window = webview.create_window(
            WINDOW_TITLE,
            f"http://{HOST}:{PORT}",
            width=1500, height=940, min_size=(1080, 680),
        )
        window.events.closed += _on_closed
        window.events.shown += lambda: _darken_titlebar(window)
        webview.start(icon=str(APP_ICON) if APP_ICON.is_file() else None)
    except Exception:
        logger.exception("Failed to open the desktop window -- shutting down cleanly instead of "
                          "leaving the monitor pipeline/HTTP server running with no window.")
        pipeline.stop()
        if http_server is not None:
            http_server.shutdown()
        raise


if __name__ == "__main__":
    sys.exit(main() or 0)
