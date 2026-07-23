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
        # Re-read config every start: settings saved in the dashboard only
        # land in config.yaml/.env, so reusing the object loaded at app launch
        # made every setting change require a full app relaunch to apply.
        self.config = load_config()
        event_queue: Queue = Queue()
        system = platform.system()

        # Confirmed bug: this used to assign self._monitors and then start them
        # with no failure path, setting self.running=True only at the very end.
        # Any raise mid-loop (watchdog's Observer.start() on a folder deleted
        # since config load, or EventStore() on an unwritable db_path) left the
        # worst possible state: the collectors that DID start kept running and
        # kept pushing into an event_queue no dispatcher was draining (unbounded
        # growth), while self.running stayed False -- so stop() returned
        # immediately at its own `if not self.running` guard and the next
        # start() sailed past its guard and built a SECOND complete set of
        # collectors, orphaning the first set for the life of the process.
        # Build into locals, publish to self only once everything is up, and
        # unwind whatever actually started if it isn't.
        started: list = []
        dispatcher = None
        try:
            platform_monitors = build_platform_monitors(system, event_queue,
                                                         self.config.poll_interval_seconds)
            folder_monitor = FolderMonitor(self.config.watched_folders, event_queue)
            session_monitor = SessionMonitor(event_queue, self.config.poll_interval_seconds)
            monitors = platform_monitors + [folder_monitor, session_monitor]
            dispatcher = Dispatcher(event_queue, self.config)

            for m in monitors:
                m.start()
                started.append(m)
            thread = threading.Thread(target=dispatcher.run_forever, daemon=True)
            thread.start()
        except Exception:
            logger.exception("Monitor pipeline failed to start -- rolling back %d "
                              "collector(s) that had already started", len(started))
            for m in started:
                try:
                    m.stop()
                except Exception:
                    logger.warning("Error rolling back %s", m.__class__.__name__, exc_info=True)
            if dispatcher is not None:
                dispatcher.stop()   # explainer pool + DB handles; the queue is dropped with us
            raise

        self._monitors = monitors
        self._dispatcher = dispatcher
        self._thread = thread
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


def _run_on_main_thread(fn) -> None:
    """Schedule `fn` on the Cocoa main thread, swallowing anything it raises.

    Both halves matter, and getting either wrong kills the whole app:

    * A Python exception escaping a block passed to addOperationWithBlock_ is
      converted by PyObjC into an OBJ-C exception, which nothing catches ->
      SIGABRT. Confirmed: Hide Window aborted the process (crash report
      Aegis-2026-07-23-064101.ips, abort inside PyObjCErr_ToObjCWithGILState),
      taking monitoring down silently with it. An outer try/except around the
      *scheduling* call does not help -- the block runs later, on another
      thread. The try/except has to be INSIDE.
    * PyObjC types these blocks as `void`, so `fn` MUST return None. Returning
      a value (e.g. the BOOL from setActivationPolicy_) raises while
      depythonifying the result -- which is exactly the abort above. Hence the
      bare `fn()` call with no return, never `lambda: obj.something_()`."""
    import AppKit

    def _block():
        try:
            fn()
        except Exception:
            logger.warning("Main-thread block failed", exc_info=True)

    AppKit.NSOperationQueue.mainQueue().addOperationWithBlock_(_block)


def _set_macos_dock_visible(visible: bool) -> None:
    """Show/hide the Dock icon + app-switcher entry (Cmd-Tab) by flipping the
    activation policy. Accessory = menu-bar-only app, which is what "hidden from
    the desktop" means on macOS -- orderOut_ alone still leaves the Dock icon.
    The NSStatusItem is unaffected, so the menu bar stays the way back in."""
    if sys.platform != "darwin":
        return
    try:
        import AppKit
        app = AppKit.NSApplication.sharedApplication()
        policy = (AppKit.NSApplicationActivationPolicyRegular if visible
                  else AppKit.NSApplicationActivationPolicyAccessory)
        _run_on_main_thread(lambda: _set_policy(app, policy))
    except Exception:
        logger.debug("Could not change macOS activation policy", exc_info=True)


def _set_policy(app, policy) -> None:
    app.setActivationPolicy_(policy)   # discard the BOOL: the block must return None


def _hide_window(window) -> None:
    """Hide Aegis from the desktop: window off-screen, no Dock/taskbar entry.
    Monitoring keeps running -- this only removes the UI, so it is deliberately
    NOT password-gated (a weaker action than Stop, not an escape from it).

    Every step is individually guarded: hiding must never be able to take the
    process down, because a dead process is a monitoring outage that looks like
    a working hide."""
    try:
        window.hide()
    except Exception:
        logger.warning("Could not hide the window", exc_info=True)
        return
    _set_macos_dock_visible(False)
    logger.info("Window hidden -- monitoring continues; reopen from the menu bar/tray.")


def _show_window(window) -> None:
    _set_macos_dock_visible(True)
    try:
        window.show()
    except Exception:
        logger.warning("Could not show the window", exc_info=True)


class _JsApi:
    """Exposed to the dashboard page as window.pywebview.api. One method: the
    Hide Window button in the More menu. `window` is filled in right after
    create_window() (pywebview needs the api object at construction time)."""

    def __init__(self):
        self.window = None

    def hide_window(self) -> bool:
        _hide_window(self.window)
        return True


def _server_already_running(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


# Strong references to the menu-bar status item and its Objective-C menu
# target -- pyobjc doesn't retain these for us, and if Python garbage-collects
# them the icon silently vanishes from the menu bar and the menu stops working.
_menubar_refs: list = []

# Set True once any quit path (menu-bar/tray Quit, or the window-close gate)
# has authenticated the user, so a subsequent programmatic window close doesn't
# prompt for the password a second time. Quitting Aegis is a protected action:
# closing the app must NOT be a free way to escape monitoring.
_quit_authorized = False


def _prompt_password_macos(AppKit, title: str, informative: str, confirm: str) -> str | None:
    """Native secure-input dialog for a password-gated action (Stop Monitoring,
    Quit) triggered from the menu bar or the window-close handler, so the tamper
    gate is honored outside the web UI too. Runs on the main thread. Returns the
    entered password, or None if cancelled."""
    alert = AppKit.NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(informative)
    field = AppKit.NSSecureTextField.alloc().initWithFrame_(((0.0, 0.0), (240.0, 24.0)))
    alert.setAccessoryView_(field)
    alert.addButtonWithTitle_(confirm)
    alert.addButtonWithTitle_("Cancel")
    if alert.runModal() == AppKit.NSAlertFirstButtonReturn:
        return str(field.stringValue())
    return None


def _info_alert_macos(AppKit, title: str, message: str) -> None:
    alert = AppKit.NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(message)
    alert.addButtonWithTitle_("OK")
    alert.runModal()


def _add_macos_menubar(window, pipeline, on_quit):
    """Add a native macOS menu-bar (status bar) item so Aegis has a persistent
    presence even when the window is closed/behind others -- this is the 'tray'
    for the desktop app. pywebview owns the Cocoa main run loop, so a separate
    pystray thread can't run here; NSStatusItem lives inside that same run loop
    instead.

    MUST build on the main thread: NSStatusItem instantiates an NSWindow
    internally, and Cocoa raises 'NSWindow should only be instantiated on the
    main thread' otherwise. pywebview fires the `shown` event on a BACKGROUND
    thread, so we hop to the main operation queue to do the actual work.
    Entirely best-effort: any failure just means no menu-bar icon, the app runs
    exactly as before (same contract as _darken_titlebar)."""
    if sys.platform != "darwin":
        return
    try:
        import AppKit

        class _AegisMenuTarget(AppKit.NSObject):
            def openAegis_(self, _sender):
                # _show_window restores the Dock icon too, so this also un-does
                # a previous Hide, not just an un-focused window.
                try:
                    _show_window(window)
                    AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
                except Exception:
                    logger.debug("menu-bar Open failed", exc_info=True)

            def hideAegis_(self, _sender):
                try:
                    _hide_window(window)
                except Exception:
                    logger.debug("menu-bar Hide failed", exc_info=True)

            def startMonitoring_(self, _sender):
                try:
                    pipeline.start()   # start is not password-gated
                    _info_alert_macos(AppKit, "Aegis", "Monitoring started.")
                except Exception:
                    logger.warning("Tray start failed", exc_info=True)

            def stopMonitoring_(self, _sender):
                # Honor the tamper gate: stopping requires the dashboard password
                # (with lockout + evidence capture), exactly like the web UI.
                try:
                    if not pipeline.running:
                        _info_alert_macos(AppKit, "Aegis", "Monitoring is already stopped.")
                        return
                    if not _authorize_action("stop_monitoring", "Stop Monitoring",
                                             "Enter the dashboard password to stop monitoring."):
                        return
                    pipeline.stop()
                    _info_alert_macos(AppKit, "Aegis", "Monitoring stopped.")
                except Exception:
                    logger.warning("Tray stop failed", exc_info=True)

            def menuWillOpen_(self, menu):
                # Start/Stop reflect the live pipeline state instead of both
                # being clickable all the time (requires autoenablesItems off).
                try:
                    running = pipeline.running
                    menu.itemWithTitle_("Start Monitoring").setEnabled_(not running)
                    menu.itemWithTitle_("Stop Monitoring").setEnabled_(running)
                except Exception:
                    logger.debug("menu enable-state update failed", exc_info=True)

            def quitAegis_(self, _sender):
                # Quitting is password-gated too: closing Aegis must not be a
                # free way to escape monitoring. Only tear down + terminate once
                # the dashboard password is verified.
                if not _authorize_action("quit", "Quit Aegis",
                                         "Enter the dashboard password to quit Aegis."):
                    return   # blocked/cancelled -> Aegis keeps running
                global _quit_authorized
                _quit_authorized = True   # let the window-close gate pass, no 2nd prompt
                on_quit()
                try:
                    AppKit.NSApplication.sharedApplication().terminate_(None)
                except Exception:
                    os._exit(0)

        def _build_on_main():
            try:
                target = _AegisMenuTarget.alloc().init()
                status_item = AppKit.NSStatusBar.systemStatusBar().statusItemWithLength_(
                    AppKit.NSVariableStatusItemLength)

                button = status_item.button()
                if APP_ICON.is_file():
                    img = AppKit.NSImage.alloc().initByReferencingFile_(str(APP_ICON))
                    img.setSize_((18.0, 18.0))  # pyobjc bridges NSSize from a 2-tuple
                    # NOT a template: the Aegis mark is a full-color logo, and
                    # template mode would flatten it to a solid white/black
                    # silhouette (the "white square" bug). Show the real colors.
                    img.setTemplate_(False)
                    button.setImage_(img)
                else:
                    button.setTitle_("Aegis")

                menu = AppKit.NSMenu.alloc().init()
                items = [
                    ("Open Aegis", "openAegis:"),
                    ("Hide Aegis", "hideAegis:"),
                    (None, None),                       # separator
                    ("Start Monitoring", "startMonitoring:"),
                    ("Stop Monitoring", "stopMonitoring:"),
                    (None, None),
                    ("Quit Aegis", "quitAegis:"),
                ]
                for title, selector in items:
                    if title is None:
                        menu.addItem_(AppKit.NSMenuItem.separatorItem())
                        continue
                    mi = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, selector, "")
                    mi.setTarget_(target)
                    menu.addItem_(mi)
                menu.setAutoenablesItems_(False)
                menu.setDelegate_(target)   # menuWillOpen_ keeps Start/Stop honest
                status_item.setMenu_(menu)

                _menubar_refs.extend([target, status_item])
                logger.info("macOS menu-bar item added")
            except Exception:
                logger.warning("Could not add macOS menu-bar item", exc_info=True)

        # Hop to the main thread; the run loop pywebview started there executes it.
        AppKit.NSOperationQueue.mainQueue().addOperationWithBlock_(_build_on_main)
    except Exception:
        logger.warning("Could not schedule macOS menu-bar item", exc_info=True)


def _prompt_password_tk(title: str, informative: str) -> str | None:
    """tkinter (stdlib) secure-input dialog -- the Windows/Linux counterpart of
    _prompt_password_macos. A fresh Tk root per call, created and destroyed on
    the calling thread. Returns the password, or None if cancelled or tkinter is
    unavailable."""
    import tkinter as tk
    from tkinter import simpledialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        return simpledialog.askstring(title, informative, show="*", parent=root)
    finally:
        root.destroy()


def _authorize_action(action: str, title: str, informative: str) -> bool:
    """Password-gate a protected action (Stop Monitoring / Quit) from the tray,
    menu bar, or the window-close handler. Returns True only if the dashboard
    password is entered correctly -- or tamper protection is disabled, in which
    case there's no prompt. Returns False on cancel, wrong password, or when no
    password dialog is available; callers treat False as "do not proceed" (keep
    monitoring / keep the window open). On a wrong password this shows the same
    block + evidence notice as the web UI (guard_protected_action logs the
    tamper attempt, captures evidence at the threshold, and locks out).

    Disabling tamper protection is the intended escape hatch on the rare box
    where no dialog can render (non-macOS without tkinter) -- otherwise the gate
    would fail closed and there'd be no way to quit."""
    from core.config import load_config
    if not load_config().tamper_require_password:
        return True   # gate disabled -> action proceeds without a prompt
    from dashboard.server import guard_protected_action
    confirm = title.split()[0]                        # "Stop" / "Quit"
    if sys.platform == "darwin":
        import AppKit
        pw = _prompt_password_macos(AppKit, title, informative, confirm)
        notify = lambda t, m: _info_alert_macos(AppKit, t, m)
    else:
        try:
            pw = _prompt_password_tk(title, informative)
        except Exception:
            logger.warning("No password dialog available (tkinter missing) -- "
                           "use the dashboard to %s, or disable tamper protection.",
                           action, exc_info=True)
            return False
        notify = _info_alert_tk
    if pw is None:
        return False   # cancelled
    result = guard_protected_action(action, pw)
    if result.get("error"):
        note = result["error"]
        if result.get("evidence_captured"):
            note += f"\nEvidence captured (incident #{result.get('incident_id')})."
        notify(f"{title} blocked", note)
        return False
    return True


def _on_closing() -> bool | None:
    """Window-close gate: red close button, Cmd-W, Cmd-Q, and (via cocoa's
    applicationShouldTerminate) the app-menu Quit all route through pywebview's
    'closing' event, which vetoes the close if a handler returns False. Quitting
    Aegis is a protected action just like Stop Monitoring -- closing the window
    must not be a free way to stop being monitored. Returns None to allow the
    close (already authorized by a menu/tray Quit, or the correct password was
    entered, or tamper protection is off) and False to VETO it (wrong/no
    password -> window stays open, monitoring continues).

    'closing' is a locking event (webview.Window builds it with should_lock=True)
    so this runs synchronously on the GUI main thread before the OS closes the
    window -- showing the native password dialog here is safe.

    Not covered: a SIGKILL / force-quit of the process bypasses this entirely;
    that path is caught after the fact by heartbeat-gap detection in
    core/dispatcher, not prevented here."""
    logger.warning("QUIT-GATE: window close intercepted -- prompting for password.")
    if _quit_authorized:
        return None   # a menu/tray Quit already authenticated this close
    try:
        allowed = _authorize_action("quit", "Quit Aegis",
                                    "Enter the dashboard password to quit Aegis.")
    except Exception:
        # pywebview's Event dispatcher swallows a handler exception and then
        # lets the window close -- i.e. any error here would be a SILENT quit
        # bypass. A tamper gate must fail CLOSED: veto on error, keep monitoring.
        logger.warning("Quit gate errored -- vetoing the close (fail closed).", exc_info=True)
        return False
    return None if allowed else False   # None = allow, False = veto


def _info_alert_tk(title: str, message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            messagebox.showinfo(title, message, parent=root)
        finally:
            root.destroy()
    except Exception:
        logger.info("%s: %s", title, message)   # headless/no-tkinter fallback


def _add_pystray_tray(window, pipeline, on_quit):
    """Windows/Linux counterpart of _add_macos_menubar: same menu (Open /
    Start / password-gated Stop / Quit) via pystray, which happily runs on a
    background thread alongside pywebview's GUI loop everywhere except macOS
    (where the Cocoa run loop conflict is exactly why the NSStatusItem path
    above exists). Same best-effort contract: any failure just means no tray
    icon -- e.g. Linux without an appindicator/X11 backend."""
    if sys.platform == "darwin":
        return
    try:
        import pystray
        from core.tray_app import _load_icon_image

        def _open(icon, item):
            try:
                window.restore()
                _show_window(window)
            except Exception:
                logger.debug("tray Open failed", exc_info=True)

        def _hide(icon, item):
            try:
                _hide_window(window)
            except Exception:
                logger.debug("tray Hide failed", exc_info=True)

        def _start(icon, item):
            try:
                pipeline.start()   # start is not password-gated
                _info_alert_tk("Aegis", "Monitoring started.")
            except Exception:
                logger.warning("Tray start failed", exc_info=True)

        def _stop(icon, item):
            # Honor the tamper gate exactly like the web UI and macOS menu bar.
            try:
                if not pipeline.running:
                    _info_alert_tk("Aegis", "Monitoring is already stopped.")
                    return
                if not _authorize_action("stop_monitoring", "Stop Monitoring",
                                         "Enter the dashboard password to stop monitoring."):
                    return
                pipeline.stop()
                _info_alert_tk("Aegis", "Monitoring stopped.")
            except Exception:
                logger.warning("Tray stop failed", exc_info=True)

        def _quit(icon, item):
            # Quitting is password-gated too. window.destroy() closes the window
            # directly (bypasses the 'closing' gate on some backends), so gate it
            # here explicitly; the flag also stops the closing gate re-prompting
            # if it does fire.
            if not _authorize_action("quit", "Quit Aegis",
                                     "Enter the dashboard password to quit Aegis."):
                return   # blocked/cancelled -> Aegis keeps running
            global _quit_authorized
            _quit_authorized = True
            icon.stop()
            try:
                window.destroy()   # fires the closed event -> normal cleanup
            except Exception:
                on_quit()
                os._exit(0)

        menu = pystray.Menu(
            pystray.MenuItem("Open Aegis", _open, default=True),
            pystray.MenuItem("Hide Aegis", _hide),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Start Monitoring", _start,
                             enabled=lambda item: not pipeline.running),
            pystray.MenuItem("Stop Monitoring", _stop,
                             enabled=lambda item: pipeline.running),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Aegis", _quit),
        )
        icon = pystray.Icon("aegis", _load_icon_image(), "Aegis", menu=menu)
        threading.Thread(target=icon.run, daemon=True).start()
        logger.info("System tray icon added (pystray)")
    except Exception:
        logger.warning("Could not add system tray icon", exc_info=True)


def _set_macos_app_name(name: str = "Aegis") -> None:
    """From-source runs (`python desktop_app.py`) show 'Python' as the app name
    in the menu bar and app switcher, because the process has no app bundle with
    a CFBundleName. Patch the main bundle's info dictionary before AppKit builds
    the application menu so it reads 'Aegis' instead. A packaged .app already
    has the right CFBundleName, so this is a no-op cosmetic fix for source runs;
    fully best-effort."""
    if sys.platform != "darwin":
        return
    try:
        from Foundation import NSBundle
        bundle = NSBundle.mainBundle()
        info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
        if info is not None:
            info["CFBundleName"] = name
    except Exception:
        logger.debug("Could not set macOS app name", exc_info=True)


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

        # Confirmed crash (not just best-effort ugliness): pywebview fires
        # `shown` on a background thread (same fact _add_macos_menubar's
        # docstring already notes and hops off of), and setAppearance_ is a
        # main-thread-only Cocoa call -- calling it here directly trapped
        # with EXC_BREAKPOINT/SIGTRAP inside -[NSView setAppearance:], taking
        # the whole app down. That's a hard OS-level main-thread assertion,
        # not a Python exception, so the try/except below never caught it.
        def _apply():
            try:
                window.native.setAppearance_(AppKit.NSAppearance.appearanceNamed_("NSAppearanceNameDarkAqua"))
            except Exception:
                logger.debug("Could not force a dark title bar", exc_info=True)

        AppKit.NSOperationQueue.mainQueue().addOperationWithBlock_(_apply)
    except Exception:
        logger.debug("Could not schedule dark title bar", exc_info=True)


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
    _set_macos_app_name()   # show "Aegis", not "Python", when run from source
    _wire_monitor_log()
    config = load_config()

    pipeline = MonitorPipeline(config)
    try:
        pipeline.start()
    except Exception:
        # Don't take the whole app down with the pipeline. start() rolls itself
        # back cleanly now, so the window and dashboard still come up, the
        # status pill honestly reads "not running", and the user can fix the
        # offending setting and hit Start -- instead of a traceback and no UI.
        logger.exception("Monitoring could not start at launch -- opening the window anyway "
                          "so the problem is visible and fixable from Settings.")

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
        # Without this, WKWebView treats a download click as ordinary navigation:
        # the window LOADS the PDF/CSV in place, back-navigation is disabled by
        # pywebview, and the dashboard is unreachable until you quit. With it, the
        # native Save panel opens and the page stays put. Must be set before start().
        webview.settings['ALLOW_DOWNLOADS'] = True
        js_api = _JsApi()
        window = webview.create_window(
            WINDOW_TITLE,
            f"http://{HOST}:{PORT}",
            width=1500, height=940, min_size=(1080, 680),
            js_api=js_api,
        )
        js_api.window = window                 # backs the page's Hide Window button
        window.events.closing += _on_closing   # password-gate closing the window
        window.events.closed += _on_closed
        # Loud, unambiguous proof at startup that THIS running build has the quit
        # gate -- a stale packaged .app (frozen before the gate existed) won't
        # print this. If you don't see this line, you're not running the gated
        # build. WARNING level so it shows even without verbose logging.
        from core.version import __version__ as _ver
        logger.warning("QUIT-GATE ARMED (v%s) -- closing this window will require the dashboard password.", _ver)
        window.events.shown += lambda: _darken_titlebar(window)
        window.events.shown += lambda: _add_macos_menubar(window, pipeline, _on_closed)
        window.events.shown += lambda: _add_pystray_tray(window, pipeline, _on_closed)
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
