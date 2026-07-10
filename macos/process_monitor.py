"""
macOS process monitoring -- READ THIS BEFORE TRUSTING IT.

There is no equivalent to Windows ETW available to an individual developer
here. The real-time, complete answer on macOS is Apple's EndpointSecurity
framework (`ES` / `es_new_client`), which requires the
`com.apple.developer.endpoint-security.client` entitlement. Apple grants
that entitlement manually, generally to established security vendors with a
business justification -- it is not something you self-serve in Xcode, and
there is no guaranteed turnaround time. Do not plan a ship date around
getting it.

Without that entitlement, this module uses two degraded-but-honest methods:

1. NSWorkspace launch notifications (via pyobjc) -- real-time, but ONLY
   fires for GUI applications (.app bundles), not for CLI tools, scripts, or
   background daemons launched via launchd/fork/exec. confidence="certain"
   because when it fires, it's accurate and immediate -- the gap is coverage,
   not timing.

2. psutil polling diff -- snapshots the full process table every
   `poll_interval_seconds` and reports new PIDs. Catches everything
   NSWorkspace misses, but inherits the same tradeoff as the Windows WMI
   fallback: a process that starts and exits between polls is invisible.
   confidence="polled".

CONFIDENCE NOTE: the NSWorkspace/pyobjc wiring below follows pyobjc's
documented pattern, but this whole module is UNTESTED -- I do not have
access to a Mac to run it. Verify on your machine before relying on it.
"""

from __future__ import annotations

import logging
import threading
import time
from queue import Queue

import psutil

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.macos.process_monitor")


class MacProcessMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 3):
        self.out_queue = out_queue
        self.poll_interval_seconds = poll_interval_seconds
        self._stop = threading.Event()
        self._poll_thread: threading.Thread | None = None
        self._nsworkspace_thread: threading.Thread | None = None

    def start(self):
        self._poll_thread = threading.Thread(target=self._poll_psutil, daemon=True)
        self._poll_thread.start()

        self._nsworkspace_thread = threading.Thread(target=self._run_nsworkspace_observer, daemon=True)
        self._nsworkspace_thread.start()

    def stop(self):
        self._stop.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
        # The NSWorkspace run loop thread is daemonized; it exits with the process.

    # ---- Coverage 1: GUI app launches via NSWorkspace (real-time) --------

    def _run_nsworkspace_observer(self):
        try:
            from AppKit import NSWorkspace, NSWorkspaceDidLaunchApplicationNotification
            from Foundation import NSObject
            from PyObjCTools import AppHelper
        except ImportError:
            logger.info("pyobjc not installed -- skipping NSWorkspace GUI-launch detection "
                        "(psutil polling will still cover this, at lower fidelity). "
                        "pip install pyobjc-framework-Cocoa")
            return

        out_queue = self.out_queue

        class _LaunchObserver(NSObject):
            def appLaunched_(self, notification):
                try:
                    app = notification.userInfo()["NSWorkspaceApplicationKey"]
                    name = app.localizedName()
                    bundle_id = app.bundleIdentifier()
                    pid = app.processIdentifier()
                    out_queue.put(MonitorEvent(
                        category=EventCategory.PROCESS_STARTED,
                        summary=f"New application launched: {name} (PID {pid})",
                        details={"app_name": str(name), "bundle_id": str(bundle_id), "pid": int(pid)},
                        source="process",
                        confidence="certain",
                    ))
                except Exception as e:
                    logger.error("Error handling NSWorkspace launch notification: %s", e)

        try:
            observer = _LaunchObserver.alloc().init()
            nc = NSWorkspace.sharedWorkspace().notificationCenter()
            nc.addObserver_selector_name_object_(
                observer, "appLaunched:", NSWorkspaceDidLaunchApplicationNotification, None
            )
            logger.info("NSWorkspace GUI-app-launch observer started.")
            AppHelper.runConsoleEventLoop(installInterrupt=False)
        except Exception as e:
            logger.error("Failed to start NSWorkspace observer (%s). GUI launches will only be "
                         "caught by the slower psutil poll.", e)

    # ---- Coverage 2: everything else via psutil polling diff -------------

    def _poll_psutil(self):
        known_pids = {p.pid for p in psutil.process_iter()}
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
                    name = info.get("name", "unknown")
                    exe = info.get("exe", "unknown")
                    ppid = info.get("ppid", "unknown")
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
