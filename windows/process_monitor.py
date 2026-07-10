"""
Windows process creation monitoring.

TWO BACKENDS, IN ORDER OF PREFERENCE:

1. ETW (Event Tracing for Windows) via `pywintrace`, listening to the
   Microsoft-Windows-Kernel-Process provider. This is genuinely real-time
   and does not miss short-lived processes the way WMI polling does.

   CONFIDENCE NOTE (read this): pywintrace is a thin, sparsely-maintained
   wrapper and its API has shifted across versions. The code below reflects
   the documented usage pattern as of pywintrace's public examples, but this
   entire module is UNTESTED -- I have no Windows machine to run it against.
   Treat this as a strong starting point, not a guarantee it runs as-is.
   Also requires: (a) running as Administrator, (b) the `pywintrace` package,
   which has had periods of being unmaintained -- check its repo activity
   before depending on it for anything you ship to someone else.

2. WMI polling fallback (Win32_Process creation events via the `wmi` package).
   This is well-established and stable, but has known multi-second latency
   and can miss processes that start and exit quickly. Every event from this
   path is tagged confidence="polled" so the AI explainer and notifications
   are honest about the gap.
"""

from __future__ import annotations

import logging
import threading
from queue import Queue

import psutil

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.windows.process_monitor")


class WindowsProcessMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 3):
        self.out_queue = out_queue
        self.poll_interval_seconds = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._backend = "none"

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        if self._try_etw():
            return
        logger.warning("ETW backend unavailable/failed -- falling back to WMI polling "
                        "(higher latency, may miss short-lived processes).")
        self._run_wmi_fallback()

    # ---- Backend 1: ETW -------------------------------------------------

    def _try_etw(self) -> bool:
        try:
            from etw import ETW, ProviderInfo
            from etw.GUID import GUID
        except ImportError:
            logger.info("pywintrace not installed -- skipping ETW backend.")
            return False

        try:
            # Microsoft-Windows-Kernel-Process provider GUID (documented,
            # stable identifier) -- emits ProcessStart/ProcessStop events.
            provider = ProviderInfo(
                "Microsoft-Windows-Kernel-Process",
                GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),
            )

            def _callback(event_tuple):
                try:
                    event_id = event_tuple.get("EventId") or event_tuple.get("EventHeader", {}).get("EventDescriptor", {}).get("Id")
                    # EventId 1 == ProcessStart on this provider (per public docs).
                    if event_id != 1:
                        return
                    image_name = event_tuple.get("ImageName", "unknown")
                    pid = event_tuple.get("ProcessID", "unknown")
                    parent_pid = event_tuple.get("ParentProcessID", "unknown")
                    details = {"image_name": image_name, "pid": pid, "parent_pid": parent_pid}

                    # v2 fix: the raw ETW ProcessStart event carries no exe path,
                    # so RuleEngine's hash-trust branch (core/rule_engine.py) could
                    # never fire on this backend -- the highest-fidelity Windows
                    # event source. Resolve it via psutil immediately, since ETW
                    # fires at/near process creation; a short-lived process can
                    # still exit before this runs, so failure here must degrade
                    # to "no exe available," never crash the callback (this thread
                    # feeds the whole ETW pipeline).
                    try:
                        details["executable_path"] = psutil.Process(pid).exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as e:
                        logger.debug("Could not resolve exe path for PID %s: %s", pid, e)

                    self.out_queue.put(
                        MonitorEvent(
                            category=EventCategory.PROCESS_STARTED,
                            summary=f"New process: {image_name} (PID {pid}, parent PID {parent_pid})",
                            details=details,
                            source="process",
                            confidence="certain",
                        )
                    )
                except Exception as e:
                    logger.error("Error handling ETW event: %s", e)

            etw_trace = ETW(providers=[provider], event_callback=_callback)
            etw_trace.start()
            self._backend = "etw"
            logger.info("ETW process monitor started (Microsoft-Windows-Kernel-Process).")

            while not self._stop.is_set():
                self._stop.wait(1)

            etw_trace.stop()
            return True

        except PermissionError:
            logger.error("ETW requires Administrator privileges. Re-run elevated, "
                         "or the app will fall back to WMI polling.")
            return False
        except Exception as e:
            logger.error("ETW backend failed to start (%s). Falling back to WMI.", e)
            return False

    # ---- Backend 2: WMI polling fallback ---------------------------------

    def _run_wmi_fallback(self):
        try:
            import wmi
        except ImportError:
            logger.error("`wmi` package not installed -- process monitoring disabled entirely. "
                         "pip install wmi pywin32")
            return

        self._backend = "wmi"
        try:
            conn = wmi.WMI()
            watcher = conn.Win32_Process.watch_for("creation")
        except Exception as e:
            logger.error("Failed to set up WMI process watcher: %s", e)
            return

        while not self._stop.is_set():
            try:
                # watch_for blocks; use a short timeout so we can check _stop.
                new_process = watcher(timeout_ms=self.poll_interval_seconds * 1000)
            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                logger.error("WMI watcher error: %s", e)
                continue

            self.out_queue.put(
                MonitorEvent(
                    category=EventCategory.PROCESS_STARTED,
                    summary=f"New process: {new_process.Caption} (PID {new_process.ProcessId})",
                    details={
                        "image_name": new_process.Caption,
                        "pid": new_process.ProcessId,
                        "executable_path": getattr(new_process, "ExecutablePath", "unknown"),
                        "command_line": getattr(new_process, "CommandLine", "unknown"),
                    },
                    source="process",
                    confidence="polled",  # honest: WMI creation events lag real spawn time
                )
            )
