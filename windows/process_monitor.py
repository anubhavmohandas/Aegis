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

ZERO-EVENT WATCHDOG (added after real-hardware evidence, 2026-07): on the one
real Windows machine this ran on, etw_probe.py proved the ETW session starts
cleanly (admin OK, provider enabled, kernel buffers written) but pywintrace
0.2.0's consumer/delivery path never invokes the callback -- so "session
started" is NOT proof events will ever arrive. Before this watchdog, _run()
treated a started session as success and sat in its wait loop for the whole
session, so the WMI fallback never engaged and Windows process monitoring
produced ZERO events while looking healthy. Now: if the callback hasn't fired
once within ETW_ZERO_EVENT_FALLBACK_SECONDS (a short-lived child process is
spawned near the deadline to guarantee at least one ProcessStart exists, the
same trick etw_probe.py uses), the ETW session is stopped and the monitor
falls back to WMI. A machine can't produce zero ProcessStart events across
that window when we spawn one ourselves, so a silent consumer is the only
thing that trips this.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from queue import Queue

import psutil

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.windows.process_monitor")

# How long a freshly-started ETW session gets to deliver its FIRST callback
# before it's declared dead and the monitor falls back to WMI. Generous on
# purpose: a false fallback only costs latency (WMI still sees everything,
# tagged "polled"), while a false "ETW is fine" costs total blindness.
ETW_ZERO_EVENT_FALLBACK_SECONDS = 30

# EventId 1 == ProcessStart on Microsoft-Windows-Kernel-Process (public manifest).
_ETW_PROCESS_START_ID = 1

# How many raw payloads to log at INFO for shape confirmation (pywintrace's
# payload keys are undocumented -- see _callback below).
_ETW_DIAGNOSTIC_PAYLOADS = 3


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
            #
            # any_keywords is REQUIRED here: pywintrace 0.2.0 defaults it to a
            # 0 bitmask (etw.py get_keywords_bitmask returns 0 for None), and
            # EnableTraceEx2 with MatchAnyKeyword=0 matches no keyword-tagged
            # events -- every Kernel-Process event carries a keyword, so the
            # session starts cleanly but the callback never fires.
            # WINEVENT_KEYWORD_PROCESS (0x10) covers ProcessStart/ProcessStop.
            provider = ProviderInfo(
                "Microsoft-Windows-Kernel-Process",
                GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),
                any_keywords=0x10,  # WINEVENT_KEYWORD_PROCESS
            )

            # pywintrace 0.2.0 invokes the callback as event_callback((event_id,
            # out)) -- a 2-tuple, not a dict (see site-packages/etw/etw.py:839).
            # The payload keys of `out` are undocumented and have never been
            # observed on real hardware (the consumer never delivered a single
            # event there -- see the module docstring), so the parse below is
            # best-effort against the provider's public manifest names with the
            # spellings pywintrace's TDH layer plausibly produces. The first few
            # raw payloads are still logged at INFO so the shape can finally be
            # confirmed the day events DO flow.
            seen = {"count": 0}

            def _first(payload: dict, *keys):
                for k in keys:
                    if k in payload:
                        return payload[k]
                return None

            def _callback(event_tuple):
                try:
                    event_id, out = event_tuple
                    seen["count"] += 1

                    if seen["count"] <= _ETW_DIAGNOSTIC_PAYLOADS:
                        logger.info("ETW payload sample %d/%d -- Event ID: %s, type: %s, payload: %r",
                                    seen["count"], _ETW_DIAGNOSTIC_PAYLOADS, event_id, type(out), out)

                    if event_id != _ETW_PROCESS_START_ID or not isinstance(out, dict):
                        return

                    image_name = str(_first(out, "ImageName", "Image Name", "ImageFileName") or "unknown")
                    pid_raw = _first(out, "ProcessID", "ProcessId", "Process ID")
                    parent_pid = _first(out, "ParentProcessID", "ParentProcessId", "Parent Process ID")
                    try:
                        pid = int(str(pid_raw), 0)  # TDH sometimes renders ints as "0x1A2B" strings
                    except (TypeError, ValueError):
                        pid = None

                    details = {"image_name": image_name,
                               "pid": pid if pid is not None else str(pid_raw),
                               "parent_pid": str(parent_pid)}

                    # The raw ETW ProcessStart event carries no exe path, so
                    # RuleEngine's hash-trust branch could never fire on this
                    # backend. Resolve it via psutil immediately -- a short-lived
                    # process can still exit before this runs, so failure must
                    # degrade to "no exe available," never crash the callback
                    # (this thread feeds the whole ETW pipeline).
                    if pid is not None:
                        try:
                            details["executable_path"] = psutil.Process(pid).exe()
                        except (psutil.Error, ValueError) as e:
                            logger.debug("Could not resolve exe path for PID %s: %s", pid, e)

                    self.out_queue.put(MonitorEvent(
                        category=EventCategory.PROCESS_STARTED,
                        summary=f"New process: {image_name} (PID {pid if pid is not None else pid_raw})",
                        details=details,
                        source="process",
                        confidence="certain",
                    ))
                except Exception as e:
                    logger.error("Error handling ETW event: %s", e)

            etw_trace = ETW(providers=[provider], event_callback=_callback)
            etw_trace.start()
            self._backend = "etw"
            logger.info("ETW process monitor started (Microsoft-Windows-Kernel-Process).")

            # Zero-event watchdog (see module docstring): a started session is
            # not a working session on this hardware. Spawn one throwaway child
            # process near the deadline so "no events" can only mean "consumer
            # is not delivering," never "the machine happened to be idle."
            deadline = ETW_ZERO_EVENT_FALLBACK_SECONDS
            waited = 0
            probe_spawned = False
            while not self._stop.is_set():
                self._stop.wait(1)
                if seen["count"] > 0:
                    break  # first event delivered -- ETW is genuinely working
                waited += 1
                if not probe_spawned and waited >= deadline - 5:
                    probe_spawned = True
                    try:
                        subprocess.run(["cmd", "/c", "ver"], capture_output=True, timeout=10)
                        logger.info("ETW watchdog: spawned a probe child process to guarantee "
                                    "a ProcessStart event exists before the fallback deadline.")
                    except Exception as e:
                        logger.warning("ETW watchdog probe spawn failed: %s", e)
                if waited >= deadline:
                    logger.error(
                        "ETW session started but delivered ZERO events in %ss (including a "
                        "self-spawned probe process) -- pywintrace's consumer is not delivering "
                        "(known issue, see windows/etw_probe.py). Stopping ETW and falling "
                        "back to WMI polling.", deadline)
                    try:
                        etw_trace.stop()
                    except Exception as e:
                        logger.warning("Stopping the dead ETW session failed (%s) -- "
                                       "continuing to WMI fallback anyway.", e)
                    return False

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
            import pythoncom
        except ImportError:
            logger.error("`wmi`/`pywin32` package not installed -- process monitoring disabled entirely. "
                         "pip install wmi pywin32")
            return

        self._backend = "wmi"
        # Confirmed bug: wmi.WMI() goes through win32com.client, which requires
        # COM to be initialized on the calling thread -- this runs on a
        # background thread (see start()), which gets no automatic COM init.
        # Without this, the very first WMI call here raised
        # pywintypes.com_error("CoInitialize has not been called"), which the
        # broad except below swallowed into a single ERROR log line --
        # process monitoring went silently dark with no further symptom.
        pythoncom.CoInitialize()
        try:
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
                            "cmdline": getattr(new_process, "CommandLine", "unknown"),
                        },
                        source="process",
                        confidence="polled",  # honest: WMI creation events lag real spawn time
                    )
                )
        finally:
            pythoncom.CoUninitialize()
