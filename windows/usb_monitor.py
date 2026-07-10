"""
Windows USB device connect/disconnect monitoring via WMI (Win32_PnPEntity
creation/deletion events).

Unlike process creation, WMI's latency here is a non-issue -- USB insert/
remove is an infrequent, human-timescale event, so polling-with-callback via
WMI is the *correct* tool for this job, not a compromise. Confidence: likely
correct (this is a widely documented WMI pattern), but still UNTESTED by me
since I have no Windows machine.
"""

from __future__ import annotations

import logging
import threading
from queue import Queue

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.windows.usb_monitor")


class WindowsUsbMonitor:
    def __init__(self, out_queue: Queue):
        self.out_queue = out_queue
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self):
        t1 = threading.Thread(target=self._watch, args=("creation", EventCategory.USB_CONNECTED), daemon=True)
        t2 = threading.Thread(target=self._watch, args=("deletion", EventCategory.USB_REMOVED), daemon=True)
        self._threads = [t1, t2]
        for t in self._threads:
            t.start()

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)

    def _watch(self, notification_type: str, category: EventCategory):
        try:
            import wmi
        except ImportError:
            logger.error("`wmi` package not installed -- USB monitoring disabled. pip install wmi pywin32")
            return

        try:
            conn = wmi.WMI()
            watcher = conn.Win32_PnPEntity.watch_for(notification_type=notification_type)
        except Exception as e:
            logger.error("Failed to set up WMI PnP watcher (%s): %s", notification_type, e)
            return

        while not self._stop.is_set():
            try:
                entity = watcher(timeout_ms=2000)
            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                logger.error("WMI PnP watcher error: %s", e)
                continue

            device_id = getattr(entity, "DeviceID", "") or ""
            pnp_class = getattr(entity, "PNPClass", "") or ""
            # Filter to USB devices specifically -- Win32_PnPEntity fires for
            # every plug-and-play device (Bluetooth, virtual adapters, etc),
            # not just USB.
            if "USB" not in device_id.upper() and pnp_class.upper() != "USB":
                continue

            name = getattr(entity, "Name", "Unknown device")
            action = "connected" if category == EventCategory.USB_CONNECTED else "removed"
            self.out_queue.put(
                MonitorEvent(
                    category=category,
                    summary=f"USB device {action}: {name}",
                    details={"device_id": device_id, "name": name, "pnp_class": pnp_class},
                    source="usb",
                    confidence="certain",
                )
            )
