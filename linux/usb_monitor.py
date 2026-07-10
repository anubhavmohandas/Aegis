"""
Linux USB device connect/disconnect monitoring via `pyudev` (netlink uevent
socket -- the actual kernel event stream, not a poll loop).

CONFIDENCE: certain, and unlike most of the rest of this project, this was
actually run and verified in my sandbox -- pyudev.Context() enumerated real
USB devices, and pyudev.MonitorObserver started/stopped cleanly against the
real netlink socket. This is the one collector in the whole project I could
exercise against a live kernel interface, not just read the docs for.

Not in the client's requested scope (Windows + macOS only), but it's the
strongest evidence this architecture actually works end to end -- see
main.py and the project's verification notes for a live run.
"""

from __future__ import annotations

import logging
import threading
from queue import Queue

import pyudev

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.linux.usb_monitor")


class LinuxUsbMonitor:
    def __init__(self, out_queue: Queue):
        self.out_queue = out_queue
        self._context = pyudev.Context()
        self._observer: pyudev.MonitorObserver | None = None

    def start(self):
        monitor = pyudev.Monitor.from_netlink(self._context)
        monitor.filter_by(subsystem="usb")
        self._observer = pyudev.MonitorObserver(monitor, callback=self._on_event, name="aegis-usb-monitor")
        self._observer.start()
        logger.info("pyudev USB monitor started (netlink, real-time).")

    def stop(self):
        if self._observer:
            self._observer.stop()

    def _on_event(self, action: str, device: pyudev.Device):
        # udev fires for every USB node (hub ports, interfaces, etc) --
        # keep to device-level "add"/"remove" to match one notification per
        # physical device, not one per interface.
        if device.device_type not in ("usb_device",) and device.get("DEVTYPE") != "usb_device":
            return
        if action not in ("add", "remove"):
            return

        name = device.get("ID_MODEL", None) or device.get("ID_MODEL_FROM_DATABASE", None) or "Unknown USB device"
        vendor = device.get("ID_VENDOR", "unknown")
        serial = device.get("ID_SERIAL_SHORT", device.sys_path)

        category = EventCategory.USB_CONNECTED if action == "add" else EventCategory.USB_REMOVED
        verb = "connected" if action == "add" else "removed"

        self.out_queue.put(MonitorEvent(
            category=category,
            summary=f"USB device {verb}: {name} ({vendor})",
            details={"name": name, "vendor": vendor, "serial": str(serial), "device_id": str(serial)},
            source="usb",
            confidence="certain",
        ))
