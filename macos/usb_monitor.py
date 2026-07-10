"""
macOS USB device connect/disconnect monitoring.

The "correct" real-time approach here is IOKit (IOServiceAddMatchingNotification),
but pyobjc's IOKit bridge is low-level/incomplete for this purpose and doing it
properly means dropping into ctypes + the IOKit C API -- a much bigger lift
than fits this MVP, and not something I can test without a Mac anyway.

This module instead polls `system_profiler SPUSBDataType -json` every
`poll_interval_seconds` and diffs the device list by serial number / location
ID. This is genuinely the weakest monitor in the project:
  - A few seconds of latency (acceptable -- USB connect/disconnect is a
    human-timescale event, unlike process creation).
  - Spawns a subprocess on every poll (system_profiler is not fast; keep
    poll_interval_seconds reasonable -- 3-5s, not sub-second).
  - Confidence tagged "polled" throughout.

If you outgrow this: `pyusb` (libusb backend) supports hotplug callbacks on
macOS and would be the natural next step, at the cost of an extra native
dependency (libusb itself, via Homebrew).
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from queue import Queue

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.macos.usb_monitor")


class MacUsbMonitor:
    def __init__(self, out_queue: Queue, poll_interval_seconds: int = 4):
        self.out_queue = out_queue
        self.poll_interval_seconds = max(poll_interval_seconds, 3)  # floor -- system_profiler is slow
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: dict[str, dict] = {}

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        self._known = self._snapshot()
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval_seconds)
            if self._stop.is_set():
                break
            current = self._snapshot()
            self._diff_and_emit(self._known, current)
            self._known = current

    def _snapshot(self) -> dict[str, dict]:
        """Returns {device_key: device_info} for every USB device currently listed."""
        try:
            out = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=15,
            )
            data = json.loads(out.stdout)
        except Exception as e:
            logger.error("system_profiler USB scan failed: %s", e)
            return dict(self._known)  # don't wipe state on a transient failure

        devices: dict[str, dict] = {}

        def walk(items):
            for item in items:
                key = item.get("serial_num") or item.get("location_id") or item.get("_name", "unknown")
                devices[str(key)] = {
                    "name": item.get("_name", "Unknown USB device"),
                    "vendor_id": item.get("vendor_id", "unknown"),
                    "product_id": item.get("product_id", "unknown"),
                }
                if "_items" in item:
                    walk(item["_items"])

        for controller in data.get("SPUSBDataType", []):
            walk(controller.get("_items", []))
        return devices

    def _diff_and_emit(self, old: dict[str, dict], new: dict[str, dict]):
        for key, info in new.items():
            if key not in old:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.USB_CONNECTED,
                    summary=f"USB device connected: {info['name']}",
                    details=info,
                    source="usb",
                    confidence="polled",
                ))
        for key, info in old.items():
            if key not in new:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.USB_REMOVED,
                    summary=f"USB device removed: {info['name']}",
                    details=info,
                    source="usb",
                    confidence="polled",
                ))
