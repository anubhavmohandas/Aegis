"""
macOS USB device connect/disconnect monitoring.

TWO SOURCES, BOTH POLLED, FOR A REASON FOUND ON REAL HARDWARE:

1. `system_profiler SPUSBDataType` -- the general USB device tree (covers
   keyboards, mice, hubs, webcams, phones, etc). This was the only source
   originally, on the assumption it would also reliably list USB mass
   storage devices.

   THAT ASSUMPTION WAS WRONG, CONFIRMED ON A REAL MAC: a genuine external
   USB flash drive ("SanDisk 3.2Gen1", protocol USB, mounted and fully
   usable, visible in Finder) was completely absent from both the JSON and
   plain-text output of `SPUSBDataType` -- not a parsing bug, `system_profiler`
   itself omitted it. This appears to be a real, undocumented reliability gap
   in `SPUSBDataType` for at least some storage devices on some macOS/hardware
   combinations. Kept in place because it may still catch non-storage USB
   devices correctly; just no longer trusted alone for storage.

2. `system_profiler SPStorageDataType` -- added after the above was found.
   Filtered to entries where `physical_drive.protocol == "USB"` and
   `physical_drive.is_internal_disk == "no"`. This reliably showed the same
   drive `SPUSBDataType` missed, confirmed against real JSON output, not
   assumed structure. Keyed by `volume_uuid` (stable across polls, unique
   per volume). This is arguably the more security-relevant signal anyway --
   a mounted, writable external volume is the actual data-exfiltration
   concern, more than USB device enumeration in the abstract.

Both are genuinely polling, not event-driven -- confidence="polled"
throughout, same latency tradeoff as before (3-5s, acceptable for a
human-timescale event like plugging in a drive).
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
        self._known_storage: dict[str, dict] = {}

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("macOS USB monitor started (system_profiler polling every %ss, "
                    "SPUSBDataType + SPStorageDataType).", self.poll_interval_seconds)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        self._known = self._snapshot_devices()
        self._known_storage = self._snapshot_storage()
        logger.info("USB monitor baseline: %d device(s) via SPUSBDataType: %s | "
                    "%d external USB volume(s) via SPStorageDataType: %s",
                    len(self._known), [d["name"] for d in self._known.values()],
                    len(self._known_storage), [d["name"] for d in self._known_storage.values()])

        while not self._stop.is_set():
            self._stop.wait(self.poll_interval_seconds)
            if self._stop.is_set():
                break

            current = self._snapshot_devices()
            self._diff_and_emit_devices(self._known, current)
            self._known = current

            current_storage = self._snapshot_storage()
            self._diff_and_emit_storage(self._known_storage, current_storage)
            self._known_storage = current_storage

    # ---- Source 1: SPUSBDataType (general device tree) --------------------

    def _snapshot_devices(self) -> dict[str, dict]:
        try:
            out = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=15,
            )
            data = json.loads(out.stdout)
        except Exception as e:
            logger.error("system_profiler SPUSBDataType scan failed: %s", e)
            return dict(self._known)

        devices: dict[str, dict] = {}

        def walk(items):
            for item in items:
                key = item.get("serial_num") or item.get("location_id") or item.get("_name", "unknown")
                devices[str(key)] = {
                    "name": item.get("_name", "Unknown USB device"),
                    "vendor_id": item.get("vendor_id", "unknown"),
                    "product_id": item.get("product_id", "unknown"),
                    # v2 fix: this diff key was computed but never copied into
                    # the event details -- core/rule_engine.py's trusted_usb_ids
                    # check reads details["device_id"]/["serial_num"], which
                    # were always absent, so no macOS USB event could ever
                    # match a trust-listed device. Windows/Linux collectors
                    # already include this key; macOS was the one gap.
                    "device_id": str(key),
                    "serial_num": str(item.get("serial_num", "")),
                }
                if "_items" in item:
                    walk(item["_items"])

        for controller in data.get("SPUSBDataType", []):
            walk(controller.get("_items", []))
        return devices

    def _diff_and_emit_devices(self, old: dict[str, dict], new: dict[str, dict]):
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

    # ---- Source 2: SPStorageDataType (USB mass storage, verified reliable) --

    def _snapshot_storage(self) -> dict[str, dict]:
        try:
            out = subprocess.run(
                ["system_profiler", "SPStorageDataType", "-json"],
                capture_output=True, text=True, timeout=15,
            )
            data = json.loads(out.stdout)
        except Exception as e:
            logger.error("system_profiler SPStorageDataType scan failed: %s", e)
            return dict(self._known_storage)

        volumes: dict[str, dict] = {}
        for entry in data.get("SPStorageDataType", []):
            drive = entry.get("physical_drive", {})
            if drive.get("protocol") != "USB" or drive.get("is_internal_disk") != "no":
                continue
            key = entry.get("volume_uuid") or entry.get("bsd_name") or entry.get("_name", "unknown")
            volumes[str(key)] = {
                "name": entry.get("_name", "Unknown volume"),
                "mount_point": entry.get("mount_point", "unknown"),
                "bsd_name": entry.get("bsd_name", "unknown"),
                "file_system": entry.get("file_system", "unknown"),
                "device_name": drive.get("device_name", "unknown"),
                "media_name": drive.get("media_name", "unknown"),
                "writable": entry.get("writable", "unknown"),
                # v2 fix: same trusted_usb_ids gap as _snapshot_devices above --
                # this diff key needs to be in `details` for the rule engine
                # to ever see it.
                "device_id": str(key),
                "volume_uuid": str(entry.get("volume_uuid", "")),
            }
        return volumes

    def _diff_and_emit_storage(self, old: dict[str, dict], new: dict[str, dict]):
        for key, info in new.items():
            if key not in old:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.USB_CONNECTED,
                    summary=f"USB storage volume mounted: {info['name']} "
                            f"({info['device_name']}, at {info['mount_point']})",
                    details=info,
                    source="usb",
                    confidence="polled",
                ))
        for key, info in old.items():
            if key not in new:
                self.out_queue.put(MonitorEvent(
                    category=EventCategory.USB_REMOVED,
                    summary=f"USB storage volume unmounted: {info['name']} ({info['device_name']})",
                    details=info,
                    source="usb",
                    confidence="polled",
                ))
