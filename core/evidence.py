"""
Tamper evidence capture -- turns repeated failed authentication on a
protected action (Stop Monitoring, etc.) into a stored Incident.

Design contract, stated plainly:

  TAMPER *EVIDENCE*, NOT TAMPER *PROOF*. A userland Python app cannot stop
  an administrator from killing the process or deleting files. What it can
  do honestly is make interference VISIBLE: log every failed attempt as a
  timeline event, capture a screenshot + system snapshot after repeated
  failures, hash the artifacts, and keep the metadata in the database so
  "the screenshot file is missing" is itself evidence.

  EVERYTHING HERE IS BEST-EFFORT AND OPT-IN (config.yaml `tamper:` block,
  editable from Settings). Every single collector below degrades to "field
  absent" on failure -- an incident with no screenshot is still an incident.

  Webcam capture is implemented (see _webcam) and off by default: it
  needs the Settings opt-in, opencv bundled in the build, and the OS
  camera permission (macOS: NSCameraUsageDescription + camera
  entitlement, both in packaging/).

Artifacts live under the per-user data dir (survives self-update, works
from a packaged .app -- see core/config.persistent_dir):

    <data dir>/incidents/incident_YYYYMMDD_HHMMSS/
        screenshot.png
        incident.json          (full metadata incl. sha256 of each artifact)
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

logger = logging.getLogger("aegis.evidence")

_PUBLIC_IP_URL = "https://api.ipify.org"   # plain-text response, 3s timeout, best-effort
_PROCESS_SNAPSHOT_LIMIT = 20               # most recently started processes


def incidents_dir(config=None) -> Path:
    custom = str(getattr(config, "evidence_dir", "") or "").strip()
    if custom:
        return Path(custom).expanduser()
    from core.config import persistent_dir
    return persistent_dir() / "incidents"


def _sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# --- individual collectors (each returns None / [] on any failure) ---------

def _screenshot(dest: Path) -> tuple[Path | None, str | None]:
    """Capture a screenshot. Returns (path, None) on success, or (None, reason)
    on failure so the incident can record WHY it's missing instead of just
    showing an empty artifacts list.

    macOS specifics: PIL's ImageGrab shells out to `screencapture`, which the
    OS blocks unless the running app has Screen Recording permission (System
    Settings > Privacy & Security > Screen Recording). A bare `python` process
    launched from a terminal is denied with 'could not create image from
    display' and macOS does NOT show the permission prompt for it -- only a
    signed .app bundle triggers that dialog. So from source, the user must
    grant the permission manually; packaged, the .app can request it."""
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        img.save(dest, "PNG")
        return dest, None
    except Exception as e:
        text = str(e).lower()
        if "could not create image" in text or "screencapture" in text:
            reason = ("macOS blocked the screenshot -- grant Screen Recording permission "
                      "to this app (System Settings > Privacy & Security > Screen Recording), "
                      "then restart Aegis.")
        else:
            reason = f"screenshot failed: {e}"
        logger.warning("Evidence screenshot failed: %s", e)
        return None, reason


def _camera_indices() -> list[int]:
    """Camera indices for _webcam to try, in order. On macOS, iPhones/iPads
    (Continuity Camera) are excluded outright -- evidence must come from the
    machine's own camera, never from whatever phone happens to be nearby --
    and the built-in camera is ranked first. Uses pyobjc-core's bridge to
    AVFoundation (no extra dependency); index order matches OpenCV's
    AVFoundation backend, which enumerates devices with the same
    devicesWithMediaType: call. Any failure -> plain 0..2 scan."""
    if platform.system() != "Darwin":
        return list(range(3))
    try:
        import objc
        objc.loadBundle("AVFoundation", {},
                        bundle_path="/System/Library/Frameworks/AVFoundation.framework")
        devs = objc.lookUpClass("AVCaptureDevice").devicesWithMediaType_("vide")  # AVMediaTypeVideo
        allowed = []
        for i, d in enumerate(devs):
            dtype = str(d.deviceType() or "")
            model = str(d.modelID() or "")
            if "Continuity" in dtype or model.startswith(("iPhone", "iPad")):
                continue   # never an Apple mobile device, even if it's the system default
            allowed.append((0 if "BuiltIn" in dtype else 1, i))
        return [i for _, i in sorted(allowed)]
    except Exception:
        logger.debug("AVFoundation camera enumeration failed", exc_info=True)
        return list(range(3))


def _webcam(dest: Path) -> tuple[Path | None, str | None]:
    """One frame from the default camera, saved as JPEG. Same contract as
    _screenshot: (path, None) on success, (None, why) on failure.

    macOS specifics: the packaged .app needs NSCameraUsageDescription in its
    Info.plist and the com.apple.security.device.camera entitlement (both in
    packaging/) or the hardened runtime kills the capture; the user grants
    Camera permission once on first use."""
    try:
        import cv2
    except ImportError:
        return None, "webcam capture needs opencv-python (not installed in this build)"
    # occam: mean-brightness heuristic for "this frame is black". A genuinely
    # pitch-dark room false-positives; good enough until that's a real report.
    _BLACK = 8.0

    def _grab(index: int):
        """Open device `index` and give auto-exposure time to converge: taking
        the FIRST non-black frame yields a severely underexposed silhouette
        (AE starts dark and brightens over ~1s of streaming). Once frames go
        non-black, keep reading for another ~1.2s and return the last one;
        a camera that stays black gives up at ~1s so the next one gets a turn."""
        # occam: fixed settle window; an exposure-stability check if 1.2s misjudges some camera
        cam = cv2.VideoCapture(index)
        try:
            if not cam.isOpened():
                return None
            frame = None
            lit_at = None
            deadline = time.time() + 1.0
            while time.time() < deadline:
                ok, f = cam.read()
                if ok and f is not None:
                    frame = f
                    if lit_at is None and f.mean() > _BLACK:
                        lit_at = time.time()
                        deadline = lit_at + 1.2
                time.sleep(0.05)
            return frame
        finally:
            cam.release()

    try:
        # Only cameras _camera_indices() allows (built-in first, never an
        # iPhone/iPad); a black feed is skipped in favor of the next camera.
        # The outer retry loop covers first-ever capture on macOS: authorization
        # is "not determined", OpenCV requests access asynchronously and fails
        # THIS open, so re-try for a few seconds so a prompt answered now (or a
        # slow camera init) still yields a photo instead of always losing the
        # first incident.
        # occam: fixed 8s retry budget blocks the tamper response; go async if that lag matters
        indices = _camera_indices()
        if not indices:
            return None, ("no usable camera -- the only camera present is an iPhone/iPad "
                          "(Continuity Camera), which Aegis deliberately never uses")
        best = None
        deadline = time.time() + 8.0
        while True:
            for index in indices:
                frame = _grab(index)
                if frame is None:
                    continue
                if best is None or frame.mean() > best.mean():
                    best = frame
                if frame.mean() > _BLACK:
                    break
            if best is not None or time.time() >= deadline:
                break
            time.sleep(1.0)
        if best is None:
            hint = {"Darwin": "System Settings > Privacy & Security > Camera",
                    "Windows": "Settings > Privacy & security > Camera"}.get(
                        platform.system(), "your OS camera permissions")
            logger.warning("Evidence webcam capture failed: camera not readable "
                           "(no camera, or Camera permission not granted)")
            return None, ("could not read from the camera -- no camera found, or Camera "
                          f"permission not granted ({hint}; if a permission prompt just "
                          "appeared, Allow means the next capture will include the photo)")
        if not cv2.imwrite(str(dest), best):
            return None, "could not write the webcam image to disk"
        if best.mean() <= _BLACK:
            # Every camera gave only black frames -- save the least-bad one
            # anyway (a black photo plus a note beats no evidence) and say why.
            return dest, ("webcam image appears black -- covered lens, closed laptop lid, "
                          "or a very dark room; photo saved anyway")
        return dest, None
    except Exception as e:
        logger.warning("Evidence webcam capture failed: %s", e)
        return None, f"webcam capture failed: {e}"


def _public_ip() -> str | None:
    try:
        with urllib.request.urlopen(_PUBLIC_IP_URL, timeout=3) as resp:
            return resp.read(64).decode("ascii", errors="replace").strip()
    except Exception:
        return None


def _local_ips() -> list[str]:
    try:
        import psutil
        ips = []
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    ips.append(a.address)
        return ips
    except Exception:
        return []


def _active_window() -> str | None:
    try:
        system = platform.system()
        if system == "Darwin":
            out = subprocess.run(
                ["osascript", "-e",
                 'tell application "System Events" to get name of first application process whose frontmost is true'],
                capture_output=True, text=True, timeout=5)
            return out.stdout.strip() or None
        if system == "Windows":
            import ctypes
            from ctypes import wintypes
            # Declare restype/argtypes explicitly. ctypes defaults a foreign
            # function's return to a 32-bit c_int; on 64-bit Windows an HWND is
            # a 64-bit handle, so the default truncates it and the (also
            # int-defaulted) text calls get a mangled handle -> wrong or empty
            # title. Typing them as HWND/LPWSTR keeps the handle intact.
            user32 = ctypes.windll.user32
            user32.GetForegroundWindow.restype = wintypes.HWND
            user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
            user32.GetWindowTextLengthW.restype = ctypes.c_int
            user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user32.GetWindowTextW.restype = ctypes.c_int
            hwnd = user32.GetForegroundWindow()
            if not hwnd:      # nothing focused (e.g. the lock screen) -> no title
                return None
            length = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            return buf.value or None
    except Exception:
        pass
    return None


def _recent_processes() -> list[dict]:
    try:
        import psutil
        procs = []
        for p in psutil.process_iter(["pid", "name", "create_time", "username"]):
            if p.info.get("create_time"):
                procs.append(p.info)
        procs.sort(key=lambda p: p["create_time"], reverse=True)
        return [{"pid": p["pid"], "name": p.get("name"), "username": p.get("username"),
                 "started": time.strftime("%H:%M:%S", time.localtime(p["create_time"]))}
                for p in procs[:_PROCESS_SNAPSHOT_LIMIT]]
    except Exception:
        return []


def _battery() -> dict | None:
    try:
        import psutil
        b = psutil.sensors_battery()
        if b is None:
            return None
        return {"percent": b.percent, "plugged_in": b.power_plugged}
    except Exception:
        return None


# --- the one entry point -----------------------------------------------------

def capture_incident(*, reason: str, attempts: int, store, config=None,
                     extra_context: dict | None = None) -> dict:
    """Capture evidence, persist an Incident row + a TAMPER_EVIDENCE timeline
    event, and return the incident dict. Never raises -- worst case is an
    incident row with empty artifacts.

    `store` is a core.database.EventStore (must be writable).
    `config` is an AppConfig; used for the screenshot/webcam toggles and to
    build the optional AI summary. None = capture with defaults, no AI.
    """
    ts = time.time()
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(ts))
    inc_dir = incidents_dir(config) / f"incident_{stamp}"
    try:
        inc_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error("Could not create incident directory %s: %s", inc_dir, e)

    artifacts: dict = {}
    capture_notes: dict = {}
    want_screenshot = getattr(config, "tamper_evidence_screenshot", True)
    want_webcam = getattr(config, "tamper_evidence_webcam", False)
    if want_screenshot:
        shot, err = _screenshot(inc_dir / "screenshot.png")
        if shot:
            artifacts["screenshot"] = {"path": str(shot), "sha256": _sha256_file(shot)}
        elif err:
            capture_notes["screenshot"] = err   # attempted but blocked -- record why
    else:
        capture_notes["screenshot"] = "screenshot evidence is turned off in Settings."
    if want_webcam:
        cam, cam_err = _webcam(inc_dir / "webcam.jpg")
        if cam:
            artifacts["webcam"] = {"path": str(cam), "sha256": _sha256_file(cam)}
        if cam_err:
            capture_notes["webcam"] = cam_err   # blocked, or saved with a caveat -- record why

    import getpass
    try:
        username = getpass.getuser()
    except Exception:
        username = None
    hostname = socket.gethostname()

    context = {
        "public_ip": _public_ip(),
        "local_ips": _local_ips(),
        "active_window": _active_window(),
        "recent_processes": _recent_processes(),
        "battery": _battery(),
        "platform": f"{platform.system()} {platform.release()}",
        **({"capture_notes": capture_notes} if capture_notes else {}),
        **(extra_context or {}),
    }

    ai_summary = None
    if config is not None:
        ai_summary = _ai_summary(reason, attempts, artifacts, context, config)

    incident = {
        "timestamp": ts, "reason": reason, "attempts": attempts,
        "username": username, "hostname": hostname,
        "artifacts": artifacts, "context": context, "ai_summary": ai_summary,
    }

    try:
        incident["id"] = store.insert_incident(
            reason=reason, attempts=attempts, username=username, hostname=hostname,
            artifacts=artifacts, context=context, ai_summary=ai_summary, timestamp=ts)
    except Exception as e:
        logger.error("Could not persist incident to the database: %s", e)

    # incident.json beside the artifacts: readable evidence even if the DB
    # is later deleted (and vice versa -- the DB row survives file deletion).
    try:
        (inc_dir / "incident.json").write_text(json.dumps(incident, indent=2), encoding="utf-8")
    except OSError as e:
        logger.error("Could not write incident.json: %s", e)

    # ...and a timeline event, so the incident shows up in the story too.
    try:
        store.insert(
            source="tamper", category="tamper_evidence",
            summary=f"Evidence captured: {reason} ({attempts} failed attempts)",
            details={"incident_id": incident.get("id"), "artifacts": list(artifacts),
                     "active_window": context.get("active_window")},
            confidence="certain", severity="critical",
            explanation=ai_summary, timestamp=ts)
    except Exception as e:
        logger.error("Could not persist tamper_evidence event: %s", e)

    logger.warning("Tamper incident #%s captured: %s (%d attempts, artifacts: %s)",
                   incident.get("id", "?"), reason, attempts, list(artifacts) or "none")
    return incident


def _ai_summary(reason: str, attempts: int, artifacts: dict, context: dict, config) -> str | None:
    try:
        from core.ai_explainer import AIExplainer
        block = "\n".join(filter(None, [
            f"Incident: {reason}",
            f"Failed authentication attempts: {attempts}",
            f"Artifacts captured: {', '.join(artifacts) or 'none'}",
            f"Active window at capture: {context.get('active_window') or 'unknown'}",
            f"Public IP: {context.get('public_ip') or 'unknown'}",
            "Most recently started processes: " +
            ", ".join(p.get("name") or "?" for p in context.get("recent_processes", [])[:8]),
        ]))
        return AIExplainer(config).summarize_incident(block)
    except Exception as e:
        logger.error("Incident AI summary failed: %s", e)
        return None


if __name__ == "__main__":
    # Self-check: full capture round-trip against a temp store, with the
    # screenshot/network collectors stubbed out (no permissions, no network).
    import tempfile
    from core.database import EventStore

    # Rebind THIS module's globals (under `python -m` this file runs as
    # __main__, so `import core.evidence` would stub a second, unused copy):
    _screenshot = lambda dest: (None, "macOS blocked the screenshot -- grant Screen Recording permission")
    _public_ip = lambda: None
    incidents_dir = lambda config=None: Path(tempfile.mkdtemp())  # don't litter the repo's incidents/

    store = EventStore(str(Path(tempfile.mkdtemp()) / "t.db"))
    inc = capture_incident(reason="unauthorized monitoring stop attempt",
                           attempts=3, store=store, config=None)
    assert inc["id"] == 1 and inc["attempts"] == 3
    rows = store.list_incidents()
    assert len(rows) == 1 and rows[0]["reason"].startswith("unauthorized")
    ctx = json.loads(rows[0]["context_json"])
    assert ctx["platform"].split()[0] in ("Darwin", "Windows", "Linux")
    # the blocked-screenshot reason is recorded, not silently dropped
    assert "Screen Recording" in ctx["capture_notes"]["screenshot"]
    store.set_incident_reviewed(1)
    assert store.get_incident(1)["reviewed"] == 1
    events = store.recent(5)
    assert events[0]["category"] == "tamper_evidence" and events[0]["severity"] == "critical"
    # collectors never raise
    assert isinstance(_local_ips(), list) and isinstance(_recent_processes(), list)
    print("evidence self-check: OK")
