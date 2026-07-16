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

  WEBCAM CAPTURE IS DELIBERATELY NOT IMPLEMENTED IN THIS VERSION. The
  settings model reserves `evidence_webcam` for v2: it needs an explicit
  opt-in flow, a camera-permission story per OS, and jurisdictional
  consent caveats that a screenshot doesn't carry. The toggle exists so
  the config shape doesn't change later; it currently only logs.

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


def incidents_dir() -> Path:
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

def _screenshot(dest: Path) -> Path | None:
    """PIL's ImageGrab wraps the native path on every OS (screencapture on
    macOS -- needs the one-time Screen Recording permission there)."""
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        img.save(dest, "PNG")
        return dest
    except Exception as e:
        logger.warning("Evidence screenshot failed (permission not granted, or headless?): %s", e)
        return None


def _webcam(dest: Path) -> Path | None:
    # occam: reserved for v2 -- needs opencv (a heavy new dependency), a
    # per-OS camera permission flow, and an explicit consent story. The
    # config toggle exists; the capture deliberately does not yet.
    logger.info("Webcam evidence is a v2 feature -- not captured (screenshot evidence only).")
    return None


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
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
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
    inc_dir = incidents_dir() / f"incident_{stamp}"
    try:
        inc_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error("Could not create incident directory %s: %s", inc_dir, e)

    artifacts: dict = {}
    want_screenshot = getattr(config, "tamper_evidence_screenshot", True)
    want_webcam = getattr(config, "tamper_evidence_webcam", False)
    if want_screenshot:
        shot = _screenshot(inc_dir / "screenshot.png")
        if shot:
            artifacts["screenshot"] = {"path": str(shot), "sha256": _sha256_file(shot)}
    if want_webcam:
        cam = _webcam(inc_dir / "webcam.jpg")
        if cam:
            artifacts["webcam"] = {"path": str(cam), "sha256": _sha256_file(cam)}

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
    import core.evidence as ev
    from core.database import EventStore

    ev._screenshot = lambda dest: None
    ev._public_ip = lambda: None

    store = EventStore(str(Path(tempfile.mkdtemp()) / "t.db"))
    inc = capture_incident(reason="unauthorized monitoring stop attempt",
                           attempts=3, store=store, config=None)
    assert inc["id"] == 1 and inc["attempts"] == 3
    rows = store.list_incidents()
    assert len(rows) == 1 and rows[0]["reason"].startswith("unauthorized")
    assert json.loads(rows[0]["context_json"])["platform"].split()[0] in ("Darwin", "Windows", "Linux")
    store.set_incident_reviewed(1)
    assert store.get_incident(1)["reviewed"] == 1
    events = store.recent(5)
    assert events[0]["category"] == "tamper_evidence" and events[0]["severity"] == "critical"
    # collectors never raise
    assert isinstance(_local_ips(), list) and isinstance(_recent_processes(), list)
    print("evidence self-check: OK")
