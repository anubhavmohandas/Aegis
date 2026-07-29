"""macOS permission priming -- ask at launch, never mid-incident.

macOS has no install-time permission grant. TCC prompts can only be raised by
the running app, and by default they fire the first time a resource is actually
touched -- which for Aegis meant the OS asking for Camera and Screen Recording
*during a tamper capture*, i.e. at the exact moment someone had just typed a
wrong password. The person who needed to see evidence collected instead saw a
permission dialog, and the first incident lost its artifacts.

This module raises the same prompts up front, at startup, while the user is
looking at the app anyway. Nothing here changes what Aegis is allowed to do --
it only moves *when* the question is asked.

Idempotent by design: once a permission is determined (granted OR denied) macOS
never re-prompts, so calling this on every launch costs nothing and self-heals
an install that predates the priming. Every call is best-effort; a failure here
must never stop the app from starting.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform

logger = logging.getLogger("aegis.permissions")

_CORE_GRAPHICS = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
_AV_FOUNDATION = "/System/Library/Frameworks/AVFoundation.framework"


def prime(config) -> None:
    """Raise every permission prompt Aegis will eventually need, now.

    Camera is asked for ONLY when webcam evidence is enabled -- a security app
    that demands the camera for a feature the user left off earns exactly the
    suspicion it deserves. Call this again after a settings change so flipping
    that toggle on prompts there and then (see dashboard/server.write_settings).
    """
    if platform.system() != "Darwin":
        return
    _prime_folders(getattr(config, "watched_folders", None) or [])
    if getattr(config, "tamper_evidence_screenshot", True):
        _prime_screen_recording()
    if getattr(config, "tamper_evidence_webcam", False):
        _prime_camera()


def _prime_folders(folders) -> None:
    """Touch each watched folder so the Desktop/Documents/Downloads prompts
    land at startup. There is no request API for these -- reading the directory
    IS the request, and watchdog's FSEvents backend does not reliably raise it."""
    for folder in folders:
        try:
            os.listdir(folder)
        except PermissionError:
            logger.warning("Folder access denied for %s -- grant it in System Settings > "
                           "Privacy & Security > Files and Folders, or file events there "
                           "will be invisible to Aegis", folder)
        except OSError as e:
            logger.debug("Could not prime folder access for %s: %s", folder, e)


def _prime_screen_recording() -> bool:
    """Screen Recording, needed by evidence._screenshot. Preflight first: when
    permission was already refused, CGRequest* re-nags on every launch."""
    try:
        cg = ctypes.CDLL(_CORE_GRAPHICS)
        cg.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool
        if cg.CGPreflightScreenCaptureAccess():
            return True
        cg.CGRequestScreenCaptureAccess.restype = ctypes.c_bool
        granted = bool(cg.CGRequestScreenCaptureAccess())
        logger.info("Screen Recording permission requested at startup: granted=%s "
                    "(unsigned/from-source runs get no prompt -- grant it manually)", granted)
        return granted
    except Exception as e:
        logger.debug("Screen Recording priming failed: %s", e)
        return False


def _prime_camera() -> None:
    """Camera, needed by evidence._webcam. requestAccess is async and returns
    immediately when the status is already determined, so this never blocks
    startup waiting on an answer."""
    try:
        import objc

        objc.loadBundle("AVFoundation", {}, bundle_path=_AV_FOUNDATION)
        # The completion handler is an ObjC block, and pyobjc refuses to bridge
        # one without a signature (TypeError: "no signature available") unless
        # pyobjc-framework-AVFoundation is installed. Declaring it here keeps
        # that framework out of requirements for a single selector.
        objc.registerMetaDataForSelector(
            b"AVCaptureDevice", b"requestAccessForMediaType:completionHandler:",
            {"arguments": {3: {"callable": {
                "retval": {"type": b"v"},
                "arguments": {0: {"type": b"^v"}, 1: {"type": b"Z"}},
            }}}},
        )
        av = objc.lookUpClass("AVCaptureDevice")
        if av.authorizationStatusForMediaType_("vide") != 0:   # not "notDetermined"
            return                                             # answered already; asking again does nothing
        av.requestAccessForMediaType_completionHandler_(
            "vide", lambda granted: logger.info("Camera permission answered at startup: granted=%s",
                                                bool(granted)))
    except Exception as e:
        logger.debug("Camera priming failed: %s", e)
