# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build recipe for the Aegis desktop app (desktop_app.py):
# monitor pipeline + dashboard server + a native window, one process.
#
# Build from the REPO ROOT (paths below resolve via SPECPATH, but keeping the
# invocation uniform keeps dist/ and build/ where .gitignore expects them):
#
#     pyinstaller packaging/aegis.spec
#
# Output: dist/Aegis/ (Windows/Linux onedir) or dist/Aegis.app (macOS).
# See packaging/PACKAGING.md for the full flow, including why you should
# validate from source BEFORE building this.
#
# onedir, not onefile, on purpose: onefile pays a self-extraction on every
# launch and makes "which file is missing from the bundle" undebuggable.
# For an app that starts at login and stays resident, onedir's only cost
# (a folder instead of a single file) is invisible behind an installer.
#
# The old tray-only entry point (main.py) still exists and still works for
# anyone who explicitly wants headless/background operation -- it's just not
# what gets packaged as "Aegis.app" anymore, since a window-less menu-bar
# icon with no way to see or configure anything was the wrong default for a
# packaged, non-technical-facing build. The old read-only PySide6 timeline
# (ui/timeline_app.py) is still not bundled -- fully superseded by the
# dashboard now, PySide6 would triple the bundle size for nothing.

import subprocess
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent  # this file lives in packaging/

sys.path.insert(0, str(ROOT))
from core.version import __version__  # single source of truth -- see core/version.py

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"

# "Aegis Dev" is a SELF-SIGNED identity that only exists in a local login
# keychain (see the codesign_identity note in EXE below). A machine without it
# -- a CI runner, or a fresh checkout on someone else's Mac -- cannot sign, and
# PyInstaller treats a codesign failure as a fatal build error, which is
# exactly how the macOS job broke while Windows kept passing. Probe for it and
# fall back to an unsigned build instead of hard-failing: a locally-built app
# still gets the stable signature that keeps its TCC grants, and CI still
# produces a DMG. Signing for public distribution is a Developer ID job, not
# this one's.
CODESIGN_IDENTITY = None
if IS_MAC:
    _identities = subprocess.run(
        ["security", "find-identity", "-v", "-p", "codesigning"],
        capture_output=True, text=True,
    ).stdout
    if '"Aegis Dev"' in _identities:
        CODESIGN_IDENTITY = "Aegis Dev"
    else:
        print("aegis.spec: no 'Aegis Dev' signing identity in the keychain -- building UNSIGNED")

# Bundled at the same repo-relative destinations the code resolves against
# (core/config.py does Path(__file__).parent.parent / "config", and
# dashboard/server.py's STATIC_DIR/ASSETS_DIR do the equivalent for its own
# tree -- all of which land inside the bundle's _internal dir at runtime).
datas = [
    (str(ROOT / "config" / "config.yaml"), "config"),
    (str(ROOT / "assets" / "tray_icon.png"), "assets"),
    (str(ROOT / "assets" / "logo.png"), "assets"),        # dashboard UI + PDF report cover both use this
    (str(ROOT / "dashboard" / "static"), "dashboard/static"),
]

# main.py imports its collector package inside build_platform_monitors(), and
# plyer/anthropic/openai are imported lazily too -- PyInstaller's bytecode
# scan finds most of these, but plyer's per-OS backend is loaded by string
# name at runtime and MUST be named explicitly or Windows notifications
# silently fall through to the print fallback in the frozen build.
hiddenimports = ["anthropic", "openai"]

# Never bundle the other platforms' collector packages or their native deps;
# they can't import on this OS and only produce warnings/bloat.
# tkinter only excluded on macOS: the tray's password/info dialogs use native
# NSAlert there, but desktop_app._prompt_stop_password_tk needs tkinter on
# Windows/Linux -- excluding it everywhere silently broke the packaged tray Stop.
excludes = ["PySide6", "pytest"]

if IS_MAC:
    # WebKit/PyObjCTools are pywebview's Cocoa backend (webview/platforms/cocoa.py)
    # -- listed explicitly for the same reason AppKit/Foundation/objc already
    # were: PyInstaller's static scan is unreliable specifically for PyObjC's
    # Objective-C bridge modules.
    hiddenimports += ["AppKit", "Foundation", "objc", "WebKit", "PyObjCTools"]
    excludes += ["tkinter", "windows", "linux", "plyer", "pyudev", "wmi", "win32com", "win32api", "etw"]
elif IS_WIN:
    hiddenimports += ["plyer.platforms.win.notification"]
    excludes += ["macos", "linux", "pyudev", "AppKit", "Foundation", "objc"]
else:
    hiddenimports += ["plyer.platforms.linux.notification"]
    excludes += ["windows", "macos", "wmi", "win32com", "win32api", "etw",
                 "AppKit", "Foundation", "objc"]

a = Analysis(
    [str(ROOT / "desktop_app.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=excludes,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="Aegis",
    # Alpha builds keep the console on Windows so `Starting Aegis ...` and
    # collector fallback warnings are visible during real-hardware validation
    # (see TEST_REPORT_TEMPLATE.md). Flip to False for the beta, once the
    # Windows collectors have hardware evidence behind them.
    console=not IS_MAC,
    icon=str(ROOT / "assets" / "aegis.ico") if IS_WIN else None,
    # Stable self-signed identity ("Aegis Dev" in the login keychain): keeps
    # the macOS TCC grants (Screen Recording for evidence capture) valid
    # across rebuilds and self-updates -- ad-hoc signatures change every
    # build and silently invalidate them. Swap for a Developer ID before
    # public beta (also fixes Gatekeeper for downloaded DMGs).
    codesign_identity=CODESIGN_IDENTITY,
    # Entitlements only mean anything attached to a signature; passing them
    # without an identity is a no-op at best.
    entitlements_file=str(ROOT / "packaging" / "entitlements.plist") if CODESIGN_IDENTITY else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="Aegis",
)

if IS_MAC:
    app = BUNDLE(
        coll,
        name="Aegis.app",
        icon=str(ROOT / "assets" / "aegis.icns"),
        bundle_identifier="com.anubhav.aegis",
        info_plist={
            # Normal foreground app now: Dock icon, app switcher entry, a real
            # window (desktop_app.py). LSUIElement/menu-bar-only made sense
            # for the old tray-only main.py entry point, not for something
            # meant to be opened, looked at, and configured.
            "CFBundleShortVersionString": __version__,
            "NSHumanReadableCopyright": "Created by Anubhav",
            # Without this string macOS refuses (and may kill) camera access
            # outright -- required for the opt-in webcam evidence capture.
            "NSCameraUsageDescription":
                "Aegis takes one webcam photo as tamper evidence when repeated "
                "wrong passwords are entered on a protected action, and only if "
                "you enable webcam evidence in Settings.",
        },
    )
