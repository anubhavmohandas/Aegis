# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build recipe for the Aegis background monitor (main.py).
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
# The timeline UI (ui/timeline_app.py, PySide6) is deliberately NOT bundled:
# it's a separate developer-facing tool until the v2 dashboard exists, and
# PySide6 would triple the bundle size for something main.py never imports.

import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent  # this file lives in packaging/

sys.path.insert(0, str(ROOT))
from core.version import __version__  # single source of truth -- see core/version.py

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"

# Bundled at the same repo-relative destinations the code resolves against
# (core/config.py and core/tray_app.py both do Path(__file__).parent.parent /
# "config" | "assets", which lands inside the bundle's _internal dir).
datas = [
    (str(ROOT / "config" / "config.yaml"), "config"),
    (str(ROOT / "assets" / "tray_icon.png"), "assets"),
]

# main.py imports its collector package inside build_platform_monitors(), and
# plyer/anthropic/openai are imported lazily too -- PyInstaller's bytecode
# scan finds most of these, but plyer's per-OS backend is loaded by string
# name at runtime and MUST be named explicitly or Windows notifications
# silently fall through to the print fallback in the frozen build.
hiddenimports = ["anthropic", "openai"]

# Never bundle the other platforms' collector packages or their native deps;
# they can't import on this OS and only produce warnings/bloat.
excludes = ["PySide6", "tkinter", "pytest"]

if IS_MAC:
    hiddenimports += ["AppKit", "Foundation", "objc"]
    excludes += ["windows", "linux", "plyer", "pyudev", "wmi", "win32com", "win32api", "etw"]
elif IS_WIN:
    hiddenimports += ["plyer.platforms.win.notification"]
    excludes += ["macos", "linux", "pyudev", "AppKit", "Foundation", "objc"]
else:
    hiddenimports += ["plyer.platforms.linux.notification"]
    excludes += ["windows", "macos", "wmi", "win32com", "win32api", "etw",
                 "AppKit", "Foundation", "objc"]

a = Analysis(
    [str(ROOT / "main.py")],
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
        # No .icns yet -- Finder shows the generic app icon. The tray icon
        # (assets/tray_icon.png) is unaffected; it's loaded by pystray at
        # runtime, not from the bundle metadata.
        icon=None,
        bundle_identifier="com.anubhav.aegis",
        info_plist={
            # Menu-bar-only app: no Dock icon, no app switcher entry. This is
            # the packaged equivalent of "lives in the system tray."
            "LSUIElement": True,
            "CFBundleShortVersionString": __version__,
            "NSHumanReadableCopyright": "Created by Anubhav",
        },
    )
