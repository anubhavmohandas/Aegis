"""
Minimal system tray icon (Windows + macOS both supported by `pystray`) so the
app has *some* visible presence and a clean way to quit, without building a
full GUI. Right-click -> Quit is the only interaction; everything else
happens via notifications.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw
import pystray

ASSET_ICON_PATH = Path(__file__).resolve().parent.parent / "assets" / "tray_icon.png"


def _make_fallback_icon_image() -> Image.Image:
    # Generated shield-ish placeholder, used only if assets/tray_icon.png is
    # missing -- keeps the app runnable even in a checkout without the logo.
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(32, 4), (58, 16), (58, 34), (32, 60), (6, 34), (6, 16)], fill=(30, 144, 255, 255))
    draw.polygon([(32, 14), (50, 22), (50, 33), (32, 50), (14, 33), (14, 22)], fill=(255, 255, 255, 255))
    return img


def _load_icon_image() -> Image.Image:
    if ASSET_ICON_PATH.exists():
        return Image.open(ASSET_ICON_PATH).convert("RGBA")
    return _make_fallback_icon_image()


class TrayApp:
    # No "Open Dashboard" item: main.py's tray-only mode does not run the
    # dashboard server (that's desktop_app.py, which has its own richer menu in
    # _add_macos_menubar/_add_pystray_tray), so the optional on_open_dashboard
    # hook this class used to accept was never passed by any caller and the
    # menu item it guarded could never appear. Removed rather than left as
    # dead flexibility.
    def __init__(self, on_quit):
        self.on_quit = on_quit
        self.icon = pystray.Icon("aegis", _load_icon_image(), "Aegis", menu=pystray.Menu(
            pystray.MenuItem("Aegis (running)", None, enabled=False),
            pystray.MenuItem("Quit", self._quit),
        ))

    def _quit(self, icon, item):
        # on_quit may veto by returning False (main.py's password gate:
        # quitting is a protected action, same as the desktop app's Quit).
        # Without this check the icon stopped regardless, and with every
        # other thread daemonized, a stopped tray loop IS a quit.
        if self.on_quit() is False:
            return
        icon.stop()

    def run_blocking(self):
        # pystray needs the OS main thread on macOS -- call this from main(),
        # not from a background thread.
        self.icon.run()
