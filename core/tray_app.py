"""
Minimal system tray icon (Windows + macOS both supported by `pystray`) so the
app has *some* visible presence and a clean way to quit, without building a
full GUI. Right-click -> Quit is the only interaction; everything else
happens via notifications.
"""

from __future__ import annotations

import threading
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
    def __init__(self, on_quit):
        self.on_quit = on_quit
        self.icon = pystray.Icon(
            "aegis",
            _load_icon_image(),
            "Aegis",
            menu=pystray.Menu(
                pystray.MenuItem("Aegis (running)", None, enabled=False),
                pystray.MenuItem("Quit", self._quit),
            ),
        )

    def _quit(self, icon, item):
        self.on_quit()
        icon.stop()

    def run_blocking(self):
        # pystray needs the OS main thread on macOS -- call this from main(),
        # not from a background thread.
        self.icon.run()

    def run_in_background(self):
        # Fine on Windows; on macOS prefer run_blocking() from the main thread.
        threading.Thread(target=self.icon.run, daemon=True).start()
