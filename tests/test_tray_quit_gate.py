"""Runnable self-check: TrayApp._quit honors an on_quit veto.

main.py's tray Quit is password-gated (same tamper gate as the desktop app);
the gate signals "blocked" by returning False, and TrayApp._quit must then
NOT stop the icon -- with every other thread daemonized, a stopped tray loop
IS a process exit, gate or no gate.

No framework: `python tests/test_tray_quit_gate.py`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.tray_app import TrayApp


class FakeIcon:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


t = TrayApp.__new__(TrayApp)   # skip __init__: _quit needs no real pystray icon
icon = FakeIcon()

# Vetoed (wrong/cancelled password): the icon must keep running.
t.on_quit = lambda: False
t._quit(icon, None)
assert not icon.stopped, "vetoed quit must not stop the tray icon"

# Authorized (gate returns None after doing the shutdown): normal quit.
calls = []
t.on_quit = lambda: calls.append(1)
t._quit(icon, None)
assert calls and icon.stopped, "authorized quit must run on_quit and stop the icon"

print("ok: tray quit honors the veto")
