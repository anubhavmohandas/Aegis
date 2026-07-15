"""
Runtime smoke checks used by local validation and CI packaging workflows.

What this verifies:
1) Core module imports that should always load in a healthy environment.
2) Dashboard HTTP server can start and serve the login page.
3) Timeline UI can construct and enter the Qt event loop once (offscreen).

The script is intentionally strict: any failed check returns a non-zero exit
code so CI fails fast instead of publishing a broken package.
"""

from __future__ import annotations

import argparse
import importlib
import os
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _import_smoke() -> None:
    modules = [
        "core.version",
        "core.config",
        "core.dispatcher",
        "core.updater",
        "dashboard.server",
        "desktop_app",
        "main",
        "ui.timeline_app",
    ]
    for module in modules:
        importlib.import_module(module)


def _pick_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _dashboard_server_smoke(host: str, port: int) -> None:
    from core.config import load_config
    from dashboard.server import build_server

    cfg = load_config()
    server = build_server(cfg.db_path, host, port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        url = f"http://{host}:{port}/login.html"
        deadline = time.time() + 15
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    body = response.read()
                    if response.status != 200 or not body:
                        raise RuntimeError(f"unexpected response: status={response.status} bytes={len(body)}")
                    return
            except Exception as exc:
                last_error = exc
                time.sleep(0.25)
        raise RuntimeError(f"dashboard server smoke check failed: {last_error}") from last_error
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _timeline_offscreen_smoke(db_path: str) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from core.database import EventStore
    from ui.timeline_app import TimelineWindow

    app = QApplication.instance() or QApplication([])
    window = TimelineWindow(EventStore(db_path))
    window.show()
    QTimer.singleShot(200, app.quit)
    app.exec()
    window.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0 means auto-pick a free port")
    parser.add_argument("--skip-timeline", action="store_true", help="Skip Qt timeline smoke check")
    args = parser.parse_args()

    try:
        _import_smoke()
        print("import_smoke_ok")

        port = args.port if args.port else _pick_free_port(args.host)
        _dashboard_server_smoke(args.host, port)
        print("dashboard_server_smoke_ok")

        if args.skip_timeline:
            print("timeline_smoke_skipped")
        else:
            from core.config import load_config

            cfg = load_config()
            _timeline_offscreen_smoke(cfg.db_path)
            print("timeline_offscreen_smoke_ok")
    except Exception as exc:
        print(f"runtime_validation_failed: {exc}", file=sys.stderr)
        return 1

    print("runtime_validation_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
