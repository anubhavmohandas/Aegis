"""The desktop app must only reuse a dashboard port that Aegis itself holds.

Argus's web server also defaulted to 127.0.0.1:8787. desktop_app saw "something
is listening" and opened the Aegis window onto it -- so the user got Argus's UI,
and Aegis's own dashboard never started. _is_aegis_server() now checks the
Server header DashboardHandler sends before reusing a listener.

No framework needed: `python tests/test_port_owner.py`.
"""
import sys
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dashboard.server as srv  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="aegis-port-"))
srv.DATA_DIR = _TMP
srv.CREDENTIALS_PATH = _TMP / "credentials.json"
srv.CONFIG_PATH = _TMP / "config.yaml"

from desktop_app import _is_aegis_server  # noqa: E402


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


aegis = srv.build_server(str(_TMP / "events.db"), "127.0.0.1", 0)
other = ThreadingHTTPServer(("127.0.0.1", 0), SimpleHTTPRequestHandler)   # stands in for Argus
try:
    assert _is_aegis_server("127.0.0.1", _serve(aegis)), "Aegis dashboard not recognised"
    assert not _is_aegis_server("127.0.0.1", _serve(other)), "foreign server mistaken for Aegis"
    closed = other.server_address[1]
finally:
    aegis.shutdown()
    other.shutdown()
    other.server_close()
assert not _is_aegis_server("127.0.0.1", closed), "closed port mistaken for Aegis"
print("ok")
