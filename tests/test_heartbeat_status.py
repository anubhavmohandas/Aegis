"""Runnable self-check for the dashboard heartbeat-age readout.

The monitor pill flips to STALLED off _heartbeat_age(): a fresh stamp reads a
small age, a missing/garbage stamp reads None (never crashes the status call).

No framework: `python tests/test_heartbeat_status.py`.
"""
import sqlite3, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.server import _heartbeat_age, DashboardHandler


def _db_with(value):
    """Temp sqlite meta table holding (or not) a last_heartbeat row."""
    path = Path(tempfile.mkdtemp()) / "hb.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    if value is not None:
        conn.execute("INSERT INTO meta (key, value) VALUES ('last_heartbeat', ?)", (value,))
    conn.commit(); conn.close()
    DashboardHandler.db_path = str(path)


def test_fresh_heartbeat_reads_small_age():
    _db_with(str(time.time()))
    age = _heartbeat_age()
    assert age is not None and age < 5, f"fresh stamp should read ~0s, got {age}"


def test_stale_heartbeat_reads_large_age():
    _db_with(str(time.time() - 600))
    assert _heartbeat_age() > 150, "10-min-old stamp must exceed the stale threshold"


def test_missing_stamp_is_none():
    _db_with(None)
    assert _heartbeat_age() is None, "no heartbeat row -> None, not a crash"


def test_garbage_stamp_is_none():
    _db_with("not-a-number")
    assert _heartbeat_age() is None, "unparseable value -> None, not a crash"


def test_missing_db_is_none():
    DashboardHandler.db_path = "/nonexistent/aegis.db"
    assert _heartbeat_age() is None, "unreadable DB -> None, never raises into status"


if __name__ == "__main__":
    test_fresh_heartbeat_reads_small_age()
    test_stale_heartbeat_reads_large_age()
    test_missing_stamp_is_none()
    test_garbage_stamp_is_none()
    test_missing_db_is_none()
    print("ok")
