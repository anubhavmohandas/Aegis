"""
SQLite-backed event history for the timeline UI.

This is the persisted, queryable record of everything the app has seen --
distinct from the flat `events.log` audit trail (which stays as a
zero-dependency, always-append fallback). If SQLite writes ever fail for
some reason, the flat log in dispatcher.py is unaffected, so you never lose
the audit trail even if this layer breaks.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    confidence TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    explanation TEXT,
    risk_hint TEXT,
    ai_skipped INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""

# Additive migration for DBs created before `severity` existed -- avoids
# forcing anyone to delete their event history when they pull this update.
_MIGRATIONS = [
    "ALTER TABLE events ADD COLUMN severity TEXT NOT NULL DEFAULT 'medium'",
]


class EventStore:
    """Thread-safe wrapper around a single SQLite file. One connection per
    thread (SQLite connections aren't safe to share across threads);
    `check_same_thread=False` + an internal lock keeps this simple instead
    of building a connection pool for what is a low-volume personal tool."""

    def __init__(self, db_path: str = "aegis_events.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True) if Path(db_path).parent != Path(".") else None
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        for migration in _MIGRATIONS:
            try:
                self._conn.execute(migration)
            except sqlite3.OperationalError:
                pass  # column already exists -- fine, this runs on every startup
        self._conn.commit()

    def insert(self, *, source: str, category: str, summary: str, details: dict,
               confidence: str, severity: str = "medium", explanation: str | None = None,
               risk_hint: str | None = None, ai_skipped: bool = False,
               timestamp: float | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (timestamp, source, category, summary, details_json, "
                "confidence, severity, explanation, risk_hint, ai_skipped) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp or time.time(), source, category, summary, json.dumps(details),
                 confidence, severity, explanation, risk_hint, int(ai_skipped)),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent(self, limit: int = 200, source: str | None = None) -> list[dict]:
        with self._lock:
            if source:
                rows = self._conn.execute(
                    "SELECT * FROM events WHERE source = ? ORDER BY timestamp DESC LIMIT ?",
                    (source, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
            cols = [d[0] for d in self._conn.execute("SELECT * FROM events LIMIT 0").description]
            return [dict(zip(cols, row)) for row in rows]

    def close(self):
        with self._lock:
            self._conn.close()
