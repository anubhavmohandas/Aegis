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
import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("aegis.database")

# Version tag embedded INSIDE every persisted details_json blob (not on the
# MonitorEvent dataclass -- that object never crosses a process boundary,
# this JSON blob is what actually gets written to disk and read back months
# later). Bump this if a collector's `details` shape changes in a way that
# would make old rows ambiguous to a future reader of the timeline.
DETAILS_SCHEMA_VERSION = 1

# Tables and indexes are deliberately SEPARATE scripts, applied either side of
# _MIGRATIONS -- see _init_schema for the bug that ordering fixes.
_TABLES = """
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
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    reason TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    username TEXT,
    hostname TEXT,
    artifacts_json TEXT NOT NULL DEFAULT '{}',
    context_json TEXT NOT NULL DEFAULT '{}',
    ai_summary TEXT,
    reviewed INTEGER NOT NULL DEFAULT 0
);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""

# Kept for anyone still importing it; the two halves above are what actually run.
SCHEMA = _TABLES + _INDEXES

# Additive migrations for databases created by an older Aegis -- avoids forcing
# anyone to delete their event history when they pull an update.
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
        self._enable_wal()
        self._init_schema()

    def _init_schema(self) -> None:
        """Tables, then migrations, then indexes -- in that order, deliberately.

        Confirmed bug this fixes: the whole schema (tables AND indexes) used to
        run as one executescript BEFORE the migrations. On a database created by
        a version of Aegis predating the `severity` column, that script reached
        `CREATE INDEX ... ON events(severity)`, raised `no such column:
        severity`, and the exception escaped __init__ -- so the ALTER TABLE
        directly below that was supposed to add the column never ran. The
        migration list could not fix the very situation it exists for: opening
        an old event store crashed the app at startup, and the comment promising
        nobody has to delete their history was describing code that could never
        execute.

        Indexes have to come after the migrations because an index can only be
        built on a column that already exists; migrations have to come after the
        tables because ALTER TABLE needs something to alter. Hence three steps
        instead of one."""
        self._conn.executescript(_TABLES)
        for migration in _MIGRATIONS:
            try:
                self._conn.execute(migration)
            except sqlite3.OperationalError:
                pass  # column already exists -- fine, this runs on every startup
        self._conn.executescript(_INDEXES)
        self._conn.commit()

    def _enable_wal(self) -> None:
        """Switch the store to write-ahead logging.

        There is exactly one writer (the dispatcher) and one reader (the
        dashboard, which opens this same file `mode=ro`) -- the case WAL exists
        for. Under the default rollback journal a commit takes an exclusive
        lock, so the dashboard's 4s poll could land on SQLITE_BUSY and spend up
        to its 5s timeout waiting; worse, a `mode=ro` connection cannot replay a
        hot journal, so an unclean writer exit could leave the dashboard unable
        to open a database a writable connection would have recovered
        automatically.

        Verified rather than assumed: with WAL on, a `mode=ro` reader sees
        commits made after it connected AND reads without blocking while a
        write transaction is open. The mode is a property of the file, so it
        persists -- existing databases are upgraded in place on the next start.

        Failure is non-fatal on purpose. WAL needs the -shm wal-index in shared
        memory, which some network filesystems don't provide; there the PRAGMA
        is a silent no-op (SQLite stays in the old mode rather than raising) and
        rarely it errors outright. Either way the store still works exactly as
        it did before, so this logs the shortfall instead of refusing to start
        -- but it does log it, because degrading silently is the failure mode
        this codebase treats as the actual bug."""
        try:
            mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        except sqlite3.Error as e:
            logger.warning("Could not enable WAL on %s (%s) -- continuing with the "
                           "default journal; dashboard reads may briefly block on writes.",
                           self.db_path, e)
            return
        if str(mode).lower() != "wal":
            logger.warning("WAL was refused on %s (still %r) -- likely a filesystem without "
                           "shared-memory support. Continuing; dashboard reads may briefly "
                           "block on writes.", self.db_path, mode)

    def insert(self, *, source: str, category: str, summary: str, details: dict,
               confidence: str, severity: str = "medium", explanation: str | None = None,
               risk_hint: str | None = None, ai_skipped: bool = False,
               timestamp: float | None = None) -> int:
        versioned_details = {"_schema": DETAILS_SCHEMA_VERSION, **details}
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (timestamp, source, category, summary, details_json, "
                "confidence, severity, explanation, risk_hint, ai_skipped) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp or time.time(), source, category, summary, json.dumps(versioned_details),
                 confidence, severity, explanation, risk_hint, int(ai_skipped)),
            )
            self._conn.commit()
            return cur.lastrowid

    def update_explanation(self, event_id: int, explanation: str | None) -> None:
        """Fill in an explanation for an already-persisted row.

        The dispatcher writes the row the moment an event arrives and asks the
        AI afterwards, so the timeline shows activity immediately instead of
        waiting on a network round-trip. This is how the answer gets back."""
        with self._lock:
            self._conn.execute("UPDATE events SET explanation = ? WHERE id = ?",
                               (explanation, event_id))
            self._conn.commit()

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

    def between(self, since: float, until: float, limit: int = 500) -> list[dict]:
        """Events inside a time window, oldest first -- the away-session recap
        reads chronologically, like a story."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ? "
                "ORDER BY timestamp, id LIMIT ?", (since, until, limit),
            ).fetchall()
            cols = [d[0] for d in self._conn.execute("SELECT * FROM events LIMIT 0").description]
            return [dict(zip(cols, row)) for row in rows]

    # --- meta (heartbeat & friends) --------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
            self._conn.commit()

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return row[0] if row else None

    # --- incidents (tamper evidence) --------------------------------------

    def insert_incident(self, *, reason: str, attempts: int, username: str | None,
                        hostname: str | None, artifacts: dict, context: dict,
                        ai_summary: str | None = None, timestamp: float | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incidents (timestamp, reason, attempts, username, hostname, "
                "artifacts_json, context_json, ai_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp or time.time(), reason, attempts, username, hostname,
                 json.dumps(artifacts), json.dumps(context), ai_summary),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_incidents(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            cols = [d[0] for d in self._conn.execute("SELECT * FROM incidents LIMIT 0").description]
            return [dict(zip(cols, row)) for row in rows]

    def get_incident(self, incident_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                return None
            cols = [d[0] for d in self._conn.execute("SELECT * FROM incidents LIMIT 0").description]
            return dict(zip(cols, row))

    def delete_incidents(self, ids: list[int]) -> int:
        if not ids:
            return 0
        with self._lock:
            marks = ",".join("?" * len(ids))
            cur = self._conn.execute(f"DELETE FROM incidents WHERE id IN ({marks})", ids)
            self._conn.commit()
            return cur.rowcount

    def set_incident_reviewed(self, incident_id: int, reviewed: bool = True) -> None:
        with self._lock:
            self._conn.execute("UPDATE incidents SET reviewed = ? WHERE id = ?",
                               (int(reviewed), incident_id))
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()
