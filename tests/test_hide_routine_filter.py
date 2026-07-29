"""Runnable self-check: the Hide Routine filter covers every routine risk_hint.

This filter has already failed silently once. The `risk_hint IS NULL OR ...`
half is load-bearing -- `NULL NOT IN (...)` evaluates to NULL, i.e. falsy, so
dropping it hides every ordinary AI-explained event rather than just the
routine ones (see the comment in dashboard/server.py). Nothing throws either
way; the timeline just quietly goes empty or quietly stops filtering.

Both failure directions are asserted here against the real query builder:

  - a hint missing from the list  -> routine noise floods back into the timeline
  - the IS NULL guard missing     -> ordinary events silently disappear

Runs against SQLite itself rather than string-matching the SQL, so a predicate
that is textually present but semantically wrong still fails.

No framework: `python tests/test_hide_routine_filter.py`.
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.server import _build_event_query

# Every hint core/rule_engine.py assigns that means "routine, already vetted".
ROUTINE = ["user_trusted_process", "user_trusted_process_hash", "user_trusted_usb",
           "os_platform_binary", "aegis_own_child"]
# Hints that must stay VISIBLE: these describe unusual burst activity, not
# vetted noise, and hiding them would be hiding the evidence of a flood.
VISIBLE = ["rate_limited", "duplicate_suppressed", None]

clause, args = _build_event_query({"hide_trusted": ["1"]})

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, risk_hint TEXT)")
for i, hint in enumerate(ROUTINE + VISIBLE):
    conn.execute("INSERT INTO events (id, risk_hint) VALUES (?, ?)", (i, hint))

rows = conn.execute(f"SELECT risk_hint FROM events{clause}", args).fetchall()
survived = [r[0] for r in rows]

for hint in ROUTINE:
    assert hint not in survived, f"{hint!r} is routine noise and must be hidden by Hide Routine"

for hint in VISIBLE:
    assert hint in survived, (
        f"{hint!r} must stay visible -- an ordinary event (risk_hint NULL) or a burst marker "
        f"disappearing from the timeline is the silent failure this filter has had before")

# The whole point of hiding Aegis's own helpers is that they are matched on
# PARENT PID, never on name (core/rule_engine.py). A process merely CALLED
# osascript carries no risk_hint and therefore must still be shown -- if that
# ever stops being true, naming a payload after a system tool would hide it.
assert None in survived, "an unhinted process named like a helper must never be filtered out"

# And with the toggle off, nothing is filtered at all.
clause_off, args_off = _build_event_query({})
all_rows = conn.execute(f"SELECT risk_hint FROM events{clause_off}", args_off).fetchall()
assert len(all_rows) == len(ROUTINE) + len(VISIBLE), "Hide Routine off must filter nothing"

conn.close()
print("ok: Hide Routine hides every routine hint and nothing else")
