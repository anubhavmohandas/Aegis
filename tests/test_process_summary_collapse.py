"""Regression test: the timeline's process-summary regex must tolerate notes.

core/dispatcher.py::_annotate_summary appends " -- <plain-English note>" to
process rows for recognised system binaries (core/process_notes.py). The
dashboard's PROCESS_SUMMARY_RE was anchored with `$` immediately after the
PID, so every *noted* row failed to match, and both features that read the
match silently degraded:

  1. displaySummary() stopped collapsing aged rows to the process name.
  2. groupKey() fell back to the whole summary -- PID included -- so no two
     rows ever shared a key and runs of identical processes never grouped.

Neither failure throws; the timeline just quietly fills with full-length
rows (mdworker_shared alone is ~1000/day on a normal Mac), which is exactly
how it was found. Pure source inspection -- no browser, runs anywhere.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_JS = (ROOT / "dashboard/static/app.js").read_text(encoding="utf-8")

# The JS literal is also a valid Python pattern, so the test exercises the
# real regex rather than a copy that could drift away from it.
_LITERAL = re.search(r"^const PROCESS_SUMMARY_RE = /(.+)/;$", APP_JS, re.MULTILINE)
assert _LITERAL, "PROCESS_SUMMARY_RE literal not found in app.js"
SUMMARY_RE = re.compile(_LITERAL.group(1))


def test_plain_row_matches_and_has_no_note():
    m = SUMMARY_RE.match("New process: netbiosd (PID 10536)")
    assert m and m.group(1) == "netbiosd"
    assert m.group(2) is None


def test_noted_row_splits_into_name_and_note():
    m = SUMMARY_RE.match("New process: screencapture (PID 10536) -- captured the screen")
    assert m, "a row carrying a process note must still match"
    assert m.group(1) == "screencapture"
    assert m.group(2) == "captured the screen"


def test_application_launched_phrasing_also_matches():
    m = SUMMARY_RE.match("New application launched: Safari (PID 1234)")
    assert m and m.group(1) == "Safari"


def test_process_name_containing_parens_survives():
    # Real name from a live timeline; the greedy capture must not stop early.
    m = SUMMARY_RE.match("New process: Brave Browser Helper (Renderer) (PID 991)")
    assert m and m.group(1) == "Brave Browser Helper (Renderer)"


def test_group_key_is_pid_free_for_every_shipped_note():
    """The whole point of the fix: two runs of the same process must produce
    the same group key even though their PIDs differ. Checked against every
    note actually shipped, so a future note containing ' -- ' or a newline
    (which would split in the wrong place) fails here instead of silently
    un-grouping that process in the UI."""
    import sys
    sys.path.insert(0, str(ROOT))
    from core.process_notes import _NOTES

    assert _NOTES, "note table is empty -- nothing would ever be annotated"
    for name, note in _NOTES.items():
        keys = set()
        for pid in (11, 22222):
            m = SUMMARY_RE.match(f"New process: {name} (PID {pid}) -- {note}")
            assert m, f"note for {name!r} breaks the summary pattern"
            assert m.group(2) == note, f"note for {name!r} was split incorrectly"
            keys.add(m.group(1))
        assert keys == {name}, f"group key for {name!r} varies with PID: {keys}"
