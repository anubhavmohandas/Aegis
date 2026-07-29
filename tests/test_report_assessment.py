"""Runnable self-check: the report's verdict block, and the quit gate around it.

WHY THIS TEST EXISTS: core/report_generator._assess is the one part of Aegis
that states a conclusion rather than a fact -- "Healthy", "Needs Attention" --
and a conclusion is the thing a user will act on without reading the evidence
under it. Two ways that goes wrong, both silent, both checked below:

  1. Calling an EMPTY period healthy. No events can mean a quiet machine or a
     period when monitoring was never running, and the verdict cannot tell them
     apart. Printing "Healthy" over a window Aegis never watched would make
     every other verdict in the report worthless. This is the branch that
     matters most and it is the first one asserted.

  2. Drifting away from core/signals.py. The verdict is computed from the same
     signal codes the console's investigation drawer renders, so a code that
     gets renamed there must not leave a check here quietly counting zero
     forever -- which reads as "None observed", i.e. an all-clear, which is the
     worst possible direction for this failure to point. The codes are asserted
     against signals.py's own output rather than hardcoded.

Also covers _quit_summary_gate's fail-OPEN contract, which is deliberately the
opposite of _authorize_action's fail-closed one: by the time the summary runs
the user has already authenticated a quit, so a broken summary must never
become a way to trap them in the app.

No framework: `python tests/test_report_assessment.py`.
"""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.report_generator import (
    _ASSESSMENT_CHECKS,
    _assess,
    _background_label,
    _compute_stats,
)
from core.signals import signals_for


def ev(severity, summary="x", **details):
    return {"severity": severity, "summary": summary, "confidence": "certain",
            "timestamp": time.time(),
            "source": details.pop("source", "process"),
            "category": details.pop("category", "process_started"),
            "risk_hint": details.pop("risk_hint", None),
            "details": details}


def assess(events):
    return _assess(events, _compute_stats(events))


# --- 1. an empty period is not an all-clear ---------------------------------
a = assess([])
assert a["status"] == "No Activity Recorded", a["status"]
assert a["tone"] == "unknown"
assert a["confidence"] == "Low", "an unwatched period must never carry high confidence"
assert "not running" in a["reason"], "the reason must name the monitoring-was-off possibility"

# --- 2. a genuinely routine period reads healthy, and says why ---------------
sip = [ev("low", risk_hint="os_platform_binary", name="ioreg", exe="/usr/sbin/ioreg")
       for _ in range(10)]
a = assess(sip)
assert a["status"] == "Healthy", a["status"]
assert a["confidence"] == "High", "SIP-cleared events are positive evidence, not just absence"
assert a["coverage"] == 100
assert all(n == 0 for _, n in a["checks"])

# ...but a period where nothing fired and nothing was positively cleared must
# NOT borrow that confidence. This is the "we ran out of things to check"
# all-clear, and core/signals.py draws the same distinction via _STRONG_CLEAR.
quiet = [ev("low", source="usb", category="usb_connected") for _ in range(10)]
a = assess(quiet)
assert a["status"] == "Healthy" and a["confidence"] == "Low", a

# --- 3. hard indicators escalate the whole period ---------------------------
malicious = sip + [ev("critical", "invoice.exe created", source="folder",
                      category="file_created", path="/Users/me/Downloads/invoice.exe",
                      threat_intel={"vt": {"detections": 41, "engines_total": 72}})]
a = assess(malicious)
assert a["status"] == "Needs Attention", a["status"]
assert a["confidence"] == "High", "a scan result stands on its own"
fired = dict(a["checks"])
assert fired["Known-malicious files"] == 1
assert fired["Executables written to watched folders"] == 1
assert fired["Tamper attempts against Aegis"] == 0

# A tamper attempt alone is enough, with no other signal anywhere near it.
a = assess([ev("high", "wrong password", source="tamper", category="tamper_attempt")])
assert a["status"] == "Needs Attention", a["status"]

# --- 4. something notable but not conclusive sits in the middle -------------
screenshot = sip + [ev("medium", "New process: screencapture (PID 9)",
                       name="screencapture", exe="/usr/sbin/screencapture")]
a = assess(screenshot)
assert a["status"] == "Review Suggested", a["status"]
assert "No malware, tampering or persistence was observed" in a["reason"]

# --- 5. the check table cannot silently drift from core/signals.py ----------
# Every code _assess counts must be a code signals_for() can actually emit. A
# renamed signal would otherwise leave its check pinned at zero -- rendering as
# "None observed", an all-clear Aegis never established.
emitted = set()
for probe in (
    {"source": "process", "category": "process_started", "confidence": "certain",
     "details": {"name": "curl", "exe": "/Users/me/Downloads/curl"}},
    {"source": "folder", "category": "file_created", "confidence": "certain",
     "details": {"path": "/Users/me/Downloads/x.exe",
                 "threat_intel": {"vt": {"detections": 3, "engines_total": 70}}}},
    {"source": "tamper", "category": "tamper_attempt", "confidence": "certain", "details": {}},
    {"source": "process", "category": "startup_item_added", "confidence": "certain", "details": {}},
    {"source": "process", "category": "monitoring_gap", "confidence": "certain", "details": {}},
):
    emitted |= {s["code"] for s in signals_for(probe)}

for code, label in _ASSESSMENT_CHECKS:
    assert code in emitted, f"check {label!r} counts signal {code!r}, which signals_for() never emits"

# --- 6. background rows collapse PID-free, like the timeline does -----------
assert (_background_label({"summary": "New process: mdworker_shared (PID 991) -- Spotlight indexing a file"})
        == _background_label({"summary": "New process: mdworker_shared (PID 12) -- Spotlight indexing a file"})), \
    "two runs of one process must collapse onto one background row"
assert _background_label({"summary": "New process: Brave Helper (Renderer) (PID 4)"}) \
    == "New process: Brave Helper (Renderer)", "a name containing parens must survive"

# --- 7. the quit summary fails OPEN ----------------------------------------
import desktop_app  # noqa: E402

# A non-quit protected action passes straight through, no dialog.
assert desktop_app._quit_summary_gate("stop_monitoring") is True

# A broken summary must still let an already-authenticated quit proceed. The
# opposite result would be a summary bug that traps the user inside the app.
_real = desktop_app.load_config
desktop_app.load_config = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
# The gate logs that failure with a traceback, which is correct in production
# and indistinguishable from a test failure in CI output. Silence it here only.
logging.disable(logging.CRITICAL)
try:
    assert desktop_app._quit_summary_gate("quit") is True, \
        "a failed session summary must never veto a quit the user already authorized"
finally:
    logging.disable(logging.NOTSET)
    desktop_app.load_config = _real

assert desktop_app._fmt_duration(0) == "0m"
assert desktop_app._fmt_duration(7 * 3600 + 21 * 60) == "7h 21m"
assert desktop_app._fmt_duration(-5) == "0m", "a clock jump must not render a negative session"

print("ok: report assessment concludes honestly and the quit summary fails open")
