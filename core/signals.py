"""Which signals fired on an event, and how much they corroborate each other.

WHY THIS EXISTS: core/severity_engine.py records only its VERDICT -- "high" --
and never which of its rules produced it. The drawer needs the opposite: the
list of triggers. That answer used to be re-derived in the browser, with
app.js carrying its own copies of the path/extension/LOLBin tables and a test
that failed when they drifted. Same rules, two languages, one test standing
between them and a drawer that explains a high-severity event with no reason
for being high.

So the rules live here, once, and the browser renders words for the codes this
emits. app.js owns the wording, this owns what fired -- neither can silently
disagree with the other, because a code with no wording is a visibly missing
row, not a wrong one (tests/test_investigation_drawer.py asserts every code
here has copy there).

Computed on READ (see dashboard/server.py), not stored at persist time: the
same choice the browser mirror made, and it keeps the events already in the
store explainable without a migration or a backfill. See the occam note below
for what that costs and when it stops being acceptable.

CONFIDENCE IS NOT SEVERITY, AND NOT `events.confidence` EITHER. Severity says
how bad this is if we read it right. `events.confidence` (real-time vs polled)
says whether we caught the moment. This says how well the evidence agrees with
itself: one heuristic firing alone is a weaker case than three independent
signals pointing the same way, and a user looking at "high severity" deserves
to know which of the two they have. Polled detection lowers it by a step
because a sampled observation can have missed the surrounding context.
"""

from __future__ import annotations

import json

# occam: signals are derived on read, so an event's explanation is whatever
# TODAY's rules say about yesterday's details -- edit a rule and the same event
# explains itself differently in April and in October, against a stored severity
# that never changed. That is fine while Aegis is alpha and the store is one
# developer's laptop. It stops being fine the moment anyone relies on the
# timeline as a record: a forensic account that silently rewrites itself is
# worse than no account.
#
# Upgrade path -- ONE change, not two, and it is also the prerequisite for
# feeding the AI structured evidence instead of a summary string:
#   1. Call annotate() in dispatcher._stage_classify, writing
#      details["signals"] + details["rule_version"] before _persist.
#   2. dashboard/server.py annotates only rows that lack the key, so pre-existing
#      events keep working and new ones become immutable.
#   3. ai_explainer gets the stored signal list in its prompt block. Today it
#      re-derives the same facts from raw details in prose (see
#      SYSTEM_PROMPT_WITH_INTEL) -- the drawer's Why list and the AI's reasoning
#      are two independent readings of one event, and only one of them is
#      testable. Handing over the list makes the model explain evidence rather
#      than rediscover it, and makes swapping models a much smaller risk.
# Bump rule_version whenever a rule below changes; that number is what lets a
# reader tell "the rules changed" from "the event changed".

# Shared with core/severity_engine.py -- these ARE the severity engine's tables,
# imported rather than copied, so "why is this high" can never name a different
# trigger than the one that made it high.
from core.severity_engine import (
    _EXECUTABLE_EXTENSIONS,
    _LOLBIN_NAMES,
    _SUSPICIOUS_PATH_FRAGMENTS,
)

# Codes that are a fact about the artifact (a scan result, a persistence entry,
# a file that is genuinely an executable) rather than an inference from where
# it sits or what it is named. Corroboration counts these double -- three soft
# heuristics agreeing is a weaker case than one hard fact plus one heuristic.
_HARD = {"vt_malicious", "tamper", "persistence", "executable_drop", "suspicious_path"}

# Hard facts that need no corroboration at all, because the corroboration is
# already inside them. Aegis watched the tamper attempt and the monitoring gap
# happen to itself -- there is no inference to be wrong about. A VirusTotal
# detection is dozens of independent engines that already agree; waiting for a
# path heuristic to second them is not what makes it credible.
#
# Everything else in _HARD is a fact whose MEANING is still an inference: a
# .exe in a watched folder is certainly a .exe, and routinely something you
# downloaded on purpose.
_CONCLUSIVE = {"vt_malicious", "tamper", "monitoring_gap"}

_TRUSTED_HINTS = {"user_trusted_process", "user_trusted_process_hash", "user_trusted_usb"}


def _sig(code: str, state: str, **extra) -> dict:
    return {"code": code, "state": state, **extra}


def signals_for(event: dict) -> list[dict]:
    """Every dimension Aegis can weigh, and where this event landed on each.

    A dimension Aegis did not or could not check still gets an entry, with
    state "none" -- the drawer renders it as a state ("Not queried") rather
    than an absence. Not-checked is never rendered as a pass.
    """
    # "details_json" is the DB row's column, "details" the in-memory MonitorEvent
    # field; both land here so a caller never has to reshape a row first.
    details = event.get("details_json") or event.get("details") or {}
    if isinstance(details, str):
        try:
            details = json.loads(details) or {}
        except ValueError:
            details = {}

    source = event.get("source") or ""
    category = event.get("category") or ""
    hint = event.get("risk_hint") or ""
    ti = details.get("threat_intel") or {}
    vt = ti.get("vt")
    mitre = ti.get("mitre") or []
    exe = str(details.get("exe") or details.get("executable_path") or "").lower()
    name = str(details.get("image_name") or details.get("name") or "").lower()

    out: list[dict] = []

    # --- provenance ---------------------------------------------------------
    if source == "process":
        if hint == "os_platform_binary":
            out.append(_sig("system_binary", "ok"))
        elif hint == "aegis_own_child":
            out.append(_sig("aegis_child", "ok"))
        else:
            out.append(_sig("unsigned", "warn"))
    if hint in _TRUSTED_HINTS:
        out.append(_sig("user_trusted", "ok"))
    elif source in ("process", "usb"):
        out.append(_sig("not_trusted", "none"))

    # --- reputation ---------------------------------------------------------
    if not vt:
        out.append(_sig("vt_not_queried", "none"))
    elif vt.get("status") == "unknown_hash":
        out.append(_sig("vt_unknown_hash", "warn"))
    elif (vt.get("detections") or 0) > 0:
        out.append(_sig("vt_malicious", "bad", n=vt["detections"],
                        total=vt.get("engines_total")))
    elif (vt.get("suspicious") or 0) > 0:
        out.append(_sig("vt_suspicious", "warn", n=vt["suspicious"]))
    else:
        # Deliberately "none", not "ok": no engine has flagged it is not the
        # same claim as no engine would.
        out.append(_sig("vt_clean", "none"))

    out.append(_sig("mitre", "warn", techniques=mitre) if mitre
               else _sig("mitre_none", "none"))

    # --- behaviour ----------------------------------------------------------
    if source == "process":
        frag = next((f for f in _SUSPICIOUS_PATH_FRAGMENTS if f in exe), None)
        if frag:
            out.append(_sig("suspicious_path", "bad"))
        elif hint == "os_platform_binary":
            out.append(_sig("system_path", "ok"))
        else:
            out.append(_sig("path_ordinary", "ok") if exe else _sig("path_unknown", "none"))
        if name in _LOLBIN_NAMES:
            out.append(_sig("lolbin", "warn", name=name))

    file_path = str(details.get("dest_path") or details.get("path") or "").lower()
    if source == "folder" and file_path:
        ext = next((e for e in _EXECUTABLE_EXTENSIONS if file_path.endswith(e)), None)
        out.append(_sig("executable_drop", "bad", ext=ext) if ext
                   else _sig("not_executable", "ok"))

    if category == "startup_item_added":
        out.append(_sig("persistence", "bad"))
    if source == "tamper":
        out.append(_sig("tamper", "bad"))
    if category == "monitoring_gap":
        out.append(_sig("monitoring_gap", "warn"))

    # Both spelled out rather than picked by expression: the code strings are
    # the contract with app.js, and the test that proves every one of them has
    # wording finds them by reading this file.
    if event.get("confidence") == "polled":
        out.append(_sig("polled", "none"))
    else:
        out.append(_sig("realtime", "none"))
    return out


# An all-clear is only as trustworthy as the thing that cleared it. These are
# integrity properties or the user's own explicit statement -- not "we ran out
# of dimensions to check", which is what every other clear signal amounts to.
_STRONG_CLEAR = {"system_binary", "aegis_child", "user_trusted"}


def confidence_for(signals: list[dict]) -> dict:
    """How well the evidence agrees with itself.

    Two different questions, depending on which way the verdict went, and
    `basis` tells the UI which one it is answering:

      basis="risk"  -- something fired. How much corroborates it? One lone
                       heuristic is a weaker case than three signals agreeing,
                       and the user deserves to know which they are looking at
                       before they act.
      basis="clear" -- nothing fired. Then confidence is about COVERAGE, not
                       doubt: did something actually clear this (SIP, the trust
                       list), or did Aegis simply find nothing to say? Those
                       are both "low risk" and they are not the same claim.

    Deliberately counts named booleans instead of summing weights into a score:
    the inputs are a handful of yes/no signals, so any 0-100 number would invent
    gradations that nothing here can distinguish -- the same reason the drawer
    shows "3 signals raised" and not "92/100".
    """
    raised = [s for s in signals if s["state"] in ("bad", "warn")]
    hard = [s for s in raised if s["code"] in _HARD]
    polled = any(s["code"] == "polled" for s in signals)

    if raised:
        basis = "risk"
        if any(s["code"] in _CONCLUSIVE for s in raised):
            level = "high"
        elif len(hard) >= 2 or (hard and len(raised) >= 3):
            level = "high"
        elif hard or len(raised) >= 3:
            level = "medium"
        else:
            level = "low"
    else:
        basis = "clear"
        level = "high" if any(s["code"] in _STRONG_CLEAR for s in signals) else "low"

    # A sampled observation can have missed the context around it -- but not the
    # thing Aegis watched happen to itself, and not a scan result, so a
    # conclusive signal keeps its level. Never applies to an all-clear: polling
    # is already why there was nothing to see.
    if polled and basis == "risk" and level != "low" \
            and not any(s["code"] in _CONCLUSIVE for s in raised):
        level = "medium" if level == "high" else "low"

    return {"level": level, "basis": basis, "corroborating": len(raised),
            "hard": len(hard), "polled": polled}


def annotate(event: dict) -> dict:
    """Attach signals + confidence to an event row, in place."""
    event["signals"] = signals_for(event)
    event["verdict_confidence"] = confidence_for(event["signals"])
    return event


if __name__ == "__main__":
    codes = lambda ev: [s["code"] for s in signals_for(ev)]
    conf = lambda ev: confidence_for(signals_for(ev))

    downloads = {"source": "process", "category": "process_started",
                 "confidence": "certain",
                 "details": {"name": "curl", "exe": "/Users/me/Downloads/curl"}}
    assert "suspicious_path" in codes(downloads)
    assert "lolbin" in codes(downloads)
    assert "unsigned" in codes(downloads)
    # One hard fact + two heuristics agreeing -> a case worth trusting.
    assert conf(downloads)["level"] == "high", conf(downloads)

    # Details arriving as a JSON string (straight off the DB row) must behave
    # identically to a parsed dict -- server.py hands over whichever it has.
    as_str = {**downloads, "details": json.dumps(downloads["details"])}
    assert codes(as_str) == codes(downloads)

    system = {"source": "process", "category": "process_started", "confidence": "certain",
              "risk_hint": "os_platform_binary",
              "details": {"name": "ioreg", "exe": "/usr/sbin/ioreg"}}
    assert codes(system) == ["system_binary", "not_trusted", "vt_not_queried",
                             "mitre_none", "system_path", "realtime"]
    # An all-clear backed by SIP is a strong all-clear, not an empty one.
    assert conf(system) == {"level": "high", "basis": "clear", "corroborating": 0,
                            "hard": 0, "polled": False}
    # ...and one backed by nothing must not borrow its confidence.
    quiet = {"source": "usb", "category": "usb_connected", "confidence": "certain",
             "details": {}}
    assert conf(quiet)["level"] == "low" and conf(quiet)["basis"] == "clear"

    malicious = {"source": "folder", "category": "file_created", "confidence": "certain",
                 "details": {"path": "/Users/me/Downloads/invoice.exe",
                             "threat_intel": {"vt": {"detections": 41, "engines_total": 72},
                                              "mitre": [{"id": "T1204", "name": "User Execution"}]}}}
    assert codes(malicious) == ["vt_malicious", "mitre", "executable_drop",
                                "realtime"], codes(malicious)
    assert conf(malicious)["level"] == "high"

    # A single unlucky heuristic is NOT a confident verdict, however loud it is:
    # a .exe in Downloads is certainly a .exe and routinely one you asked for.
    lone = {"source": "folder", "category": "file_created", "confidence": "certain",
            "details": {"path": "/Users/me/Downloads/setup.exe"}}
    assert conf(lone) == {"level": "medium", "basis": "risk", "corroborating": 1,
                          "hard": 1, "polled": False}

    # Things Aegis watched happen to itself carry their own corroboration -- a
    # wrong password on a protected action is observed, not inferred, so it is
    # high confidence standing completely alone.
    tamper = {"source": "tamper", "category": "tamper_attempt", "confidence": "certain",
              "details": {}}
    assert conf(tamper) == {"level": "high", "basis": "risk", "corroborating": 1,
                            "hard": 1, "polled": False}
    assert conf({**tamper, "confidence": "polled"})["level"] == "high", "polling cannot weaken it"

    # Polled detection can have missed the surrounding context -> one step down,
    # but never below a conclusive signal or an all-clear.
    assert conf({**lone, "confidence": "polled"})["level"] == "low"
    assert conf({**malicious, "confidence": "polled"})["level"] == "high", "a scan result stands"
    assert conf({**system, "confidence": "polled"})["level"] == "high", "clear is unaffected"

    # Zero VT detections must never read as a pass.
    clean = {"source": "process", "category": "process_started", "confidence": "certain",
             "details": {"name": "app", "exe": "/Applications/app",
                         "threat_intel": {"vt": {"detections": 0, "engines_total": 70}}}}
    assert next(s for s in signals_for(clean) if s["code"] == "vt_clean")["state"] == "none"

    print("signals self-check: OK")
