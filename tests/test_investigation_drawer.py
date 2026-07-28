"""Self-check for the three console changes that promise not to make things up.

All three replaced a bare number or an empty box with a sentence that *claims*
something, so each one has a way to be confidently wrong:

1. The stat tiles now say "+4 since yesterday". That is only true if the
   comparison window is the 24 hours BEFORE the current one -- an off-by-one
   day boundary, or a window that overlaps the current one, produces a real
   number that means nothing. Exercised against real SQLite, not a stub.

2. The all-clear empty state lists what is being monitored. It reads that list
   from the running pipeline's own collector gauge, so the failure mode to
   guard is a stale or missing snapshot silently becoming "we're watching
   everything". _monitor_collectors must return [] there.

3. The drawer's forensic groups must cover every key core/ actually writes into
   details_json, with no key claimed by two groups. A key in no group falls
   into the ungrouped "Other" table (fine, nothing is lost); a key in two
   groups renders twice, and a label drifting away from the real key name
   renders nothing at all while looking like it worked.

4. The drawer says WHY an event scored the way it did. Those rules used to be
   mirrored into app.js and policed by a drift test; they now live once in
   core/signals.py, which app.js renders rather than re-derives. So the checks
   here are the seam instead: every code Python emits has wording in the
   browser, no wording is dead, and no copy of the heuristics has crept back.
   The JS fixtures below are annotated by the real core/signals.py, so the
   drawer assertions exercise both halves at once.

5. Confidence qualifies severity without inventing precision. It is a rank over
   the signals that actually fired -- so "high risk, one lone heuristic" must
   not read identically to "high risk, three signals agreeing", and neither may
   render as a percentage or a 0-100 score.

No framework: `python tests/test_investigation_drawer.py`.
"""
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

APP_JS = (ROOT / "dashboard/static/app.js").read_text(encoding="utf-8")

DAY = 86400.0


def _seed(conn, rows):
    """rows: (timestamp, severity). Only the columns the stats query reads."""
    conn.execute("""CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, source TEXT,
        category TEXT, summary TEXT, details_json TEXT, confidence TEXT,
        severity TEXT, explanation TEXT, risk_hint TEXT, ai_skipped INTEGER)""")
    conn.executemany(
        "INSERT INTO events (timestamp, source, category, summary, details_json, "
        "confidence, severity, ai_skipped) VALUES (?, 'process', 'exec', 's', '{}', "
        "'certain', ?, 0)", rows)
    conn.commit()


def test_prev_window_is_the_day_before_and_does_not_overlap():
    from dashboard.server import _query_stats_inner

    now = time.time()
    day_ago = now - DAY
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _seed(conn, [
        (now - 3600, "high"),           # current window
        (now - 7200, "high"),           # current window
        (now - 7200, "low"),            # current window
        (day_ago - 3600, "high"),       # previous window
        (day_ago - DAY + 60, "low"),    # previous window, just inside the far edge
        (day_ago - DAY - 60, "high"),   # two days back -- must NOT be counted
    ])
    s = _query_stats_inner(conn, day_ago)

    assert s["last_24h"] == 3, s["last_24h"]
    assert s["prev_24h"] == 2, f"previous window must hold exactly its own 24h, got {s['prev_24h']}"
    assert s["prev_by_severity"] == {"high": 1, "low": 1}, s["prev_by_severity"]
    # The whole point of the tile: a real delta, not a guess.
    assert s["last_24h"] - s["prev_24h"] == 1

    # The two windows must be disjoint -- if prev overlapped current, an event
    # in the last 24h would be counted on both sides and the delta would read 0.
    assert s["prev_24h"] + s["last_24h"] <= s["total"]


def test_prev_window_is_zero_before_any_history_exists():
    """A brand-new install must not produce "+311 since yesterday" out of a
    baseline that never existed. Zero here is what makes the UI say "first 24
    hours of data" instead."""
    from dashboard.server import _query_stats_inner

    now = time.time()
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _seed(conn, [(now - 60, "low"), (now - 120, "critical")])
    s = _query_stats_inner(conn, now - DAY)
    assert s["prev_24h"] == 0 and s["prev_by_severity"] == {}
    assert s["total"] == s["last_24h"], "no history yet -- the UI must not claim a trend"


def test_stale_or_missing_snapshot_yields_no_collector_claims():
    import dashboard.server as server

    original = server._monitor_metrics
    try:
        for snap, why in [
            ({"available": False, "reason": "monitor has not published metrics yet"}, "unavailable"),
            ({"available": True, "stale": True, "gauges": {"collectors": ["MacUsbMonitor"]}}, "stale"),
            ({"available": True, "stale": False, "gauges": {}}, "no gauge"),
            ({"available": True, "stale": False, "gauges": {"collectors": "MacUsbMonitor"}}, "not a list"),
        ]:
            server._monitor_metrics = lambda s=snap: s
            got = server._monitor_collectors()
            assert got == [], f"{why}: must claim nothing, got {got!r}"

        server._monitor_metrics = lambda: {
            "available": True, "stale": False,
            "gauges": {"collectors": ["FolderMonitor", "MacUsbMonitor"]}}
        assert server._monitor_collectors() == ["FolderMonitor", "MacUsbMonitor"]
    finally:
        server._monitor_metrics = original


# A group header is `["Title", [`; a field is `["key", "Label"]`. Matching both
# in one ordered scan avoids counting nested brackets -- an earlier version
# tried to slice each group's body out with a non-greedy `(.*?)\]\]\]` and
# silently swallowed the last field of every group, which made the coverage
# assertions below pass without ever seeing `cmdline`, `writable` or `md5`.
_FACT_TOKEN = re.compile(r'\["([A-Za-z][\w ]*)",\s*\[|\["(\w+)",\s*"([^"]*)"\]')


def _fact_groups():
    """Parse FACT_GROUPS out of app.js so this tests the real table, not a copy
    of it that can drift."""
    block = re.search(r"^const FACT_GROUPS = \[\n(.*?)^\];$", APP_JS, re.MULTILINE | re.DOTALL)
    assert block, "FACT_GROUPS literal not found in app.js"
    groups, current = {}, None
    for m in _FACT_TOKEN.finditer(block.group(1)):
        if m.group(1) is not None:
            current = m.group(1)
            groups[current] = []
        else:
            assert current, "a field appeared before any group header"
            groups[current].append((m.group(2), m.group(3)))
    assert groups and all(groups.values()), "FACT_GROUPS parsed empty -- the literal's shape changed"
    return groups


SIGNALS_PY = (ROOT / "core/signals.py").read_text(encoding="utf-8")


def test_every_signal_python_emits_has_wording_in_the_drawer():
    """core/signals.py decides WHICH signals fired; app.js decides how each one
    reads. That split is what replaced the old mirrored heuristic tables, and it
    holds only while every code has copy on the other side.

    A code with no entry in SIGNAL_COPY does not crash -- it renders as an
    unlabelled "Signal" row with the raw code as its status, and produces no
    "Why" line at all. So a high-severity event would explain itself with a row
    reading `suspicious_path` and no reason. Visible, but only if someone looks;
    this makes it fail in CI instead."""
    py_codes = set(re.findall(r'_sig\(\s*"(\w+)"', SIGNALS_PY))
    assert len(py_codes) > 10, f"signals.py parsed only {py_codes} -- its shape changed"

    block = re.search(r"^const SIGNAL_COPY = \{\n(.*?)^\};$", APP_JS, re.MULTILINE | re.DOTALL)
    assert block, "SIGNAL_COPY literal not found in app.js"
    js_codes = set(re.findall(r"^  (\w+): \{", block.group(1), re.MULTILINE))

    assert not (py_codes - js_codes), (
        f"emitted by core/signals.py with no wording in app.js: {sorted(py_codes - js_codes)}")
    assert not (js_codes - py_codes), (
        f"worded in app.js but never emitted -- dead copy: {sorted(js_codes - py_codes)}")


def test_the_browser_holds_no_copy_of_the_severity_rules():
    """The rules moved to core/signals.py precisely so there is one of them. A
    reintroduced table in app.js is the exact regression this file used to spend
    a drift test defending against."""
    for gone in ("SUSPICIOUS_PATH_FRAGMENTS", "EXECUTABLE_EXTENSIONS", "LOLBIN_NAMES"):
        assert gone not in APP_JS, (
            f"{gone} is back in app.js -- the severity heuristics belong in "
            "core/signals.py, which app.js renders rather than re-derives")


def test_no_fact_key_is_claimed_by_two_groups():
    seen = {}
    for title, fields in _fact_groups().items():
        for key, _label in fields:
            assert key not in seen, f"{key!r} is in both {seen[key]!r} and {title!r} -- it would render twice"
            seen[key] = title


def test_every_key_core_writes_is_either_grouped_or_falls_through():
    """The keys core/ actually emits, by source. Grouped keys get a friendly
    label; anything else must still reach the ungrouped "Other" table via
    FACT_KEYS, so no evidence is silently dropped from the drawer."""
    emitted = {
        "process": ["name", "pid", "exe", "parent_pid"],
        "folder": ["path", "dest_path", "sha256"],
        "usb": ["name", "mount_point", "bsd_name", "file_system",
                "device_name", "media_name", "writable"],
        "session": ["offline_from", "offline_until", "gap_seconds", "lid_closed",
                    "locked_at", "unlocked_at", "away_seconds"],
        "tamper": ["action", "attempt", "locked_out", "incident_id", "artifacts",
                   "active_window", "incident_ids"],
    }
    grouped = {k for fields in _fact_groups().values() for k, _ in fields}
    fact_keys = set(re.findall(r'"(\w+)"', re.search(
        r"const FACT_KEYS = new Set\(\[(.*?)\]\);", APP_JS, re.DOTALL).group(1)))

    # threat_intel and _schema have their own handling and must never be listed
    # as ordinary facts.
    assert {"_schema", "threat_intel"} <= fact_keys
    assert not ({"_schema", "threat_intel"} & grouped)

    for source, keys in emitted.items():
        for key in keys:
            assert key in grouped or key not in fact_keys, (
                f"{source}.{key} is excluded from the Other table but has no group -- "
                "it would vanish from the drawer")

    # The fields the request names explicitly must be labelled, not dumped raw.
    for key in ("pid", "parent_pid", "exe", "path", "sha256"):
        assert key in grouped, f"{key} must have a human label in the drawer"


# macOS ships a JavaScriptCore shell, and CI runs on macos-latest, so the
# browser-side logic can be *executed* here rather than pattern-matched. Absent
# (a Linux dev box), the JS checks skip and the source-inspection ones above
# still run.
JSC = Path("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc")

# app.js is a plain script, not a module: everything is a global, and the only
# top-level side effect is the final init(). Strip that one call, stub the
# handful of browser objects the declarations touch on the way past, and the
# real functions are callable.
_JS_HARNESS = r"""
var src = readFile(SRC).replace(/^init\(\);\s*$/m, "");
var g = this;
// One stub element per id, kept so the assertions can read back what
// openDrawer wrote into #drawer-body.
var els = {};
function el(id) {
  if (!els[id]) els[id] = { id: id, innerHTML: "", hidden: true, textContent: "",
                            classList: { add: function(){}, remove: function(){}, toggle: function(){} },
                            querySelector: function(){ return null; },
                            querySelectorAll: function(){ return []; },
                            insertAdjacentHTML: function(){}, options: { length: 0 } };
  return els[id];
}
g.document = { getElementById: el, querySelectorAll: function(){ return []; },
  querySelector: function(){ return null; }, addEventListener: function(){},
  documentElement: { dataset: {}, style: { setProperty: function(){} },
                     classList: { toggle: function(){}, add: function(){} } },
  body: { classList: { toggle: function(){} } } };
g.window = { matchMedia: function(){ return { matches: false, addEventListener: function(){} }; },
             addEventListener: function(){} };
g.localStorage = { getItem: function(){ return null; }, setItem: function(){} };
g.performance = { now: function(){ return 0; } };
g.setTimeout = function(){}; g.setInterval = function(){};
g.fetch = function(){ return Promise.resolve({ ok: true, status: 200,
  json: function(){ return Promise.resolve({ events: [] }); } }); };
(0, eval)(src + "\n;this.__api = { trendText: trendText, recommendedAction: recommendedAction," +
                 " factsHtml: factsHtml, collectorLabel: collectorLabel, state: state," +
                 " openDrawer: openDrawer, emptyStateHtml: emptyStateHtml };");
var api = g.__api, failures = [];
function eq(got, want, what) {
  if (got !== want) failures.push(what + ": expected " + JSON.stringify(want) + ", got " + JSON.stringify(got));
}
function has(hay, needle, what) {
  if (String(hay).indexOf(needle) === -1) failures.push(what + ": missing " + JSON.stringify(needle));
}
function lacks(hay, needle, what) {
  if (String(hay).indexOf(needle) !== -1) failures.push(what + ": must not contain " + JSON.stringify(needle));
}

// --- trendText: counts, never percentages, never an invented baseline -------
eq(api.trendText(10, 6, true), "+4 since yesterday", "rise");
eq(api.trendText(5, 9, true), "−4 since yesterday", "fall uses a real minus sign");
eq(api.trendText(3, 3, true), "No change since yesterday", "flat");
eq(api.trendText(5, 0, false), "First 24 hours of data", "no history must not read as +5");
eq(api.trendText(5, undefined, true), "Last 24 hours", "older server without prev_24h");
eq(api.trendText(0, 0, true), "No change since yesterday", "quiet day");

// --- collectorLabel: one entry covers all three platforms -------------------
["MacUsbMonitor", "WindowsUsbMonitor", "LinuxUsbMonitor"].forEach(function (c) {
  eq(api.collectorLabel(c), "USB devices", c);
});
eq(api.collectorLabel("FolderMonitor"), "File changes", "FolderMonitor");
eq(api.collectorLabel("MacProcessMonitor"), "Processes", "MacProcessMonitor");
eq(api.collectorLabel("SomeFutureMonitor"), null, "unknown collector must be dropped, not shown raw");

// --- recommendedAction: the dangerous verdicts win over everything ----------
var mal = api.recommendedAction({ severity: "low", source: "process" },
  { threat_intel: { vt: { detections: 3, engines_total: 70 } } });
eq(mal.cls, "bad", "detections outrank a low severity");
has(mal.text, "3 VirusTotal engines", "malicious cites the real count");
eq(api.recommendedAction({ severity: "low", source: "tamper" }, {}).cls, "bad", "tamper");
eq(api.recommendedAction({ severity: "low", source: "process" },
   { threat_intel: { vt: { detections: 0, suspicious: 2 } } }).cls, "warn", "suspicious");
eq(api.recommendedAction({ severity: "high", source: "process" }, {}).cls, "warn", "high severity");
// Same severity, different strength of case -> different instruction. A high
// resting on one lone heuristic must not be phrased like one with three
// signals behind it; that is what teaches people to ignore the drawer.
var thin = api.recommendedAction({ severity: "high", source: "process",
  verdict_confidence: { level: "low", corroborating: 1, hard: 1, polled: false } }, {});
var solid = api.recommendedAction({ severity: "high", source: "process",
  verdict_confidence: { level: "high", corroborating: 3, hard: 2, polled: false } }, {});
eq(thin.cls, "warn", "low-confidence high is still a warn");
has(thin.text, "nothing else corroborates", "a thin case says so");
if (thin.text === solid.text)
  failures.push("high/low-confidence and high/high-confidence must not read identically");
lacks(solid.text, "corroborates", "a corroborated verdict does not hedge");
eq(api.recommendedAction({ severity: "low", source: "process",
   risk_hint: "os_platform_binary" }, {}).cls, "ok", "verified Apple binary");
// Zero detections is not a clean bill of health -- same rule tiVerdict follows.
var undet = api.recommendedAction({ severity: "low", source: "process" },
  { threat_intel: { vt: { detections: 0, suspicious: 0, engines_total: 70 } } });
lacks(undet.text.toLowerCase(), "safe", "undetected must never be called safe");

// --- factsHtml: labels the known keys, hides the absent ones, loses none ----
var html = api.factsHtml({ name: "bash", pid: 5, parent_pid: 1, exe: "/bin/bash",
                           action: "stop_monitoring", _schema: 1, threat_intel: {} });
has(html, ">Process<", "process group rendered");
has(html, ">Parent PID<", "parent pid labelled, not raw key");
has(html, ">Executable path<", "exe labelled");
has(html, ">Other<", "ungrouped key still reaches the Other table");
has(html, "stop_monitoring", "ungrouped value not dropped");
lacks(html, ">Network<", "no network data means no Network section at all");
lacks(html, ">Hashes<", "no hash means no Hashes section");
lacks(html, "_schema", "internal keys stay out of the drawer");
lacks(html, "threat_intel", "threat_intel has its own panel");
// Absent, null and empty-string are all "we don't have it" -- none may render.
var sparse = api.factsHtml({ name: "x", pid: 0, exe: null, path: "" });
has(sparse, ">PID<", "pid 0 is a real value and must render");
lacks(sparse, ">Executable path<", "null must not render");
lacks(sparse, ">Path<", "empty string must not render");
// Escaping still applies on the forensic path -- these values come off disk.
has(api.factsHtml({ name: "<img src=x onerror=alert(1)>" }), "&lt;img", "fact values are escaped");

// --- openDrawer: the AI summary must lead, and lead the tabs ---------------
// The fixtures come through core/signals.py, exactly as the server serves
// them, so these assertions exercise both halves of the split at once: the
// codes Python chose AND the words app.js puts on them.
var FIX = FIXTURES;
var ev = FIX.proc;
api.state.byId = new Map([[42, ev]]);
api.state.events = [ev];
api.openDrawer(42);
var body = els["drawer-body"].innerHTML;

has(body, "AI Analysis", "the AI section is titled and present");
has(body, "Unknown app launched from Downloads.", "the explanation itself is rendered");
has(body, "Recommended action", "recommended action is present");

// The lede leads with the verdict; the identity metadata is demoted below the
// headline and above the AI, never a badge grid opening the drawer.
var ledeAt = body.indexOf("drawer-lede"), metaAt = body.indexOf("lede-meta");
var panelAt = body.indexOf("ai-panel");
if (!(ledeAt > -1 && ledeAt < panelAt)) failures.push("the lede must come before the AI panel");
if (!(metaAt > body.indexOf("lede-title") && metaAt < panelAt))
  failures.push("identity metadata belongs under the headline, above the AI panel");
lacks(body, "drawer-badges", "the old badge grid must be gone from the event drawer");
has(body, "critical risk", "severity stated as a verdict");
// A count of signals that fired -- never a fabricated 0-100 score.
has(body, "signals raised", "signal count shown");
if (/\b\d{1,3}\s*\/\s*100\b/.test(body))
  failures.push("a 0-100 risk score is fabricated precision -- severity has four levels");

// "Why" must cite the actual triggers behind the recommendation.
has(body, "Recommended action", "recommendation");
has(body, "rec-why", "why block present");
has(body, "Temp / Downloads", "the Downloads path that raised this is named");

// The signal table replaces the floating italic apologies.
has(body, "Signal check", "signal table heading");
has(body, "Reputation", "reputation dimension always listed");
has(body, "Not queried", "unchecked dimension reads as state, not error");
has(body, "Signature", "signature dimension listed");
lacks(body, "No threat-intelligence lookup", "the apologetic wording is gone");
lacks(body, "Trust: unknown", "the apologetic wording is gone");
// Dominance is structural, not just stylistic: the AI panel has to come before
// the tab strip, because anything inside a tab is invisible until clicked --
// which is exactly the bug this change exists to fix.
var aiAt = body.indexOf("ai-panel"), tabsAt = body.indexOf("drawer-tabs");
if (!(aiAt > -1 && tabsAt > -1 && aiAt < tabsAt))
  failures.push("AI panel must render before the tab strip (ai-panel@" + aiAt + ", tabs@" + tabsAt + ")");
lacks(body, 'data-tab="ai"', "the AI must no longer be hidden behind a tab");
// Every field the drawer promises, for an event that has them.
["PID", "Parent PID", "Executable path", "SHA-256"].forEach(function (label) {
  has(body, ">" + label + "<", "labelled field " + label);
});
has(body, "critical", "severity shown");
lacks(body, ">Network<", "no network data on this event -- section must be absent");

// A genuinely malicious event: the Why must cite the real triggers, and the
// signal table must show the same numbers the recommendation quotes.
var mal2 = FIX.malicious;
api.state.byId.set(7, mal2);
api.openDrawer(7);
var mbody = els["drawer-body"].innerHTML;
has(mbody, "41 of 72 engines flag it", "signal table cites the real detection ratio");
has(mbody, "Flagged malicious by 41 VirusTotal engines", "why cites the detections");
has(mbody, "Matches T1204 User Execution", "why cites the MITRE technique");
has(mbody, "An executable .exe file appeared", "why cites the file type");
has(mbody, "3 signals raised", "signal count matches the why list");
// Signals the event does not have must not be invented into the why.
lacks(mbody, "Signature", "a folder event has no signature dimension to check");

// An all-clear verdict must justify itself too, from the lowering signals.
var trusted = FIX.trusted;
api.state.byId.set(8, trusted);
api.openDrawer(8);
var tbody = els["drawer-body"].innerHTML;
has(tbody, "no risk signals raised", "nothing fired");
has(tbody, "Verified system binary", "the lowering signal is stated");
has(tbody, "rec-why", "an all-clear still shows why");
has(tbody, "SIP prevents anyone from modifying", "why cites the integrity property");
// An all-clear is only as good as what cleared it: SIP is a strong reason, so
// this must read as a confident all-clear, not merely a quiet one.
has(tbody, "high confidence", "a SIP-backed all-clear is confident");

// --- confidence: stated next to severity, and never as an invented number --
has(body, "confidence", "confidence is shown alongside severity");
has(mbody, "high confidence", "three agreeing signals -> high confidence");
has(mbody, "3 corroborating signals", "confidence cites the count, not a score");
if (/confidence[^<]*\b\d{1,3}\s*%/.test(mbody))
  failures.push("confidence is a rank over a handful of booleans -- a percentage is invented");
// Detection method is folded into confidence and listed as a signal row; the
// old chip meant something different by the same word, right next to it.
has(mbody, ">Detection<", "detection method survives as a signal row");
lacks(body, 'class="conf conf-certain"', "the real-time/polled chip is gone from the drawer lede");

// A not-yet-explained event dims the panel instead of showing an empty accent box.
var pending = FIX.pending;
api.state.byId.set(43, pending);
api.openDrawer(43);
var pbody = els["drawer-body"].innerHTML;
has(pbody, "ai-panel-pending", "unexplained events dim the AI panel");
// Nothing raised AND nothing cleared it. That is a real state and the most
// common one in a live store -- it must read as unverified coverage, not as a
// verified all-clear borrowing confidence it never earned.
has(pbody, "no risk signals raised", "nothing fired");
has(pbody, "low confidence", "an unbacked all-clear does not claim to be checked");
has(pbody, "nothing verified it either", "and says which kind of low it is");

// --- empty state: claims coverage only when the pipeline reports it --------
api.state.events = [];
api.state.filters = { q: "", severity: new Set(), source: new Set(), category: "",
                      rangeSeconds: 0, hideTrusted: false };
api.state.monitor = { running: true, collectors: [] };
lacks(api.emptyStateHtml(), "Currently monitoring", "no collector gauge -> no coverage claim");
api.state.monitor = { running: true, collectors: ["MacUsbMonitor", "FolderMonitor", "MacProcessMonitor"] };
var empty = api.emptyStateHtml();
has(empty, "Everything looks normal", "all-clear headline");
has(empty, "Currently monitoring", "checklist heading");
["USB devices", "File changes", "Processes"].forEach(function (n) {
  has(empty, ">" + n + "<", "checklist lists " + n);
});
lacks(empty, "Startup items", "must not list a collector that is not running");
// Monitoring off is the one state that must never claim to be watching.
api.state.monitor = { running: false, collectors: ["MacUsbMonitor"] };
lacks(api.emptyStateHtml(), "Currently monitoring", "stopped must not claim coverage");

if (failures.length) { failures.forEach(function (f) { print("FAIL " + f); }); print("FAILED"); }
else print("PASSED");
"""


def _fixtures() -> dict:
    """The drawer's test events, annotated by the real core/signals.py -- the
    same call dashboard/server.py makes on every row it serves. Hand-written
    signal arrays here would test app.js against a guess at what Python emits,
    which is the drift this whole change exists to remove."""
    from core.signals import annotate

    events = {
        "proc": {
            "id": 42, "severity": "critical", "source": "process",
            "category": "process_started", "summary": "New process: curl (PID 900)",
            "timestamp": 1770000000, "confidence": "certain",
            "explanation": "Unknown app launched from Downloads.\n\n"
                           "A program in your Downloads folder ran.",
            "details_json": json.dumps({"name": "curl", "pid": 900, "parent_pid": 1,
                                        "exe": "/tmp/curl", "sha256": "abc123"}),
        },
        "malicious": {
            "id": 7, "severity": "critical", "source": "folder",
            "category": "file_created", "summary": "New file: invoice.exe",
            "timestamp": 1770000000, "confidence": "certain",
            "explanation": "Executable dropped in Downloads.\n\n"
                           "A program appeared in a folder you watch.",
            "details_json": json.dumps({
                "path": "/Users/me/Downloads/invoice.exe", "sha256": "deadbeef",
                "threat_intel": {
                    "vt": {"status": "ok", "detections": 41, "engines_total": 72,
                           "family": "Emotet"},
                    "mitre": [{"id": "T1204", "name": "User Execution"}]}}),
        },
        "trusted": {
            "id": 8, "severity": "low", "source": "process",
            "category": "process_started", "summary": "New process: ioreg (PID 12)",
            "timestamp": 1770000000, "confidence": "certain",
            "risk_hint": "os_platform_binary",
            "explanation": "System tool ran.\n\nRoutine.",
            "details_json": json.dumps({"name": "ioreg", "pid": 12,
                                        "exe": "/usr/sbin/ioreg"}),
        },
        "pending": {
            "id": 43, "severity": "low", "source": "usb", "category": "usb_connected",
            "summary": "USB inserted", "timestamp": 1770000000, "details_json": "{}",
        },
    }
    return {k: annotate(v) for k, v in events.items()}


def test_drawer_and_stat_logic_executes_correctly():
    import subprocess
    import tempfile

    if not JSC.exists():
        print("skip (no JavaScriptCore shell -- macOS only)")
        return
    harness = (_JS_HARNESS
               .replace("SRC", json.dumps(str(ROOT / "dashboard/static/app.js")))
               .replace("FIXTURES", json.dumps(_fixtures())))
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(harness)
        path = fh.name
    try:
        out = subprocess.run([str(JSC), path], capture_output=True, text=True, timeout=60)
    finally:
        Path(path).unlink(missing_ok=True)
    combined = out.stdout + out.stderr
    assert "PASSED" in combined, combined or "jsc produced no output"


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("\nall checks passed")
