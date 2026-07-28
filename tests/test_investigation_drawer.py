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
var ev = { id: 42, severity: "critical", source: "process", category: "process_exec",
  summary: "New process: curl (PID 900)", timestamp: 1770000000, confidence: "certain",
  explanation: "Unknown app launched from Downloads.\n\nA program in your Downloads folder ran.",
  details_json: JSON.stringify({ name: "curl", pid: 900, parent_pid: 1, exe: "/tmp/curl",
                                 sha256: "abc123" }) };
api.state.byId = new Map([[42, ev]]);
api.state.events = [ev];
api.openDrawer(42);
var body = els["drawer-body"].innerHTML;

has(body, "AI Summary", "the AI section is titled and present");
has(body, "Unknown app launched from Downloads.", "the explanation itself is rendered");
has(body, "Recommended action", "recommended action is present");
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

// A not-yet-explained event dims the panel instead of showing an empty accent box.
var pending = { id: 43, severity: "low", source: "usb", category: "usb_insert",
  summary: "USB inserted", timestamp: 1770000000, details_json: "{}" };
api.state.byId.set(43, pending);
api.openDrawer(43);
has(els["drawer-body"].innerHTML, "ai-panel-pending", "unexplained events dim the AI panel");

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


def test_drawer_and_stat_logic_executes_correctly():
    import subprocess
    import tempfile

    if not JSC.exists():
        print("skip (no JavaScriptCore shell -- macOS only)")
        return
    harness = _JS_HARNESS.replace("SRC", json.dumps(str(ROOT / "dashboard/static/app.js")))
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
