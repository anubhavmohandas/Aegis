"""
Event-driven threat enrichment: a VirusTotal hash lookup plus local MITRE
ATT&CK annotations, attached to event.details["threat_intel"] BEFORE the AI
explainer runs -- so the explanation is grounded in structured evidence
instead of model inference. See ai_explainer.py's intel-aware system prompt:
the AI is told these values are fetched facts, and that zero detections is
NOT evidence of safety.

WHY THIS IS OPT-IN (enrich_enabled defaults to false) AND GATED:

  - Privacy: querying a hash tells VirusTotal (and its ecosystem) that this
    hash exists on your machine. Consistent with the rule engine's opt-in
    allowlist philosophy, Aegis never sends anything off-box without the
    user explicitly turning it on.
  - Quota: the VT free tier is 4 lookups/min, 500/day. The dispatcher allows
    20 events/min, so enrichment CANNOT be per-event: only high/critical
    events are enriched, results are cached in SQLite (so chrome.exe starting
    400 times costs one lookup, and cached verdicts work offline), and an
    in-process budget stays under the free-tier rate.
  - Hash-only, never upload: a file VT has never seen returns 404 and is
    reported as "unknown_hash" -- uploading the user's file to a public
    corpus would leak private documents and is deliberately not implemented.

EVERY FAILURE PATH ATTACHES NOTHING: no key, over budget, timeout, HTTP
error, unhashable file -- the event proceeds through the pipeline exactly as
if enrichment were disabled (the AI prompt then makes no threat-intel claims
at all). Enrichment can only ever add evidence, never block or degrade the
existing flow.

MITRE annotations are the OFFLINE half: a small static mapping from event
shapes to ATT&CK technique ids. They are annotations for context, not
verdicts -- same contract as the severity engine's heuristics.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import urllib.error
import urllib.request
from collections import deque

from core.events import EventCategory, MonitorEvent
from core.rule_engine import _sha256_of  # reuse: same size cap + locked-file handling
from core.severity_engine import _SUSPICIOUS_PATH_FRAGMENTS

logger = logging.getLogger("aegis.enrichment")

_VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
_VT_TIMEOUT_SECONDS = 5          # a hung lookup stalls the single dispatcher thread -- keep it tight
_VT_BUDGET_PER_MINUTE = 4        # VT free tier; occam: single flat budget, no daily counter --
                                 # the severity gate + cache keep daily volume far below 500
_CACHE_TTL_SECONDS = 24 * 3600   # occam: one flat TTL; verdicts do change (esp. 0-detection files
                                 # gaining detections days later), so "forever" would be wrong
_QUOTA_BACKOFF_SECONDS = 600     # after a 429, stop trying for a while instead of burning the budget

_ENRICHABLE_SEVERITIES = {"high", "critical"}

# The four stats buckets that mean "an engine actually scanned this" -- the
# denominator VT's own UI uses. Excludes timeout/failure/type-unsupported.
_ENGINE_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected")


def _hash_target_path(event: MonitorEvent) -> str | None:
    """Which on-disk file, if any, this event is 'about' for hashing purposes."""
    if event.category == EventCategory.PROCESS_STARTED:
        return event.details.get("exe") or event.details.get("executable_path") or None
    if event.category in (EventCategory.FILE_CREATED, EventCategory.FILE_MODIFIED):
        return event.details.get("path") or None
    if event.category == EventCategory.FILE_MOVED:
        return event.details.get("dest_path") or None
    return None


def mitre_techniques(event: MonitorEvent) -> list[dict]:
    """Local, offline ATT&CK annotations. Deliberately tiny: only mappings
    defensible from a single event's shape are included -- e.g. a mere USB
    connection is NOT tagged T1091, because the mapping would be a guess.
    These annotate ("possibly relevant technique"), they never conclude."""
    techniques: list[dict] = []
    if event.category == EventCategory.STARTUP_ITEM_ADDED:
        techniques.append({"id": "T1547", "name": "Boot or Logon Autostart Execution"})
    if event.category == EventCategory.PROCESS_STARTED:
        path = str(
            event.details.get("exe") or event.details.get("executable_path") or ""
        ).lower()
        if any(frag in path for frag in _SUSPICIOUS_PATH_FRAGMENTS):
            techniques.append({"id": "T1204.002", "name": "User Execution: Malicious File"})
    return techniques


def _trim_vt_response(data: dict, sha256: str) -> dict:
    """Reduce VT's very large file object to the handful of structured facts
    the AI prompt and the timeline actually use. Only this trimmed form is
    cached and persisted -- never the raw response."""
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    out = {
        "source": "virustotal",
        "status": "known",
        "detections": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "engines_total": sum(int(stats.get(k) or 0) for k in _ENGINE_STAT_KEYS),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    if label:
        out["family"] = str(label)
    for vt_key, out_key in (("first_submission_date", "first_seen_utc"),
                             ("last_analysis_date", "last_analysis_utc")):
        ts = attrs.get(vt_key)
        if isinstance(ts, (int, float)) and ts > 0:
            out[out_key] = time.strftime("%Y-%m-%d", time.gmtime(ts))
    return out


class ThreatEnricher:
    """Owned by the Dispatcher, only ever called from its single consumer
    thread -- so no locking here. The sqlite connection is created lazily on
    first use (i.e. on the dispatcher thread, not the main thread that
    constructs the Dispatcher)."""

    def __init__(self, config):
        self.config = config
        self._conn: sqlite3.Connection | None = None
        self._minute_bucket: deque[float] = deque()
        self._auth_failed = False          # bad key: fail once, log once, stop calling until restart
        self._quota_backoff_until = 0.0

    # --- pipeline entry point (never raises) ------------------------------

    def annotate(self, event: MonitorEvent, severity: str) -> None:
        """Attach details["threat_intel"] when there is evidence to attach.
        Every failure path attaches nothing and the pipeline proceeds as if
        enrichment were off."""
        try:
            if severity not in _ENRICHABLE_SEVERITIES:
                return
            intel: dict = {}
            techniques = mitre_techniques(event)
            if techniques:
                intel["mitre"] = techniques
            vt = self._vt_lookup_for(event)
            if vt:
                intel["vt"] = vt
            if intel:
                event.details["threat_intel"] = intel
        except Exception:
            # Same contract as every other pipeline stage guard: enrichment
            # must never take the dispatcher down or block the explanation.
            logger.exception("Enrichment failed for %r -- continuing without it", event.summary)

    # --- VirusTotal --------------------------------------------------------

    def _vt_lookup_for(self, event: MonitorEvent) -> dict | None:
        path = _hash_target_path(event)
        if not path:
            return None
        sha256 = event.details.get("sha256") or _sha256_of(str(path))
        if not sha256:
            return None
        event.details["sha256"] = sha256  # persist what was actually looked up (audit trail)

        cached = self._cache_get(sha256)
        if cached is not None:
            return cached

        if not self.config.vt_api_key:
            return None  # load_config already warned once at startup
        if self._auth_failed or time.time() < self._quota_backoff_until:
            return None
        if not self._under_budget():
            logger.warning("VT rate budget (%s/min) exhausted -- skipping lookup for %s",
                           _VT_BUDGET_PER_MINUTE, sha256)
            return None

        result = self._vt_fetch(sha256)
        if result is not None:
            self._cache_put(sha256, result)
        return result

    def _vt_fetch(self, sha256: str) -> dict | None:
        req = urllib.request.Request(
            _VT_FILE_URL.format(sha256),
            headers={"x-apikey": self.config.vt_api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_VT_TIMEOUT_SECONDS) as resp:
                return _trim_vt_response(json.load(resp), sha256)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # VT has never seen this file. That's evidence, not an error --
                # and exactly the case the prompt's "unknown != safe" rule covers.
                return {"source": "virustotal", "status": "unknown_hash"}
            if e.code == 401:
                self._auth_failed = True
                logger.error("VirusTotal rejected the API key (401) -- "
                             "enrichment disabled until restart. Check VT_API_KEY.")
                return None
            if e.code == 429:
                self._quota_backoff_until = time.time() + _QUOTA_BACKOFF_SECONDS
                logger.warning("VirusTotal quota exceeded (429) -- backing off for %ss",
                               _QUOTA_BACKOFF_SECONDS)
                return None
            logger.warning("VirusTotal lookup failed for %s: HTTP %s", sha256, e.code)
            return None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            logger.warning("VirusTotal lookup failed for %s: %s", sha256, e)
            return None

    def _under_budget(self) -> bool:
        now = time.time()
        while self._minute_bucket and now - self._minute_bucket[0] > 60:
            self._minute_bucket.popleft()
        if len(self._minute_bucket) >= _VT_BUDGET_PER_MINUTE:
            return False
        self._minute_bucket.append(now)
        return True

    # --- cache (same SQLite file as the event store, own table) ------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.config.db_path)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS vt_cache ("
                "sha256 TEXT PRIMARY KEY, fetched_at REAL NOT NULL, payload_json TEXT NOT NULL)"
            )
            self._conn.commit()
        return self._conn

    def _cache_get(self, sha256: str) -> dict | None:
        try:
            row = self._get_conn().execute(
                "SELECT fetched_at, payload_json FROM vt_cache WHERE sha256 = ?", (sha256,)
            ).fetchone()
            if row is None or time.time() - row[0] > _CACHE_TTL_SECONDS:
                return None
            return json.loads(row[1])
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.warning("VT cache read failed (%s) -- treating as miss", e)
            return None

    def _cache_put(self, sha256: str, payload: dict) -> None:
        try:
            conn = self._get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO vt_cache (sha256, fetched_at, payload_json) VALUES (?, ?, ?)",
                (sha256, time.time(), json.dumps(payload)),
            )
            conn.commit()
        except sqlite3.Error as e:
            logger.warning("VT cache write failed (%s) -- lookup not cached", e)


if __name__ == "__main__":
    # Self-check: everything except the live VT call (no network, no key).
    import os
    import tempfile

    # --- response trimming against a canned VT v3 file object shape
    canned = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 48, "suspicious": 3, "harmless": 2,
                                 "undetected": 19, "type-unsupported": 9},
        "popular_threat_classification": {"suggested_threat_label": "trojan.lumma"},
        "first_submission_date": 1752105600,
    }}}
    trimmed = _trim_vt_response(canned, "ab" * 32)
    assert trimmed["detections"] == 48 and trimmed["engines_total"] == 72
    assert trimmed["family"] == "trojan.lumma" and trimmed["status"] == "known"
    assert trimmed["first_seen_utc"] == "2025-07-10"  # 1752105600 = 2025-07-10T00:00:00Z
    assert _trim_vt_response({}, "ab" * 32)["detections"] == 0  # malformed reply never raises

    # --- MITRE mapping
    ev = lambda cat, details: MonitorEvent(category=cat, summary="t", details=details)
    assert mitre_techniques(ev(EventCategory.STARTUP_ITEM_ADDED, {}))[0]["id"] == "T1547"
    assert mitre_techniques(ev(EventCategory.PROCESS_STARTED,
                               {"exe": "/Users/x/Downloads/a.exe"}))[0]["id"] == "T1204.002"
    assert mitre_techniques(ev(EventCategory.PROCESS_STARTED, {"exe": "/Applications/S.app/x"})) == []
    assert mitre_techniques(ev(EventCategory.USB_CONNECTED, {})) == []  # deliberately unmapped

    # --- hash target resolution
    assert _hash_target_path(ev(EventCategory.FILE_MOVED, {"dest_path": "/d/x.exe"})) == "/d/x.exe"
    assert _hash_target_path(ev(EventCategory.PROCESS_STARTED, {"exe": "/bin/ls"})) == "/bin/ls"
    assert _hash_target_path(ev(EventCategory.USB_CONNECTED, {})) is None

    # --- cache round trip + TTL expiry, against a real temp sqlite file
    class _Cfg:
        db_path = os.path.join(tempfile.mkdtemp(), "t.db")
        vt_api_key = None
    e = ThreatEnricher(_Cfg())
    assert e._cache_get("x" * 64) is None
    e._cache_put("x" * 64, {"status": "known", "detections": 1})
    assert e._cache_get("x" * 64)["detections"] == 1
    e._get_conn().execute("UPDATE vt_cache SET fetched_at = ?", (time.time() - _CACHE_TTL_SECONDS - 1,))
    assert e._cache_get("x" * 64) is None  # expired -> miss

    # --- rate budget: 4 allowed, 5th denied
    assert all(e._under_budget() for _ in range(_VT_BUDGET_PER_MINUTE))
    assert not e._under_budget()

    # --- severity gate + no-key path: annotate() attaches nothing, never raises
    low = ev(EventCategory.PROCESS_STARTED, {"exe": "/Users/x/Downloads/a.exe"})
    e.annotate(low, "medium")
    assert "threat_intel" not in low.details
    hi = ev(EventCategory.STARTUP_ITEM_ADDED, {"name": "evil", "path": "/nonexistent"})
    e.annotate(hi, "high")
    assert hi.details["threat_intel"]["mitre"][0]["id"] == "T1547"  # offline half still works keyless

    print("enrichment self-check: OK")

    # Live VT validation: python -m core.enrichment --live
    # Needs a real key (VT_API_KEY env/.env, or saved via Settings -> Threat
    # Intelligence). Three lookups, inside the 4/min free-tier budget, against
    # a throwaway cache db -- never the real event store.
    import sys
    if "--live" in sys.argv:
        from core.config import load_config
        cfg = load_config()
        if not cfg.vt_api_key:
            sys.exit("--live needs VT_API_KEY (env, .env, or Settings → Threat Intelligence)")

        class _LiveCfg:
            db_path = os.path.join(tempfile.mkdtemp(), "live.db")
            vt_api_key = cfg.vt_api_key
        live = ThreatEnricher(_LiveCfg())

        # 1. EICAR test file: must be known to VT with real detections.
        eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        r = live._vt_fetch(eicar)
        print("EICAR:", json.dumps(r, indent=2))
        assert r and r["status"] == "known" and r["detections"] > 0, \
            "EICAR should be a known detection (401 in the log means a bad key)"

        # 2. Nonsense hash: must map to the unknown_hash verdict, not an error.
        r = live._vt_fetch("f" * 64)
        print("bogus hash:", r)
        assert r == {"source": "virustotal", "status": "unknown_hash"}

        # 3. Full annotate() pipeline on a real local binary: hash -> lookup
        #    -> details["threat_intel"] -> cached.
        evt = MonitorEvent(category=EventCategory.PROCESS_STARTED,
                           summary="live test", details={"exe": "/bin/ls"})
        live.annotate(evt, "high")
        print("/bin/ls:", json.dumps(evt.details.get("threat_intel"), indent=2))
        assert "vt" in evt.details.get("threat_intel", {}), "annotate() attached no VT verdict"
        assert live._cache_get(evt.details["sha256"]) is not None, "lookup was not cached"

        print("enrichment live check: OK")
