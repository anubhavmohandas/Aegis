/* Aegis dashboard frontend.
   Talks only to the read-only JSON API in server.py. Polls for new events;
   all filtering happens server-side so the view and the exports always agree. */

"use strict";

const POLL_MS = 4000;
const PAGE_SIZE = 200;

// A "New process: X (PID Y)" / "New application launched: X (PID Y)" row
// only needs the full phrasing while it's actually news -- ten seconds in,
// every collector on every OS uses one of these two exact phrasings
// (windows/linux/macos process_monitor.py), so once a row ages past that,
// collapse it down to just the process name. Cuts the repeated "New
// process:" noise on a long list without losing any information the row's
// own "Process" source tag + timestamp don't already carry.
const FRESH_SUMMARY_MS = 10000;
const PROCESS_SUMMARY_RE = /^New (?:process|application launched): (.+) \(PID \d+\)$/;

function displaySummary(ev, now = Date.now()) {
  if (now - ev.timestamp * 1000 <= FRESH_SUMMARY_MS) return ev.summary;
  const m = PROCESS_SUMMARY_RE.exec(ev.summary);
  return m ? m[1] : ev.summary;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SOURCE_LABELS = { process: "Process", usb: "USB", startup: "Startup", folder: "Folder",
                        session: "Session", tamper: "Tamper" };

/* Per-source glyph shown at the head of each event row and in the drawer,
   the way the reference SOC dashboards give USB / shell / file their own
   icon. Inline 16x16 SVG (stroke = currentColor) so they inherit the row's
   severity tint and theme color with zero extra requests. */
const SOURCE_ICONS = {
  process: '<path d="M3 4.5h10v7H3z"/><polyline points="5,7 6.8,8.5 5,10"/><line x1="8.2" y1="10" x2="11" y2="10"/>',
  usb: '<line x1="8" y1="2.5" x2="8" y2="13.5"/><polygon points="8,2.5 6.6,4.6 9.4,4.6" fill="currentColor" stroke="none"/><circle cx="5.2" cy="9" r="1.1"/><line x1="5.2" y1="9" x2="8" y2="7"/><rect x="9.8" y="6.2" width="2.4" height="2.4"/><line x1="11" y1="8.6" x2="8" y2="10.5"/>',
  startup: '<rect x="3" y="3" width="4" height="4" rx="1"/><rect x="9" y="3" width="4" height="4" rx="1"/><rect x="3" y="9" width="4" height="4" rx="1"/><rect x="9" y="9" width="4" height="4" rx="1"/>',
  folder: '<path d="M2.5 5.5 A1 1 0 0 1 3.5 4.5 H6.2 L7.5 6 H12.5 A1 1 0 0 1 13.5 7 V11.5 A1 1 0 0 1 12.5 12.5 H3.5 A1 1 0 0 1 2.5 11.5 Z"/>',
  session: '<rect x="4" y="7" width="8" height="6" rx="1"/><path d="M5.8 7 V5.2 A2.2 2.2 0 0 1 10.2 5.2 V7"/>',
  tamper: '<path d="M8 2 L13 4 V8 C13 11 10.8 13.2 8 14 C5.2 13.2 3 11 3 8 V4 Z"/><line x1="8" y1="5.5" x2="8" y2="9"/><circle cx="8" cy="11" r="0.5" fill="currentColor" stroke="none"/>',
};
function sourceIcon(source) {
  const glyph = SOURCE_ICONS[source] || SOURCE_ICONS.process;
  return `<span class="event-icon src-${source}" aria-hidden="true"><svg viewBox="0 0 16 16" fill="none"
    stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">${glyph}</svg></span>`;
}
const CONFIDENCE_TITLES = {
  certain: "Real-time detection",
  polled: "Polled detection — may be delayed or incomplete",
  degraded: "Degraded detection backend",
};

/* Theme metadata drives the picker popover; the actual colors live in
   style.css theme blocks keyed by [data-theme]. Swatch colors here are only
   for the preview cards. */
const THEMES = [
  { id: "obsidian",  label: "Obsidian",  mode: "dark",  bg: "#0e1116", accent: "#3cb179" },
  { id: "indigo",    label: "Indigo",    mode: "dark",  bg: "#0d0d1b", accent: "#8f8ff2" },
  { id: "phosphor",  label: "Phosphor",  mode: "dark",  bg: "#090f0a", accent: "#45d97e" },
  { id: "daylight",  label: "Daylight",  mode: "light", bg: "#f3f5f9", accent: "#0d7d8c" },
  { id: "sandstone", label: "Sandstone", mode: "light", bg: "#f6f1e8", accent: "#a3600f" },
  { id: "arctic",    label: "Arctic",    mode: "light", bg: "#edf2f6", accent: "#1e6fb0" },
];
const THEME_KEY = "aegis-theme";

/* Provider presets mirror the examples documented in config/config.yaml.
   Picking one fills endpoint/env-var/model suggestions; "custom" leaves
   everything editable for any other OpenAI-compatible endpoint. */
const PROVIDERS = [
  { id: "nvidia",     label: "NVIDIA",     provider: "openai-compatible",
    base_url: "https://integrate.api.nvidia.com/v1", api_key_env: "NVIDIA_API_KEY",
    models: ["nvidia/nemotron-3-ultra-550b-a55b", "meta/llama-3.3-70b-instruct"] },
  { id: "openai",     label: "OpenAI",     provider: "openai-compatible",
    base_url: "https://api.openai.com/v1", api_key_env: "OPENAI_API_KEY",
    models: ["gpt-4.1-mini", "gpt-4.1", "gpt-4o-mini"] },
  { id: "anthropic",  label: "Anthropic",  provider: "anthropic",
    base_url: "", api_key_env: "ANTHROPIC_API_KEY",
    models: ["claude-sonnet-5", "claude-haiku-4-5-20251001", "claude-opus-4-8"] },
  { id: "openrouter", label: "OpenRouter", provider: "openai-compatible",
    base_url: "https://openrouter.ai/api/v1", api_key_env: "OPENROUTER_API_KEY", models: [] },
  { id: "ollama",     label: "Ollama",     provider: "openai-compatible",
    base_url: "http://localhost:11434/v1", api_key_env: "OLLAMA_API_KEY",
    models: ["llama3", "mistral", "qwen2.5"] },
  { id: "custom",     label: "Custom",     provider: "openai-compatible",
    base_url: "", api_key_env: "AI_API_KEY", models: [] },
];

const HIDE_TRUSTED_KEY = "aegis-hide-trusted";

const state = {
  events: [],            // newest first, as returned by the API
  byId: new Map(),
  maxId: 0,
  minId: null,
  filters: {
    q: "", severity: new Set(), source: new Set(), category: "", rangeSeconds: 0,
    // Persistent view preference, not a "clear filters" candidate -- default
    // ON, since routine trust-listed noise (mdworker_shared, WebKit helper
    // processes, ...) otherwise buries everything else in the timeline.
    hideTrusted: localStorage.getItem(HIDE_TRUSTED_KEY) !== "0",
  },
  selectedId: null,
  pollTimer: null,
  unseenCount: 0,        // live arrivals while the user is scrolled down
  loading: false,
  consoleReachable: null,     // null = not checked yet; the dashboard API itself
  monitor: { running: false, pid: null, uptimeSeconds: null },
  monitorBusy: false,         // a start/stop request is in flight
};

const $ = (id) => document.getElementById(id);

/* ---------- helpers ---------- */

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* The AI explainer emits light markdown (**bold**, `code`, "- " bullets).
   Render just that subset, after escaping everything — never trust stored text. */
function renderMarkdownLite(text) {
  const inline = (s) =>
    escapeHtml(s)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");

  const blocks = [];
  let list = null;
  for (const rawLine of String(text).split("\n")) {
    const line = rawLine.trim();
    const bullet = line.match(/^[-*]\s+(.*)/);
    if (bullet) {
      (list ??= []).push(`<li>${inline(bullet[1])}</li>`);
      continue;
    }
    if (list) { blocks.push(`<ul>${list.join("")}</ul>`); list = null; }
    if (line) blocks.push(`<p>${inline(line)}</p>`);
  }
  if (list) blocks.push(`<ul>${list.join("")}</ul>`);
  return blocks.join("");
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtFullTime(ts) {
  return new Date(ts * 1000).toLocaleString([], {
    weekday: "short", year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function dayLabel(ts) {
  const d = new Date(ts * 1000);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const yesterday = new Date(today.getTime() - 86400e3);
  if (d >= today) return "Today";
  if (d >= yesterday) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "long", month: "long", day: "numeric", year: "numeric" });
}

function prettyCategory(cat) {
  return String(cat).replaceAll("_", " ");
}

/* ---------- API ---------- */

function filterQuery(extra = {}) {
  const p = new URLSearchParams();
  const f = state.filters;
  if (f.q) p.set("q", f.q);
  if (f.severity.size) p.set("severity", [...f.severity].join(","));
  if (f.source.size) p.set("source", [...f.source].join(","));
  if (f.category) p.set("category", f.category);
  if (f.rangeSeconds) p.set("since", String(Date.now() / 1000 - f.rangeSeconds));
  if (f.hideTrusted) p.set("hide_trusted", "1");
  for (const [k, v] of Object.entries(extra)) p.set(k, String(v));
  return p.toString();
}

async function api(path) {
  const res = await fetch(path);
  if (res.status === 401) {
    location.replace("/login");        // session expired or missing
    throw new Error("unauthenticated");
  }
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

/* ---------- themes ---------- */

function applyTheme(id) {
  document.documentElement.dataset.theme = id;
  localStorage.setItem(THEME_KEY, id);
  document.querySelectorAll(".theme-card").forEach((c) =>
    c.classList.toggle("active", c.dataset.theme === id));
}

function buildThemePicker() {
  const grid = $("theme-grid");
  const current = localStorage.getItem(THEME_KEY) || "obsidian";
  grid.innerHTML = THEMES.map((t) => `
    <button class="theme-card ${t.id === current ? "active" : ""}" data-theme="${t.id}">
      <span class="theme-swatch" style="background:${t.bg}">
        <i style="background:${t.accent}"></i>
        <i style="background:var(--sev-critical)"></i>
        <i style="background:var(--sev-medium)"></i>
      </span>
      <span class="theme-card-name">${t.label}
        <span class="theme-card-mode">${t.mode}</span></span>
    </button>`).join("");

  const pop = $("theme-pop");
  const btn = $("theme-btn");
  const close = () => { pop.hidden = true; btn.setAttribute("aria-expanded", "false"); };

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    pop.hidden = !pop.hidden;
    btn.setAttribute("aria-expanded", String(!pop.hidden));
  });
  grid.addEventListener("click", (e) => {
    const card = e.target.closest(".theme-card");
    if (card) applyTheme(card.dataset.theme);
  });
  document.addEventListener("click", (e) => {
    if (!pop.hidden && !pop.contains(e.target) && e.target !== btn) close();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
}

/* ---------- stats band ---------- */

function renderStats(stats) {
  // Not dismissible on purpose: while this is true, the password that guards
  // Stop Monitoring, Quit and Settings is still the documented default.
  $("default-creds-banner").hidden = !stats.default_credentials;

  $("stat-24h").textContent = stats.last_24h;
  $("stat-total").textContent = stats.total;
  $("stat-sources").textContent = Object.keys(stats.by_source).length;

  const hicrit = (stats.by_severity.high || 0) + (stats.by_severity.critical || 0);
  const hicritEl = $("stat-hicrit");
  hicritEl.textContent = hicrit;
  hicritEl.classList.toggle("alert", hicrit > 0);

  // The closure line: one always-visible sentence answering "so... am I okay?"
  // — the question the stats band's raw numbers make the user compute
  // themselves. Same 24h-scoped stats the band above already shows.
  renderVerdictLine(stats);

  const bar = $("severity-bar");
  const legend = $("severity-legend");
  bar.innerHTML = "";
  legend.innerHTML = "";
  const total = SEVERITY_ORDER.reduce((n, s) => n + (stats.by_severity[s] || 0), 0);
  for (const sev of SEVERITY_ORDER) {
    const count = stats.by_severity[sev] || 0;
    if (count > 0) {
      const seg = document.createElement("div");
      seg.className = "seg";
      seg.style.background = `var(--sev-${sev})`;
      seg.style.flexGrow = count;
      seg.title = `${sev}: ${count}`;
      bar.appendChild(seg);
    }
    legend.insertAdjacentHTML("beforeend",
      `<span class="key"><span class="swatch" style="background:var(--sev-${sev})"></span>` +
      `${sev} <span class="count">${count}</span></span>`);
  }
  if (total === 0) bar.innerHTML = '<div class="seg empty" title="no events in the last 24 hours"></div>';

  const catSelect = $("category-select");
  if (catSelect.options.length === 1 && stats.categories.length) {
    for (const cat of stats.categories) {
      catSelect.insertAdjacentHTML("beforeend",
        `<option value="${escapeHtml(cat)}">${escapeHtml(prettyCategory(cat))}</option>`);
    }
  }
}

function renderVerdictLine(stats) {
  const el = $("footer-verdict");
  if (!el) return;
  const crit = stats.by_severity.critical || 0;
  const high = stats.by_severity.high || 0;
  let text, cls;
  if (crit > 0)       { text = `${stats.last_24h} events · ${crit} critical — review now`; cls = "alert"; }
  else if (high > 0)  { text = `${stats.last_24h} events · ${high} high — review recommended`; cls = "warn"; }
  else if (!stats.last_24h) { text = "quiet — nothing recorded"; cls = "ok"; }
  else                { text = `${stats.last_24h} events — everything looks normal`; cls = "ok"; }
  el.textContent = `last 24h: ${text}`;
  el.className = cls;
  el.hidden = false;
  $("footer-verdict-sep").hidden = false;
}


/* ---------- timeline ---------- */

/* Parsed details_json, cached per event object. Keyed in a WeakMap rather
   than stashed on the event itself so the drawer's raw-JSON view never shows
   a cache field that isn't really part of the row. */
const detailsCache = new WeakMap();
function eventDetails(ev) {
  let d = detailsCache.get(ev);
  if (!d) {
    try { d = JSON.parse(ev.details_json) || {}; } catch { d = {}; }
    detailsCache.set(ev, d);
  }
  return d;
}

/* Trust at a glance — green/amber/red, faster to read than a severity word.
   Derived entirely from data every row already carries: the rule engine's
   risk_hint (SIP-verified Apple binary, user Trust List) and the enrichment
   stage's VirusTotal verdict. Only definite states earn a badge — stamping
   "unknown" on every third-party process would be a wall of amber that says
   nothing; the drawer's Summary tab states unknown explicitly instead. */
function trustFor(ev) {
  const vt = (eventDetails(ev).threat_intel || {}).vt;
  if (vt && (vt.detections || 0) > 0)
    return { cls: "bad", label: "Malicious",
             note: `Flagged malicious by ${vt.detections} of ${vt.engines_total || "?"} VirusTotal engines` };
  if (vt && (vt.suspicious || 0) > 0)
    return { cls: "warn", label: "Suspicious",
             note: `Called suspicious by ${vt.suspicious} VirusTotal engine${vt.suspicious === 1 ? "" : "s"}` };
  if (ev.risk_hint === "os_platform_binary")
    return { cls: "ok", label: "Apple system",
             note: "Verified Apple system binary — it lives in a directory macOS itself (SIP) prevents anyone from modifying" };
  if (ev.risk_hint === "aegis_own_child")
    return { cls: "ok", label: "Aegis", note: "Started by Aegis itself" };
  if ((ev.risk_hint || "").startsWith("user_trusted"))
    return { cls: "ok", label: "Trusted", note: "On your Trust List" };
  return null;
}

function trustBadgeHtml(ev) {
  const t = trustFor(ev);
  return t ? `<span class="trust-badge ${t.cls}" title="${escapeHtml(t.note)}">${t.label}</span>` : "";
}

function eventRowHtml(ev, fresh) {
  const conf = ev.confidence || "certain";
  const aiSkipped = ev.ai_skipped ? '<span class="ai-skipped-tag">AI skipped</span>' : "";
  return `
    <button class="event-row ${fresh ? "fresh" : ""}" data-id="${ev.id}"
            style="--sev-color: var(--sev-${ev.severity})">
      <span class="event-time">${fmtTime(ev.timestamp)}</span>
      ${sourceIcon(ev.source)}
      <span class="badge badge-${ev.severity}">${ev.severity}</span>
      <span class="event-main">
        <span class="event-summary">${escapeHtml(displaySummary(ev))}</span>
        <span class="event-sub">
          <span class="src">${SOURCE_LABELS[ev.source] || escapeHtml(ev.source)}</span>
          <span>${escapeHtml(prettyCategory(ev.category))}</span>
          <span class="conf conf-${conf}" title="${CONFIDENCE_TITLES[conf] || conf}">
            <span class="conf-dot"></span>${conf}</span>
          ${trustBadgeHtml(ev)}
          ${aiSkipped}
        </span>
      </span>
      <span class="event-chevron">›</span>
    </button>`;
}

/* Consecutive near-identical rows (same source+severity+category+subject)
   collapse into one <details> group — "Chrome · 17 events ▸" instead of 17
   rows. <details> is the whole widget: open/closed state needs no JS and
   the existing .event-row click delegation still opens the drawer for the
   inner rows. Runs shorter than GROUP_MIN stay individual rows. */
const GROUP_MIN = 4;

function groupKey(ev) {
  const m = PROCESS_SUMMARY_RE.exec(ev.summary);
  return `${ev.source}|${ev.severity}|${ev.category}|${m ? m[1] : ev.summary}`;
}

function groupHtml(run, freshIds) {
  const newest = run[0], oldest = run[run.length - 1];
  // Never hide the row the user is looking at, or ones that just arrived.
  const open = run.some((ev) => freshIds.has(ev.id) || ev.id === state.selectedId);
  const m = PROCESS_SUMMARY_RE.exec(newest.summary);
  const name = m ? m[1] : newest.summary;
  return `
    <details class="event-group" ${open ? "open" : ""}>
      <summary class="event-row" style="--sev-color: var(--sev-${newest.severity})">
        <span class="event-time">${fmtTime(newest.timestamp)}</span>
        ${sourceIcon(newest.source)}
        <span class="badge badge-${newest.severity}">${newest.severity}</span>
        <span class="event-main">
          <span class="event-summary">${escapeHtml(name)}</span>
          <span class="event-sub">
            <span class="src">${SOURCE_LABELS[newest.source] || escapeHtml(newest.source)}</span>
            <span>${run.length} events · ${fmtTime(oldest.timestamp)} – ${fmtTime(newest.timestamp)}</span>
            ${trustBadgeHtml(newest)}
          </span>
        </span>
        <span class="event-chevron group-chevron">›</span>
      </summary>
      <div class="event-group-body">
        ${run.map((ev) => eventRowHtml(ev, freshIds.has(ev.id))).join("")}
      </div>
    </details>`;
}

function renderTimeline(freshIds = new Set()) {
  const timeline = $("timeline");

  if (!state.events.length) {
    timeline.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24"><path d="M12 2 L20 5.5 V11 C20 16.5 16.7 20.6 12 22 C7.3 20.6 4 16.5 4 11 V5.5 Z"
          fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>
        <span class="empty-title">No events match</span>
        <span>Adjust the filters, or wait — the monitors are still watching.</span>
      </div>`;
    $("load-older-wrap").hidden = true;
    updateFooter();
    return;
  }

  const parts = [];
  let currentDay = null;
  const counts = new Map();
  for (const ev of state.events) {
    const label = dayLabel(ev.timestamp);
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  let run = [];
  const flush = () => {
    if (!run.length) return;
    if (run.length >= GROUP_MIN) parts.push(groupHtml(run, freshIds));
    else for (const ev of run) parts.push(eventRowHtml(ev, freshIds.has(ev.id)));
    run = [];
  };
  for (const ev of state.events) {
    const label = dayLabel(ev.timestamp);
    const dayChanged = label !== currentDay;
    if (dayChanged || (run.length && groupKey(run[0]) !== groupKey(ev))) flush();
    if (dayChanged) {
      currentDay = label;
      parts.push(`<div class="day-header">${label}
        <span class="day-count">${counts.get(label)} event${counts.get(label) === 1 ? "" : "s"}</span></div>`);
    }
    run.push(ev);
  }
  flush();
  timeline.innerHTML = parts.join("");

  if (state.selectedId != null) {
    timeline.querySelector(`[data-id="${state.selectedId}"]`)?.classList.add("selected");
  }
  $("load-older-wrap").hidden = state.events.length < PAGE_SIZE;
  updateFooter();
}

function updateFooter() {
  $("footer-shown").textContent = `${state.events.length} events shown`;
}

// Rows age past FRESH_SUMMARY_MS on the clock, not on the next poll -- a
// full renderTimeline() on a timer would rebuild the whole list (losing
// scroll position, closing the drawer's selected-row highlight, restarting
// the .fresh flash animation) just to change some text. Patching only the
// rows whose displayed text is actually stale is cheap and invisible.
function refreshAgingSummaries() {
  const now = Date.now();
  for (const row of document.querySelectorAll("#timeline .event-row[data-id]")) {
    const ev = state.byId.get(Number(row.dataset.id));
    if (!ev) continue;
    const summaryEl = row.querySelector(".event-summary");
    const wanted = displaySummary(ev, now);
    if (summaryEl && summaryEl.textContent !== wanted) summaryEl.textContent = wanted;
  }
}

/* ---------- data flow ---------- */

function ingest(events) {
  for (const ev of events) {
    state.byId.set(ev.id, ev);
    if (ev.id > state.maxId) state.maxId = ev.id;
    if (state.minId === null || ev.id < state.minId) state.minId = ev.id;
  }
}

async function reload() {
  state.loading = true;
  $("timeline").innerHTML = '<div class="skeleton-row"></div>'.repeat(6);
  state.events = [];
  state.byId.clear();
  state.maxId = 0;
  state.minId = null;
  state.unseenCount = 0;
  hidePill();
  try {
    const data = await api(`/api/events?${filterQuery({ limit: PAGE_SIZE })}`);
    state.events = data.events;
    ingest(data.events);
    setConsoleReachable(true);
    renderTimeline();
  } catch {
    setConsoleReachable(false);
    $("timeline").innerHTML = `
      <div class="empty-state">
        <span class="empty-title">Event store unreachable</span>
        <span>Is dashboard/server.py still running?</span>
      </div>`;
  } finally {
    state.loading = false;
  }
}

async function loadOlder() {
  if (state.minId === null || state.loading) return;
  state.loading = true;
  try {
    const data = await api(`/api/events?${filterQuery({ limit: PAGE_SIZE, before_id: state.minId })}`);
    if (data.events.length) {
      state.events = state.events.concat(data.events);
      ingest(data.events);
      renderTimeline();
    }
    if (data.events.length < PAGE_SIZE) $("load-older-wrap").hidden = true;
  } finally {
    state.loading = false;
  }
}

async function poll() {
  try {
    const [stats, fresh] = await Promise.all([
      api("/api/stats"),
      state.maxId
        ? api(`/api/events?${filterQuery({ limit: PAGE_SIZE, after_id: state.maxId })}`)
        : Promise.resolve({ events: [] }),
    ]);
    renderStats(stats);
    setConsoleReachable(true);

    if (fresh.events.length && !state.loading) {
      state.events = fresh.events.concat(state.events);
      ingest(fresh.events);
      renderTimeline(new Set(fresh.events.map((e) => e.id)));
      if (window.scrollY > 300) {
        state.unseenCount += fresh.events.length;
        showPill();
      }
    }
    await refreshPendingExplanations();
  } catch {
    setConsoleReachable(false);
  }
  refreshMonitorStatus();
  refreshShield();
}

/* Events are written to the DB the instant they happen and explained a few
   seconds later (see core/dispatcher.py). The live fetch above only asks for
   rows newer than maxId, so an explanation that lands after we've already
   cached the row would never reach us. Re-fetch the still-pending rows -- one
   query from the oldest pending id, which is all that can have changed. */
async function refreshPendingExplanations() {
  let oldest = null;
  for (const ev of state.byId.values()) {
    if (ev.explanation || ev.ai_skipped) continue;
    if (oldest === null || ev.id < oldest) oldest = ev.id;
  }
  if (oldest === null) return;
  const data = await api(`/api/events?${filterQuery({ limit: 200, after_id: oldest - 1 })}`);
  let changed = false;
  for (const fresh of data.events) {
    const cached = state.byId.get(fresh.id);
    if (!cached || cached.explanation === fresh.explanation) continue;
    Object.assign(cached, fresh);
    const inList = state.events.find((e) => e.id === fresh.id);
    if (inList) Object.assign(inList, fresh);
    changed = true;
  }
  // The timeline row shows the summary, which never changes -- only the open
  // drawer displays an explanation. Patch just that block rather than calling
  // openDrawer again, which would rebuild the drawer and snap the user back to
  // the Summary tab while they're sitting on the AI tab waiting for this.
  const aiBody = changed ? document.getElementById("drawer-ai-body") : null;
  if (aiBody && state.selectedId && state.byId.has(state.selectedId)) {
    aiBody.innerHTML = explanationHtml(state.byId.get(state.selectedId));
  }
}

/* ---------- monitor status pill + start/stop control ----------
   "LIVE" used to mean only "the dashboard's own fetch succeeded" -- that's
   true even when nothing is watching the system. The pill now reflects
   whether main.py (the actual monitor process) is running, polled from
   /api/monitor/status, which detects both dashboard-launched AND
   independently-started (e.g. from a terminal) instances. */

function setConsoleReachable(ok) {
  state.consoleReachable = ok;
  if (ok) $("sync-time").textContent = `synced ${new Date().toLocaleTimeString()}`;
  renderMonitorPill();
}

async function refreshMonitorStatus() {
  try {
    state.monitor = await api("/api/monitor/status");
  } catch {
    return;  // setConsoleReachable already handles the unreachable case
  }
  renderMonitorPill();
}

// The dispatcher stamps a heartbeat every 60s (core/dispatcher). Past this
// many seconds without one, the process is up but its loop isn't ticking --
// so the pulse stops lying and flips to STALLED. 150s = miss ~2.5 beats
// before warning, so one slow tick never false-alarms.
const HEARTBEAT_STALE_SECONDS = 150;

function renderMonitorPill() {
  const el = $("live-indicator");
  const label = $("live-label");
  const beat = $("live-beat");
  const toggle = $("monitor-toggle");

  el.classList.remove("stale", "idle");
  const inProcess = state.monitor.managed === "in_process";
  const hbAge = state.monitor.heartbeat_age;
  // Running process, but its heartbeat has gone quiet -> loop stalled, not healthy.
  const stalled = state.monitor.running && !state.monitorBusy
                  && hbAge != null && hbAge > HEARTBEAT_STALE_SECONDS;
  if (state.consoleReachable === false) {
    el.classList.add("stale");
    label.textContent = "CONSOLE OFFLINE";
  } else if (state.monitorBusy) {
    el.classList.add("idle");
    label.textContent = state.monitor.running ? "STOPPING…" : "STARTING…";
  } else if (stalled) {
    el.classList.add("stale");
    label.textContent = "MONITORING STALLED";
    el.title = `No heartbeat for ${formatUptime(hbAge)} — process is up but its loop may be stuck`;
  } else if (state.monitor.running) {
    label.textContent = "MONITORING ACTIVE";
    el.title = inProcess ? "" : `PID ${state.monitor.pid} · up ${formatUptime(state.monitor.uptime_seconds)}`;
  } else {
    el.classList.add("idle");
    label.textContent = "MONITORING STOPPED";
    el.title = "";
  }

  // The visible heartbeat: a steadily pulsing heart while monitoring is
  // confirmed alive (heartbeat still fresh as of this poll), gone the moment we
  // stall/stop/go offline. The CSS animation carries the continuous beat; the
  // exact age is tucked into the tooltip rather than shown as a climbing number.
  if (beat) {
    const healthy = state.monitor.running && !state.monitorBusy && !stalled
                    && state.consoleReachable !== false;
    const alive = healthy && hbAge != null;
    // U+FE0E (text variation selector) forces the ♥ to a CSS-colorable glyph
    // instead of the OS red-heart emoji, so it takes --sev-critical and scales.
    beat.textContent = alive ? "♥︎" : "";
    beat.title = alive ? `last heartbeat ${Math.round(hbAge)}s ago` : "";
  }

  // Mirror the same state into the sidebar footer badge.
  const sideMon = $("side-monitor"), sideSub = $("side-monitor-sub");
  if (sideMon && sideSub) {
    const stopped = state.consoleReachable === false || (!state.monitor.running && !state.monitorBusy);
    sideMon.classList.toggle("stopped", stopped || stalled);
    sideSub.textContent = state.consoleReachable === false ? "Console offline"
      : state.monitorBusy ? "Working…"
      : stalled ? "Monitor stalled — loop not responding"
      : state.monitor.running ? "All systems operational" : "Monitoring stopped";
  }

  if (!toggle) return;
  toggle.hidden = false;
  if (state.consoleReachable === false) { toggle.disabled = true; return; }
  toggle.disabled = state.monitorBusy;
  toggle.textContent = state.monitorBusy
    ? (state.monitor.running ? "Stopping…" : "Starting…")
    : (state.monitor.running ? "Stop Monitoring" : "Start Monitoring");
  toggle.classList.toggle("btn-stop", state.monitor.running);
  toggle.classList.toggle("btn-primary", !state.monitor.running);
}

function formatUptime(seconds) {
  if (!seconds && seconds !== 0) return "—";
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

function toggleMonitor() {
  // Starting is not gated; stopping is a protected action that opens an
  // in-page password modal (a native window.prompt() is unreliable inside the
  // desktop app's pywebview shell, so we never use it).
  if (state.monitor.running) {
    openStopModal();
  } else {
    startMonitor();
  }
}

async function startMonitor() {
  state.monitorBusy = true;
  renderMonitorPill();
  try {
    const res = await fetch("/api/monitor/start", { method: "POST" });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    state.monitor = data;
    toast(data.running ? "Monitoring started"
                       : "Monitor process exited immediately — check the log", !data.running);
  } catch {
    toast("Request failed — is the dashboard server still running?", true);
  } finally {
    state.monitorBusy = false;
    renderMonitorPill();
    refreshStatsOnly();
  }
}

async function restartMonitoring() {
  const btn = $("settings-restart");
  btn.disabled = true;
  state.monitorBusy = true;
  renderMonitorPill();
  try {
    const res = await fetch("/api/monitor/restart", { method: "POST" });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    state.monitor = data;
    toast(data.running ? "Monitoring restarted — saved settings are now active"
                       : "Restart failed — monitoring did not come back up, check the log", !data.running);
  } catch {
    toast("Request failed — is the dashboard server still running?", true);
  } finally {
    btn.disabled = false;
    state.monitorBusy = false;
    renderMonitorPill();
    refreshStatsOnly();
  }
}

let stopLockoutTimer = null;   // non-null while a lockout countdown is running

/* One password modal, three protected actions — they share the server's
   guard_protected_action contract exactly (same 403 + tamper_blocked shape,
   same lockout, same evidence capture), so they share the UI too. */
let pwMode = "stop";           // "stop" | "delete" | "unlock"
let deleteIds = null;          // "delete" mode: which incidents
let afterUnlock = null;        // "unlock" mode: what to run once it succeeds

function openStopModal() {
  pwMode = "stop";
  deleteIds = null;
  $("stoppw-title").textContent = "STOP MONITORING";
  $("stoppw-desc").textContent = "Stopping monitoring is a protected action. Enter the dashboard password to confirm. Wrong attempts are logged, and repeated failures capture evidence.";
  $("stoppw-confirm").textContent = "Stop Monitoring";
  showPasswordModal();
}

function openDeleteModal(ids) {
  pwMode = "delete";
  deleteIds = ids;
  const what = ids.length === 1 ? "this incident" : `these ${ids.length} incidents`;
  $("stoppw-title").textContent = "DELETE EVIDENCE";
  $("stoppw-desc").textContent = `Permanently delete ${what} and the captured evidence files. This cannot be undone and is a protected action — enter the dashboard password to confirm. Wrong attempts are logged, and repeated failures capture evidence.`;
  $("stoppw-confirm").textContent = ids.length === 1 ? "Delete Incident" : `Delete ${ids.length} Incidents`;
  showPasswordModal();
}

/* Settings can turn tamper protection itself off, so it's gated like Stop
   Monitoring. `next` is re-run after a successful unlock — the action the
   user was actually trying to do. */
function openUnlockModal(next) {
  pwMode = "unlock";
  afterUnlock = next || null;
  $("stoppw-title").textContent = "UNLOCK SETTINGS";
  $("stoppw-desc").textContent = "Settings control the monitors, the trust lists and tamper protection itself, so changing them is a protected action. Enter the dashboard password to unlock. Wrong attempts are logged, and repeated failures capture evidence.";
  $("stoppw-confirm").textContent = "Unlock Settings";
  showPasswordModal();
}

function showPasswordModal() {
  // Stop/Delete are destructive; unlocking isn't -- don't dress it in the
  // danger button just because it shares the modal.
  const confirmBtn = $("stoppw-confirm");
  confirmBtn.classList.toggle("btn-stop", pwMode !== "unlock");
  confirmBtn.classList.toggle("btn-primary", pwMode === "unlock");
  $("stoppw-overlay").hidden = false;
  $("stoppw-modal").hidden = false;
  $("stoppw-note").textContent = "";
  $("stoppw-input").value = "";
  setTimeout(() => $("stoppw-input").focus(), 50);
}

function closeStopModal() {
  $("stoppw-overlay").hidden = true;
  $("stoppw-modal").hidden = true;
}

/* Server-enforced lockout after too many wrong passwords: disable the modal
   and count down. The server rejects attempts during this window regardless,
   so this is honest UX, not the actual gate. */
function startStopLockout(seconds) {
  clearInterval(stopLockoutTimer);
  const note = $("stoppw-note");
  const input = $("stoppw-input");
  const confirm = $("stoppw-confirm");
  input.disabled = true;
  confirm.disabled = true;
  let remaining = seconds;
  const tick = () => {
    if (remaining <= 0) {
      clearInterval(stopLockoutTimer);
      stopLockoutTimer = null;
      input.disabled = false;
      confirm.disabled = false;
      note.textContent = "You can try again now.";
      return;
    }
    note.textContent = `Too many incorrect attempts — locked for ${remaining}s.`;
    remaining -= 1;
  };
  tick();
  stopLockoutTimer = setInterval(tick, 1000);
}

const PW_ENDPOINT = {
  stop:   () => ["/api/monitor/stop", {}],
  delete: () => ["/api/incidents/delete", { ids: deleteIds }],
  unlock: () => ["/api/settings/unlock", {}],
};

async function confirmPasswordAction() {
  if (stopLockoutTimer) return;   // locked out — ignore clicks/Enter
  const password = $("stoppw-input").value;
  const btn = $("stoppw-confirm");
  const mode = pwMode;
  const [url, extra] = PW_ENDPOINT[mode]();
  btn.disabled = true;
  if (mode === "stop") { state.monitorBusy = true; renderMonitorPill(); }
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...extra, password }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    if (res.status === 403 && data.tamper_blocked) {
      // Wrong password -- nothing happened; keep the modal open.
      if (data.locked) {
        startStopLockout(data.retry_after);
        if (data.evidence_captured) refreshShield();
        return;   // finally must NOT re-enable the button mid-lockout
      }
      const captured = data.evidence_captured
        ? ` Evidence captured (incident #${data.incident_id}).` : "";
      $("stoppw-note").textContent = `Incorrect password — attempt ${data.attempts}.${captured}`;
      $("stoppw-input").value = "";      // don't make them clear the wrong one by hand
      $("stoppw-input").focus();
      if (data.evidence_captured) { refreshShield(); toast("Tamper evidence captured", true); }
      return;
    }
    if (data.error) {
      $("stoppw-note").textContent = data.error;
      return;
    }
    if (mode === "delete") {
      closeStopModal();
      closeIncidentDrawer();
      toast(`Deleted ${data.deleted} incident${data.deleted === 1 ? "" : "s"}`);
      if (data.file_errors) toast("Some evidence files could not be removed — see logs", true);
      loadIncidents();   // re-renders the list and refreshes the shield
      return;
    }
    if (mode === "unlock") {
      closeStopModal();
      toast("Settings unlocked");
      const next = afterUnlock;
      afterUnlock = null;
      if (next) next();
      return;
    }
    state.monitor = data;
    closeStopModal();
    toast("Monitoring stopped");
  } catch {
    $("stoppw-note").textContent = "Request failed — is the dashboard server still running?";
  } finally {
    if (!stopLockoutTimer) btn.disabled = false;   // stay disabled while locked out
    if (mode === "stop") {
      state.monitorBusy = false;
      renderMonitorPill();
      refreshStatsOnly();
    }
  }
}

async function refreshStatsOnly() {
  try { renderStats(await api("/api/stats")); } catch { /* poll() will retry */ }
}

/* ---------- PDF report modal ---------- */

function openReportModal() {
  $("report-overlay").hidden = false;
  $("report-modal").hidden = false;
  $("report-note").textContent = "";
}
function closeReportModal() {
  $("report-overlay").hidden = true;
  $("report-modal").hidden = true;
}

function selectReportRange(range) {
  document.querySelectorAll("#report-range-chips .chip").forEach((c) =>
    c.classList.toggle("active", c.dataset.range === range));
  $("report-custom-range").hidden = range !== "custom";
}

function reportRangeBounds() {
  const active = document.querySelector("#report-range-chips .chip.active")?.dataset.range || "today";
  const now = Date.now() / 1000;
  if (active === "today") {
    const start = new Date(); start.setHours(0, 0, 0, 0);
    return { since: start.getTime() / 1000, until: now, label: "Today" };
  }
  if (active === "7d") return { since: now - 7 * 86400, until: now, label: "Last 7 Days" };
  if (active === "30d") return { since: now - 30 * 86400, until: now, label: "Last 30 Days" };

  // custom
  const startVal = $("report-start").value;
  const endVal = $("report-end").value;
  if (!startVal || !endVal) return null;
  const since = new Date(startVal + "T00:00:00").getTime() / 1000;
  const until = new Date(endVal + "T23:59:59").getTime() / 1000;
  if (since > until) return null;
  return { since, until, label: `${startVal} - ${endVal}` };
}

/* Every file the dashboard hands the user goes through here. Never navigate the
   window to a download URL: in the desktop app that REPLACES the dashboard with
   the file (WKWebView renders PDF/CSV/JSON inline and pywebview blocks going
   back), leaving quitting as the only way out. A blob + download attribute keeps
   the page where it is. */
async function saveResponseAsFile(res, filename) {
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* Shared by the report modal and the drawer's "this window" button. Throws
   on failure so each caller can surface the error in its own UI. */
async function downloadReportPdf(since, until, label) {
  const qs = new URLSearchParams({ since, until, label });
  const res = await fetch(`/api/report/pdf?${qs.toString()}`);
  if (res.status === 401) { location.replace("/login"); throw new Error("unauthenticated"); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `report failed (${res.status})`);
  }
  await saveResponseAsFile(res, `aegis-report-${new Date().toISOString().slice(0, 10)}.pdf`);
}

async function generateReport() {
  const bounds = reportRangeBounds();
  if (!bounds) {
    $("report-note").textContent = "Pick a valid start and end date.";
    return;
  }
  const btn = $("report-generate");
  btn.disabled = true;
  btn.textContent = "Generating…";
  $("report-note").textContent = "Asking the AI to summarize this period — this can take a few seconds.";
  try {
    await downloadReportPdf(bounds.since, bounds.until, bounds.label);
    closeReportModal();
    toast("Report downloaded");
  } catch (err) {
    $("report-note").textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate Report";
  }
}

/* ---------- monitor log modal ---------- */

async function openLogModal() {
  $("log-overlay").hidden = false;
  $("log-modal").hidden = false;
  $("log-pre").textContent = "Loading…";
  await refreshLogModal();
}

async function refreshLogModal() {
  try {
    const data = await api("/api/monitor/log?lines=400");
    $("log-pre").textContent = data.log || "(log is empty — nothing has been written yet)";
    $("log-pre").scrollTop = $("log-pre").scrollHeight;
  } catch {
    $("log-pre").textContent = "Could not load the log.";
  }
}

function closeLogModal() {
  $("log-overlay").hidden = true;
  $("log-modal").hidden = true;
}

function showPill() {
  $("new-events-count").textContent = state.unseenCount;
  $("new-events-pill").hidden = false;
}
function hidePill() {
  state.unseenCount = 0;
  $("new-events-pill").hidden = true;
}

/* ---------- drawer ---------- */

/* details.threat_intel is Aegis's own normalized shape (core/enrichment.py),
   never raw VT JSON: { mitre?: [{id,name}], vt?: { status, detections,
   suspicious, engines_total, link, family?, first_seen_utc? } }.

   Rendered as a labelled forensic block — Verdict / Detection Ratio / MITRE /
   Family / Confidence — not prose. Verdict framing follows the enrichment
   philosophy: unknown / zero detections are stated as "not proof of safety",
   never a green all-clear, and Confidence for those rows says exactly that
   instead of implying a clean result. VT returns no confidence field of its
   own, so it's derived here from how many engines actually agree. */
function tiVerdict(vt) {
  if (!vt) return { label: "Technique annotation", cls: "", confidence: "Annotation only",
    note: "Matched offline — no file hash was looked up for this event." };
  if (vt.status === "unknown_hash") return { label: "Unknown", cls: "", confidence: "No data yet",
    note: "No engine has scanned this file's hash yet. Unknown is not safe — brand-new files start here." };
  const det = vt.detections || 0, sus = vt.suspicious || 0;
  if (det > 0) return { label: "Malicious", cls: "bad",
    confidence: det >= 10 ? "High" : det >= 4 ? "Medium" : "Low", note: "" };
  if (sus > 0) return { label: "Suspicious", cls: "warn",
    confidence: sus >= 3 ? "Medium" : "Low", note: "" };
  return { label: "Undetected", cls: "", confidence: "Not a safety signal",
    note: "Zero detections is not proof of safety — only that no engine flags this hash yet." };
}

function threatIntelHtml(details) {
  const ti = details.threat_intel;
  if (!ti || (!ti.vt && !(ti.mitre || []).length)) return "";
  const vt = ti.vt;
  const v = tiVerdict(vt);

  const rows = [];  // [label, value-html] pairs, in the order the user sketched
  if (vt && vt.status !== "unknown_hash") {
    let ratio = `<span class="mono">${vt.detections || 0} / ${vt.engines_total || 0}</span>`;
    if ((vt.suspicious || 0) > 0) ratio += ` <span class="ti-note">+${vt.suspicious} suspicious</span>`;
    rows.push(["Detection Ratio", ratio]);
  } else if (vt) {
    rows.push(["Detection Ratio", `<span class="ti-note">not yet scanned</span>`]);
  }
  const mitre = (ti.mitre || []).map((t) =>
    `<span class="meta-badge" title="MITRE ATT&amp;CK — ${escapeHtml(t.name)}">${escapeHtml(t.id)} · ${escapeHtml(t.name)}</span>`);
  rows.push(["MITRE", mitre.length ? mitre.join("") : `<span class="ti-note">none mapped</span>`]);
  if (vt) rows.push(["Family", vt.family ? `<b>${escapeHtml(vt.family)}</b>` : `<span class="ti-note">not classified</span>`]);
  rows.push(["Confidence", escapeHtml(v.confidence)]);
  if (vt && vt.first_seen_utc) rows.push(["First seen", `<span class="mono">${escapeHtml(vt.first_seen_utc)}</span>`]);

  const link = vt && typeof vt.link === "string" && vt.link.startsWith("https://www.virustotal.com/")
    ? `<a class="ti-link" href="${escapeHtml(vt.link)}" target="_blank" rel="noopener">View on VirusTotal ↗</a>` : "";
  const grid = rows.map(([k, val]) => `<div class="ti-k">${k}</div><div class="ti-v">${val}</div>`).join("");
  return `
    <div class="drawer-section-label">Threat Intelligence</div>
    <div class="ti-panel ${v.cls}">
      <div class="ti-head"><span class="ti-dot"></span>${escapeHtml(v.label)}${link}</div>
      <div class="ti-grid">${grid}</div>
      ${v.note ? `<div class="ti-sub">${v.note}</div>` : ""}
    </div>`;
}

/* An event is stored the moment it happens and explained a few seconds later,
   so "not explained yet" is a normal, temporary state -- distinct from
   ai_skipped (deliberately never explained) and from a stored failure. */
function explanationHtml(ev) {
  if (ev.explanation) return `<div class="explanation">${renderMarkdownLite(ev.explanation)}</div>`;
  if (ev.ai_skipped) {
    return '<div class="ai-skipped-note">AI explanation was skipped for this event ' +
           '(trusted/ignored by config, or the explainer was unavailable).</div>';
  }
  return '<div class="ai-skipped-note">Explaining this event… the timeline never waits ' +
         'on the AI, so this arrives a few seconds after the event itself.</div>';
}

function openDrawer(id) {
  const ev = state.byId.get(id);
  if (!ev) return;
  state.selectedId = id;
  document.querySelectorAll(".event-row.selected").forEach((r) => r.classList.remove("selected"));
  document.querySelector(`.event-row[data-id="${id}"]`)?.classList.add("selected");

  const details = eventDetails(ev);
  const detailRows = Object.entries(details)
    .filter(([k]) => k !== "_schema" && k !== "threat_intel")  // threat_intel has its own panel
    .map(([k, v]) => `<tr><td class="k">${escapeHtml(k)}</td>
                      <td class="v">${escapeHtml(typeof v === "object" ? JSON.stringify(v) : String(v))}</td></tr>`)
    .join("");

  const trust = trustTargetFor(ev, details);
  const trustBtn = trust
    ? `<button class="btn" id="drawer-trust-btn" data-kind="${trust.kind}"
               data-value="${escapeHtml(trust.value)}" data-label="${escapeHtml(trust.label)}"
               title="Skip the AI call for ${escapeHtml(trust.label)} from now on">
         Always Trust · ${escapeHtml(trust.label)}</button>`
    : "";

  const conf = ev.confidence || "certain";
  const ti = threatIntelHtml(details);
  // The row only badges definite trust states; here in the drawer the unknown
  // state is stated outright — "unknown" is the honest answer for most
  // third-party software, and saying it beats letting the user infer safety
  // from silence.
  const tstate = trustFor(ev);
  const trustLine = !tstate && ev.source === "process"
    ? '<div class="ai-skipped-note">Trust: unknown — not a verified Apple system binary and not on your Trust List. That is normal for third-party apps.</div>'
    : "";
  $("drawer-body").innerHTML = `
    <div class="drawer-badges">
      ${sourceIcon(ev.source)}
      <span class="badge badge-${ev.severity}">${ev.severity}</span>
      ${trustBadgeHtml(ev)}
      <span class="meta-badge">${SOURCE_LABELS[ev.source] || escapeHtml(ev.source)}</span>
      <span class="meta-badge">${escapeHtml(prettyCategory(ev.category))}</span>
      <span class="meta-badge conf conf-${conf}" title="${CONFIDENCE_TITLES[conf] || conf}">
        <span class="conf-dot"></span>&nbsp;${conf}</span>
      <span class="meta-badge">#${ev.id}</span>
    </div>
    <div class="drawer-summary">${escapeHtml(ev.summary)}</div>
    <div class="drawer-time">${fmtFullTime(ev.timestamp)}</div>

    <div class="drawer-tabs" role="tablist">
      <button class="drawer-tab active" data-tab="summary" role="tab">Summary</button>
      <button class="drawer-tab" data-tab="ai" role="tab">AI Explanation</button>
      <button class="drawer-tab" data-tab="details" role="tab">Details</button>
      <button class="drawer-tab" data-tab="related" role="tab">Related</button>
    </div>

    <div class="tab-panel active" data-panel="summary">
      ${ti || '<div class="ai-skipped-note">No threat-intelligence lookup for this event.</div>'}
      ${trustLine}
    </div>

    <div class="tab-panel" data-panel="ai" hidden>
      <div class="drawer-section-label">${ev.ai_skipped ? "Explanation" : "AI Explanation"}</div>
      <div id="drawer-ai-body">${explanationHtml(ev)}</div>
      ${ev.risk_hint ? `
        <div class="drawer-section-label">Risk Hint</div>
        <div class="risk-hint">${renderMarkdownLite(ev.risk_hint)}</div>` : ""}
    </div>

    <div class="tab-panel" data-panel="details" hidden>
      <div class="drawer-section-label">Details</div>
      ${detailRows ? `<table class="details-table">${detailRows}</table>`
                   : '<div class="ai-skipped-note">No structured details.</div>'}
      <details class="raw-json">
        <summary>raw event JSON</summary>
        <pre>${escapeHtml(JSON.stringify({ ...ev, details_json: details }, null, 2))}</pre>
      </details>
    </div>

    <div class="tab-panel" data-panel="related" hidden>
      <div class="drawer-section-label">Related Events · ±5 min</div>
      <div class="related-list" id="related-list">
        <div class="ai-skipped-note">Loading…</div>
      </div>
    </div>`;

  // Persistent action footer sits below the tabs, always visible.
  $("drawer-foot").innerHTML = `
    <button class="btn" id="drawer-report-btn"
            title="AI-summarized PDF report of everything in the ±5 minute window around this event">
      PDF Report · this window</button>
    ${trustBtn}`;

  $("drawer").hidden = false;
  $("drawer-overlay").hidden = false;
  loadRelated(id);
}

/* Tab switching for the event drawer — toggles which .tab-panel is shown.
   Delegated once on the drawer body; panels are rebuilt on each openDrawer. */
function switchDrawerTab(tab) {
  document.querySelectorAll("#drawer-body .drawer-tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.tab === tab));
  document.querySelectorAll("#drawer-body .tab-panel").forEach((p) =>
    p.hidden = p.dataset.panel !== tab);
}

/* Time-proximity context for the investigation flow: what else happened
   around this event. Rows are clickable and re-open the drawer on that
   event, so a story (USB inserted -> shell -> archiver -> upload) can be
   walked without leaving the drawer. */
async function loadRelated(id) {
  try {
    const data = await api(`/api/events/related?id=${id}`);
    if (state.selectedId !== id) return;   // user already moved to another event
    const box = $("related-list");
    if (!box) return;
    if (!data.events.length) {
      box.innerHTML = '<div class="ai-skipped-note">Nothing else happened within 5 minutes of this event.</div>';
      return;
    }
    // Register in byId so clicking a related row can open it, but never via
    // ingest(): related rows may skip past ids the current filters exclude,
    // and bumping state.maxId there would make the live poll miss events.
    for (const ev of data.events) if (!state.byId.has(ev.id)) state.byId.set(ev.id, ev);
    box.innerHTML = data.events.map((ev) => `
      <button class="related-row" data-id="${ev.id}"
              style="--sev-color: var(--sev-${ev.severity})">
        <span class="related-delta">${fmtDelta(ev.timestamp - data.anchor_timestamp)}</span>
        <span class="badge badge-${ev.severity}">${ev.severity}</span>
        <span class="related-summary">${escapeHtml(ev.summary)}</span>
      </button>`).join("");
  } catch {
    const box = $("related-list");
    if (box && state.selectedId === id) {
      box.innerHTML = '<div class="ai-skipped-note">Could not load related events.</div>';
    }
  }
}

function fmtDelta(seconds) {
  const s = Math.round(Math.abs(seconds));
  const dir = seconds < 0 ? "before" : "after";
  if (s === 0) return "same time";
  if (s < 60) return `${s}s ${dir}`;
  return `${Math.floor(s / 60)}m ${s % 60}s ${dir}`;
}

async function reportEventWindow() {
  const ev = state.byId.get(state.selectedId);
  const btn = $("drawer-report-btn");
  if (!ev || !btn) return;
  btn.disabled = true;
  btn.textContent = "Generating…";
  try {
    await downloadReportPdf(ev.timestamp - 300, ev.timestamp + 300,
                            `±5 min around: ${ev.summary}`.slice(0, 120));
    toast("Report downloaded");
  } catch (err) {
    toast(String(err.message || err), true);
  } finally {
    btn.disabled = false;
    btn.textContent = "PDF Report · this window";
  }
}

function closeDrawer() {
  state.selectedId = null;
  $("drawer").hidden = true;
  $("drawer-overlay").hidden = true;
  document.querySelectorAll(".event-row.selected").forEach((r) => r.classList.remove("selected"));
}

/* ---------- filters UI ---------- */

function updateClearButton() {
  const f = state.filters;
  $("clear-filters").hidden =
    !f.q && !f.severity.size && !f.source.size && !f.category && !f.rangeSeconds;
}

function bindFilters() {
  let debounce = null;
  $("search").addEventListener("input", (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.filters.q = e.target.value.trim();
      updateClearButton();
      reload();
    }, 250);
  });

  for (const groupId of ["severity-chips", "source-chips"]) {
    const group = $(groupId);
    const key = group.dataset.filter;
    group.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (!chip) return;
      const set = state.filters[key];
      chip.classList.toggle("active");
      set.has(chip.dataset.value) ? set.delete(chip.dataset.value) : set.add(chip.dataset.value);
      updateClearButton();
      reload();
    });
  }

  $("category-select").addEventListener("change", (e) => {
    state.filters.category = e.target.value;
    updateClearButton();
    reload();
  });

  $("range-select").addEventListener("change", (e) => {
    state.filters.rangeSeconds = Number(e.target.value) || 0;
    updateClearButton();
    reload();
  });

  $("hide-trusted-toggle").addEventListener("click", (e) => {
    state.filters.hideTrusted = !state.filters.hideTrusted;
    localStorage.setItem(HIDE_TRUSTED_KEY, state.filters.hideTrusted ? "1" : "0");
    e.target.classList.toggle("active", state.filters.hideTrusted);
    reload();
  });

  $("clear-filters").addEventListener("click", () => {
    // hideTrusted is a persistent view preference, not a transient filter --
    // "Clear" resets search/severity/source/category/range, same as theme
    // isn't reset here either.
    state.filters = {
      q: "", severity: new Set(), source: new Set(), category: "", rangeSeconds: 0,
      hideTrusted: state.filters.hideTrusted,
    };
    $("search").value = "";
    $("category-select").value = "";
    $("range-select").value = "";
    document.querySelectorAll("#severity-chips .chip.active, #source-chips .chip.active")
      .forEach((c) => c.classList.remove("active"));
    updateClearButton();
    reload();
  });
}

/* ---------- settings view ---------- */

let settingsLoaded = false;

/* Settings is password-gated (see openUnlockModal): the view only opens once
   the server actually hands over the settings, so a locked tab can't be
   walked into by editing the DOM. The server's own 403 is the gate — this
   just reacts to it. */
async function switchView(view) {
  if (view === "settings" && !settingsLoaded) {
    // Only a genuine "locked" answer opens the password prompt — a server
    // that's simply unreachable must not look like a security challenge.
    const result = await loadSettings();
    if (result !== true) {
      if (result === "locked") openUnlockModal(() => switchView("settings"));
      return;
    }
  }
  $("view-console").hidden = view !== "console";
  $("view-incidents").hidden = view !== "incidents";
  $("view-settings").hidden = view !== "settings";
  document.querySelectorAll(".side-item[data-view]").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === view));
  if (view === "incidents") loadIncidents();
}

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("toast-error", isError);
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3500);
}

function detectProvider(ai) {
  if (ai.provider === "anthropic") return "anthropic";
  const match = PROVIDERS.find((p) => p.base_url && p.base_url === ai.base_url);
  return match ? match.id : "custom";
}

function selectProvider(id, { applyPreset } = { applyPreset: true }) {
  document.querySelectorAll(".provider-card").forEach((c) =>
    c.classList.toggle("active", c.dataset.provider === id));
  const preset = PROVIDERS.find((p) => p.id === id);
  $("set-base-url").disabled = id === "anthropic";   // anthropic ignores base_url
  $("model-list").innerHTML = preset.models.map((m) => `<option value="${m}">`).join("");
  if (applyPreset) {
    if (id === "anthropic") $("set-base-url").value = "";
    else if (preset.base_url) $("set-base-url").value = preset.base_url;
    $("set-key-env").value = preset.api_key_env;
    if (preset.models.length) $("set-model").value = preset.models[0];
    $("key-status").textContent = "";   // env var changed: existing key status unknown
  }
}

/* true = loaded, "locked" = server wants the password, false = something else
   went wrong (the caller must not turn that into a password prompt). */
async function loadSettings() {
  try {
    const res = await fetch("/api/settings");
    if (res.status === 401) { location.replace("/login"); return false; }
    if (res.status === 403) return "locked";
    if (!res.ok) throw new Error(`settings -> ${res.status}`);
    const s = await res.json();
    settingsLoaded = true;

    // The click handler lives in bindSettings(), bound once — this function
    // can run more than once (it re-runs after "Always Trust" invalidates the
    // cache), and binding here stacked a duplicate listener each time.
    $("provider-grid").innerHTML = PROVIDERS.map((p) =>
      `<button class="provider-card" data-provider="${p.id}">${p.label}</button>`).join("");

    selectProvider(detectProvider(s.ai), { applyPreset: false });
    $("set-base-url").value = s.ai.base_url;
    $("set-model").value = s.ai.model;
    $("set-key-env").value = s.ai.api_key_env;
    $("set-temp").value = s.ai.temperature;
    $("temp-val").textContent = Number(s.ai.temperature).toFixed(2);
    $("key-status").textContent = s.ai.api_key_set ? `configured ${s.ai.api_key_hint}` : "not set";

    document.querySelectorAll("#severity-floor .chip").forEach((c) =>
      c.classList.toggle("active", c.dataset.value === s.notify_min_severity));
    $("set-notify-enabled").checked = s.notify_enabled;
    $("set-startup-scan").checked = s.notify_on_startup_scan;
    applyNotifyEnabledState(s.notify_enabled);
    $("set-folders").value = s.watched_folders.join("\n");
    $("set-poll").value = s.poll_interval_seconds;
    $("set-trusted-names").value = s.trusted_process_names.join("\n");
    $("set-trusted-hashes").value = s.trusted_process_hashes.join("\n");
    $("set-trusted-usb").value = s.trusted_usb_ids.join("\n");

    $("set-enrich-enabled").checked = s.enrich_enabled;
    $("vt-key-status").textContent = s.vt_api_key_set ? "configured" : "not set";
    $("set-tamper-require").checked = s.tamper_require_password;
    $("set-tamper-screenshot").checked = s.tamper_evidence_screenshot;
    $("set-tamper-webcam").checked = s.tamper_evidence_webcam;
    $("set-tamper-attempts").value = s.tamper_attempts_before_capture;
    $("set-evidence-dir").value = s.evidence_dir || "";
    $("set-evidence-dir").placeholder = s.evidence_dir_default || "";

    startSettingsCountdown(s.unlock_expires_in);
    checkForUpdate();
    return true;
  } catch {
    toast("Could not load settings", true);
    return false;
  }
}

/* The unlock expires on the server after SETTINGS_UNLOCK_TTL, but until now
   nothing said so and nothing closed the tab — walk away mid-edit and the page
   sat there looking open. Mirror the server clock here (it hands back the real
   remaining seconds) and drop out of the view when it runs out, plus a manual
   "Lock now" for stepping away deliberately. */
let settingsLockTimer = null;

function startSettingsCountdown(seconds) {
  clearInterval(settingsLockTimer);
  settingsLockTimer = null;
  const el = $("settings-lock-timer");
  // null/0 = the user turned tamper_require_password off: nothing to count down
  // to, and nothing for "Lock now" to lock.
  $("settings-lock").hidden = !(seconds > 0);
  if (!(seconds > 0)) { el.textContent = ""; return; }
  let remaining = Math.floor(seconds);
  const tick = () => {
    if (remaining <= 0) { lockSettings("Settings re-locked — unlock expired"); return; }
    el.textContent = `Auto-locks in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`;
    remaining -= 1;
  };
  tick();
  settingsLockTimer = setInterval(tick, 1000);
}

async function lockSettings(message = "Settings locked") {
  clearInterval(settingsLockTimer);
  settingsLockTimer = null;
  $("settings-lock-timer").textContent = "";
  settingsLoaded = false;      // next visit has to pass the password gate again
  switchView("console");
  toast(message);
  // Best effort: the server's own TTL still closes it if this never lands.
  try { await fetch("/api/settings/lock", { method: "POST" }); } catch { /* ignore */ }
}

/* ---------- self-update ---------- */

let latestUpdateInfo = null;  // {download_url, asset_name, version} from the last successful check

async function checkForUpdate() {
  const card = $("update-card");
  const btn = $("update-check-btn");
  try {
    const data = await api("/api/update/check");
    if (data.reason) { card.hidden = true; return; }  // not a packaged desktop install -- nothing to show
    card.hidden = false;
    latestUpdateInfo = null;
    $("update-notes-field").hidden = true;
    $("update-install-btn").hidden = true;

    if (data.check_failed) {
      // Distinct from "no update" -- the check itself didn't complete, so
      // this must never be shown as a verified "you're up to date."
      $("update-desc").textContent = "Could not check for updates — no network, or GitHub is unreachable.";
    } else if (data.update_available) {
      latestUpdateInfo = data;
      $("update-desc").textContent = `Version ${data.version} is available (you're on ${data.current_version}).`;
      $("update-notes-field").hidden = !data.notes;
      $("update-notes").innerHTML = data.notes ? renderMarkdownLite(data.notes) : "";
      $("update-install-btn").hidden = false;
    } else {
      $("update-desc").textContent = `You're on the latest version (${data.current_version}).`;
    }
  } catch {
    card.hidden = false;
    $("update-desc").textContent = "Could not check for updates — no network, or GitHub is unreachable.";
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function installUpdate() {
  if (!latestUpdateInfo) return;
  const btn = $("update-install-btn");
  btn.disabled = true;
  $("update-status").textContent = "Downloading update…";
  try {
    const res = await fetch("/api/update/install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        download_url: latestUpdateInfo.download_url,
        asset_name: latestUpdateInfo.asset_name,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 403 && data.settings_locked) {
      $("update-status").textContent = "";
      btn.disabled = false;
      openUnlockModal(installUpdate);
      return;
    }
    if (!res.ok) {
      $("update-status").textContent = data.error || "Update failed.";
      btn.disabled = false;
      return;
    }
    $("update-status").textContent = "Installing — Aegis will restart in a moment…";
  } catch {
    // The app process exits itself right after responding (see
    // desktop_app.py's _quit_for_update) -- a dropped connection here is
    // the EXPECTED outcome of a successful install, not a failure.
    $("update-status").textContent = "Installing — Aegis will restart in a moment…";
  }
}

/* ---------- change password ---------- */

async function changePassword() {
  const current = $("pw-current").value;
  const next = $("pw-new").value;
  const confirm = $("pw-confirm").value;
  const status = $("password-status");
  const btn = $("password-save");

  if (!current || !next) { status.textContent = "Fill in both password fields."; return; }
  if (next !== confirm) { status.textContent = "New passwords don't match."; return; }
  if (next.length < 8) { status.textContent = "New password must be at least 8 characters."; return; }

  btn.disabled = true;
  status.textContent = "Saving…";
  try {
    const res = await fetch("/api/settings/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: current, new_password: next }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    if (!res.ok) { status.textContent = data.error || "Could not change password."; return; }
    $("pw-current").value = "";
    $("pw-new").value = "";
    $("pw-confirm").value = "";
    status.textContent = "Password changed.";
    toast("Password changed");
  } catch {
    status.textContent = "Save failed — server unreachable.";
  } finally {
    btn.disabled = false;
  }
}

function applyNotifyEnabledState(enabled) {
  $("notify-subfields").classList.toggle("disabled", !enabled);
  $("set-startup-scan").closest(".switch-row").classList.toggle("disabled", !enabled);
}

const splitLines = (id) => $(id).value.split("\n").map((l) => l.trim()).filter(Boolean);

async function saveSettings() {
  const activeProvider = document.querySelector(".provider-card.active")?.dataset.provider;
  const preset = PROVIDERS.find((p) => p.id === activeProvider) || PROVIDERS[0];
  const floor = document.querySelector("#severity-floor .chip.active")?.dataset.value || "low";
  const btn = $("settings-save");
  btn.disabled = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ai: {
          provider: preset.provider,
          base_url: $("set-base-url").value.trim(),
          api_key_env: $("set-key-env").value.trim(),
          model: $("set-model").value.trim(),
          temperature: Number($("set-temp").value),
          api_key: $("set-api-key").value,   // blank = keep existing
        },
        notify_enabled: $("set-notify-enabled").checked,
        notify_min_severity: floor,
        notify_on_startup_scan: $("set-startup-scan").checked,
        watched_folders: splitLines("set-folders"),
        poll_interval_seconds: Number($("set-poll").value) || 3,
        trusted_process_names: splitLines("set-trusted-names"),
        trusted_process_hashes: splitLines("set-trusted-hashes"),
        trusted_usb_ids: splitLines("set-trusted-usb"),
        enrich_enabled: $("set-enrich-enabled").checked,
        vt_api_key: $("set-vt-key").value,   // blank = keep existing
        tamper_require_password: $("set-tamper-require").checked,
        tamper_evidence_screenshot: $("set-tamper-screenshot").checked,
        tamper_evidence_webcam: $("set-tamper-webcam").checked,
        tamper_attempts_before_capture: Number($("set-tamper-attempts").value) || 3,
        evidence_dir: $("set-evidence-dir").value.trim(),
      }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    // The unlock expires on its own (SETTINGS_UNLOCK_TTL) — re-prompt and
    // then finish the save the user already asked for, rather than losing it.
    if (res.status === 403 && data.settings_locked) {
      openUnlockModal(saveSettings);
      return;
    }
    if (!res.ok) { toast(data.error || `Save failed (${res.status})`, true); return; }
    $("set-api-key").value = "";
    $("set-vt-key").value = "";
    if (data.settings) $("vt-key-status").textContent = data.settings.vt_api_key_set ? "configured" : "not set";
    $("key-status").textContent = data.settings.ai.api_key_set
      ? `configured ${data.settings.ai.api_key_hint}` : "not set";
    toast("Settings saved — restart Aegis monitors to apply");
  } catch {
    toast("Save failed — server unreachable", true);
  } finally {
    btn.disabled = false;
  }
}

function bindSettings() {
  // Sidebar: data-view items switch the main view; data-action items fire
  // their existing modal/handler (Daily Brief, Reports, Monitor Log).
  const SIDE_ACTIONS = { daily: openDailyBrief, report: openReportModal, log: openLogModal };
  document.querySelectorAll(".side-item").forEach((t) =>
    t.addEventListener("click", () => {
      if (t.dataset.view) switchView(t.dataset.view);
      else if (t.dataset.action) SIDE_ACTIONS[t.dataset.action]?.();
    }));

  $("set-notify-enabled").addEventListener("change", (e) => {
    applyNotifyEnabledState(e.target.checked);
  });

  $("severity-floor").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    document.querySelectorAll("#severity-floor .chip").forEach((c) =>
      c.classList.toggle("active", c === chip));
  });

  $("set-temp").addEventListener("input", (e) => {
    $("temp-val").textContent = Number(e.target.value).toFixed(2);
  });

  $("settings-lock").addEventListener("click", () => lockSettings());
  $("settings-save").addEventListener("click", saveSettings);
  $("settings-restart").addEventListener("click", restartMonitoring);
  // Bound once, on the container: loadSettings() rebuilds the cards inside it
  // and can run more than once per page load.
  $("provider-grid").addEventListener("click", (e) => {
    const card = e.target.closest(".provider-card");
    if (card) selectProvider(card.dataset.provider);
  });

  $("vt-test-btn").addEventListener("click", async () => {
    const btn = $("vt-test-btn"), out = $("vt-test-result");
    btn.disabled = true;
    out.className = "vt-test-result";
    out.textContent = "Looking up the EICAR test file on VirusTotal…";
    try {
      const res = await fetch("/api/enrich/test", { method: "POST" });
      if (res.status === 401) { location.replace("/login"); return; }
      const data = await res.json().catch(() => ({}));
      if (res.status === 403 && data.settings_locked) {
        out.textContent = "";
        openUnlockModal(() => $("vt-test-btn").click());
        return;
      }
      if (data.ok) {
        out.classList.add("ok");
        out.textContent = `✓ Working — test file flagged by ${data.detections}/${data.engines_total} engines`;
      } else {
        out.classList.add("err");
        out.textContent = data.error || "Test failed.";
      }
    } catch {
      out.classList.add("err");
      out.textContent = "Could not reach Aegis.";
    } finally {
      btn.disabled = false;
    }
  });
  $("password-save").addEventListener("click", changePassword);

  $("update-check-btn").addEventListener("click", (e) => {
    e.target.disabled = true;
    $("update-status").textContent = "";
    checkForUpdate();
  });
  $("update-install-btn").addEventListener("click", installUpdate);
}

/* ---------- incidents + shield ---------- */

function renderShield(unreviewed) {
  const shield = $("shield");
  const label = $("shield-label");
  const badge = $("incidents-badge");
  if (unreviewed > 0) {
    shield.classList.add("alert");
    label.textContent = `${unreviewed} INCIDENT${unreviewed === 1 ? "" : "S"}`;
    shield.title = `${unreviewed} unreviewed tamper incident(s) — click Incidents`;
    badge.hidden = false;
    badge.textContent = unreviewed;
  } else {
    shield.classList.remove("alert");
    label.textContent = "PROTECTED";
    shield.title = "No unreviewed tamper incidents";
    badge.hidden = true;
  }
}

async function refreshShield() {
  try {
    const data = await api("/api/incidents");
    renderShield(data.unreviewed);
  } catch { /* leave the shield as-is on a transient failure */ }
}

function incidentRowHtml(inc) {
  const when = fmtFullTime(inc.timestamp);
  let artifacts = {};
  try { artifacts = JSON.parse(inc.artifacts_json) || {}; } catch { /* ignore */ }
  const tags = Object.keys(artifacts).map((k) => `<span class="meta-badge">${escapeHtml(k)}</span>`).join("");
  return `
  <div class="incident-row">
    <input type="checkbox" class="incident-check" data-id="${inc.id}" aria-label="Select incident #${inc.id}">
    <button class="incident-card ${inc.reviewed ? "" : "unreviewed"}" data-id="${inc.id}">
      <div class="incident-card-head">
        <span class="badge badge-critical">tamper</span>
        <span class="incident-reason">${escapeHtml(inc.reason)}</span>
        ${inc.reviewed ? "" : '<span class="incident-new">NEW</span>'}
      </div>
      <div class="incident-card-meta">
        <span>${escapeHtml(when)}</span>
        <span>${inc.attempts} failed attempt${inc.attempts === 1 ? "" : "s"}</span>
        ${inc.username ? `<span>${escapeHtml(inc.username)}@${escapeHtml(inc.hostname || "?")}</span>` : ""}
        ${tags}
      </div>
    </button>
  </div>`;
}

function checkedIncidentIds() {
  return [...document.querySelectorAll(".incident-check:checked")].map((c) => Number(c.dataset.id));
}

async function loadIncidents() {
  const list = $("incidents-list");
  $("incidents-delete-btn").hidden = true;   // re-render resets the checkboxes
  list.innerHTML = '<div class="ai-skipped-note">Loading…</div>';
  try {
    const data = await api("/api/incidents");
    renderShield(data.unreviewed);
    if (!data.incidents.length) {
      list.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24"><path d="M12 2 L20 5.5 V11 C20 16.5 16.7 20.6 12 22 C7.3 20.6 4 16.5 4 11 V5.5 Z"
            fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>
          <span class="empty-title">No tamper incidents</span>
          <span>Nobody has failed a protected action. If someone does, the evidence lands here.</span>
        </div>`;
      return;
    }
    list.innerHTML = data.incidents.map(incidentRowHtml).join("");
  } catch {
    list.innerHTML = '<div class="ai-skipped-note">Could not load incidents.</div>';
  }
}

async function openIncident(id) {
  try {
    const inc = await api(`/api/incidents/get?id=${id}`);
    if (inc.error) { toast(inc.error, true); return; }
    let artifacts = {}, context = {};
    try { artifacts = JSON.parse(inc.artifacts_json) || {}; } catch { /* ignore */ }
    try { context = JSON.parse(inc.context_json) || {}; } catch { /* ignore */ }

    const artifactRows = Object.entries(artifacts).map(([k, v]) =>
      `<tr><td class="k">${escapeHtml(k)}</td>
       <td class="v">${escapeHtml(v.path || "")}<br><span class="hash">sha256 ${escapeHtml(v.sha256 || "—")}</span></td></tr>`).join("");
    const procList = (context.recent_processes || []).slice(0, 12)
      .map((p) => `${escapeHtml(p.started || "")} ${escapeHtml(p.name || "?")} (${p.pid})`).join("<br>");
    const ctxRows = [
      ["Active window", context.active_window],
      ["Public IP", context.public_ip],
      ["Local IPs", (context.local_ips || []).join(", ")],
      ["Platform", context.platform],
      ["Battery", context.battery ? `${context.battery.percent}%${context.battery.plugged_in ? " (plugged in)" : ""}` : null],
    ].filter(([, v]) => v).map(([k, v]) =>
      `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(String(v))}</td></tr>`).join("");

    $("incident-drawer-body").innerHTML = `
      <div class="drawer-badges">
        <span class="badge badge-critical">tamper</span>
        <span class="meta-badge">${inc.attempts} failed attempts</span>
        <span class="meta-badge">#${inc.id}</span>
        ${inc.reviewed ? '<span class="meta-badge">reviewed</span>' : '<span class="incident-new">NEW</span>'}
      </div>
      <div class="drawer-summary">${escapeHtml(inc.reason)}</div>
      <div class="drawer-time">${fmtFullTime(inc.timestamp)} · ${escapeHtml(inc.username || "?")}@${escapeHtml(inc.hostname || "?")}</div>

      ${inc.ai_summary ? `<div class="drawer-section-label">AI Summary</div>
        <div class="explanation">${renderMarkdownLite(inc.ai_summary)}</div>` : ""}

      <div class="drawer-section-label">Evidence Artifacts</div>
      ${artifactRows ? `<table class="details-table">${artifactRows}</table>`
        : `<div class="ai-skipped-note">${escapeHtml(
             (context.capture_notes && context.capture_notes.screenshot)
             || "No artifacts captured.")}</div>`}

      <div class="drawer-section-label">Context At Capture</div>
      ${ctxRows ? `<table class="details-table">${ctxRows}</table>` : '<div class="ai-skipped-note">No context.</div>'}

      ${procList ? `<div class="drawer-section-label">Processes Running</div>
        <div class="explanation" style="font-family:var(--font-mono);font-size:12px">${procList}</div>` : ""}

      <div class="drawer-actions">
        ${inc.reviewed ? "" : `<button class="btn btn-primary" id="incident-review-btn" data-id="${inc.id}">Mark Reviewed</button>`}
        <button class="btn btn-stop" id="incident-delete-btn" data-id="${inc.id}">Delete Evidence</button>
      </div>`;

    $("incident-drawer").hidden = false;
    $("incident-overlay").hidden = false;
  } catch {
    toast("Could not load incident", true);
  }
}

function closeIncidentDrawer() {
  $("incident-drawer").hidden = true;
  $("incident-overlay").hidden = true;
}

async function reviewIncident(id) {
  try {
    const res = await fetch("/api/incidents/review", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: Number(id) }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    if (res.ok) { toast("Incident marked reviewed"); closeIncidentDrawer(); loadIncidents(); refreshShield(); }
  } catch { toast("Could not update incident", true); }
}

/* ---------- daily brief ---------- */

async function openDailyBrief() {
  $("daily-overlay").hidden = false;
  $("daily-modal").hidden = false;
  $("daily-body").innerHTML = '<div class="ai-skipped-note">Asking the AI to summarize the last 24 hours…</div>';
  try {
    const d = await api("/api/daily");
    const c = d.counts;
    const tiles = [
      ["Events", c.total], ["High / Critical", c.high_critical],
      ["USB connected", c.usb_connected], ["New startup items", c.startup_added],
      ["Away sessions", c.away_sessions], ["Tamper attempts", c.tamper_attempts],
    ];
    const topRows = d.top_events.length
      ? d.top_events.map((e) => `
          <button class="related-row" data-jump="${e.id}" style="--sev-color: var(--sev-${e.severity})">
            <span class="related-delta">${new Date(e.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
            <span class="badge badge-${e.severity}">${e.severity}</span>
            <span class="related-summary">${escapeHtml(e.summary)}</span>
          </button>`).join("")
      : '<div class="ai-skipped-note">No high or critical events in the last 24 hours.</div>';
    $("daily-body").innerHTML = `
      <div class="daily-tiles">
        ${tiles.map(([l, v]) => `<div class="stat-tile"><span class="stat-label">${l}</span>
          <span class="stat-value ${l === "Tamper attempts" && v > 0 ? "alert" : ""}">${v}</span></div>`).join("")}
      </div>
      <div class="drawer-section-label">Overview</div>
      <div class="explanation">${renderMarkdownLite(d.summary)}</div>
      <div class="drawer-section-label">Highlights</div>
      <div class="related-list" id="daily-highlights">${topRows}</div>`;
  } catch {
    $("daily-body").innerHTML = '<div class="ai-skipped-note">Could not load the daily brief.</div>';
  }
}

function closeDailyBrief() {
  $("daily-overlay").hidden = true;
  $("daily-modal").hidden = true;
}

/* ---------- trust learning ---------- */

/* "Always trust" from the event drawer: teaches the rule engine to skip the
   AI call for this signer/device next time (core/rule_engine.py). Only offered
   for events where a stable identifier exists. */
function trustTargetFor(ev, details) {
  if (ev.source === "process") {
    if (details.sha256) return { kind: "process_hashes", value: details.sha256, label: "this exact binary (by hash)" };
    const name = details.image_name || details.name;
    if (name) return { kind: "process_names", value: name, label: `all processes named "${name}"` };
  }
  if (ev.source === "usb") {
    const id = details.device_id || details.serial_num;
    if (id) return { kind: "usb_ids", value: id, label: "this USB device" };
  }
  return null;
}

async function addTrust(kind, value, btn) {
  if (btn) { btn.disabled = true; btn.textContent = "Trusting…"; }
  try {
    const res = await fetch("/api/trust/add", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, value }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    if (res.status === 403 && data.settings_locked) {
      // Trust entries are a config change like any other -- same gate.
      if (btn) { btn.disabled = false; btn.textContent = `Always Trust · ${btn.dataset.label || "this"}`; }
      openUnlockModal(() => addTrust(kind, value, btn));
      return;
    }
    if (!res.ok) { toast(data.error || "Could not add trust", true); if (btn) { btn.disabled = false; } return; }
    toast("Added to Trust List — future matches skip the AI call");
    settingsLoaded = false;   // force settings reload so the new entry shows
    if (btn) { btn.textContent = "Trusted ✓"; }
  } catch {
    toast("Could not add trust — server unreachable", true);
    if (btn) { btn.disabled = false; }
  }
}

/* ---------- wiring ---------- */

function wireMorePopover() {
  const pop = $("more-pop");
  const btn = $("more-btn");
  const close = () => { pop.hidden = true; btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    pop.hidden = !pop.hidden;
    btn.setAttribute("aria-expanded", String(!pop.hidden));
  });
  // any item click closes the menu; each item keeps its own action handler
  pop.addEventListener("click", close);
  document.addEventListener("click", (e) => {
    if (!pop.hidden && !pop.contains(e.target) && !btn.contains(e.target)) close();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
}

function bind() {
  bindSettings();
  bindFilters();
  wireMorePopover();
  $("hide-trusted-toggle").classList.toggle("active", state.filters.hideTrusted);

  $("timeline").addEventListener("click", (e) => {
    const row = e.target.closest(".event-row");
    if (row && row.dataset.id) openDrawer(Number(row.dataset.id));  // group summaries have no id — <details> handles them
  });

  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-overlay").addEventListener("click", closeDrawer);
  // Delegated: the drawer body/foot are re-rendered per event, so tab,
  // related-row and action-button handlers live here on the stable #drawer.
  $("drawer").addEventListener("click", (e) => {
    const tab = e.target.closest(".drawer-tab");
    if (tab) { switchDrawerTab(tab.dataset.tab); return; }
    const row = e.target.closest(".related-row");
    if (row) { openDrawer(Number(row.dataset.id)); return; }
    if (e.target.closest("#drawer-report-btn")) reportEventWindow();
    const trustBtn = e.target.closest("#drawer-trust-btn");
    if (trustBtn) addTrust(trustBtn.dataset.kind, trustBtn.dataset.value, trustBtn);
  });
  $("load-older").addEventListener("click", loadOlder);

  $("open-evidence-btn").addEventListener("click", async () => {
    const res = await fetch("/api/evidence/open-folder", { method: "POST" });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) toast(data.error || "Could not open folder", true);
  });

  $("new-events-pill").addEventListener("click", () => {
    hidePill();
    switchView("console");   // the pill can appear over Settings/Incidents; new events live in Memory
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  window.addEventListener("scroll", () => { if (window.scrollY < 100) hidePill(); }, { passive: true });

  const exportEvents = async (format) => {
    try {
      const res = await fetch(`/api/export?${filterQuery({ format })}`);
      if (res.status === 401) { location.replace("/login"); return; }
      if (!res.ok) throw new Error(`export failed (${res.status})`);
      const stamp = new Date().toISOString().slice(0, 10);
      await saveResponseAsFile(res, `aegis-events-${stamp}.${format}`);
    } catch (err) {
      toast(String(err.message || err), true);
    }
  };
  $("export-json").addEventListener("click", () => exportEvents("json"));
  $("export-csv").addEventListener("click", () => exportEvents("csv"));

  $("logout-btn").addEventListener("click", async () => {
    try { await fetch("/api/logout", { method: "POST" }); } catch { /* redirect regardless */ }
    location.replace("/login");
  });

  $("monitor-toggle").addEventListener("click", toggleMonitor);
  $("monitor-log-btn").addEventListener("click", openLogModal);

  // Hide Window is desktop-app only (there's nothing to hide in a browser tab).
  // pywebview injects window.pywebview.api asynchronously, hence the ready
  // event as well as the immediate check in case it already fired.
  const hideBtn = $("hide-window-btn");
  const showHideBtn = () => { hideBtn.hidden = false; };
  if (window.pywebview && window.pywebview.api) showHideBtn();
  window.addEventListener("pywebviewready", showHideBtn);
  hideBtn.addEventListener("click", () => window.pywebview.api.hide_window());

  // stop-monitoring password modal
  $("stoppw-close").addEventListener("click", closeStopModal);
  $("stoppw-cancel").addEventListener("click", closeStopModal);
  $("stoppw-overlay").addEventListener("click", closeStopModal);
  $("stoppw-confirm").addEventListener("click", confirmPasswordAction);
  $("stoppw-input").addEventListener("keydown", (e) => { if (e.key === "Enter") confirmPasswordAction(); });

  // daily brief (opened from the sidebar; see bindSettings SIDE_ACTIONS)
  $("daily-modal-close").addEventListener("click", closeDailyBrief);
  $("daily-overlay").addEventListener("click", closeDailyBrief);
  $("daily-body").addEventListener("click", (e) => {
    const jump = e.target.closest("[data-jump]");
    if (jump) { closeDailyBrief(); switchView("console"); openDrawer(Number(jump.dataset.jump)); }
  });

  // incidents
  $("shield").addEventListener("click", () => switchView("incidents"));
  $("incidents-list").addEventListener("click", (e) => {
    const card = e.target.closest(".incident-card");
    if (card) openIncident(Number(card.dataset.id));
  });
  $("incidents-list").addEventListener("change", (e) => {
    if (e.target.classList.contains("incident-check"))
      $("incidents-delete-btn").hidden = checkedIncidentIds().length === 0;
  });
  $("incidents-delete-btn").addEventListener("click", () => {
    const ids = checkedIncidentIds();
    if (ids.length) openDeleteModal(ids);
  });
  $("incident-drawer-close").addEventListener("click", closeIncidentDrawer);
  $("incident-overlay").addEventListener("click", closeIncidentDrawer);
  $("incident-drawer-body").addEventListener("click", (e) => {
    const btn = e.target.closest("#incident-review-btn");
    if (btn) reviewIncident(btn.dataset.id);
    const del = e.target.closest("#incident-delete-btn");
    if (del) openDeleteModal([Number(del.dataset.id)]);
  });
  $("log-modal-close").addEventListener("click", closeLogModal);
  $("log-overlay").addEventListener("click", closeLogModal);
  $("log-refresh").addEventListener("click", refreshLogModal);

  $("export-pdf-btn").addEventListener("click", openReportModal);
  $("report-modal-close").addEventListener("click", closeReportModal);
  $("report-overlay").addEventListener("click", closeReportModal);
  $("report-range-chips").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (chip) selectReportRange(chip.dataset.range);
  });
  $("report-generate").addEventListener("click", generateReport);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); closeLogModal(); closeReportModal(); closeDailyBrief(); closeIncidentDrawer(); closeStopModal(); }
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
    if (e.key === "/" && !typing && !$("view-console").hidden) {
      e.preventDefault();
      $("search").focus();
    }
  });
}

async function init() {
  const bootStarted = performance.now();
  bind();
  buildThemePicker();
  try { renderStats(await api("/api/stats")); } catch { setConsoleReachable(false); }
  await refreshMonitorStatus();
  refreshShield();
  await reload();
  state.pollTimer = setInterval(poll, POLL_MS);
  setInterval(refreshAgingSummaries, 2000);

  // hold the boot screen long enough for its animation to land, then fade
  const MIN_BOOT_MS = 1500;
  const wait = Math.max(0, MIN_BOOT_MS - (performance.now() - bootStarted));
  setTimeout(() => {
    const boot = $("boot");
    boot.classList.add("done");
    setTimeout(() => { boot.hidden = true; }, 650);
  }, wait);
}

init();
