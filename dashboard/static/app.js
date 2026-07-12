/* Aegis dashboard frontend.
   Talks only to the read-only JSON API in server.py. Polls for new events;
   all filtering happens server-side so the view and the exports always agree. */

"use strict";

const POLL_MS = 4000;
const PAGE_SIZE = 200;

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SOURCE_LABELS = { process: "Process", usb: "USB", startup: "Startup", folder: "Folder" };
const CONFIDENCE_TITLES = {
  certain: "Real-time detection",
  polled: "Polled detection — may be delayed or incomplete",
  degraded: "Degraded detection backend",
};

/* Theme metadata drives the picker popover; the actual colors live in
   style.css theme blocks keyed by [data-theme]. Swatch colors here are only
   for the preview cards. */
const THEMES = [
  { id: "obsidian",  label: "Obsidian",  mode: "dark",  bg: "#0b0f16", accent: "#46d3bd" },
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

const state = {
  events: [],            // newest first, as returned by the API
  byId: new Map(),
  maxId: 0,
  minId: null,
  filters: { q: "", severity: new Set(), source: new Set(), category: "", rangeSeconds: 0 },
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
  $("stat-24h").textContent = stats.last_24h;
  $("stat-total").textContent = stats.total;
  $("stat-sources").textContent = Object.keys(stats.by_source).length;

  const hicrit = (stats.by_severity.high || 0) + (stats.by_severity.critical || 0);
  const hicritEl = $("stat-hicrit");
  hicritEl.textContent = hicrit;
  hicritEl.classList.toggle("alert", hicrit > 0);

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

/* ---------- timeline ---------- */

function eventRowHtml(ev, fresh) {
  const conf = ev.confidence || "certain";
  const aiSkipped = ev.ai_skipped ? '<span class="ai-skipped-tag">AI skipped</span>' : "";
  return `
    <button class="event-row ${fresh ? "fresh" : ""}" data-id="${ev.id}"
            style="--sev-color: var(--sev-${ev.severity})">
      <span class="event-time">${fmtTime(ev.timestamp)}</span>
      <span class="badge badge-${ev.severity}">${ev.severity}</span>
      <span class="event-main">
        <span class="event-summary">${escapeHtml(ev.summary)}</span>
        <span class="event-sub">
          <span class="src">${SOURCE_LABELS[ev.source] || escapeHtml(ev.source)}</span>
          <span>${escapeHtml(prettyCategory(ev.category))}</span>
          <span class="conf conf-${conf}" title="${CONFIDENCE_TITLES[conf] || conf}">
            <span class="conf-dot"></span>${conf}</span>
          ${aiSkipped}
        </span>
      </span>
      <span class="event-chevron">›</span>
    </button>`;
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
  for (const ev of state.events) {
    const label = dayLabel(ev.timestamp);
    if (label !== currentDay) {
      currentDay = label;
      parts.push(`<div class="day-header">${label}
        <span class="day-count">${counts.get(label)} event${counts.get(label) === 1 ? "" : "s"}</span></div>`);
    }
    parts.push(eventRowHtml(ev, freshIds.has(ev.id)));
  }
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
  } catch {
    setConsoleReachable(false);
  }
  refreshMonitorStatus();
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

function renderMonitorPill() {
  const el = $("live-indicator");
  const label = $("live-label");
  const toggle = $("monitor-toggle");

  el.classList.remove("stale", "idle");
  if (state.consoleReachable === false) {
    el.classList.add("stale");
    label.textContent = "CONSOLE OFFLINE";
  } else if (state.monitorBusy) {
    el.classList.add("idle");
    label.textContent = state.monitor.running ? "STOPPING…" : "STARTING…";
  } else if (state.monitor.running) {
    label.textContent = "MONITORING ACTIVE";
    el.title = `PID ${state.monitor.pid} · up ${formatUptime(state.monitor.uptime_seconds)}`;
  } else {
    el.classList.add("idle");
    label.textContent = "MONITORING STOPPED";
    el.title = "";
  }

  if (!toggle) return;
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

async function toggleMonitor() {
  const startingUp = !state.monitor.running;
  state.monitorBusy = true;
  renderMonitorPill();
  try {
    const res = await fetch(startingUp ? "/api/monitor/start" : "/api/monitor/stop", { method: "POST" });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    state.monitor = data;
    if (startingUp && data.running) {
      toast("Monitoring started");
    } else if (startingUp && !data.running) {
      toast("Monitor process exited immediately — check the log", true);
    } else {
      toast("Monitoring stopped");
    }
  } catch {
    toast("Request failed — is the dashboard server still running?", true);
  } finally {
    state.monitorBusy = false;
    renderMonitorPill();
    refreshStatsOnly();
  }
}

async function refreshStatsOnly() {
  try { renderStats(await api("/api/stats")); } catch { /* poll() will retry */ }
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

function openDrawer(id) {
  const ev = state.byId.get(id);
  if (!ev) return;
  state.selectedId = id;
  document.querySelectorAll(".event-row.selected").forEach((r) => r.classList.remove("selected"));
  document.querySelector(`.event-row[data-id="${id}"]`)?.classList.add("selected");

  let details = {};
  try { details = JSON.parse(ev.details_json) || {}; } catch { /* show raw below regardless */ }
  const detailRows = Object.entries(details)
    .filter(([k]) => k !== "_schema")
    .map(([k, v]) => `<tr><td class="k">${escapeHtml(k)}</td>
                      <td class="v">${escapeHtml(typeof v === "object" ? JSON.stringify(v) : String(v))}</td></tr>`)
    .join("");

  const conf = ev.confidence || "certain";
  $("drawer-body").innerHTML = `
    <div class="drawer-badges">
      <span class="badge badge-${ev.severity}">${ev.severity}</span>
      <span class="meta-badge">${SOURCE_LABELS[ev.source] || escapeHtml(ev.source)}</span>
      <span class="meta-badge">${escapeHtml(prettyCategory(ev.category))}</span>
      <span class="meta-badge conf conf-${conf}" title="${CONFIDENCE_TITLES[conf] || conf}">
        <span class="conf-dot"></span>&nbsp;${conf}</span>
      <span class="meta-badge">#${ev.id}</span>
    </div>
    <div class="drawer-summary">${escapeHtml(ev.summary)}</div>
    <div class="drawer-time">${fmtFullTime(ev.timestamp)}</div>

    <div class="drawer-section-label">AI Explanation</div>
    ${ev.ai_skipped
      ? '<div class="ai-skipped-note">AI explanation was skipped for this event (trusted/ignored by config, or the explainer was unavailable).</div>'
      : ev.explanation
        ? `<div class="explanation">${renderMarkdownLite(ev.explanation)}</div>`
        : '<div class="ai-skipped-note">No explanation stored.</div>'}

    ${ev.risk_hint ? `
      <div class="drawer-section-label">Risk Hint</div>
      <div class="risk-hint">${renderMarkdownLite(ev.risk_hint)}</div>` : ""}

    <div class="drawer-section-label">Details</div>
    ${detailRows ? `<table class="details-table">${detailRows}</table>`
                 : '<div class="ai-skipped-note">No structured details.</div>'}
    <details class="raw-json">
      <summary>raw event JSON</summary>
      <pre>${escapeHtml(JSON.stringify({ ...ev, details_json: details }, null, 2))}</pre>
    </details>`;

  $("drawer").hidden = false;
  $("drawer-overlay").hidden = false;
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

  $("clear-filters").addEventListener("click", () => {
    state.filters = { q: "", severity: new Set(), source: new Set(), category: "", rangeSeconds: 0 };
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

function switchView(view) {
  $("view-console").hidden = view !== "console";
  $("view-settings").hidden = view !== "settings";
  document.querySelectorAll(".view-tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === view));
  if (view === "settings" && !settingsLoaded) loadSettings();
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

async function loadSettings() {
  try {
    const s = await api("/api/settings");
    settingsLoaded = true;

    $("provider-grid").innerHTML = PROVIDERS.map((p) =>
      `<button class="provider-card" data-provider="${p.id}">${p.label}</button>`).join("");
    $("provider-grid").addEventListener("click", (e) => {
      const card = e.target.closest(".provider-card");
      if (card) selectProvider(card.dataset.provider);
    });

    selectProvider(detectProvider(s.ai), { applyPreset: false });
    $("set-base-url").value = s.ai.base_url;
    $("set-model").value = s.ai.model;
    $("set-key-env").value = s.ai.api_key_env;
    $("set-temp").value = s.ai.temperature;
    $("temp-val").textContent = Number(s.ai.temperature).toFixed(2);
    $("key-status").textContent = s.ai.api_key_set ? `configured ${s.ai.api_key_hint}` : "not set";

    document.querySelectorAll("#severity-floor .chip").forEach((c) =>
      c.classList.toggle("active", c.dataset.value === s.notify_min_severity));
    $("set-startup-scan").checked = s.notify_on_startup_scan;
    $("set-folders").value = s.watched_folders.join("\n");
    $("set-poll").value = s.poll_interval_seconds;
    $("set-trusted-names").value = s.trusted_process_names.join("\n");
    $("set-trusted-hashes").value = s.trusted_process_hashes.join("\n");
    $("set-trusted-usb").value = s.trusted_usb_ids.join("\n");
  } catch (err) {
    if (String(err).includes("unauthenticated")) return;
    toast("Could not load settings", true);
  }
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
        notify_min_severity: floor,
        notify_on_startup_scan: $("set-startup-scan").checked,
        watched_folders: splitLines("set-folders"),
        poll_interval_seconds: Number($("set-poll").value) || 3,
        trusted_process_names: splitLines("set-trusted-names"),
        trusted_process_hashes: splitLines("set-trusted-hashes"),
        trusted_usb_ids: splitLines("set-trusted-usb"),
      }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    const data = await res.json();
    if (!res.ok) { toast(data.error || `Save failed (${res.status})`, true); return; }
    $("set-api-key").value = "";
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
  document.querySelectorAll(".view-tab").forEach((t) =>
    t.addEventListener("click", () => switchView(t.dataset.view)));

  $("severity-floor").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    document.querySelectorAll("#severity-floor .chip").forEach((c) =>
      c.classList.toggle("active", c === chip));
  });

  $("set-temp").addEventListener("input", (e) => {
    $("temp-val").textContent = Number(e.target.value).toFixed(2);
  });

  $("settings-save").addEventListener("click", saveSettings);
}

/* ---------- wiring ---------- */

function bind() {
  bindSettings();
  bindFilters();

  $("timeline").addEventListener("click", (e) => {
    const row = e.target.closest(".event-row");
    if (row) openDrawer(Number(row.dataset.id));
  });

  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-overlay").addEventListener("click", closeDrawer);
  $("load-older").addEventListener("click", loadOlder);

  $("new-events-pill").addEventListener("click", () => {
    hidePill();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  window.addEventListener("scroll", () => { if (window.scrollY < 100) hidePill(); }, { passive: true });

  $("export-json").addEventListener("click", () => {
    window.location.href = `/api/export?${filterQuery({ format: "json" })}`;
  });
  $("export-csv").addEventListener("click", () => {
    window.location.href = `/api/export?${filterQuery({ format: "csv" })}`;
  });

  $("logout-btn").addEventListener("click", async () => {
    try { await fetch("/api/logout", { method: "POST" }); } catch { /* redirect regardless */ }
    location.replace("/login");
  });

  $("monitor-toggle").addEventListener("click", toggleMonitor);
  $("monitor-log-btn").addEventListener("click", openLogModal);
  $("log-modal-close").addEventListener("click", closeLogModal);
  $("log-overlay").addEventListener("click", closeLogModal);
  $("log-refresh").addEventListener("click", refreshLogModal);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); closeLogModal(); }
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
  await reload();
  state.pollTimer = setInterval(poll, POLL_MS);

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
