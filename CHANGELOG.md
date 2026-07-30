# Changelog

All notable changes to Aegis are recorded here. Versioning tracks
**validation, not features** (see `core/version.py`):

- **alpha** — features done, macOS validated live on real hardware
- **beta** — Windows *also* validated on real hardware (source + packaged)
- **x.y.z** (no suffix) — public release: signed builds, installer, screenshots

The format loosely follows [Keep a Changelog](https://keepachangelog.com).

> **Where `v2.0.3` actually sits.** The shipped tag carries no pre-release
> suffix, but it does **not** yet meet the "public release" bar above: builds
> are unsigned (`packaging/aegis.spec` falls back to unsigned without the local
> `Aegis Dev` identity; Gatekeeper still needs right-click → Open) and the
> Windows hardware validation below is still open. The suffix is not being
> retrofitted, because `is_newer("v2.0.3", "2.0.3-alpha")` is true — renaming a
> published version downward makes every installed copy see the release it is
> already running as an update, which is the self-update loop that `v2.0.1`
> hit. The bar moves at the next version bump instead.

## [Unreleased] — remaining gate for a signed public release

> **This is gated on Windows hardware validation, not on the items below.**
> Everything here is code-complete and running on macOS. Per ADR-008
> (`docs/DECISIONS.md`), that gate is not cleared until the Windows
> packaged build, installer (`packaging/windows-installer.iss`), and
> self-update path are run and confirmed on real Windows hardware. Track that
> run with `TEST_REPORT_TEMPLATE.md`.

### Security
- **The shipped `admin`/`admin` is now a gate, not a warning.** That one
  password also unlocks Stop Monitoring, Quit, Settings and Delete Evidence, so
  an install left on the default had every tamper protection open to anyone who
  read the README — a banner was the only thing saying so. The server now
  refuses **every** route except change-password and logout until it has been
  replaced (`dashboard/server.py` `PW_CHANGE_EXEMPT_PATHS`), and the console
  opens on a non-dismissable "set your password" dialog. Enforced server-side
  on purpose: a first-run modal alone is decoration, since the same session
  cookie still reaches `/api/events` and `/api/monitor/stop` from anything that
  can make an HTTP request.
- **`/api/monitor/restart` could switch monitoring off without the password.**
  It was session-only, on the reasoning that "it ends with monitoring RUNNING."
  It stops first, and a failed start is returned as JSON rather than raised — so
  a caller just refused by `/api/monitor/stop` for a wrong password (403, tamper
  attempt logged) could call restart instead and land on `running: false` with
  no password, no lockout, no timeline entry and no evidence capture; repeated
  calls could also manufacture monitoring gaps. Now behind the Settings unlock,
  which is where the button already lives. Regression test:
  `tests/test_first_run_password.py`.
- **Changing the password now ends every existing session** and drops any
  Settings unlock they held. A stolen cookie — the most likely reason to rotate
  it — used to outlive the change. The caller gets a fresh cookie, so the flow
  is unchanged for them.

### Added
- **The PDF report now reaches a verdict instead of only listing events.** It
  opened on an AI narrative and 250 severity-sorted rows, which answered "what
  happened" and left "should I worry" to the reader — the one question they
  opened it to have answered. Page 2 now leads with an overall assessment
  (Healthy / Review Suggested / Needs Attention), the confidence behind it, a
  recommended action, and a *What Aegis Checked* list naming each indicator and
  whether it was observed. Computed from `core/signals.py` — the same rules the
  console drawer renders — so the report cannot call a period healthy while the
  drawer shows persistence on one of its events. Also computed *locally and
  before* the AI call, so an unreachable provider now degrades to a report with
  its verdict intact rather than a 500: the footer has always promised the
  narrative is a convenience rather than the verdict, and that is now
  structurally true (`core/report_generator.py`).
  - An **empty period is never reported as Healthy.** No events can mean a quiet
    machine or a stretch when monitoring was off, and the report cannot tell
    those apart — it says so, at Low confidence, instead of printing an
    all-clear over a period Aegis never watched.
  - Confidence rests on **coverage, not silence**: the percentage counts events
    positively cleared (SIP-verified or on your Trust List), not events that
    merely failed to trip anything.
- **Executables are detected by content, not just by extension.** Detection was
  extension-only, so a Mach-O binary saved as `invoice.pdf` scored the same as
  a text file — and on macOS that is the realistic drop, since native Mach-O
  executables carry no extension at all and never matched the extension list to
  begin with. Mach-O (all four byte orders plus universal binaries), ELF, PE and
  `#!` scripts are now recognised from their magic bytes whatever the file is
  called, including on the rename path (`core/severity_engine.py::executable_kind`).
  The verdict is recorded on the event at detection time rather than re-derived
  on read: the drawer annotates every visible row on every poll, so sniffing
  there would put a disk read in the poll loop and would let the drawer say
  "not executable" under a severity raised for exactly the opposite reason once
  the file was deleted. Rows written before this fall back to the extension
  check, so the existing store keeps explaining itself.
- **Detection confidence, next to severity.** Severity said how bad an event
  is; nothing said how well the evidence backed it, so a "high" resting on one
  path heuristic looked identical to a "high" with a VirusTotal detection and
  two corroborating signals behind it. The drawer now states both, and the
  recommended action softens its instruction when a high severity has nothing
  corroborating it — telling both cases to "check this" is how a tool teaches
  people to ignore it. Confidence is a rank over the signals that actually
  fired, never a percentage: the inputs are a handful of booleans, so a number
  would invent gradations nothing here can distinguish (`core/signals.py`).
  Signals Aegis *watched happen to itself* — a tamper attempt, a monitoring gap
  — and scan results carry their own corroboration and read confident standing
  alone. An all-clear is graded too, on coverage rather than doubt: "cleared by
  SIP" and "nothing had anything to say about it" are both low risk and are not
  the same claim.

### Changed
- **Watched folders are now recursive.** They were top-level only, which quietly
  made "watch my Downloads folder" mean "watch the top level of my Downloads
  folder" — a drop into `~/Downloads/installer/` produced no event at all, which
  is a blind spot nobody reading the setting would assume they had. Recursion is
  paired with a deliberately short ignore list (`.git`, `node_modules`,
  `__pycache__`, `.Trash`, editor swap files, partial downloads) plus a new
  `folder_ignore_patterns` config key that *extends* it. The default list
  pointedly omits `build/`, `dist/`, `target/` and `Library/`: they are noisy,
  and they are also exactly where a compiled binary legitimately lands — a
  watcher that ignores where executables appear is not watching for executables.
  Partial-download suffixes are safe to skip because the completed file is
  *renamed* into place, which fires the move path and is classified on the
  destination (`core/folder_monitor.py`).
- **"Hide Trusted" is now "Hide Routine", and covers Aegis's own helpers.** The
  filter already hid your Trust List and SIP-protected Apple binaries but not
  the subprocesses Aegis itself starts for notifications, evidence capture and
  system checks — so the timeline showed the user Aegis reacting to itself.
  Folded into the existing default-on filter rather than given a second toggle:
  it is the same category of noise, and `core/signals.py` already treats it as a
  strong all-clear alongside the other two. Safe to hide specifically because
  the rule matches on **parent PID, not name** — a payload called `osascript`
  is not covered and stays visible. Still fully persisted; this only changes
  what the view returns (`dashboard/server.py`).
- **The report separates important events from background activity.** All 250
  rows shared one table, so the one event worth acting on and 200 Spotlight
  indexer entries carried identical visual weight. Critical/high/medium are now
  listed in full; low-severity activity is grouped to counts underneath, using
  the same PID-stripping collapse the console timeline uses.
- **The severity heuristics live in one language again.** The investigation
  drawer explained *why* an event scored high by re-running the severity
  engine's rules in the browser, because the engine records only its verdict —
  which meant `app.js` carried its own copies of the suspicious-path, executable
  -extension and LOLBin tables, and a test whose entire job was to fail when the
  two drifted. The rules now sit once in `core/signals.py`, next to the engine
  they explain; the dashboard derives the fired-signal list on read and `app.js`
  only supplies the wording for each code. Nothing to drift: a code with no
  wording is a missing row, not a wrong one, and the drift test is replaced by
  one asserting every emitted code has copy (and that no copy is dead).

- **Event retention.** Nothing ever pruned the event store and nothing capped
  `events.log`: both grew forever on a resident install (Spotlight alone is
  ~1000 events/day on a normal Mac) while every 4s dashboard poll aggregated
  over the whole table. Ordinary events now age out after `retention_days`
  (90 by default; `0` keeps everything) via a sweep on the dispatcher loop, and
  `events.log` rotates at 5MB × 3 through a stdlib `RotatingFileHandler` — the
  same treatment `monitor.log` already had. **Tamper Incidents are never
  pruned**, whatever the setting: evidence of someone disabling monitoring is
  the one record that must not quietly age out.
- **The test suite has a runner.** `pytest` appeared in no requirements file,
  wasn't installed in the project venv, and no CI job ran `tests/` at all — a
  tagged release could ship with the whole suite red. Added
  `requirements-dev.txt` and a `tests` job that the release job now depends on,
  covering both `pytest tests/` and the in-module self-checks pytest never
  collects. `test_process_summary_collapse.py` was pytest-only with no
  `__main__`, so running it directly exited 0 having executed none of its five
  checks; it now runs either way like every other file.
- **Threat enrichment (optional).** When enabled, Aegis enriches the events that
  warrant it with VirusTotal reputation and MITRE ATT&CK mappings before
  generating the AI explanation, and surfaces both in the drawer (verdict,
  detection count, MITRE badges, VirusTotal link).

  **Files are never uploaded.** Only the sha256 Aegis already computed locally
  leaves the machine: VirusTotal is asked "have you seen this hash", never given
  the file, and a file it has never seen comes back `unknown_hash` rather than
  prompting a submission. Lookups are gated at `enrich_min_severity` (medium and
  above by default) and cached in SQLite, so repeat binaries cost one lookup and
  keep working offline. MITRE mapping is fully offline and needs no key at all.
  Master switch `enrich_enabled`; key via `VT_API_KEY`, never stored in
  `config.yaml`. A live "test enrichment" button checks the EICAR hash end to end.
- **Away Sessions.** Screen lock/unlock now bracket what happened while you
  were away, with a gap-detection summary.
- **Tamper evidence & Incidents.** Repeated failed auth on a protected action
  (e.g. Stop Monitoring) captures webcam + screenshot evidence into a stored,
  password-gated Incident. Evidence is written only to the local machine.
- **Daily Brief.** One-tap AI summary of the last 24 hours.
- **Timeline event grouping.** Runs of ≥4 same-source events collapse into a
  single expandable group instead of flooding the timeline.
- **Trust-list editing from Settings.** Trusted process names / SHA-256
  hashes / USB IDs are editable in the UI (previously hand-edited YAML), with
  a "Hide Trusted" timeline toggle.
- **One-click trust from the drawer.** "Ignore this source" adds the event's
  process to your trusted list without leaving the timeline.

### Fixed
- `tests/test_ask_aegis.py` made a real 30s AI call against its own 10s client
  timeout whenever a provider key existed, despite clearing `*_API_KEY` and
  redirecting `ENV_FILE_PATH`: `load_config()` calls `_load_env_file()`, whose
  `path` default argument bound to the real repo `.env` at definition time, so
  every call put the key straight back into `os.environ`.
- "Test connection" (VirusTotal) leaked a SQLite handle per click — the
  enricher's lazily-opened cache connection was abandoned on every early return.
- `RuleEngine.__init__` called `_sip_enabled()` directly, bypassing the
  `lru_cache`d `_sip_ok()` right above it, re-forking `csrutil status` on every
  Stop/Start and every Settings save for an answer that can't change without a
  reboot.
- Dead code removed: `database.SCHEMA`, `secrets_store.delete_secret` /
  `SecretsStore.delete`, `TrayApp.run_in_background`, and `TrayApp`'s
  `on_open_dashboard` hook (never passed by any caller, so the menu item it
  guarded could never appear); two unused imports.
- **Windows evidence: active-window title could be wrong/empty on 64-bit
  Windows.** `evidence._active_window()` called `GetForegroundWindow` /
  `GetWindowTextW` via ctypes without declaring `restype`/`argtypes`, so the
  64-bit `HWND` was truncated to a 32-bit `c_int`. Now typed as `HWND`/`LPWSTR`
  (plus a null-focus guard for the lock screen). Hardened by review; still
  pending a real-Windows-hardware confirmation run (ADR-008).
- Underexposed webcam evidence (first-frame grab before auto-exposure settled)
  — now waits ~1.2 s for exposure to settle.
- Nemotron/NVIDIA endpoint leaking chain-of-thought into AI summaries — gated
  off via `chat_template_kwargs`.
- Crash on Stop Monitoring; assorted stability fixes.
- AI explanations could be `None` and break rendering.

## [2.0.2-alpha] — released

- macOS validated live on real hardware (process, folder, USB, notifications);
  packaged `.app` built and smoke-run on Apple Silicon.
- Windows validated **from source** on real hardware via the WMI polling
  fallback (ETW callback never fires with the current third-party library —
  see `docs/DECISIONS.md`); packaged/installer/self-update path still pending.
- Encrypted local API-key storage that survives self-update; changeable
  dashboard login password; self-update from GitHub Releases (macOS-verified).
- Third full over-engineering/security audit — real bugs found and fixed,
  including a self-update RCE.

## [v02-alpha] / [v01] — earlier

- Core pipeline: process / USB / startup / folder monitoring → dedupe → rule
  engine → severity heuristic → rate limit → AI explanation → SQLite + flat
  log, across Windows / macOS / Linux collectors.
- Desktop app (`desktop_app.py`), live dashboard timeline with filters/search
  and a details drawer, AI-generated PDF report export, opt-in trusted-process
  noise reduction, configurable notification severity floor.

[Unreleased]: https://github.com/anubhavmohandas/Aegis/compare/v2.0.2-alpha...HEAD
[2.0.2-alpha]: https://github.com/anubhavmohandas/Aegis/releases/tag/v2.0.2-alpha
