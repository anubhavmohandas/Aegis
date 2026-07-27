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
- **Threat enrichment (opt-in).** VirusTotal hash reputation (hash-only — the
  file is never uploaded; verdicts cached in SQLite, so repeats cost one
  lookup and work offline) plus offline MITRE ATT&CK annotations, attached to
  high/critical events before the AI runs and surfaced in the drawer (verdict,
  detection count, MITRE badges, VirusTotal link). Master switch
  `enrich_enabled`; key via `VT_API_KEY`, never stored in `config.yaml`.
  A live "test enrichment" button checks the EICAR hash end to end.
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
