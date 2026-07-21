# Changelog

All notable changes to Aegis are recorded here. Versioning tracks
**validation, not features** (see `core/version.py`):

- **alpha** — features done, macOS validated live on real hardware
- **beta** — Windows *also* validated on real hardware (source + packaged)
- **x.y.z** (no suffix) — public release: signed builds, installer, screenshots

The format loosely follows [Keep a Changelog](https://keepachangelog.com).

## [Unreleased] — targeting `v2.0.0-beta`

> **Beta is gated on Windows hardware validation, not on the items below.**
> Everything here is code-complete and running on macOS. Per ADR-008
> (`docs/DECISIONS.md`), the `beta` tag is not applied until the Windows
> packaged build, installer (`packaging/windows-installer.iss`), and
> self-update path are run and confirmed on real Windows hardware. Track that
> run with `TEST_REPORT_TEMPLATE.md`.

### Added
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
