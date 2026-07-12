# Aegis — Architecture

Cross-platform AI security assistant: monitors process starts, USB activity,
startup persistence, and watched folders; explains events in plain English;
keeps a queryable timeline. Not antivirus, no security guarantees.

## Layout

```
Aegis/
  core/              cross-platform, OS-agnostic
    events.py         MonitorEvent model (the only thing collectors and the
                       AI/UI layers agree on)
    config.py         config.yaml + env var loading
    ai_explainer.py    Claude/OpenAI plain-English explanation
    rule_engine.py     opt-in allowlist gate (skip AI call for user-trusted items)
    severity_engine.py  local low/medium/high/critical heuristic (runs before the AI call)
    database.py        SQLite event history (read by ui/timeline_app.py)
    dispatcher.py       queue -> dedupe -> rule engine -> severity -> rate-limit -> AI -> notify -> persist
    notifier.py         desktop notifications, per platform (macOS: osascript primary; Windows/Linux: plyer)
    folder_monitor.py   watchdog-based folder watching (real-time on all OSes)
    tray_app.py         system tray icon (pystray)
  windows/            Windows collector
    process_monitor.py  ETW (pywintrace) with WMI polling fallback
    usb_monitor.py       WMI Win32_PnPEntity creation/deletion events
    startup_monitor.py   startup folder (watchdog) + registry Run/RunOnce (polled)
  macos/              macOS collector
    process_monitor.py  NSWorkspace launch notifications (GUI apps) + psutil polling (all processes)
    usb_monitor.py       system_profiler SPUSBDataType polling
    startup_monitor.py   LaunchAgents/Daemons (watchdog) + Login Items (osascript, polled)
  linux/              Linux collector (not in client scope -- see "Live verification" below)
    process_monitor.py  psutil polling diff (same tradeoff as macOS)
    usb_monitor.py       pyudev netlink monitor (real-time, kernel-sourced)
    startup_monitor.py   XDG autostart .desktop files (watchdog)
  ui/
    timeline_app.py     read-only PySide6 timeline viewer over the SQLite store
  main.py              entry point: detects OS, wires collectors, runs tray + dispatcher
```

Every collector's only contract is: produce `MonitorEvent` objects and push
them onto the shared queue. The dispatcher, AI explainer, database, and UI
never know or care which OS or which specific collector produced an event.
Adding a new signal (network connections, scheduled tasks, PowerShell
execution logging, etc.) means writing one new collector class — nothing
else in the pipeline changes.

## Event flow

```
Collector (OS-specific)
       |
       v
  shared Queue[MonitorEvent]
       |
       v
   Dispatcher
       |-- always: write to flat log (events.log) + SQLite (aegis_events.db)
       |-- dedupe (drop identical summary within 30s)
       |-- rule engine (skip AI call only for items on YOUR trusted list)
       |-- severity engine (low/medium/high/critical, local heuristic)
       |-- rate limit (hard cap 20 AI calls/min -- high/critical are EXEMPT)
       |-- AI explainer (Claude/OpenAI) -> plain-English explanation, told the severity
       v
   Notification (desktop toast, title tagged with severity) + persisted row
       |
       v
  ui/timeline_app.py reads the SQLite store on demand, independent process
```

Severity is computed before the rate limiter specifically so a burst of
low-severity noise (an installer spawning twenty child processes) can hit
the cap, while a single high/critical event never gets silently dropped
just because it landed inside a noisy window. See `core/severity_engine.py`
for why it defaults to "medium," never "low," for anything it doesn't have
a specific reason to move — same false-confidence trap as the rule engine,
addressed the same way.

## Why the rule engine is an allowlist, not a "known safe" database

Hardcoding "svchost.exe is always safe" is exactly the wrong instinct for a
security tool — process name impersonation is a real technique, and a
built-in safe-list would create false confidence in precisely the cases an
attacker is most likely to exploit. `core/rule_engine.py` only skips the AI
call for process names / USB device IDs **you** add to `config.yaml`. It's
a personal noise filter for things you already recognize, not a verdict the
tool hands down on your behalf. Every event is still logged and persisted
regardless of whether the AI was called.

## Confidence tagging (`certain` vs `polled`)

Every `MonitorEvent` carries a `confidence` field that flows through to the
AI prompt and the UI:

| Collector | certain (real-time) | polled (best-effort, delayed) |
|---|---|---|
| Windows process | ETW, if `pywintrace` works + admin | WMI fallback |
| Windows USB | WMI event callback | — |
| Windows startup | Startup folder (watchdog) | Registry Run/RunOnce |
| macOS process | NSWorkspace (GUI app launches only) | psutil diff (all processes), verified live |
| macOS USB | — | `system_profiler` polling (2 sources, see below), verified live |
| macOS startup | LaunchAgents/Daemons (watchdog) | Login Items (`osascript`) |
| Linux process | — | psutil diff (same tradeoff as macOS) |
| Linux USB | pyudev netlink monitor | — |
| Linux startup | XDG autostart (watchdog) | — |
| Folders (all OSes) | watchdog (ReadDirectoryChangesW / FSEvents / inotify) | — |

This matters because the two weakest links — Windows process fallback and
macOS process/USB monitoring — are the ones most likely to matter if you're
using this for anything beyond casual awareness. See "Known gaps" below.

## Live verification (the one collector set that isn't a guess)

Linux isn't in the client's requested scope (Windows + macOS only). It's in
this build because it's the one platform whose collectors I could actually
run against a live kernel in my sandbox, instead of writing code against
documentation I couldn't test. What was actually observed, live, in one run:

- **pyudev USB monitor**: `pyudev.Context()` enumerated real USB devices on
  the sandbox's virtual bus, and `pyudev.MonitorObserver` started/stopped
  cleanly against the real netlink socket.
- **Folder monitor**: creating a real file, then a real `.exe`-named file,
  in a watched folder produced real `FILE_CREATED`/`FILE_MODIFIED` events,
  and the executable-named one was correctly classified `HIGH` severity by
  the heuristic in `severity_engine.py` — the pipeline's own severity logic
  reacted to a real filesystem event, not a mocked one.
- **Process monitor, and its documented gap, both proven in the same run**:
  spawning `echo` (near-instantaneous) was **missed** — exactly the
  "polled detection can miss short-lived processes" limitation documented
  throughout this project. Spawning `sleep 6` (long-lived) was **correctly
  detected** one poll cycle later. That's not a bug demonstration or a
  hedge — it's the actual, measured boundary of what polling-based process
  detection can and can't see, observed rather than asserted.
- **XDG autostart monitor**: dropping a real `.desktop` file into a watched
  autostart directory produced a real `STARTUP_ITEM_ADDED` event via
  inotify.

Windows and macOS collectors follow the same code patterns but could not be
run this way — no machine to run them on. Treat the Linux results as
evidence the *architecture* works end to end, not as evidence the Windows/
macOS API calls are correct — those still need verification on real hardware.

**Update: macOS has since been verified live too**, on real hardware, in a
real testing session — not by me (I still have no Mac access), by the
person building this, pasting real console output back for me to read and
fix against. What that surfaced, in order:

- **A real bug in the notifier**: `plyer`'s macOS notification backend
  imports `pyobjus`, which `requirements-macos.txt` never installs (it
  installs `pyobjc`, a different library). Confirmed via a real
  `ModuleNotFoundError` traceback, not guessed. Fixed by adding an
  `osascript -e 'display notification ...'` fallback in `core/notifier.py`
  — ships on every Mac, no new dependency needed. (v2 follow-through: since
  the plyer attempt was failing on *every* stock-install macOS notification
  before falling back anyway, osascript is now the *primary* macOS backend
  and plyer isn't tried at all on Darwin — it remains the backend on
  Windows/Linux, untouched per ADR-008.)
- **A real design bug in the dispatcher**: rule-engine-trusted events and
  rate-limited events were still calling `notify()`, defeating the purpose
  of both mechanisms — confirmed by a real flood of `mdworker_shared`
  notifications (macOS Spotlight indexing spawns it constantly). Both
  paths in `core/dispatcher.py` now persist and log silently instead of
  popping a notification, once an event has already been explicitly
  deprioritized by the rule engine or the rate limiter.
- **A real, undocumented reliability gap in `system_profiler SPUSBDataType`**:
  a genuine external USB flash drive (visible in Finder, fully mounted and
  usable) was completely absent from both the JSON and plain-text output of
  `SPUSBDataType` — not a parsing bug, `system_profiler` itself omitted a
  real device. Confirmed by cross-checking `SPStorageDataType`, which
  correctly showed the same drive with `physical_drive.protocol: "USB"` and
  `is_internal_disk: "no"`. `macos/usb_monitor.py` now polls both sources;
  `SPStorageDataType`, filtered to that protocol/internal-disk condition,
  is the one that turned out to be reliable for external storage. Verified
  end to end: unmounting and remounting the real drive produced real
  `USB_REMOVED`/`USB_CONNECTED` events with correct severity classification.
- **Process, folder, and notification pipeline** all confirmed working
  against real macOS process spawns (`git`, `Brave Browser Helper`, system
  daemons) and a real file create/modify/delete cycle on the real Desktop.

Every fix above was made only after seeing real command output or a real
traceback — none of it was patched blind. macOS is now the second platform
(after Linux) with actual evidence behind it, not just documented API
patterns. Windows remains completely unverified.

## Validating v1 — current status

Be precise about what "done" means: everything below was run via
`python3 main.py` from source. **None of it has been through a packaged
build yet** — that's still untouched, on either OS.

```
macOS, from source (python3 main.py):
  [x] Launches, runs continuously without crashing
  [x] Process monitor    -- real spawns detected (git, browser helpers, system daemons)
  [x] Folder monitor     -- real create/modify/delete cycle detected, severity correct
  [x] USB monitor        -- real mount/unmount detected (after the SPStorageDataType fix)
  [x] Notifications       -- real banners confirmed on screen (after the osascript fix)
  [x] Rule engine / severity / rate limiting -- all confirmed against real event bursts
  [ ] Tray icon visually confirmed in the menu bar -- never explicitly checked
  [ ] AI explanations against a real API key -- only tested key-less so far
  [ ] Timeline UI (ui/timeline_app.py) -- never run
  [x] Packaged .app -- built with PyInstaller (packaging/aegis.spec) and
      smoke-run on real Apple Silicon hardware: version banner, NSWorkspace
      observer, USB baseline, rule-engine gating of real daemons, a real
      Desktop file-create classified HIGH and persisted, notifications via
      osascript with zero fallbacks, log/db correctly anchored under
      ~/Library/Application Support/Aegis. Tray icon visibility still not
      explicitly confirmed (same caveat as the source run).

Windows: nothing tested yet, still zero real-hardware evidence.
```

The `pystray`/NSWorkspace thread-interaction concern (`pystray.Icon.run()`
wanting the main thread while the NSWorkspace observer runs its own loop on
a background thread) didn't cause a hang — the app ran continuously for
20+ minutes without freezing. Decent indirect evidence they coexist fine,
but the tray icon's actual visibility in the menu bar hasn't been confirmed
separately from "didn't crash."

If `python main.py` works but a packaged `.exe`/`.app` doesn't, that's a
packaging problem (hidden imports, missing bundled data files), not a
monitoring-logic bug — see "Packaging" below before debugging the wrong
layer. Use `TEST_REPORT_TEMPLATE.md` for anything that doesn't match
expectations.

## Packaging

The end user sees `Aegis.exe` / `Aegis.app`, not the source language — a
GUI app doesn't need to be C#/Swift to look and feel native. Package with
`PyInstaller` or `Nuitka` for Windows, `py2app`/`Briefcase` for macOS
(`.app` → `.dmg`). Reach for native code (Rust/Swift) later only for a
specific capability gap — e.g. holding the macOS EndpointSecurity
entitlement conversation, or replacing `pywintrace` if it becomes
unmaintained — not for performance; nothing in this pipeline is
performance-bound. The collector architecture already supports this: a
native binary that prints JSON lines to stdout slots into the existing
queue with no changes to `core/`.

**This is no longer hypothetical:** the build recipe is checked in at
`packaging/aegis.spec` (one spec, platform-conditional), with the full flow
— including the "validate from source first" rule and where a frozen build
keeps its files — documented in `packaging/PACKAGING.md`. The macOS `.app`
has been built and smoke-run on real hardware; the Windows branch of the
spec and the Inno Setup installer template
(`packaging/windows-installer.iss`) are written but have never been run on
Windows (ADR-008 applies).

**Known PyInstaller gotchas the spec already handles — check these before
debugging anything else if you modify it:** `config/config.yaml` and
`assets/tray_icon.png` are read relative to the module location and must be
bundled explicitly as data files (`core/config.py` and `core/tray_app.py`
fall back gracefully if missing — defaults / placeholder shield icon — so a
missing bundle silently runs with the wrong config and icon, which looks
like a bug and isn't one). plyer loads its per-OS backend by string name at
runtime, so on Windows it must be a hidden import or notifications silently
drop to the print fallback. And relative `log_path`/`db_path` would be
written to `/` from a Finder-launched `.app` — `core/config.py` anchors
them to a per-user data dir when running frozen.

## Known gaps and deliberate tradeoffs

1. **No EndpointSecurity on macOS.** ES is the only way to get Windows-ETW-
   equivalent, kernel-level process visibility on Mac, and it requires an
   Apple-granted entitlement that isn't self-serve — there's no guaranteed
   timeline for getting it, and it's typically granted to established
   security vendors, not individual developers. Current ceiling without it:
   NSWorkspace (real-time, GUI apps only) + psutil polling (everything else,
   a few seconds of lag, can miss processes that start and exit fast).

2. **Unified Logging (`log stream` / `os_log`) as a partial mitigation —
   recommended, not yet implemented.** macOS's Unified Logging system
   captures a meaningful amount of process/exec activity across subsystems
   without needing the ES entitlement, and would likely improve macOS
   process coverage beyond what psutil polling gets today. This was NOT
   implemented in this pass because doing it correctly means tuning
   `log stream --predicate` filters against real macOS behavior, which I
   cannot verify without a Mac — shipping a guessed predicate would risk
   looking more capable than it actually is. Worth prioritizing as the next
   concrete improvement to macOS process visibility; test predicates on
   real hardware before trusting the output.

3. **`pywintrace` is sparsely maintained.** The Windows ETW backend depends
   on it; if it breaks on a future Windows/Python combination, the app
   degrades automatically to WMI polling (see `windows/process_monitor.py`),
   but don't build new features on top of `pywintrace` without checking its
   repo's current state first.

4. **AI explanations are not a security verdict.** No malware database, no
   hash reputation, no threat intel feed — a plain-English narrator with an
   opinion, not a detector. Every event is persisted regardless of what the
   AI says or whether it was called at all.

5. **Windows remains untested; macOS no longer is.** This was built without
   access to a Windows or Mac machine (Linux sandbox only), but macOS has
   since been run and debugged live on real hardware — see "Live
   verification" above for exactly what was found and fixed. `windows/`
   still only compiles and follows documented API patterns; none of it has
   run against the real APIs it targets. The PySide6 timeline UI passes
   Python syntax/import checks and its data-loading logic was verified
   against a real SQLite file, but the actual window has not been visually
   confirmed on either platform yet (I have no display access; the Mac
   testing session so far has focused on the monitors, not the UI).

## On the "Aegis" name

Confidence: likely, not certain — worth checking before you commit to public
branding. "Aegis Authenticator" is a well-known open-source 2FA/TOTP app on
Android/F-Droid, and there may be other security tools using the name. Not
a legal blocker for a portfolio project, but if you plan to publish this
under the name, a quick trademark/namespace check is cheap insurance against
SEO collision and "wait, is this the 2FA app?" confusion.

## Roadmap (as scoped)

- **v0.1 (this build):** process/USB/startup/folder monitoring, desktop
  notifications, AI explanation, SQLite event history, opt-in rule-engine
  gate, local severity heuristic, read-only timeline UI. Plus a Linux
  collector (out of scope, included because it's verifiable — see above).
- **v0.2:** network connections, PowerShell execution logging, services,
  scheduled tasks, registry modification monitoring beyond Run keys, AI risk
  scoring.
- **v0.3:** Sigma rules, YARA, VirusTotal lookups, MITRE ATT&CK mapping,
  timeline/behavioral analysis across events.

Each of these is a new collector or a new dispatcher-stage plugin under the
existing architecture — none of them require restructuring `core/`.
