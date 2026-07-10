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
    notifier.py         cross-platform desktop notifications (plyer)
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
| macOS process | NSWorkspace (GUI app launches only) | psutil diff (all processes) |
| macOS USB | — | `system_profiler` polling |
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

5. **Untested platform-specific code.** This was built without access to a
   Windows or Mac machine (Linux sandbox only). Everything in `core/` was
   exercised against real behavior (SQLite writes, rule engine logic,
   dedup/rate-limit, folder watching via real inotify events). Everything
   in `windows/` and `macos/` compiles and follows documented API patterns,
   but has not run against the real APIs it targets. The PySide6 timeline UI
   passes Python syntax/import checks and its data-loading logic was
   verified against a real SQLite file, but the actual window could not be
   instantiated in this sandbox (missing system graphics libraries, no root
   to install them) — visually verify it once you have a real display.

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
