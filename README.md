<p align="center">
  <img src="assets/logo.png" width="180" alt="Aegis logo">
</p>

# Aegis — AI-Powered Cross-Platform Security Assistant (v0.1)

Background monitor for Windows, macOS, and Linux: watches process launches,
USB connect/disconnect, startup-persistence changes, and selected folders,
then explains each event in plain English via Claude or OpenAI, scores a
local severity level, keeps a queryable event history (SQLite), and shows it
in a read-only timeline UI. **Not antivirus, no security guarantees** — a
personal awareness tool.

See `ARCHITECTURE.md` for the full design, the event-flow diagram, the
confidence/severity systems, the live-verification results, and the
complete list of known gaps. This README is setup + a summary; that file
has the substance.

## Status — what's actually been proven to work, not just written

Built without access to a real Windows or Mac machine (Linux sandbox only).
Rather than guess at everything, the Linux collector set was added
specifically so at least one full platform could be run against a live
kernel instead of just read against documentation:

- **Live, in a real run**: spawning a long-lived process was detected;
  spawning a near-instant process (`echo`) was correctly *missed* —
  demonstrating the documented "polling can miss short-lived processes"
  limitation on real behavior, not as a hedge. A real file drop into a
  watched folder triggered a real `HIGH` severity classification. A real
  USB netlink monitor (`pyudev`) started and enumerated real devices. A
  real `.desktop` file drop triggered a real inotify-based startup event.
  Full details in `ARCHITECTURE.md` → "Live verification."
- **Verified via targeted tests**: SQLite event store, rule engine
  (trusted/untrusted process+USB cases), severity engine (baseline +
  path-heuristic bumps), the full dispatcher pipeline including the
  high-severity rate-limit exemption, and the folder monitor.
- **Not verified — no machine to run it on**: all of `windows/` (ETW,
  WMI, registry) and all of `macos/` (`pyobjc`, `osascript`,
  `system_profiler`). These compile and follow documented API patterns but
  have not run against the real APIs. `ui/timeline_app.py`'s data logic was
  verified against a real SQLite file, but the Qt window itself couldn't be
  instantiated in this sandbox (missing graphics libraries, no root) —
  visually verify once you have a real display.

Run this on the target OS and expect to debug the Windows/macOS modules
first. The pipeline architecture (queue → dedupe → rules → severity → rate
limit → AI → notify → persist) is tested end to end; the OS integration
points for Windows/macOS are first drafts.

## Setup

```
python -m venv venv
# Windows:
venv\Scripts\activate
pip install -r requirements-windows.txt
# macOS:
source venv/bin/activate
pip install -r requirements-macos.txt
# Linux (not the client's requested scope, included for verification):
pip install -r requirements-linux.txt

export ANTHROPIC_API_KEY=sk-...      # or OPENAI_API_KEY, and set ai_provider: openai in config/config.yaml
python main.py                        # background monitor + tray icon
python ui/timeline_app.py             # separate process: view event history
```

Windows: run from an **elevated (Administrator)** terminal so the ETW
process backend can start. Without elevation it falls back automatically to
WMI polling — check the log output to see which backend actually activated.

macOS: the first time it queries login items via `osascript`, macOS will
prompt for Automation permission for your terminal/Python — approve it, or
that one feature silently stops working.

## Validating v1 (do this before adding anything else)

Code-complete is not the same as working. Nothing here has run on a real
Windows or Mac kernel. Suggested order, highest technical risk first:

```
Day 1: python main.py works -> PyInstaller build -> launches -> tray icon
       visible -> ETW process events fire (highest-risk single component --
       pywintrace is sparsely maintained, see windows/process_monitor.py)
Day 2: file monitor
Day 3: USB monitor
Day 4: timeline UI, AI explanations, notifications
Day 5: packaging regression pass, release
```

If `python main.py` works but the packaged `.exe`/`.app` doesn't, it's a
packaging problem (hidden imports, missing bundled data files), not a
monitoring-logic bug — see the PyInstaller note below before debugging the
wrong layer. Use `TEST_REPORT_TEMPLATE.md` to log anything that doesn't
match expectations; the "only happens in the packaged build" note in that
template is the single fastest way to tell the two failure classes apart.

Two things worth checking specifically on macOS, flagged as uncertain in
the code itself: `core/tray_app.py`'s `pystray.Icon.run()` wants the main
thread, and `macos/process_monitor.py`'s NSWorkspace observer runs its own
run loop on a background thread. They should coexist, but this has never
been run — if the tray icon never appears or the app hangs on launch, this
interaction is where to look first.

## Packaging (why this stays Python)

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

**Known PyInstaller gotcha, check this before debugging anything else:**
`config/config.yaml`, `assets/logo.png`, and `assets/tray_icon.png` are read
relative to the script location — they will not be bundled automatically.
`core/config.py` and `core/tray_app.py` already fall back gracefully if
these are missing (defaults / placeholder shield icon), so a missing bundle
won't crash the app, but it will silently run with the wrong config and the
wrong icon, which looks like a bug and isn't one. Bundle them explicitly:

```
pyinstaller main.py --name Aegis --add-data "config;config" --add-data "assets;assets"
```

(macOS/Linux use `:` instead of `;` in `--add-data`.)

## What's real-time vs. polled, per feature

| Feature | Windows | macOS | Linux |
|---|---|---|---|
| Process start | ETW (real-time) if `pywintrace` works + admin; else WMI polling | NSWorkspace (real-time, GUI apps only) + psutil polling (all processes) | psutil polling (same tradeoff) |
| USB connect/remove | WMI event callback (real-time) | `system_profiler` polling (3-5s lag) | pyudev netlink monitor (real-time) |
| Startup items | Startup folder = real-time; registry Run keys = polling | LaunchAgents/Daemons = real-time; Login Items = polling | XDG autostart = real-time |
| Watched folders | Real-time (ReadDirectoryChangesW) | Real-time (FSEvents) | Real-time (inotify) |

Every event carries a `confidence` field (`certain`/`polled`) and a
`severity` field (`low`/`medium`/`high`/`critical`) that flow through to the
AI prompt and the timeline UI — see `ARCHITECTURE.md` for why these are two
separate axes, not one.

## Reducing AI calls: rule engine + severity engine

`core/rule_engine.py` skips the AI explainer only for process names / USB
device IDs you explicitly add to `config.yaml`. Deliberately **not** a
built-in "known safe" database — hardcoding e.g. "svchost.exe is always
safe" is exactly wrong, since process-name impersonation is a real attack
technique. It only skips items you've personally told it about.

`core/severity_engine.py` classifies every event locally (low/medium/high/
critical) before the AI call, using boring, well-established heuristics
(process launched from a temp/downloads path, executable dropped in a
watched folder) — never defaulting to "low" for anything unrecognized. This
lets the rate limiter exempt high/critical events instead of applying one
flat cap to everything. Every event is still logged and persisted
regardless of rule/severity/rate-limit outcome.

## Known gaps, stated plainly

1. **No macOS EndpointSecurity integration** — gated behind an Apple
   entitlement that isn't self-serve. Unified Logging is a documented,
   not-yet-implemented partial fix — see `ARCHITECTURE.md`.
2. **`pywintrace` is sparsely maintained.** Degrades to WMI polling
   automatically if it breaks.
3. **AI explanations are not a security verdict.** No malware database, no
   hash reputation, no threat intel. A narrator, not a detector.
4. **Rate limiting is basic**: 20 AI calls/minute cap (high/critical
   severity exempt), 30-second summary dedupe.
5. **Notifications use `plyer`** — cross-platform but less control than
   native toast/NSUserNotification code.
6. **"Aegis" may collide with existing tools** (Aegis Authenticator, a
   well-known open-source 2FA app) — check before public branding.
7. **Linux collector is out of the client's requested scope** — included
   because it's the one platform verifiable in this environment; not a
   deliverable unless you want it to be.

## Project layout

```
Aegis/
  core/            cross-platform: config, event model, AI explainer,
                   rule engine, severity engine, SQLite event store,
                   notifier, folder monitor, dispatcher, tray icon
  windows/         process_monitor.py (ETW+WMI), usb_monitor.py (WMI),
                   startup_monitor.py (registry + startup folder)
  macos/           process_monitor.py (NSWorkspace+psutil), usb_monitor.py
                   (system_profiler polling), startup_monitor.py
                   (LaunchAgents + login items)
  linux/           process_monitor.py (psutil), usb_monitor.py (pyudev,
                   real-time), startup_monitor.py (XDG autostart)
  ui/
    timeline_app.py  read-only PySide6 timeline viewer
  config/
    config.yaml
  main.py
  ARCHITECTURE.md
  requirements-common.txt
  requirements-windows.txt
  requirements-macos.txt
  requirements-linux.txt
```

## Roadmap

- **v0.1 (this build):** process/USB/startup/folder monitoring, notifications,
  AI explanation, SQLite history, rule-engine gate, severity heuristic,
  timeline UI, Linux collector (bonus, verified live).
- **v0.2:** network connections, PowerShell execution logging, services,
  scheduled tasks, deeper registry monitoring, AI risk scoring.
- **v0.3:** Sigma rules, YARA, VirusTotal, MITRE ATT&CK mapping, timeline
  analysis.

Every monitor's only job is to put `MonitorEvent` objects on a shared queue
(see `core/events.py`) — each roadmap item above is a new collector or a new
dispatcher stage, not a rewrite of `core/`.
