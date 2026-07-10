# Aegis — Architecture Decision Records

Engineering history, not user docs. Each entry: the decision, why it was made,
and what would have to change for it to become wrong. Pulled from the
reasoning already embedded in module docstrings — this file exists so that
reasoning survives a reread of the code without someone having to
re-derive it, not because the code comments were insufficient on their own.

---

## ADR-001: One event type for every collector (`MonitorEvent`)

Every monitor (process, USB, startup, folder), on every OS, produces the same
`MonitorEvent` dataclass. The dispatcher, rule engine, severity engine, AI
explainer, and UI only ever see this type.

**Why:** Adding a new monitor later means implementing one function that
returns `MonitorEvent` objects — nothing downstream needs to change.

**Would become wrong if:** a future collector needs to carry structured data
that doesn't fit the `details: dict` shape (e.g. a multi-step chain of
related events). Source: `core/events.py`.

---

## ADR-002: Rule engine is a user-configured opt-in allowlist, never a built-in "known safe" list

`RuleEngine` only skips the AI call for items the user explicitly added to
`config.yaml` (`trusted_process_names` / `trusted_process_hashes` /
`trusted_usb_ids`).

**Why:** A hardcoded "these are always safe" list is a malware-masquerade
vector — e.g. trusting `svchost.exe` by name is exactly wrong, since
`svchost.exe` impersonation is a real technique. Baking in a global
safe-list would make Aegis *less* trustworthy by creating false confidence
in exactly the cases an attacker is most likely to exploit.

**Would become wrong if:** never, as a security posture — this is a
foundational decision, not a placeholder. Source: `core/rule_engine.py`.

---

## ADR-003: Severity and confidence are tracked independently

`confidence` answers "how sure are we we detected this correctly" (real-time
vs. polled). `severity` answers "how concerning is this, assuming we detected
it correctly." Severity defaults to `"medium"`, never `"low"`, for anything
without a specific reason to downgrade.

**Why:** Conflating the two would mean a real-time detection of something
harmless reads as more alarming than a polled detection of something
dangerous — backwards. And silently defaulting unrecognized events to "low"
severity is the same failure mode ADR-002 exists to avoid. Source:
`core/severity_engine.py`.

---

## ADR-004: `FILE_MOVED` checks the destination path, not the source

`FolderMonitor` now handles `watchdog`'s `on_moved` (previously dropped
entirely), and `SeverityEngine` classifies it by `dest_path`, not `path`.

**Why:** The specific evasion this closes: drop `payload.txt` (extension
check on `on_created` finds nothing), then rename it to `payload.exe` — only
`on_moved` fires for that, and checking the source name instead of the
destination would let the rename through unclassified. Source:
`core/folder_monitor.py`, `core/severity_engine.py`.

---

## ADR-005: Collectors enrich events; `RuleEngine` stays OS-agnostic

When `trusted_process_hashes` needs a file to hash, the exe path is resolved
**inside each collector**, at emission time, and attached to `details` —
not resolved lazily inside `RuleEngine` by looking up the PID itself.

**Why:** If `RuleEngine` did the PID→path resolution, it would become
OS-aware (needs `psutil` or platform APIs directly), breaking its current
`Event -> Decision` simplicity. Keeping enrichment at the collector layer
means `RuleEngine` only ever has to ask "is there an `exe`/`executable_path`
key," regardless of which OS or which backend produced the event.

**Context this fixes:** before 2026-07-10, ETW (Windows) and NSWorkspace
(macOS) events carried no exe path at all, so the hash-trust branch was
unreachable on both of the highest-fidelity (`confidence="certain"`)
collector paths — it only ever worked on the degraded WMI/psutil-poll
fallbacks. Found by static code reading, confirmed with a synthetic
`RuleEngine.evaluate()` test using mocked event shapes (not real hardware).
Source: `core/rule_engine.py`, `windows/process_monitor.py`,
`macos/process_monitor.py`.

---

## ADR-006: macOS and Windows resolve the exe path differently, on purpose

macOS: `NSRunningApplication.executableURL()`, read directly off the object
the NSWorkspace notification already hands you. Windows: `psutil.Process(pid).exe()`,
called immediately after the ETW callback fires.

**Why not the same method on both:** NSWorkspace already gives you the
running-application object — a second PID-based lookup would add an
unnecessary syscall and reintroduce a PID-reuse race that doesn't need to
exist. ETW gives you only a bare PID, so a `psutil` lookup is the only
option there. Both are wrapped so a process that exits before resolution
completes degrades to "no exe available" rather than crashing the collector
thread — monitoring should always prefer less information over no
monitoring.

**Still unverified:** whether `executableURL()` behaves as documented on a
live NSWorkspace notification, and whether the ETW→psutil window is fast
enough in practice, both require real hardware. Not yet run.

---

## ADR-007: Dispatcher is one pipeline stage per method, not one long `_handle()`

`_handle()` now calls `_stage_dedupe` → `_stage_classify` → `_stage_rule_gate`
→ `_stage_rate_limit` → `_stage_explain_and_notify`, each returning whether
it fully handled the event.

**Why:** The prior single-function version was heading toward 200+ lines and
becoming unreviewable. Named stages make the pipeline order enforced by code
structure, not just a comment, and make each stage independently testable.
Source: `core/dispatcher.py`.

---

## ADR-008: Windows collectors are untouched until real Windows hardware evidence exists

Despite macOS live-testing surfacing three real bugs (dedupe by summary
string instead of `(category, pid)`, USB polling missing a real mounted
drive, notification backend crashing on missing `pyobjus`), none of those
fixes were spontaneously ported to the analogous Windows code paths.

**Why:** Explicit decision — porting a fix based on "this is probably also
broken on Windows" is a guess, not a verified fix, and this project's stated
priority is closing real-hardware gaps, not compounding unverified guesses.
Windows fixes happen only after Windows fixes have a Windows bug report
behind them.

---

## A note on "tested" language

This repo's own docs (`ARCHITECTURE.md`, `README.md`) are already precise
about this — they distinguish "verified live" (run on real hardware) from
"tested" (ran, key-less, in the dev sandbox) from "implemented and
unit-testable" (compiles and passes a synthetic test, never run against a
real OS API). That precision doesn't automatically carry into informal
session handoffs pasted into chat, which is where looser phrasing like
"unit-tested" has crept in without any committed test file to back it.
**Rule going forward: session handoffs get held to the same standard as
these docs.** Say what was actually run — "verified with a synthetic
validation script," "manually verified on real hardware," "compiles,
never run" — not "unit-tested," unless a `pytest`/`unittest` file exists in
the repo to point at.
