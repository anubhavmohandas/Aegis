# Packaging Aegis

How to turn the source checkout into a distributable build, and — more
importantly — the order to do it in.

## Rule zero: validate from source before you package

If a packaged build misbehaves, you need to already know the collectors work
on that machine, so the only remaining suspect is packaging. Never make
"first run on this OS" and "first packaged run" the same run.

```
Source run works  ──►  then package  ──►  breakage = packaging bug
```

On a fresh machine that means: clone, `python -m venv venv`, activate,
`pip install -r requirements-<os>.txt`, put the API key in `.env`, run
`python main.py`, and work through `TEST_REPORT_TEMPLATE.md`. Only then
continue below.

## Building the bundle (all platforms)

One spec file, platform-conditional: [`packaging/aegis.spec`](aegis.spec).
Build **from the repo root**:

```
pip install pyinstaller
pyinstaller packaging/aegis.spec
```

Output lands in `dist/` (gitignored):

| Platform | Output | Mode |
|----------|--------|------|
| macOS    | `dist/Aegis.app` | menu-bar-only app (`LSUIElement`), windowed |
| Windows  | `dist/Aegis/` (onedir with `Aegis.exe`) | console kept ON for alpha builds — see the spec comment |
| Linux    | `dist/Aegis/` | console |

The timeline UI (`ui/timeline_app.py`) is deliberately not bundled — it's a
developer tool until the v2 dashboard exists, and PySide6 would triple the
bundle size for something `main.py` never imports.

## Where a packaged build keeps its files

Running from source keeps v1 behavior (`events.log` / `aegis_events.db`
relative to the checkout). A **frozen** build can't do that — a
Finder-launched `.app` has `/` as its working directory and Program Files
isn't user-writable — so `core/config.py` anchors relative paths to a
per-user data directory instead:

| Platform | Data directory |
|----------|----------------|
| macOS    | `~/Library/Application Support/Aegis/` |
| Windows  | `%LOCALAPPDATA%\Aegis\` |
| Linux    | `~/.local/share/aegis/` |

That same directory is also where a packaged user configures Aegis, since
editing files inside an installed bundle is not a reasonable ask:

- **`.env`** in the data dir → API key (`NVIDIA_API_KEY=...`). The checkout's
  `.env` is never bundled.
- **`config.yaml`** in the data dir → overrides the bundled default config
  entirely.

## Windows installer

[`packaging/windows-installer.iss`](windows-installer.iss) is an Inno Setup 6
script: installs the onedir bundle to Program Files, Start Menu shortcuts,
an **opt-in, unchecked-by-default** "start at login" task, and an
uninstaller that removes the app but deliberately preserves
`%LOCALAPPDATA%\Aegis` (the event history is an audit trail; uninstall
shouldn't destroy it).

The version string in the `.iss` duplicates `core/version.py` because Inno
Setup can't import Python — **bump both together**.

macOS gets no installer for the alpha: drag `Aegis.app` to `/Applications`.
A DMG (`create-dmg`) is a beta task.

## Verification status (held to the ARCHITECTURE.md standard)

- **macOS bundle: built and smoke-run on real hardware** (Apple Silicon,
  Python 3.14, PyInstaller 6.21) — see the build/run log summary in the PR
  or session notes for what exactly was observed.
- **Windows bundle: never built.** The spec's Windows branch (hidden plyer
  backend import, icon, console flag, excludes) follows PyInstaller
  documentation but has zero hardware evidence behind it (ADR-008 applies).
- **Windows installer: never compiled.** Treat the first Inno Setup build as
  part of Windows validation.

## One-click release: `packaging/release.command`

Double-click it (or run it from a terminal) to bump the version, commit,
tag, push, and then watch GitHub Actions build and publish the release --
the same manual sequence above, automated end to end, including confirming
the published release actually has installable assets attached (an empty or
unparseable-tag release, both of which have happened before, would otherwise
silently look fine). Writes a timestamped log to `packaging/release-logs/`
and fires a macOS notification with the outcome, so a run kicked off
unattended still tells you what happened. See the script's own header
comment for the exact sequence and requirements (a git remote that can push
without an interactive prompt).

## Known limitations (alpha)

- **Unsigned builds.** macOS: PyInstaller ad-hoc signs the bundle; on
  another Mac, Gatekeeper will require right-click → Open the first time.
  Windows: SmartScreen will warn on the installer. Real signing
  (Developer ID + notarization, Authenticode) is a post-beta task and costs
  money — do it once releases are public.
- **No `.icns`** — Finder shows the generic app icon (the tray icon itself
  is fine; it's loaded at runtime from `assets/tray_icon.png`).
- **Windows console window** is intentionally visible in alpha builds for
  validation; flip `console` in the spec at beta.
