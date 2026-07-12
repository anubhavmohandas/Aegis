<p align="center">
  <img src="assets/logo.png" width="160" alt="Aegis logo">
</p>

<h1 align="center">Aegis</h1>
<p align="center"><b>AI-powered desktop security assistant for Windows, macOS, and Linux.</b></p>

Aegis watches your machine in the background — new processes, USB devices,
startup persistence, and your Desktop/Downloads/Documents folders — and
explains what it sees in plain English using Claude or OpenAI, with a local
severity score (low/medium/high/critical) computed before any AI call.
Everything's logged to a searchable timeline. **Not antivirus. No security
guarantees. A personal awareness tool, not a detector.**

## Quick start

```
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements-macos.txt                # or -windows.txt / -linux.txt
echo "NVIDIA_API_KEY=nvapi-..." > .env                # optional — runs fine without one
python main.py
```

The AI layer speaks to any OpenAI-compatible endpoint (NVIDIA, OpenAI,
OpenRouter, local Ollama) or Anthropic — pick provider/model/key in
`config/config.yaml`. Windows needs an **Administrator** terminal for full
process-monitoring power. macOS will prompt for Automation permission the
first time it checks login items. Run `python ui/timeline_app.py` separately
to browse history. Notification noise too high? Raise the popup floor with
`notify_min_severity: high` in config — everything still lands in the
timeline.

## Status — v2.0.0-alpha

Versioning tracks validation, not features: **alpha** = features done, macOS
validated; **beta** = Windows also validated on real hardware; **2.0.0** =
public release.

- ✅ Multi-provider AI (OpenAI-compatible + Anthropic)
- ✅ macOS validation on real hardware — process, folder, USB, notifications;
  three real bugs found and fixed along the way
- ✅ Native macOS notification backend (osascript primary, plyer no longer
  involved on Mac)
- ✅ Noise reduction: opt-in trusted lists, dedupe, rate limiting, and a
  configurable popup severity floor
- ✅ Packaging: `pyinstaller packaging/aegis.spec` — macOS `.app` built and
  smoke-run on real hardware ([`packaging/PACKAGING.md`](packaging/PACKAGING.md))
- 🔲 Windows validation — run from source first, then the packaged build
  ([`TEST_REPORT_TEMPLATE.md`](TEST_REPORT_TEMPLATE.md))
- 🔲 Windows installer — Inno Setup template written, never compiled
- 🔲 Dashboard UI (settings, timeline, search) — planned, deliberately after
  validation
- 🔲 Signed releases, screenshots & demo

Full verification log, architecture, and every known gap:
**[`ARCHITECTURE.md`](ARCHITECTURE.md)**. Engineering decisions:
**[`docs/DECISIONS.md`](docs/DECISIONS.md)**.

---

<p align="center">Created with ❤️ by Anubhav </p>
