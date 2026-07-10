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
export ANTHROPIC_API_KEY=sk-...                       # optional — runs fine without one
python main.py
```

Windows needs an **Administrator** terminal for full process-monitoring
power. macOS will prompt for Automation permission the first time it checks
login items. Run `python ui/timeline_app.py` separately to browse history.

## Status

macOS has been tested live on real hardware — process, folder, USB, and
notifications all confirmed working, three real bugs found and fixed along
the way. Windows is written but not yet run on real hardware. Full
verification log, architecture, and every known gap: **[`ARCHITECTURE.md`](ARCHITECTURE.md)**.

---

<p align="center">Created with love by Anubhav 🛡️</p>
