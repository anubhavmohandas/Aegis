# The demo needs re-recording before the next push

`build-media.sh` cuts everything — the README GIF, the three README stills, the
four site clips — from two takes in `Videos/`. Both predate the drawer redesign,
so every generated asset now shows a UI the app does not have.

## What is stale, and why

| Asset | Why it's wrong now |
|---|---|
| `docs/media/macos-explain.png` | Shot at `Ask Aegis.mov` 10.6s, captioned "the AI Explanation tab". There is no AI tab: the analysis is a panel **above** the tab strip, and the tabs are Forensics / Raw / Related. |
| `docs/media/aegis-demo.gif` | Cut `[b]` (`Ask Aegis.mov` 9.4–13.0s) is that same tab click — the demo's whole "here is the AI" beat is a click on a control that no longer exists. |
| `media/incident.mp4` | Same footage, same click ("click -> drawer -> AI explanation"). |
| `docs/media/macos-dashboard.png`, `media/hero.mp4`, `media/memory.mp4`, `media/ask.mp4` | Timeline and Ask pages, structurally unchanged — but they intercut with the above, so a viewer sees two different drawers in one reel. |

This is the same failure the script's own header already documents for the
retired `Dashboard.mov` / `Daily Brief.mov`: footage kept past the UI change it
was shot against.

## The one question the recording has to answer

> **Can someone tell what Aegis is within the first 10 seconds?**

Not what it monitors. What it *does with what it monitors*. The old reel opened
on a dashboard, which reads as "another monitoring tool" for its first eight
seconds — the AI, the actual product, arrived at second twelve behind a tab
click. Open on the answer instead.

## Shot list — 45–60s

| # | Time | Shot | The point |
|---|---|---|---|
| 1 | 0:00–0:04 | Timeline, one **high** row visible. Click it. | Something happened. |
| 2 | 0:04–0:14 | **Hold on the open drawer, unscrolled.** Verdict + confidence, headline, AI panel. | The whole pitch. If a viewer stops here they still understand the product. |
| 3 | 0:14–0:22 | Scroll to Recommended action + Why. | It tells you what to do, and names what triggered it. |
| 4 | 0:22–0:32 | Forensics tab: signal table, then the fields. | The evidence is all still there. |
| 5 | 0:32–0:42 | Ask Aegis: question → cited answer. Cut the model's wait. | It answers questions about the history. |
| 6 | 0:42–0:50 | Password-gated Stop Monitoring. | It defends itself. |

Shot 2 is the one that has to land. Record it on an event whose drawer is worth
holding on: a **high or critical with a real Why list** — a VirusTotal detection
or an executable in a watched folder, not a bare `unsigned` on some third-party
app, which renders "high risk · low confidence" and one lukewarm line.
`python -m core.signals` shows what any given event produces.

Watch the cut back **with the sound off** before shipping it.

## After recording

Both takes must be re-shot together — `build-media.sh` intercuts them, so
replacing one leaves the reel showing two different drawers. Drop the new files
in `Videos/`, then retime: every `enc`/`shot`/`trim` timestamp in the script is
keyed to the old takes and none of them survive a re-record. Run
`./build-media.sh`, then check the README `alt` text and the caption on
`macos-explain.png` — both still describe the tab.
