# Design System: Aegis — audit record

## 2026-07-13, step 1 result — `ui-ux-pro-max/scripts/search.py --design-system`

Query: `"desktop security monitoring assistant developer tool dark console"`

Recommended: Dark Mode (OLED) style; colors Primary `#1E293B`, Accent
`#22C55E` (green), Background `#0F172A`, Foreground `#F8FAFC`, slate/grey
supporting palette; typography Inter (heading + body); pattern "Trust &
Authority + Conversion."

## 2026-07-13, step 2 — `integrations/webdev.py tokens --out`

Emitted placeholder defaults correctly (by design — "the defaults are
placeholders, not a brand"). Overwritten with real values, see history below.

## Decision history

1. **First pass:** kept the original logo-derived palette (chrome `#dbe4f0`,
   electric blue `#39a1ff`, Chakra Petch + IBM Plex) and only wired
   `tokens.css` in as a linked file instead of an inline duplicate. No visual
   change — reasoning was a real logo is a stronger signal than a generic
   industry-category match.
2. **Repainted, on request:** switched the live site to the search.py
   recommendation (slate-navy `#0f172a` bg, green `#22c55e` accent, Inter).
   Shipped, then verified for leftover old-color traces (zero found).
3. **Reverted, on request:** "pehle wala color hi better" — switched back to
   the original chrome/electric-blue/Chakra Petch palette. Verified zero
   leftover green/Inter traces and confirmed every CSS variable the page
   uses is still defined after the revert.

## What's actually live now (as of the revert)

The original palette: `--bg: #04070e`, `--panel: #0a1120`, `--chrome:
#dbe4f0`, `--blue: #39a1ff` (real blue), `--font-display`/`--font-body`:
Chakra Petch / IBM Plex Sans, `--font-mono`: IBM Plex Mono, `--font-pixel`:
Silkscreen. This matches what originally shipped, including every hardcoded
(non-token) accent shade in `index.html`'s inline `<style>` block — the
revert was done line-by-line against the exact pre-repaint values, not a
blind reverse-substitution, because several distinct original shades had
collapsed onto the same repainted value and a naive reverse would have
mixed them up.

The green-accent/slate/Inter repaint is preserved in this file's git history
(if committed) and in step 3 above — not currently on the live page.

## Still true regardless of which palette is live

- `--font-mono` / `--font-pixel` were never touched by either pass — not
  covered by the search.py recommendation, load-bearing for the console-mock
  and retro labels either way.
- Severity chip colors (`--sev-low/med/high/crit`) were never touched —
  functional status colors, not brand identity.
- Logo assets (`assets/logo.png`, `assets/tray_icon.png`, `assets/aegis.ico`)
  were never regenerated in either direction — moot now since the palette is
  back to what the logo was originally derived from, so there's no mismatch
  to flag anymore.

## Files in this directory

- `tokens.css` — linked from `../index.html`'s `<head>`, single source of
  truth for the color/font custom properties. Currently holds the original
  (reverted) palette.
- `tokens.json` — same values, JS-consumable mirror.
