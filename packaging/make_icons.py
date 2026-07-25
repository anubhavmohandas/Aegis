#!/usr/bin/env python3
"""Regenerate every icon asset from assets/logo.png.

All three shipped icons were the same mistake: assets/logo.png -- the full
marketing lockup (shield + AEGIS wordmark + tagline, on an opaque black
square) -- used verbatim as an app icon.

  * aegis.icns had no macOS icon grid. Every other app icon is a rounded
    "squircle" body inset inside its 1024 canvas, so a full-bleed square
    renders visibly LARGER than its neighbours even though the canvas
    matches -- the icon that ignores the padding is the one that looks
    oversized in the Dock and Cmd-Tab.
  * aegis.ico contained a single 16x16 image, so Windows upscaled it for the
    taskbar (32), shortcuts (48) and Alt-Tab (256). It's also the installer's
    SetupIconFile.
  * tray_icon.png kept the opaque black background, which renders as a black
    square in the macOS menu bar instead of adapting to it.

And in all three the wordmark and tagline are illegible below ~128px, which
is every size that actually gets drawn (Dock ~64-128, Cmd-Tab ~128, menu bar
~22, Finder list 16-32). Apple's and Microsoft's own icons are a single glyph
for exactly this reason.

So: crop to the shield alone, then lay it out per platform.

Needs only Pillow (already in requirements-common.txt) and, for the .icns,
iconutil (ships with macOS). Run from anywhere:
`python packaging/make_icons.py`
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
LOGO = ROOT / "assets" / "logo.png"
OUT_ICNS = ROOT / "assets" / "aegis.icns"
OUT_ICO = ROOT / "assets" / "aegis.ico"
OUT_TRAY = ROOT / "assets" / "tray_icon.png"

# --- Apple's macOS (Big Sur and later) app icon grid -------------------------
# On a 1024pt canvas the icon body is an 824pt rounded square, centred, which
# leaves 100pt of transparent padding on every side. These are not arbitrary
# -- they're what makes an icon sit at the same visual weight as its Dock
# neighbours.
CANVAS = 1024
BODY = 824
PAD = (CANVAS - BODY) // 2

# macOS corners are a continuous-curvature "squircle" (a superellipse), not a
# circular-arc rounded rect. n=5 is the standard fit; a plain rounded
# rectangle reads subtly but noticeably wrong next to real icons.
SQUIRCLE_N = 5
SUPERSAMPLE = 4  # render the mask big, downsample -> free antialiasing

# Sampled from logo.png's own background (1,1,7), lifted a touch so the body
# doesn't read as a hole punched in a dark Dock.
BODY_FILL = (10, 14, 24, 255)

# Shield bounding box within logo.png, measured by luminance-thresholding the
# rows/columns (the wordmark band starts at y=840, so this stops short of it).
SHIELD_BOX = (376, 148, 879, 790)

# Fraction of the body's height the shield occupies. Apple's glyphs sit around
# 55-65% for a framed icon; below that the icon looks empty, above it the
# glyph crowds the corners.
GLYPH_HEIGHT_RATIO = 0.64


def squircle_mask(size: int, n: int = SQUIRCLE_N) -> Image.Image:
    """8-bit alpha mask of a superellipse |x/a|^n + |y/a|^n = 1."""
    big = size * SUPERSAMPLE
    mask = Image.new("L", (big, big), 0)
    draw = ImageDraw.Draw(mask)
    a = big / 2
    # One horizontal span per row: solve for x at each y. Cheap, exact, and
    # antialiased by the downsample below.
    for i in range(big):
        y = (i + 0.5) - a
        t = 1 - abs(y / a) ** n
        if t <= 0:
            continue
        half = a * (t ** (1 / n))
        draw.line([(a - half, i), (a + half, i)], fill=255)
    return mask.resize((size, size), Image.LANCZOS)


def extract_glyph() -> Image.Image:
    """Crop the shield out of logo.png and give it a real alpha channel.

    The artwork is additive on a pure-black field (glows, soft metallic
    edges), so the correct un-premultiply is alpha = max(r,g,b) with the
    colour divided back out. Compositing that over any background reproduces
    the intended 'screen against black' look -- a hard threshold or a plain
    rectangular paste would either clip the glow or leave a visible seam.
    """
    shield = Image.open(LOGO).convert("RGB").crop(SHIELD_BOX)
    out = Image.new("RGBA", shield.size)
    src, dst = shield.load(), out.load()
    for y in range(shield.height):
        for x in range(shield.width):
            r, g, b = src[x, y]
            a = max(r, g, b)
            if a == 0:
                continue
            s = 255 / a
            dst[x, y] = (min(255, int(r * s)), min(255, int(g * s)),
                         min(255, int(b * s)), a)
    return out


def _place_glyph(body: Image.Image, glyph: Image.Image, ratio: float) -> None:
    """Scale the shield to `ratio` of the body's height and composite it,
    optically centred. The shield's visual mass sits high (it tapers to a
    point at the bottom), so a true arithmetic centre looks bottom-heavy --
    nudge up by 1.5% of the body."""
    h = int(body.height * ratio)
    w = round(glyph.width * h / glyph.height)
    glyph = glyph.resize((w, h), Image.LANCZOS)
    body.alpha_composite(glyph, ((body.width - w) // 2,
                                 (body.height - h) // 2 - int(body.height * 0.015)))


def build_icon() -> Image.Image:
    """macOS: squircle body on Apple's 1024/824 grid."""
    body = Image.new("RGBA", (BODY, BODY), BODY_FILL)
    body.putalpha(squircle_mask(BODY))
    _place_glyph(body, extract_glyph(), GLYPH_HEIGHT_RATIO)

    canvas = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    canvas.paste(body, (PAD, PAD), body)
    return canvas


def build_windows_icon() -> Image.Image:
    """Windows: full-bleed square. Windows does NOT mask icon corners the way
    macOS does, so the squircle+padding treatment above would just render as
    a smaller icon with wasted canvas here."""
    body = Image.new("RGBA", (CANVAS, CANVAS), BODY_FILL)
    _place_glyph(body, extract_glyph(), 0.72)
    return body


def build_tray_icon() -> Image.Image:
    """Menu bar / system tray: shield on transparent, no plate. The opaque
    black background is what made this render as a black square in the macOS
    menu bar; transparent reads correctly on both light and dark."""
    canvas = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    _place_glyph(canvas, extract_glyph(), 0.92)
    return canvas


def write_icns(icon: Image.Image, dest: Path) -> None:
    if not shutil.which("iconutil"):
        sys.exit("iconutil not found -- this script only runs on macOS.")
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "aegis.iconset"
        iconset.mkdir()
        for base in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                px = base * scale
                suffix = "@2x" if scale == 2 else ""
                icon.resize((px, px), Image.LANCZOS).save(
                    iconset / f"icon_{base}x{base}{suffix}.png")
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(dest)],
                       check=True)


if __name__ == "__main__":
    if not LOGO.is_file():
        sys.exit(f"missing source artwork: {LOGO}")

    icon = build_icon()
    write_icns(icon, OUT_ICNS)

    # Every size Windows actually asks for: 16 (Explorer list), 32 (taskbar),
    # 48 (desktop shortcut), 256 (Alt-Tab). Pillow writes them into one .ico.
    build_windows_icon().save(
        OUT_ICO, sizes=[(s, s) for s in (16, 32, 48, 64, 128, 256)])

    for p in (OUT_ICNS, OUT_ICO):
        print(f"wrote {p.relative_to(ROOT)} ({p.stat().st_size:,} bytes)")

    # Self-checks: the whole point is the geometry, so assert it rather than
    # eyeballing a 1024px PNG. Catches a bad crop or a broken mask.
    a = icon.split()[3]
    assert a.getbbox() == (PAD, PAD, CANVAS - PAD, CANVAS - PAD), \
        f"macOS body not on Apple's grid: {a.getbbox()}"
    assert a.getpixel((PAD + 2, PAD + 2)) < 40, "macOS corner not rounded"
    assert a.getpixel((CANVAS // 2, PAD + 2)) == 255, "macOS top edge should be solid"

    with Image.open(OUT_ICO) as ico:
        assert ico.ico.sizes() >= {(16, 16), (32, 32), (48, 48), (256, 256)}, \
            f"Windows .ico missing sizes: {ico.ico.sizes()}"

    print("checks passed: Apple 824/1024 grid, .ico 16-256")
