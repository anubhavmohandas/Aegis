#!/usr/bin/env python3
"""Generate the Finder background art for the installer DMG.

A DMG built straight out of `hdiutil create -srcfolder` opens as a bare Finder
window: two items in whatever arrangement Finder feels like, no indication that
the gesture being asked for is "drag the left thing onto the right thing". Every
shipped Mac app solves this the same way -- a background image with the drop
target drawn on it, and the two icons pinned to positions that line up with the
art. packaging/make_dmg.sh does the pinning; this makes the art.

Outputs into assets/dmg/:
  background.png     640x400   -- 1x
  background@2x.png  1280x800  -- 2x (Retina)
  background.tiff              -- both of the above in one multi-representation
                                  file, which is what Finder actually reads

The .tiff is the deliverable. Finder's `background picture` only accepts a
single file, so the only way to ship both scale factors is a multi-page TIFF
built by `tiffutil -cathidpicheck` (ships with macOS). Point Finder at a plain
@1x PNG instead and it renders soft on every Mac sold in the last decade; point
it at the @2x PNG and the art comes out double size and cropped.

ICON_* below must stay in sync with the same constants in make_dmg.sh -- they
are what makes the drawn drop-target sit under the real Finder icon rather than
next to it. Change them in one place only and the arrow points at nothing.

Needs only Pillow (already in requirements-common.txt), same as make_icons.py.
Run from anywhere: `python packaging/make_dmg_background.py`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "assets" / "dmg"

# Finder window content size. The background is drawn at exactly these
# dimensions so that background pixel (x, y) == Finder icon coordinate (x, y).
WIDTH, HEIGHT = 640, 400

# Icon centres, mirrored in make_dmg.sh. y is shared: the two icons sit on one
# baseline so the arrow between them is horizontal.
ICON_Y = 185
ICON_X_APP = 170          # Aegis.app
ICON_X_APPLICATIONS = 470  # /Applications symlink

# Tagline sits below the *Finder-drawn* name label, not below the icon art: a
# 128px icon centred on ICON_Y ends at ICON_Y + 64, and Finder puts the label in
# the ~24px under that. Anything above ~280 collides with the word "Aegis".
TAGLINE_Y = 292

# Aegis palette, lifted from assets/logo.png: the shield's electric blue over
# the deep navy of the wordmark.
BLUE = (47, 134, 246)
NAVY = (27, 42, 68)
SLATE = (98, 116, 145)
GRAD_TOP = (244, 248, 254)
GRAD_BOTTOM = (216, 230, 250)

# Shapes are drawn on a canvas this many times larger, then downscaled with
# LANCZOS. ImageDraw has no anti-aliasing of its own, so without this every
# diagonal in the arrow comes out as a staircase.
SUPERSAMPLE = 3


def load_font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    """Best available system font at `size`, preferring the real macOS UI face.

    SFNS.ttf is the system font but it is a *variable* font -- Pillow opens it
    fine, yet whether the weight axis can be moved depends on the FreeType it
    was linked against, so treat a successful open as necessary but not
    sufficient and fall back the moment set_variation_by_name raises.
    """
    candidates: list[tuple[str, int]] = [
        ("/System/Library/Fonts/HelveticaNeue.ttc", 1 if bold else 0),
        ("/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold
         else "/System/Library/Fonts/Supplemental/Arial.ttf", 0),
        ("/System/Library/Fonts/Helvetica.ttc", 1 if bold else 0),
    ]
    if bold:
        try:
            font = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", size)
            font.set_variation_by_name("Bold")
            return font
        except Exception:
            pass
    else:
        try:
            return ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", size)
        except OSError:
            pass

    for path, index in candidates:
        try:
            return ImageFont.truetype(path, size, index=index)
        except OSError:
            continue
    return ImageFont.load_default()


def gradient(scale: int) -> Image.Image:
    """Vertical wash from GRAD_TOP to GRAD_BOTTOM."""
    img = Image.new("RGB", (WIDTH * scale, HEIGHT * scale))
    draw = ImageDraw.Draw(img)
    height = HEIGHT * scale
    for y in range(height):
        t = y / max(height - 1, 1)
        draw.line(
            [(0, y), (WIDTH * scale, y)],
            fill=tuple(
                round(a + (b - a) * t) for a, b in zip(GRAD_TOP, GRAD_BOTTOM)
            ),
        )
    return img


def radial_glow(scale: int, cx: int, cy: int, radius: int,
                colour: tuple[int, int, int], peak_alpha: int) -> Image.Image:
    """Soft circular falloff, used both for the centre wash and the icon pads.

    Drawn as concentric ellipses from the outside in; at these radii the banding
    is well under one 8-bit step, and it is an order of magnitude cheaper than
    evaluating the falloff per pixel.
    """
    layer = Image.new("RGBA", (WIDTH * scale, HEIGHT * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    steps = 64
    for i in range(steps, 0, -1):
        t = i / steps
        r = radius * scale * t
        alpha = round(peak_alpha * (1 - t) ** 1.6)
        if alpha <= 0:
            continue
        draw.ellipse(
            [cx * scale - r, cy * scale - r, cx * scale + r, cy * scale + r],
            fill=(*colour, alpha),
        )
    return layer


def draw_shapes(scale: int) -> Image.Image:
    """Arrow, circuit traces and their supersampled anti-aliasing."""
    ss = scale * SUPERSAMPLE
    layer = Image.new("RGBA", (WIDTH * ss, HEIGHT * ss), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)

    # Three chevrons pointing at the Applications folder, fading in towards it,
    # which reads as direction of travel without needing a caption to explain
    # the gesture.
    chevron_w, chevron_h = 15, 26
    for offset, alpha in ((-34, 132), (0, 190), (34, 255)):
        cx = (WIDTH // 2 + offset) * ss
        cy = ICON_Y * ss
        draw.line(
            [
                (cx - chevron_w * ss // 2, cy - chevron_h * ss // 2),
                (cx + chevron_w * ss // 2, cy),
                (cx - chevron_w * ss // 2, cy + chevron_h * ss // 2),
            ],
            fill=(*BLUE, alpha),
            width=max(1, 5 * ss),
            joint="curve",
        )

    # Circuit traces echoing the right-hand side of the shield in the logo.
    # Kept to the top-right corner at low alpha: this is texture, and anything
    # with enough contrast to be read as content competes with the two icons.
    # The bottom-left corner is deliberately left bare -- it is where the
    # tagline under the app icon lands, and traces behind small 10px type read
    # as strikethrough rather than as background.
    traces = [
        [(516, 40), (566, 40), (586, 60), (620, 60)],
        [(546, 74), (566, 74), (592, 100), (620, 100)],
        [(560, 18), (580, 18), (600, 38)],
    ]
    for points in traces:
        scaled = [(x * ss, y * ss) for x, y in points]
        draw.line(scaled, fill=(*BLUE, 46), width=max(1, 2 * ss), joint="curve")
        vx, vy = scaled[-1]
        r = 3 * ss
        draw.ellipse([vx - r, vy - r, vx + r, vy + r], fill=(*BLUE, 62))

    return layer.resize((WIDTH * scale, HEIGHT * scale), Image.LANCZOS)


def draw_tracked_text(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str,
                      font: ImageFont.FreeTypeFont, fill, tracking: float) -> None:
    """Centred text with manual letter-spacing.

    Pillow has no tracking control, so the string is measured per character and
    placed by hand; without it the small-caps wordmark sets far too tight to
    read as a wordmark.
    """
    widths = [draw.textlength(ch, font=font) for ch in text]
    total = sum(widths) + tracking * (len(text) - 1)
    x = xy[0] - total / 2
    for ch, w in zip(text, widths):
        draw.text((x, xy[1]), ch, font=font, fill=fill, anchor="lm")
        x += w + tracking


def render(scale: int) -> Image.Image:
    img = gradient(scale).convert("RGBA")

    # Centre wash lifts the middle of the window away from the flat gradient.
    img.alpha_composite(radial_glow(scale, WIDTH // 2, ICON_Y, 250, BLUE, 26))

    # Pads behind each icon slot. The Finder icons composite straight onto the
    # background with no shadow of their own, so without something brighter
    # underneath they sink into the gradient.
    for cx in (ICON_X_APP, ICON_X_APPLICATIONS):
        img.alpha_composite(
            radial_glow(scale, cx, ICON_Y - 6, 96, (255, 255, 255), 190)
        )

    img.alpha_composite(draw_shapes(scale))

    draw = ImageDraw.Draw(img)
    draw_tracked_text(
        draw, (WIDTH // 2 * scale, 52 * scale), "AEGIS",
        load_font(21 * scale, bold=True), (*NAVY, 255), 7.0 * scale,
    )
    # The tagline rides under the app icon rather than under the wordmark, so
    # the left-hand column reads as one lockup: icon, name, what it is. Finder
    # supplies the middle line for free -- it is the item's own filename label.
    draw_tracked_text(
        draw, (ICON_X_APP * scale, TAGLINE_Y * scale),
        "AI-Powered Desktop Security Assistant",
        load_font(10 * scale), (*SLATE, 245), 0.25 * scale,
    )
    draw_tracked_text(
        draw, (WIDTH // 2 * scale, 350 * scale),
        "Drag Aegis into your Applications folder",
        load_font(13 * scale), (*SLATE, 255), 0.35 * scale,
    )

    return img.convert("RGB")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    one_x = OUT_DIR / "background.png"
    two_x = OUT_DIR / "background@2x.png"
    tiff = OUT_DIR / "background.tiff"

    render(1).save(one_x)
    render(2).save(two_x)
    print(f"wrote {one_x.relative_to(ROOT)} ({WIDTH}x{HEIGHT})")
    print(f"wrote {two_x.relative_to(ROOT)} ({WIDTH * 2}x{HEIGHT * 2})")

    # -cathidpicheck is the flag that marks the second representation as the
    # HiDPI variant of the first rather than as a second unrelated page.
    try:
        subprocess.run(
            ["tiffutil", "-cathidpicheck", str(one_x), str(two_x),
             "-out", str(tiff)],
            check=True, capture_output=True,
        )
    except FileNotFoundError:
        print("warning: tiffutil not found (macOS only) -- skipped background.tiff",
              file=sys.stderr)
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"error: tiffutil failed: {exc.stderr.decode().strip()}", file=sys.stderr)
        return 1

    print(f"wrote {tiff.relative_to(ROOT)} (1x + 2x)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
