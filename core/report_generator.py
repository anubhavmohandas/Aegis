"""
Renders the dashboard's "Export PDF Report" feature: takes the events for a
requested time range, asks the configured AI provider for an executive
summary (AIExplainer.summarize_period), and lays out a printable PDF with
fpdf2 (pure Python -- no system PDF/HTML engine, so it packages the same way
the rest of Aegis does).

Presentation only, same caveat as core/ai_explainer.py: the narrative
section is a convenience summary, not a security verdict -- every event in
the table beneath it is the actual, unfiltered record, computed locally from
`events`, never from what the AI said about them.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from .ai_explainer import AIExplainer
from .config import AppConfig
from .version import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGO_PATH = REPO_ROOT / "assets" / "logo.png"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SOURCE_LABELS = {"process": "Process", "usb": "USB", "startup": "Startup", "folder": "Folder"}

# Print-safe palette: same hues as the dashboard's "daylight" (light) theme,
# not the dark console theme -- chosen for contrast on a white printed page.
NAVY = (11, 15, 22)
INK = (24, 33, 47)
INK_2 = (75, 90, 113)
INK_3 = (130, 145, 167)
BORDER = (223, 228, 237)
PANEL = (247, 249, 252)
TEAL = (13, 125, 140)
SEV_COLOR = {
    "critical": (204, 34, 68),
    "high": (162, 56, 10),
    "medium": (176, 128, 0),
    "low": (53, 103, 168),
}

PAGE_W = 210  # A4 mm
MARGIN = 14
CONTENT_W = PAGE_W - 2 * MARGIN


def format_range_label(start: float, end: float) -> str:
    s = time.strftime("%b %-d, %Y", time.localtime(start))
    e = time.strftime("%b %-d, %Y", time.localtime(end))
    return s if s == e else f"{s} - {e}"


def _letterspaced(s: str, gap: str = " ") -> str:
    return gap.join(s.upper())


# fpdf2's built-in Helvetica is a Latin-1 (not Unicode) font -- it raises
# instead of silently dropping a glyph. AI-generated text and event data
# (filenames, app names, ...) can contain smart quotes/dashes/bullets/emoji
# well outside Latin-1, and a report must never 500 because of what the AI
# happened to write. Map the common typographic characters to their ASCII
# equivalent, then replace anything left over that still doesn't fit.
_ASCII_MAP = str.maketrans({
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "–": "-", "—": "-", "…": "...", "•": "-", " ": " ",
})


def _safe(text) -> str:
    return str(text).translate(_ASCII_MAP).encode("latin-1", errors="replace").decode("latin-1")


def _sev_key(ev: dict) -> int:
    sev = ev.get("severity", "low")
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


class _ReportPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return  # the cover page draws its own full-bleed layout
        self.set_fill_color(*NAVY)
        self.rect(0, 0, self.w, 16, style="F")
        self.set_xy(MARGIN, 4)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(255, 255, 255)
        self.cell(60, 8, "AEGIS", new_x=XPos.LEFT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(140, 195, 190)
        self.set_xy(PAGE_W - MARGIN - 90, 6)
        self.cell(90, 6, _letterspaced("Security Activity Report"), align="R")
        self.set_y(24)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_draw_color(*BORDER)
        self.line(MARGIN, self.get_y(), PAGE_W - MARGIN, self.get_y())
        self.set_y(-12)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*INK_3)
        self.cell(CONTENT_W - 20, 8,
                  f"Aegis {__version__} - AI narrative is a convenience summary, not a security verdict.")
        self.cell(20, 8, f"Page {self.page_no() - 1}", align="R")

    def section_title(self, text: str):
        self.ln(4)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*TEAL)
        self.cell(0, 8, _letterspaced(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*BORDER)
        self.line(MARGIN, self.get_y(), PAGE_W - MARGIN, self.get_y())
        self.ln(4)


def _summary_prompt_block(events: list[dict], stats: dict, range_label: str) -> str:
    lines = [
        f"Report period: {range_label}",
        f"Total events: {stats['total']}",
        "By severity: " + ", ".join(f"{k}={stats['by_severity'].get(k, 0)}" for k in SEVERITY_ORDER),
        "By source: " + ", ".join(f"{SOURCE_LABELS.get(k, k)}={v}" for k, v in stats["by_source"].items()) or "none",
        "",
        "Highest-severity events in this period (subset):",
    ]
    top = sorted(events, key=lambda e: (_sev_key(e), -e.get("timestamp", 0)))[:15]
    for ev in top:
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(ev.get("timestamp", 0)))
        lines.append(f"- [{ev.get('severity', '?')}] {ts} {SOURCE_LABELS.get(ev.get('source'), ev.get('source'))}: "
                     f"{ev.get('summary', '')}")
    if not top:
        lines.append("(no events in this period)")
    return "\n".join(lines)


def _compute_stats(events: list[dict]) -> dict:
    by_severity = Counter(ev.get("severity", "low") for ev in events)
    by_source = Counter(ev.get("source", "unknown") for ev in events)
    by_category = Counter(ev.get("category", "unknown") for ev in events)
    explained = sum(1 for ev in events if not ev.get("ai_skipped"))
    return {
        "total": len(events),
        "by_severity": by_severity,
        "by_source": by_source,
        "by_category": by_category,
        "explained": explained,
        "hicrit": by_severity.get("high", 0) + by_severity.get("critical", 0),
    }


def generate_pdf_report(events: list[dict], range_label: str, range_start: float,
                         range_end: float, config: AppConfig) -> bytes:
    stats = _compute_stats(events)
    summary_text = AIExplainer(config).summarize_period(_summary_prompt_block(events, stats, range_label))

    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.set_margins(MARGIN, MARGIN, MARGIN)

    _draw_cover(pdf, stats, range_label)
    pdf.add_page()
    _draw_summary(pdf, summary_text)
    _draw_stat_tiles(pdf, stats)
    _draw_severity_bar(pdf, stats)
    _draw_breakdown(pdf, stats)
    _draw_event_table(pdf, events)

    return bytes(pdf.output())


def _draw_cover(pdf: _ReportPDF, stats: dict, range_label: str):
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, pdf.h, style="F")

    if LOGO_PATH.is_file():
        logo_w = 30
        pdf.image(str(LOGO_PATH), x=(PAGE_W - logo_w) / 2, y=46, w=logo_w)

    pdf.set_y(88)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, _letterspaced("AEGIS", "  "), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(120, 200, 190)
    pdf.cell(0, 8, _letterspaced("Security Activity Report"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(6)
    pdf.set_draw_color(60, 75, 95)
    pdf.line(PAGE_W / 2 - 20, pdf.get_y(), PAGE_W / 2 + 20, pdf.get_y())

    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(230, 236, 245)
    pdf.cell(0, 10, _safe(range_label), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(140, 155, 178)
    generated = time.strftime("Generated %B %-d, %Y at %-I:%M %p")
    pdf.cell(0, 7, generated, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # cover stat trio, echoing the dashboard's own stat tiles
    pdf.set_y(215)
    col_w = CONTENT_W / 3
    trio = [
        (str(stats["total"]), "Total Events"),
        (str(stats["hicrit"]), "High / Critical"),
        (f"{len(stats['by_source'])}", "Active Sources"),
    ]
    trio_y = pdf.get_y()  # fixed baseline -- re-reading get_y() per column would drift,
                          # since each column's label cell leaves the cursor wherever it ended
    for i, (value, label) in enumerate(trio):
        x = MARGIN + i * col_w
        pdf.set_xy(x, trio_y)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(*(230, 90, 110) if label == "High / Critical" and value != "0" else (255, 255, 255))
        pdf.cell(col_w, 12, value, align="C")
        pdf.set_xy(x, trio_y + 12)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(140, 155, 178)
        pdf.cell(col_w, 6, _letterspaced(label), align="C")
    pdf.set_y(255)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(90, 105, 128)
    pdf.cell(0, 6, "AI explanations are a convenience layer, not a security verdict.", align="C")


def _draw_summary(pdf: _ReportPDF, summary_text: str):
    pdf.section_title("Executive Summary")
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(*INK)
    for para in _safe(summary_text).split("\n"):
        para = para.strip()
        if not para:
            pdf.ln(2)
            continue
        if para.startswith(("- ", "* ")):
            pdf.set_x(MARGIN + 4)
            pdf.multi_cell(CONTENT_W - 4, 6, f"- {para[2:]}")
        else:
            pdf.multi_cell(CONTENT_W, 6, para)


def _draw_stat_tiles(pdf: _ReportPDF, stats: dict):
    pdf.section_title("Activity At A Glance")
    tiles = [
        ("Total Events", str(stats["total"])),
        ("High / Critical", str(stats["hicrit"])),
        ("Active Sources", str(len(stats["by_source"]))),
        ("AI-Explained", f"{stats['explained']}/{stats['total']}" if stats["total"] else "0/0"),
    ]
    gap = 5
    tile_w = (CONTENT_W - gap * 3) / 4
    y = pdf.get_y()
    for i, (label, value) in enumerate(tiles):
        x = MARGIN + i * (tile_w + gap)
        pdf.set_draw_color(*BORDER)
        pdf.set_fill_color(*PANEL)
        pdf.rect(x, y, tile_w, 20, style="DF")
        pdf.set_xy(x + 3, y + 3)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*INK_3)
        pdf.cell(tile_w - 6, 5, _letterspaced(label))
        pdf.set_xy(x + 3, y + 9)
        pdf.set_font("Helvetica", "B", 15)
        pdf.set_text_color(*INK)
        pdf.cell(tile_w - 6, 8, value)
    pdf.set_y(y + 20)
    pdf.ln(6)


def _draw_severity_bar(pdf: _ReportPDF, stats: dict):
    total = sum(stats["by_severity"].get(s, 0) for s in SEVERITY_ORDER)
    y = pdf.get_y()
    bar_h = 6
    pdf.set_draw_color(*BORDER)
    if total == 0:
        pdf.set_fill_color(*PANEL)
        pdf.rect(MARGIN, y, CONTENT_W, bar_h, style="DF")
    else:
        x = MARGIN
        for sev in SEVERITY_ORDER:
            count = stats["by_severity"].get(sev, 0)
            if not count:
                continue
            seg_w = CONTENT_W * count / total
            pdf.set_fill_color(*SEV_COLOR[sev])
            pdf.rect(x, y, seg_w, bar_h, style="F")
            x += seg_w
    pdf.set_y(y + bar_h + 3)

    pdf.set_font("Helvetica", "", 8.5)
    legend_x = MARGIN
    for sev in SEVERITY_ORDER:
        count = stats["by_severity"].get(sev, 0)
        pdf.set_xy(legend_x, pdf.get_y())
        pdf.set_fill_color(*SEV_COLOR[sev])
        pdf.rect(legend_x, pdf.get_y() + 1, 3, 3, style="F")
        pdf.set_text_color(*INK_2)
        pdf.set_x(legend_x + 4.5)
        pdf.cell(30, 5, f"{sev} {count}")
        legend_x += 32
    pdf.ln(9)


def _draw_breakdown(pdf: _ReportPDF, stats: dict):
    if not stats["by_category"]:
        return
    pdf.section_title("Top Categories")
    pdf.set_font("Helvetica", "", 9.5)
    top_categories = stats["by_category"].most_common(8)
    max_count = top_categories[0][1] if top_categories else 1
    for category, count in top_categories:
        y = pdf.get_y()
        label = _safe(str(category).replace("_", " "))
        pdf.set_text_color(*INK)
        pdf.set_x(MARGIN)
        pdf.cell(55, 6, label)
        bar_max_w = CONTENT_W - 55 - 12
        bar_w = max(2, bar_max_w * count / max_count)
        pdf.set_fill_color(*TEAL)
        pdf.rect(MARGIN + 55, y + 1.2, bar_w, 3.6, style="F")
        pdf.set_xy(MARGIN + 55 + bar_max_w + 2, y)
        pdf.set_text_color(*INK_2)
        pdf.cell(10, 6, str(count), align="R")
        pdf.set_y(y + 6.5)
    pdf.ln(4)


def _draw_event_table(pdf: _ReportPDF, events: list[dict]):
    pdf.section_title(f"Event Log ({len(events)} events)")
    ordered = sorted(events, key=lambda e: (_sev_key(e), -e.get("timestamp", 0)))
    cap = 250
    shown = ordered[:cap]

    col_time, col_sev, col_src, col_summary = 26, 20, 22, CONTENT_W - 26 - 20 - 22
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*INK_3)
    pdf.set_x(MARGIN)
    for w, label in ((col_time, "TIME"), (col_sev, "SEVERITY"), (col_src, "SOURCE"), (col_summary, "SUMMARY")):
        pdf.cell(w, 6, label)
    pdf.ln(6)
    pdf.set_draw_color(*BORDER)
    pdf.line(MARGIN, pdf.get_y(), PAGE_W - MARGIN, pdf.get_y())
    pdf.ln(1.5)

    # Manual pagination for this loop only, auto_page_break turned off for the
    # duration: with both active, fpdf2's own auto-break (margin=22, set in
    # generate_pdf_report) can fire *inside* a row's cell() calls -- the row's
    # height alone (6.2mm) is enough to cross its trigger even when our own
    # `y > page_bottom` check just passed on the *previous* row. That silently
    # jumps to a new page mid-row while our loop still holds the stale
    # pre-break `y`, then our own check fires too on the next iteration using
    # that stale y -- two page breaks for one overflow, which is exactly what
    # produced a page with a single orphaned row and nothing else on it.
    pdf.set_auto_page_break(auto=False)
    row_h = 6.2
    pdf.set_font("Helvetica", "", 8.5)
    for i, ev in enumerate(shown):
        if pdf.get_y() + row_h > pdf.h - 20:
            pdf.add_page()
        y = pdf.get_y()
        if i % 2 == 0:
            pdf.set_fill_color(*PANEL)
            pdf.rect(MARGIN, y, CONTENT_W, row_h, style="F")
        pdf.set_xy(MARGIN, y)
        pdf.set_text_color(*INK_2)
        ts = time.strftime("%m/%d %H:%M", time.localtime(ev.get("timestamp", 0)))
        pdf.cell(col_time, row_h, ts)
        sev = ev.get("severity", "low")
        pdf.set_text_color(*SEV_COLOR.get(sev, INK_2))
        pdf.cell(col_sev, row_h, sev.upper())
        pdf.set_text_color(*INK_2)
        pdf.cell(col_src, row_h, _safe(SOURCE_LABELS.get(ev.get("source"), str(ev.get("source", "")))))
        pdf.set_text_color(*INK)
        summary = _safe(ev.get("summary", ""))
        if len(summary) > 95:
            summary = summary[:94] + "..."
        pdf.cell(col_summary, row_h, summary)
        pdf.set_y(y + row_h)
    pdf.set_auto_page_break(auto=True, margin=22)

    if len(events) > cap:
        pdf.ln(3)
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(*INK_3)
        pdf.multi_cell(CONTENT_W, 5,
                       f"Showing the {cap} highest-severity events of {len(events)} total in this period "
                       f"(highest severity first). Use Export CSV/JSON from the console for the full set.")
