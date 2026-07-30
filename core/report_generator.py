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

import logging
import time
from collections import Counter
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from .ai_explainer import AIExplainer
from .config import AppConfig
from .signals import confidence_for, signals_for
from .version import __version__

logger = logging.getLogger("aegis.report_generator")

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGO_PATH = REPO_ROOT / "assets" / "logo.png"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
# Medium is on the important side of the line deliberately: it is where the
# screenshot / LOLBin / USB-insert events land, which are precisely the ones a
# reader is opening the report to check on.
_IMPORTANT_SEVERITIES = ("critical", "high", "medium")
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
TONE_COLOR = {
    "ok": (17, 122, 86),
    "warn": (176, 128, 0),
    "bad": (204, 34, 68),
    "unknown": (100, 115, 138),
}

# WHAT THE VERDICT BLOCK IS FOR: a reader who opens this PDF is asking "should
# I worry?", and a table of 250 rows does not answer that -- it makes them do
# the analysis Aegis already did. This block answers it on page 2 and lets
# everything after it be supporting evidence.
#
# It is computed from core/signals.py -- the SAME rules the console's
# investigation drawer renders -- and never from a second table of its own. A
# report that calls a period "healthy" while the drawer shows a persistence
# entry on one of its events would be worse than shipping no verdict at all,
# and two rule sets is exactly how that happens.
#
# Pairs of (signal code, the thing being counted). Deliberately noun phrases
# rather than "No X detected": each row renders as `<thing> ..... None` or
# `<thing> ..... 2 observed`, so one label stays truthful in both directions --
# a negated label ("No tamper attempts") reads as a lie the moment the count is
# non-zero, which is exactly the row a reader is most likely to be scanning for.
#
# And the verdict column says "None", never "Clean": it reports what Aegis
# OBSERVED in this period, which is a claim it can support. "Clean" would be a
# claim about the machine, which no amount of event data can establish.
_ASSESSMENT_CHECKS = [
    ("vt_malicious", "Known-malicious files"),
    ("tamper", "Tamper attempts against Aegis"),
    ("persistence", "New startup or persistence entries"),
    ("suspicious_path", "Executables run from suspicious locations"),
    ("executable_drop", "Executables written to watched folders"),
    ("monitoring_gap", "Gaps in monitoring coverage"),
]

# The three that escalate the whole period on their own, because each is a fact
# about the artifact rather than an inference about it -- core/signals.py calls
# the same three _CONCLUSIVE and lets them carry high confidence unaccompanied.
_SERIOUS = {"vt_malicious", "tamper", "persistence"}

PAGE_W = 210  # A4 mm
MARGIN = 14
CONTENT_W = PAGE_W - 2 * MARGIN


def _no_pad_date(ts: float) -> str:
    # time.strftime's "%-d" (no leading zero) is a glibc/BSD libc extension --
    # Windows' CRT-backed strftime doesn't support it and raises ValueError.
    # Confirmed bug: this ran on every "Export PDF Report" click, so the
    # report feature would crash outright on Windows. tm_mday is already an
    # int, so building the string by hand sidesteps the platform-specific
    # flag entirely instead of trying to find a portable format-string spin.
    t = time.localtime(ts)
    return f"{time.strftime('%b', t)} {t.tm_mday}, {t.tm_year}"


def format_range_label(start: float, end: float) -> str:
    s = _no_pad_date(start)
    e = _no_pad_date(end)
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
        # Parenthesized so `or "none"` applies to the join, not the whole
        # concatenation (which is always truthy -- the fallback never fired).
        "By source: " + (", ".join(f"{SOURCE_LABELS.get(k, k)}={v}" for k, v in stats["by_source"].items()) or "none"),
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


def _assess(events: list[dict], stats: dict) -> dict:
    """The report's own verdict: status, how much to trust it, and why.

    Local and deterministic -- this is the part of the report that must stay
    true when the AI narrative is unavailable, wrong, or turned off entirely,
    so it reads only the signals on the events and never `summary_text`.
    """
    fired = Counter()
    strong_clear = 0
    for ev in events:
        # dashboard/server.py::query_events already annotated these. Recompute
        # only for a caller that handed over raw rows (a test, or a future
        # non-dashboard entry point) -- never trust the key being present.
        sigs = ev.get("signals") or signals_for(ev)
        for s in sigs:
            if s["state"] in ("bad", "warn"):
                fired[s["code"]] += 1
        conf = ev.get("verdict_confidence") or confidence_for(sigs)
        # "Nothing fired" is not evidence. "SIP or the user's own Trust List
        # positively cleared this" is. Only the latter counts toward coverage.
        if conf["basis"] == "clear" and conf["level"] == "high":
            strong_clear += 1

    checks = [(label, fired.get(code, 0)) for code, label in _ASSESSMENT_CHECKS]
    serious = sum(fired.get(code, 0) for code in _SERIOUS)
    flagged = sum(n for _, n in checks)
    # Anything the report is going to PRINT under "Important Events" has to keep
    # the verdict off "Healthy", medium included. A page-1 all-clear sitting
    # above a table of events the same report called important is the one
    # internal contradiction guaranteed to cost the reader their trust in both.
    notable = sum(stats["by_severity"].get(s, 0) for s in _IMPORTANT_SEVERITIES)

    if not events:
        # An empty period is NOT an all-clear, and this is the single most
        # important branch in the function: monitoring may simply have been off.
        # Printing "Healthy" over a period Aegis never watched is the one
        # mistake that would make every other verdict in this report worthless.
        return {
            "status": "No Activity Recorded", "tone": "unknown", "confidence": "Low",
            "reason": "No events were recorded for this period. That can mean a quiet system "
                      "or a period when monitoring was not running -- this report cannot "
                      "distinguish between the two.",
            "action": "Confirm monitoring was active across this period before treating it as clean.",
            "checks": checks, "coverage": 0,
        }

    if serious:
        status, tone = "Needs Attention", "bad"
        reason = (f"{serious} event{'s' if serious != 1 else ''} carried a hard indicator "
                  f"(a malicious-file detection, a tamper attempt, or a new persistence entry). "
                  f"These are observations rather than inferences, so they warrant review "
                  f"regardless of how routine the rest of the period looks.")
        action = "Review the flagged events below before treating this machine as trusted."
    elif notable or flagged:
        n = notable or flagged
        status, tone = "Review Suggested", "warn"
        reason = (f"No malware, tampering or persistence was observed, but {n} "
                  f"event{'s' if n != 1 else ''} rose above routine activity. Most such events "
                  f"are explained by something the user did themselves.")
        action = "Skim the important events below and confirm each was expected."
    else:
        status, tone = "Healthy", "ok"
        reason = ("Routine operating-system and application activity only. None of the "
                  "indicators Aegis checks for were observed in this period.")
        action = "No action required."

    # occam: coverage thresholds are judgement, not measurement -- they say how
    # much of the period was positively cleared (SIP-verified or user-trusted)
    # rather than merely un-flagged. Tune against real timelines if "Low" starts
    # showing up on days that are genuinely fine; replace with a per-source
    # coverage model if it ever needs to justify itself to an auditor.
    coverage = strong_clear / len(events)
    if serious:
        confidence = "High"       # a scan result or a watched tamper attempt stands alone
    elif coverage >= 0.6:
        confidence = "High"
    elif coverage >= 0.25:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {"status": status, "tone": tone, "confidence": confidence, "reason": reason,
            "action": action, "checks": checks, "coverage": round(coverage * 100)}


def generate_pdf_report(events: list[dict], range_label: str, range_start: float,
                         range_end: float, config: AppConfig) -> bytes:
    stats = _compute_stats(events)
    assessment = _assess(events, stats)
    try:
        summary_text = AIExplainer(config).summarize_period(
            _summary_prompt_block(events, stats, range_label))
    except Exception as exc:
        # The footer on every page promises the narrative is a convenience, not
        # the verdict. That has to be structurally true, not just printed: an
        # unreachable provider, an expired key or a rate limit must not be able
        # to take down a report whose verdict block was computed locally and is
        # sitting right above this section, fully valid.
        logger.warning("Period summary unavailable -- rendering report without it.", exc_info=True)
        summary_text = (f"The AI narrative could not be generated for this period ({exc.__class__.__name__}). "
                        f"The assessment above and every event below are computed locally and are unaffected.")

    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.set_margins(MARGIN, MARGIN, MARGIN)

    _draw_cover(pdf, stats, range_label)
    pdf.add_page()
    _draw_assessment(pdf, assessment)
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
    # Same non-portable "%-d"/"%-I" issue as _no_pad_date above -- built by
    # hand rather than strftime so this doesn't crash on Windows.
    _now = time.localtime()
    _hour12 = _now.tm_hour % 12 or 12
    generated = (f"Generated {time.strftime('%B', _now)} {_now.tm_mday}, {_now.tm_year} "
                 f"at {_hour12}:{_now.tm_min:02d} {time.strftime('%p', _now)}")
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


def _ensure_room(pdf: _ReportPDF, needed_mm: float):
    """Page-break ahead of a block that draws itself with rect() and set_xy().

    fpdf2's auto page break only fires from inside cell()/multi_cell(). The stat
    tiles, the severity bar and its legend, and the assessment band are painted
    with rect() and an explicit cursor, so nothing stops them rendering straight
    through the footer -- which is exactly what they did once the assessment
    block above them pushed the cursor further down the page.
    """
    if pdf.get_y() + needed_mm > pdf.h - 22:
        pdf.add_page()


def _draw_assessment(pdf: _ReportPDF, a: dict):
    """The 'should I worry?' block -- first thing on page 2, above the narrative.

    Drawn as a fixed-height status band plus ordinary flowing text rather than
    one dynamically-sized panel: boxing the whole block would mean measuring
    wrapped text to size the rectangle behind it, and getting that wrong pushes
    a border through the middle of a sentence or across a page break. The band
    carries the colour, the text below it just flows.
    """
    tone = TONE_COLOR.get(a["tone"], TONE_COLOR["unknown"])

    band_h = 15
    _ensure_room(pdf, band_h + 20)   # band + the first lines of the reason
    y = pdf.get_y()
    pdf.set_fill_color(*tone)
    pdf.rect(MARGIN, y, CONTENT_W, band_h, style="F")

    pdf.set_xy(MARGIN + 5, y + 3.4)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(CONTENT_W * 0.6, 8, _safe(a["status"]))

    pdf.set_xy(MARGIN + CONTENT_W * 0.6, y + 4.6)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.cell(CONTENT_W * 0.4 - 5, 6, _letterspaced(f"Confidence: {a['confidence']}"), align="R")

    pdf.set_y(y + band_h + 5)
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(*INK)
    pdf.multi_cell(CONTENT_W, 5.6, _safe(a["reason"]))

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*INK_3)
    pdf.cell(0, 5, _letterspaced("Recommended Action"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*tone)
    pdf.multi_cell(CONTENT_W, 5.6, _safe(a["action"]))

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*INK_3)
    pdf.cell(0, 5, _letterspaced("What Aegis Checked"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    val_w = 30
    for label, count in a["checks"]:
        _ensure_room(pdf, 6)   # the tone square is a rect(); don't orphan it
        row_y = pdf.get_y()
        ok = count == 0
        pdf.set_fill_color(*(TONE_COLOR["ok"] if ok else TONE_COLOR["bad"]))
        pdf.rect(MARGIN + 1, row_y + 1.9, 2.4, 2.4, style="F")
        pdf.set_xy(MARGIN + 6, row_y)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*INK)
        pdf.cell(CONTENT_W - val_w - 6, 6, _safe(label))
        pdf.set_font("Helvetica", "B" if not ok else "", 9.5)
        pdf.set_text_color(*(INK_2 if ok else TONE_COLOR["bad"]))
        pdf.cell(val_w, 6, "None" if ok else f"{count} observed", align="R")
        pdf.set_y(row_y + 6)

    if a["coverage"]:
        pdf.ln(1)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*INK_3)
        # Says what the confidence figure above actually rests on. Without this
        # a reader has no way to tell a well-evidenced "Healthy" from one that
        # only means Aegis had nothing to say about anything it saw.
        pdf.multi_cell(CONTENT_W, 4.6,
                       f"{a['coverage']}% of events in this period were positively cleared "
                       f"(SIP-verified Apple binaries or entries on your Trust List) rather than "
                       f"merely unflagged. Analysis is performed locally; your files are never uploaded.")
    pdf.ln(3)


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
    _ensure_room(pdf, 46)   # section title + 20mm tiles + the severity bar under them
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
    _ensure_room(pdf, 20)   # bar + legend row, both rect()-drawn
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


def _background_label(ev: dict) -> str:
    # Same collapse the console timeline does (dashboard/static/app.js::groupKey):
    # drop the PID so repeat runs of one process land on one line instead of
    # one line each. mdworker_shared alone is ~1000 rows/day on a normal Mac.
    return _safe(str(ev.get("summary", "")).split(" (PID")[0])


def _draw_background(pdf: _ReportPDF, background: list[dict]):
    """Routine low-severity activity, collapsed to counts.

    Printed as counts rather than rows because the full rows are already
    available -- the footnote points at the CSV/JSON export. Nobody reads page
    8 of identical Spotlight entries, and a report that makes them scroll past
    it to reach the events that matter has buried its own conclusion.
    """
    if not background:
        return
    # Keep the heading with its content. fpdf2's auto-break only triggers on the
    # NEXT write, so a section_title that just fits at the foot of a page leaves
    # the heading stranded there with its whole list overleaf -- observed with
    # "BACKGROUND ACTIVITY (300)" alone under the last event row. The title,
    # intro paragraph and a few rows need roughly 45mm between them.
    if pdf.get_y() + 45 > pdf.h - 20:
        pdf.add_page()
    pdf.section_title(f"Background Activity ({len(background)})")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*INK_3)
    pdf.multi_cell(CONTENT_W, 5,
                   "Low-severity, routine activity, grouped by what produced it. Listed for "
                   "completeness -- none of it contributed to the assessment on page 1.")
    pdf.ln(2)

    counts = Counter(_background_label(ev) for ev in background)
    grouped = counts.most_common(20)
    val_w = 22
    # Same manual-pagination-with-auto-break-OFF dance as _draw_rows below, and
    # for the same reason: this loop drives the cursor with set_y(), so leaving
    # fpdf2's auto-break armed lets it fire inside a row's own cell() calls
    # while the loop still holds the stale pre-break y -- two page breaks for
    # one overflow, which is what produces a page holding a single orphan row.
    pdf.set_auto_page_break(auto=False)
    for label, count in grouped:
        if pdf.get_y() + 6 > pdf.h - 20:
            pdf.add_page()
        y = pdf.get_y()
        pdf.set_xy(MARGIN, y)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*INK)
        text = label if len(label) <= 105 else label[:104] + "..."
        pdf.cell(CONTENT_W - val_w, 6, text)
        pdf.set_text_color(*INK_2)
        pdf.cell(val_w, 6, f"x{count}", align="R")
        pdf.set_y(y + 6)
    pdf.set_auto_page_break(auto=True, margin=22)

    remaining = len(counts) - len(grouped)
    if remaining > 0:
        pdf.ln(1)
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(*INK_3)
        pdf.cell(0, 5, f"...and {remaining} further background group(s).")


def _draw_event_table(pdf: _ReportPDF, events: list[dict]):
    """Important events in full, routine activity collapsed underneath them.

    The old single "Event Log" listed all 250 severity-sorted rows together, so
    the one event worth acting on and the 200 Spotlight indexer entries got the
    same visual weight and the same amount of the reader's attention.
    """
    important = [e for e in events if e.get("severity") in _IMPORTANT_SEVERITIES]
    background = [e for e in events if e.get("severity") not in _IMPORTANT_SEVERITIES]

    pdf.section_title(f"Important Events ({len(important)})")
    if not important:
        pdf.set_font("Helvetica", "I", 9.5)
        pdf.set_text_color(*INK_3)
        pdf.multi_cell(CONTENT_W, 5.5,
                       f"No events above low severity in this period. All {len(events)} "
                       f"recorded events were routine and are grouped below.")
        pdf.ln(2)
        _draw_background(pdf, background)
        return

    _draw_rows(pdf, important)
    _draw_background(pdf, background)


def _draw_rows(pdf: _ReportPDF, events: list[dict]):
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
                       f"Showing the {cap} highest-severity of {len(events)} important events in this "
                       f"period. Use Export CSV/JSON from the console for the full set.")
