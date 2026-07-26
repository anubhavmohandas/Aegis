"""
Read-only PySide6 timeline viewer over the SQLite event store.

Deliberately read-only and separate from main.py's monitor/tray process --
run this whenever you want to look at history; it doesn't need to run
continuously. Polls the database on a timer instead of pushing events live,
which keeps this decoupled from the monitor threads entirely (no shared
in-process queue, no risk of a UI bug taking down monitoring).

Run with:
    python ui/timeline_app.py [--db path/to/aegis_events.db]

CONFIDENCE NOTE: this imports and runs cleanly against a real SQLite file in
a headless (offscreen) Qt smoke test -- see the verification step in this
project's build notes. It has NOT been visually verified on a real desktop
(no GUI environment available to me). Sizing/spacing may need small tweaks
once you actually look at it.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QListWidget, QListWidgetItem, QComboBox, QPushButton, QFrame,
)

# `python ui/timeline_app.py` (this file's own documented invocation) puts
# ui/ -- not the repo root -- at sys.path[0], so `import core.*` failed with
# ModuleNotFoundError unless this happened to be imported as a module from
# the root instead. Same fix dashboard/server.py already carries.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.database import EventStore  # noqa: E402 -- needs REPO_ROOT on sys.path first

RISK_COLORS = {
    "certain": "#2e7d32",     # green-ish: high-confidence detection
    "polled": "#f9a825",      # amber: best-effort/delayed detection
}

SEVERITY_COLORS = {
    "low": "#455a64",
    "medium": "#f9a825",
    "high": "#e64a19",
    "critical": "#b71c1c",
}

SOURCE_LABELS = {
    "process": "Process",
    "usb": "USB",
    "startup": "Startup",
    "folder": "Folder",
}


class TimelineWindow(QMainWindow):
    def __init__(self, store: EventStore):
        super().__init__()
        self.store = store
        self.setWindowTitle("Aegis - Event Timeline")
        self.resize(820, 600)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        header = QHBoxLayout()
        title = QLabel("Aegis Event Timeline")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        header.addWidget(title)
        header.addStretch()

        self.filter_box = QComboBox()
        self.filter_box.addItems(["All sources", "Process", "USB", "Startup", "Folder"])
        self.filter_box.currentIndexChanged.connect(self.refresh)
        header.addWidget(self.filter_box)

        refresh_btn = QPushButton("Refresh now")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        self.list_widget = QListWidget()
        self.list_widget.setSpacing(4)
        layout.addWidget(self.list_widget)

        self.status_label = QLabel("Loading...")
        self.status_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(5000)  # auto-refresh every 5s -- cheap local SQLite read, not an API call

        self.refresh()

    def _source_filter(self) -> str | None:
        text = self.filter_box.currentText()
        mapping = {v: k for k, v in SOURCE_LABELS.items()}
        return mapping.get(text)

    def refresh(self):
        source = self._source_filter()
        rows = self.store.recent(limit=200, source=source)
        self.list_widget.clear()

        for row in rows:
            item = QListWidgetItem()
            widget = self._build_row_widget(row)
            item.setSizeHint(widget.sizeHint())
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, widget)

        self.status_label.setText(
            f"{len(rows)} events shown | last refreshed {datetime.now().strftime('%H:%M:%S')}"
        )

    def _build_row_widget(self, row: dict) -> QWidget:
        w = QFrame()
        w.setFrameShape(QFrame.Shape.StyledPanel)
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 6, 8, 6)

        ts = datetime.fromtimestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        source_label = SOURCE_LABELS.get(row["source"], row["source"])
        color = RISK_COLORS.get(row["confidence"], "#757575")

        top = QHBoxLayout()
        time_label = QLabel(ts)
        time_label.setStyleSheet("color: gray; font-size: 11px;")
        top.addWidget(time_label)

        badge = QLabel(f" {source_label} · {row['confidence']} ")
        badge.setStyleSheet(f"background-color: {color}; color: white; border-radius: 4px; font-size: 11px;")
        top.addWidget(badge)

        severity = row.get("severity", "medium")
        sev_color = SEVERITY_COLORS.get(severity, "#757575")
        sev_badge = QLabel(f" {severity.upper()} ")
        sev_badge.setStyleSheet(f"background-color: {sev_color}; color: white; border-radius: 4px; "
                                 f"font-size: 11px; font-weight: 600;")
        top.addWidget(sev_badge)

        if row["ai_skipped"]:
            skipped = QLabel(" AI skipped ")
            skipped.setStyleSheet("background-color: #616161; color: white; border-radius: 4px; font-size: 11px;")
            top.addWidget(skipped)

        top.addStretch()
        v.addLayout(top)

        summary_label = QLabel(row["summary"])
        summary_label.setStyleSheet("font-weight: 600;")
        summary_label.setWordWrap(True)
        v.addWidget(summary_label)

        if row.get("explanation"):
            explanation_label = QLabel(row["explanation"])
            explanation_label.setWordWrap(True)
            explanation_label.setStyleSheet("color: #333;")
            v.addWidget(explanation_label)

        return w


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="aegis_events.db", help="Path to the SQLite event store")
    args = parser.parse_args()

    # Same guard dashboard/server.py's CLI has: EventStore(path) CREATEs a
    # fresh empty DB if the path is wrong, so a typo'd --db silently showed
    # an empty timeline instead of an error.
    if not Path(args.db).is_file():
        sys.exit(f"error: event store not found at {args.db!r} -- run main.py first, "
                 f"or pass --db path/to/aegis_events.db")

    app = QApplication(sys.argv)
    store = EventStore(args.db)
    window = TimelineWindow(store)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
