"""Regression test: generating a report used to strand the desktop app.

pywebview's ALLOW_DOWNLOADS defaults to False, so WKWebView handled the PDF
download click as ordinary navigation -- the window loaded the PDF in place,
pywebview's cocoa backend blocks back-navigation, and the only way out was
quitting. Two invariants pin the fix:

  1. desktop_app enables ALLOW_DOWNLOADS before webview.start().
  2. No dashboard code navigates the window to a file endpoint; downloads go
     through saveResponseAsFile()'s blob + download attribute instead.

Pure source inspection -- no GUI, runs anywhere.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_JS = (ROOT / "dashboard/static/app.js").read_text()


def test_downloads_enabled_before_start():
    src = (ROOT / "desktop_app.py").read_text()
    setting = src.index("webview.settings['ALLOW_DOWNLOADS'] = True")
    assert setting < src.index("webview.start(")


def test_no_navigation_to_file_endpoints():
    # `location.href = "/api/export..."` and friends replace the dashboard.
    nav = re.findall(r"location\.(?:href|assign|replace)\s*\(?\s*=?\s*[`'\"]([^`'\"]*)",
                     APP_JS)
    assert [u for u in nav if "/api/export" in u or "/api/report" in u] == []


def test_report_and_export_use_the_blob_saver():
    for caller in ("downloadReportPdf", "exportEvents"):
        body = APP_JS[APP_JS.index(caller + " ="):] if caller + " =" in APP_JS \
            else APP_JS[APP_JS.index("function " + caller):]
        assert "saveResponseAsFile" in body[:900], caller


if __name__ == "__main__":
    test_downloads_enabled_before_start()
    test_no_navigation_to_file_endpoints()
    test_report_and_export_use_the_blob_saver()
    print("ok")
