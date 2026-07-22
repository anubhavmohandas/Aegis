#!/usr/bin/env bash
# One-click LOCAL rebuild: wipe the old build, rebuild Aegis.app with
# PyInstaller, then swap the copy in /Applications for the fresh one and
# relaunch it. Double-click in Finder, or run from a terminal.
#
# Order matters: we build and verify the new bundle BEFORE touching
# /Applications, so a failed build never leaves you with no installed app.
#
# This is the local dev loop -- it does NOT tag/push/release. For a real
# published release, use packaging/release.command instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PYINSTALLER="$REPO_ROOT/venv/bin/pyinstaller"
NEW_APP="$REPO_ROOT/dist/Aegis.app"
INSTALLED_APP="/Applications/Aegis.app"
EXE="$INSTALLED_APP/Contents/MacOS/Aegis"

fail() { echo "REBUILD FAILED: $1"; read -r -p "Press Enter to close."; exit 1; }

[ -x "$PYINSTALLER" ] || fail "no venv pyinstaller at $PYINSTALLER -- run 'python3 -m venv venv && venv/bin/pip install -r requirements-macos.txt'"

echo "=== 1/4  wiping old build ==="
rm -rf "$REPO_ROOT/build" "$REPO_ROOT/dist"

echo "=== 2/4  building (this takes a minute) ==="
"$PYINSTALLER" packaging/aegis.spec --noconfirm

[ -d "$NEW_APP" ] || fail "build finished but $NEW_APP is missing -- /Applications left untouched"

echo "=== 3/4  quitting running Aegis + swapping /Applications ==="
# SIGTERM the installed app (this intentionally bypasses the UI's
# password-gated quit -- it's your machine doing a dev rebuild), give it a
# moment, then SIGKILL anything still holding the bundle.
pkill -f "$EXE" 2>/dev/null || true
sleep 2
pkill -9 -f "$EXE" 2>/dev/null || true

rm -rf "$INSTALLED_APP" || fail "could not remove $INSTALLED_APP (permission?) -- new build is in dist/, copy it over manually"
cp -R "$NEW_APP" "$INSTALLED_APP"

echo "=== 4/4  relaunching ==="
open "$INSTALLED_APP"

echo "=== DONE: $INSTALLED_APP replaced with the fresh build and relaunched. ==="
read -r -p "Press Enter to close."
