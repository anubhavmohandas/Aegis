#!/usr/bin/env bash
# Builds a distributable DMG from dist/Aegis.app using only macOS-native
# tooling (hdiutil, osascript, tiffutil) -- no Homebrew `create-dmg` dependency
# required.
#
# Two stages, because a styled DMG cannot be produced in one shot: the window
# layout (background picture, icon positions, icon size, no toolbar) lives in
# the volume's .DS_Store, and the only thing that writes a .DS_Store is Finder
# itself. So this creates a *writable* UDRW image, mounts it, drives Finder over
# AppleScript to arrange the window, unmounts, and only then compresses to the
# read-only UDZO image that actually ships.
#
# The styling is best-effort. Driving Finder needs a GUI login session and, on
# recent macOS, Automation consent for whatever is running this script -- on a
# CI runner or over SSH that can simply be unavailable. A DMG that installs fine
# but looks plain is a cosmetic regression; a release build that hard-fails at
# the last step is an outage, so an unstyled DMG is still emitted in that case
# with a warning.
#
# Usage (from repo root, after `pyinstaller packaging/aegis.spec`):
#   packaging/make_dmg.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/dist/Aegis.app"
VERSION=$(python3 -c "import sys; sys.path.insert(0, '$ROOT'); from core.version import __version__; print(__version__)")
OUT="$ROOT/dist/aegis-$VERSION.dmg"
STAGE="$ROOT/build/dmg-stage"
RW_DMG="$ROOT/build/aegis-rw.dmg"
BACKGROUND="$ROOT/assets/dmg/background.tiff"
VOLICON="$ROOT/assets/aegis.icns"

# Volume name doubles as the Finder window title and the mount point under
# /Volumes, and AppleScript addresses the disk by it. Keep it free of
# characters that need escaping in either.
VOLNAME="Aegis $VERSION"
MOUNT="/Volumes/$VOLNAME"

# Window geometry. WINDOW_W/H must match the background art's pixel dimensions,
# and the ICON_* values must match the constants at the top of
# make_dmg_background.py -- that correspondence is the whole trick, it is what
# puts the real Finder icons on top of the slots drawn into the art.
WINDOW_W=640
WINDOW_H=400
ICON_SIZE=128
ICON_Y=185
ICON_X_APP=170
ICON_X_APPLICATIONS=470

if [ ! -d "$APP" ]; then
  echo "error: $APP not found -- run 'pyinstaller packaging/aegis.spec' first" >&2
  exit 1
fi

# Leftovers from an interrupted earlier run will otherwise fail the `hdiutil
# attach` below with "resource busy" rather than anything self-explanatory.
if [ -d "$MOUNT" ]; then
  hdiutil detach "$MOUNT" -force >/dev/null 2>&1 || true
fi

rm -rf "$STAGE" "$OUT" "$RW_DMG"
mkdir -p "$STAGE" "$ROOT/dist"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

styled=0
if [ -f "$BACKGROUND" ]; then
  mkdir -p "$STAGE/.background"
  cp "$BACKGROUND" "$STAGE/.background/background.tiff"
  styled=1
else
  echo "warning: $BACKGROUND missing -- run 'python packaging/make_dmg_background.py'" >&2
  echo "         building an unstyled DMG" >&2
fi

# Volume icon: Finder shows this on the mounted disk and in the sidebar.
if [ -f "$VOLICON" ]; then
  cp "$VOLICON" "$STAGE/.VolumeIcon.icns"
fi

# Size the writable image with headroom. hdiutil sizes from the source folder,
# but Finder needs room to write .DS_Store and the HFS metadata that the custom
# volume icon lives in; an exactly-sized image runs out and the styling half
# applies.
SIZE_KB=$(du -sk "$STAGE" | cut -f1)
SIZE_MB=$(( SIZE_KB / 1024 + 60 ))

hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -ov \
  -fs HFS+ -format UDRW -size "${SIZE_MB}m" "$RW_DMG" >/dev/null

# -nobrowse keeps the volume out of Finder's sidebar while it is being built,
# so a stray user click cannot retitle or reposition anything mid-script.
hdiutil attach "$RW_DMG" -readwrite -noverify -nobrowse -mountpoint "$MOUNT" >/dev/null

cleanup() {
  hdiutil detach "$MOUNT" >/dev/null 2>&1 || hdiutil detach "$MOUNT" -force >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$styled" -eq 1 ]; then
  # `update without registering applications` is what forces the .DS_Store
  # write; the delay after it is not superstition, Finder writes it
  # asynchronously and detaching too early loses the whole layout.
  if osascript >/dev/null 2>&1 <<APPLESCRIPT
tell application "Finder"
  tell disk "$VOLNAME"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set the bounds of container window to {200, 140, $((200 + WINDOW_W)), $((140 + WINDOW_H))}
    set viewOptions to the icon view options of container window
    set arrangement of viewOptions to not arranged
    set icon size of viewOptions to $ICON_SIZE
    set text size of viewOptions to 13
    set label position of viewOptions to bottom
    set background picture of viewOptions to file ".background:background.tiff"
    set position of item "Aegis.app" of container window to {$ICON_X_APP, $ICON_Y}
    set position of item "Applications" of container window to {$ICON_X_APPLICATIONS, $ICON_Y}
    close
    open
    update without registering applications
    delay 3
  end tell
end tell
APPLESCRIPT
  then
    echo "applied Finder window styling"
  else
    echo "warning: Finder styling failed (needs a GUI session + Automation" >&2
    echo "         permission) -- shipping an unstyled DMG" >&2
  fi
fi

# Tells Finder the volume has a custom icon; without the attribute the
# .VolumeIcon.icns file is just an inert file. SetFile ships with the Xcode
# command line tools, which are not guaranteed to be present.
if [ -f "$MOUNT/.VolumeIcon.icns" ] && command -v SetFile >/dev/null 2>&1; then
  SetFile -a C "$MOUNT" || true
fi

chmod -Rf go-w "$MOUNT" 2>/dev/null || true
sync

cleanup
trap - EXIT

hdiutil convert "$RW_DMG" -format UDZO -imagekey zlib-level=9 -ov -o "$OUT" >/dev/null
rm -rf "$STAGE" "$RW_DMG"

echo "Built $OUT"
