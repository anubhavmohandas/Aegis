#!/usr/bin/env bash
# Builds a distributable DMG from dist/Aegis.app using only macOS-native
# tooling (hdiutil) -- no Homebrew `create-dmg` dependency required.
#
# Usage (from repo root, after `pyinstaller packaging/aegis.spec`):
#   packaging/make_dmg.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/dist/Aegis.app"
VERSION=$(python3 -c "import sys; sys.path.insert(0, '$ROOT'); from core.version import __version__; print(__version__)")
OUT="$ROOT/dist/aegis-$VERSION.dmg"
STAGE="$ROOT/build/dmg-stage"

if [ ! -d "$APP" ]; then
  echo "error: $APP not found -- run 'pyinstaller packaging/aegis.spec' first" >&2
  exit 1
fi

rm -rf "$STAGE" "$OUT"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

hdiutil create -volname "Aegis $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$OUT"
rm -rf "$STAGE"

echo "Built $OUT"
