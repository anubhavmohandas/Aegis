#!/usr/bin/env bash
# Publish a release from ALREADY-COMMITTED code.
#
# Deliberately separate from release.command, which is the local "ship
# whatever is on my machine right now" path (it does `git add -A`). This one
# refuses to run on a dirty working tree, so a half-finished experiment
# sitting in your editor can never end up inside a published installer. The
# only commit it creates is the version bump itself.
#
# It also drops the pre-release suffix: 2.0.2-alpha -> 2.0.3. core/updater.py's
# _parse_version() sorts a suffix-less version ABOVE a pre-release one, so
# existing -alpha installs see this as an upgrade.
#
# What it does:
#   1. Refuses to continue unless the tree is clean and main is pushed.
#   2. Suggests the next version (patch +1, suffix stripped); Enter accepts it,
#      or type your own.
#   3. Bumps core/version.py + packaging/windows-installer.iss (Inno Setup
#      can't import Python, so that copy is kept in sync by hand) and, best
#      effort, the version pills in website/index.html.
#   4. Commits ONLY those files, tags, pushes both.
#   5. That tag push triggers .github/workflows/build.yml, which builds the
#      .dmg + .exe and attaches them to a GitHub Release. This script builds
#      nothing itself -- it does the git side, then watches.
#   6. Polls until CI finishes, then confirms the release really has assets
#      attached (an assetless release still reports "success" to CI while
#      being useless to the in-app update button).
#   7. macOS notification + timestamped log either way.
#
# Usage:
#   Double-click in Finder, or:  packaging/publish.command [X.Y.Z]
#   An argument skips the prompt entirely.
#
# Requires: git able to push to origin without an interactive prompt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LOG_DIR="$REPO_ROOT/packaging/release-logs"
mkdir -p "$LOG_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOG_DIR/publish-$STAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

notify() {
    # Same argv-passing pattern as core/notifier.py's _notify_macos(): the
    # strings go to osascript as plain argv data, never interpolated into the
    # AppleScript source, so there is nothing to escape and no injection
    # surface.
    osascript \
        -e "on run argv" \
        -e "display notification (item 1 of argv) with title (item 2 of argv)" \
        -e "end run" \
        "$2" "$1" 2>/dev/null || true
}

fail() {
    echo
    echo "PUBLISH FAILED: $1"
    notify "Aegis publish failed" "$1"
    echo "Log saved to: $LOG_FILE"
    read -r -p "Press Enter to close this window."
    exit 1
}

echo "=== Aegis publish @ $STAMP ==="

command -v git >/dev/null || fail "git not found"
command -v curl >/dev/null || fail "curl not found"
command -v python3 >/dev/null || fail "python3 not found"

# --- 1. refuse to publish anything that isn't already committed -------------

BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Branch: $BRANCH"
[ "$BRANCH" == "main" ] || fail "not on main (on '$BRANCH') -- publish from main"

DIRTY=$(git status --porcelain)
if [ -n "$DIRTY" ]; then
    echo "Uncommitted changes:"
    echo "$DIRTY" | sed 's/^/  /'
    fail "working tree is dirty -- commit or stash first. This script only publishes committed code, on purpose (use release.command if you really do want to ship the working tree)."
fi

git fetch origin main --quiet
if [ -n "$(git log origin/main..HEAD --oneline)" ]; then
    git log origin/main..HEAD --oneline | sed 's/^/  /'
    fail "local main has commits that aren't pushed -- push them first so the tag and the branch agree"
fi
if [ -n "$(git log HEAD..origin/main --oneline)" ]; then
    fail "origin/main is ahead of local main -- pull first"
fi
echo "Working tree clean, main in sync with origin."

REMOTE_URL=$(git remote get-url origin)
GITHUB_REPO=$(python3 -c "
import re, sys
m = re.search(r'github\.com[:/](.+?)(?:\.git)?\$', sys.argv[1])
print(m.group(1) if m else '')
" "$REMOTE_URL")
[ -n "$GITHUB_REPO" ] || fail "could not parse a GitHub owner/repo out of origin URL: $REMOTE_URL"
echo "Repo: $GITHUB_REPO"

# --- 2. pick the version ----------------------------------------------------

CURRENT_VERSION=$(python3 -c "
import sys
sys.path.insert(0, '.')
from core.version import __version__
print(__version__)
")
echo "Current version: $CURRENT_VERSION"

SUGGESTED=$(python3 -c "
import re, sys
m = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-.*)?\$', sys.argv[1])
if not m:
    print(f'current version {sys.argv[1]!r} is not major.minor.patch[-suffix]', file=sys.stderr)
    sys.exit(1)
major, minor, patch = m.groups()
print(f'{major}.{minor}.{int(patch)+1}')  # suffix intentionally dropped
" "$CURRENT_VERSION") || fail "could not compute the next version from $CURRENT_VERSION"

if [ "${1:-}" != "" ]; then
    NEW_VERSION="$1"
else
    read -r -p "Version to publish [$SUGGESTED]: " ANSWER
    NEW_VERSION="${ANSWER:-$SUGGESTED}"
fi

# This becomes a git tag and an installer filename, so validate it rather than
# trusting whatever was typed at the prompt.
python3 -c "
import re, sys
if not re.match(r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?\$', sys.argv[1]):
    sys.exit(1)
" "$NEW_VERSION" || fail "'$NEW_VERSION' is not a valid version (expected X.Y.Z or X.Y.Z-suffix)"

python3 -c "
import sys
sys.path.insert(0, '.')
from core.updater import is_newer
sys.exit(0 if is_newer(sys.argv[1], sys.argv[2]) else 1)
" "$NEW_VERSION" "$CURRENT_VERSION" \
    || fail "$NEW_VERSION is not newer than $CURRENT_VERSION -- installs would never offer it as an update"

TAG="v$NEW_VERSION"
if git rev-parse "$TAG" >/dev/null 2>&1 || git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
    fail "tag $TAG already exists (locally or on origin) -- pick another version"
fi
echo "Publishing: $CURRENT_VERSION -> $NEW_VERSION (tag $TAG)"

# --- 3. bump the version files ---------------------------------------------

python3 -c "
import sys
from pathlib import Path

current, new = sys.argv[1], sys.argv[2]

def bump(path, template, required=True):
    p = Path(path)
    text = p.read_text()
    old = template.format(current)
    if old not in text:
        if required:
            print(f'{path}: expected {old!r}, not found', file=sys.stderr)
            sys.exit(1)
        print(f'  {path}: no version string found, skipped (cosmetic only)')
        return
    p.write_text(text.replace(old, template.format(new)))
    print(f'  {path}: {current} -> {new}')

bump('core/version.py', '__version__ = \"{}\"')
bump('packaging/windows-installer.iss', '#define MyAppVersion \"{}\"')
# Cosmetic: the download page advertises a version number. Non-fatal, since a
# stale pill on the site must never block a real release.
bump('website/index.html', 'v{}', required=False)
" "$CURRENT_VERSION" "$NEW_VERSION" || fail "failed to bump the version files"

# Only the version files -- never `git add -A`. That separation is the entire
# reason this script exists alongside release.command.
git add core/version.py packaging/windows-installer.iss website/index.html
STAGED=$(git diff --cached --name-only)
[ -n "$STAGED" ] || fail "version bump produced no changes -- aborting"
echo "Committing:"
echo "$STAGED" | sed 's/^/  /'

git commit -m "Release $TAG"
git tag "$TAG"
git push origin main
git push origin "$TAG"
echo "Pushed main and tag $TAG -- CI should pick this up now."

# --- 4. wait for CI ---------------------------------------------------------

echo "Waiting for the CI run to appear..."
RUN_ID=""
for _ in $(seq 1 20); do
    RUN_ID=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/actions/runs?event=push&per_page=10" | python3 -c "
import json, sys
target = sys.argv[1]
for r in json.load(sys.stdin).get('workflow_runs', []):
    if r.get('head_branch') == target:
        print(r['id'])
        break
" "$TAG")
    [ -n "$RUN_ID" ] && break
    sleep 10
done
[ -n "$RUN_ID" ] || fail "no CI run appeared for tag $TAG after 200s -- check the Actions tab"
echo "CI run: https://github.com/$GITHUB_REPO/actions/runs/$RUN_ID"

echo "Waiting for it to finish (Windows + macOS builds, typically 5-15 minutes)..."
CONCLUSION=""
for _ in $(seq 1 90); do
    STATUS_JSON=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/actions/runs/$RUN_ID")
    STATUS=$(echo "$STATUS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))")
    if [ "$STATUS" == "completed" ]; then
        CONCLUSION=$(echo "$STATUS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('conclusion',''))")
        break
    fi
    sleep 20
done
[ -n "$CONCLUSION" ] || fail "CI didn't finish within 30 minutes -- https://github.com/$GITHUB_REPO/actions/runs/$RUN_ID"

echo "CI conclusion: $CONCLUSION"
echo "--- per-job status ---"
curl -s "https://api.github.com/repos/$GITHUB_REPO/actions/runs/$RUN_ID/jobs" | python3 -c "
import json, sys
for j in json.load(sys.stdin).get('jobs', []):
    print(f\"  {j['name']:10s} -> {j['status']} / {j['conclusion']}\")
"
[ "$CONCLUSION" == "success" ] \
    || fail "CI did not succeed for $TAG ($CONCLUSION) -- https://github.com/$GITHUB_REPO/actions/runs/$RUN_ID"

# --- 5. confirm the release actually carries the installers -----------------

echo "--- verifying the published release ---"
RELEASE_JSON=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest")
RELEASE_TAG=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))")
echo "$RELEASE_JSON" | python3 -c "
import json, sys
for a in json.load(sys.stdin).get('assets', []):
    print(f\"  {a['name']}  ({a['size']/1048576:.1f} MB)\")
"
ASSET_COUNT=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('assets',[])))")

[ "$RELEASE_TAG" == "$TAG" ] \
    || fail "latest release is '$RELEASE_TAG', expected '$TAG' -- the release didn't publish under the new tag"
[ "$ASSET_COUNT" -ge 2 ] \
    || fail "release $TAG published with only $ASSET_COUNT asset(s) -- expected the .dmg and the .exe"

echo "=== SUCCESS: $TAG is live with $ASSET_COUNT asset(s) ==="
notify "Aegis $TAG released" "$ASSET_COUNT asset(s) published. Existing installs can now self-update."
echo "Log saved to: $LOG_FILE"
read -r -p "Done -- press Enter to close this window."
