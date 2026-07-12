#!/usr/bin/env bash
# One-click release: bump the version, commit whatever's pending, tag, push,
# then wait for GitHub Actions to build + publish the release and tell you
# (via a native macOS notification, plus a log file) whether it actually
# worked -- so "double-click this before bed" is a real workflow, not just
# "kick off a build and hope."
#
# What it does, in order:
#   1. Bumps core/version.py + packaging/windows-installer.iss (kept in sync
#      by hand otherwise -- Inno Setup can't import Python) -- patch version
#      bump by default, e.g. 2.0.1-alpha -> 2.0.2-alpha.
#   2. Commits whatever's currently sitting in the working tree, tags the new
#      version, pushes both.
#   3. That push is what actually triggers .github/workflows/build.yml's
#      tag-triggered `release` job -- this script does not build/upload
#      anything itself, it just does the git side, then watches.
#   4. Polls the GitHub Actions API until the run finishes, then confirms the
#      published release actually has the .dmg/.exe attached (the same two
#      checks that caught the empty-release and unparseable-tag bugs earlier
#      tonight -- an assetless or unparseable-tag release would otherwise
#      report "success" here while still being useless to the update button).
#   5. Notifies you (osascript) and writes a timestamped log either way, so a
#      run you weren't watching still tells you what happened.
#
# Usage:
#   Double-click in Finder (opens Terminal, runs to completion).
#   Or from a terminal:  packaging/release.command [X.Y.Z-suffix]
#   The optional argument overrides the auto patch-bump with an exact version.
#
# Requires: git already configured to push to origin without an interactive
# prompt (SSH key or a cached credential helper) -- if push needs a password
# every time, this can't run unattended overnight.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LOG_DIR="$REPO_ROOT/packaging/release-logs"
mkdir -p "$LOG_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOG_DIR/release-$STAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

notify() {
    # Same argv-passing pattern as core/notifier.py's _notify_macos(): title
    # and message go to osascript as plain argv data, never interpolated into
    # the AppleScript source itself, so there's nothing to escape and no
    # AppleScript-injection surface even though these particular strings are
    # only ever built by this script, not attacker/user input.
    osascript \
        -e "on run argv" \
        -e "display notification (item 1 of argv) with title (item 2 of argv)" \
        -e "end run" \
        "$2" "$1" 2>/dev/null || true
}

fail() {
    echo "RELEASE FAILED: $1"
    notify "Aegis release failed" "$1"
    exit 1
}

echo "=== Aegis release @ $STAMP ==="

command -v git >/dev/null || fail "git not found"
command -v curl >/dev/null || fail "curl not found"
command -v python3 >/dev/null || fail "python3 not found"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Branch: $BRANCH"
if [ "$BRANCH" != "main" ]; then
    echo "WARNING: not on main (on '$BRANCH') -- releasing from a feature branch is unusual, continuing anyway."
fi

REMOTE_URL=$(git remote get-url origin)
GITHUB_REPO=$(python3 -c "
import re, sys
m = re.search(r'github\.com[:/](.+?)(?:\.git)?\$', sys.argv[1])
print(m.group(1) if m else '')
" "$REMOTE_URL")
[ -n "$GITHUB_REPO" ] || fail "could not parse a GitHub owner/repo out of origin URL: $REMOTE_URL"
echo "Repo: $GITHUB_REPO"

# --- 1. compute the next version -------------------------------------------

CURRENT_VERSION=$(python3 -c "
import sys
sys.path.insert(0, '.')
from core.version import __version__
print(__version__)
")
echo "Current version: $CURRENT_VERSION"

if [ "${1:-}" != "" ]; then
    NEW_VERSION="$1"
    echo "Using explicit version override: $NEW_VERSION"
else
    NEW_VERSION=$(python3 -c "
import re, sys
current = sys.argv[1]
m = re.match(r'^(\d+)\.(\d+)\.(\d+)(-.*)?\$', current)
if not m:
    print(f'current version {current!r} is not major.minor.patch[-suffix] -- pass an explicit version as \$1', file=sys.stderr)
    sys.exit(1)
major, minor, patch, suffix = m.groups()
print(f'{major}.{minor}.{int(patch)+1}{suffix or \"\"}')
" "$CURRENT_VERSION") || fail "could not auto-bump the version -- $CURRENT_VERSION"
    echo "Auto-bumped version: $NEW_VERSION"
fi
TAG="v$NEW_VERSION"

# --- 2. bump the two version files, commit, tag, push ----------------------

python3 -c "
import sys
from pathlib import Path
current, new = sys.argv[1], sys.argv[2]
p = Path('core/version.py')
text = p.read_text()
updated = text.replace(f'__version__ = \"{current}\"', f'__version__ = \"{new}\"')
if updated == text:
    print('core/version.py: expected string not found, nothing changed', file=sys.stderr)
    sys.exit(1)
p.write_text(updated)
" "$CURRENT_VERSION" "$NEW_VERSION" || fail "failed to bump core/version.py"

python3 -c "
import sys
from pathlib import Path
current, new = sys.argv[1], sys.argv[2]
p = Path('packaging/windows-installer.iss')
text = p.read_text()
updated = text.replace(f'#define MyAppVersion \"{current}\"', f'#define MyAppVersion \"{new}\"')
if updated == text:
    print('windows-installer.iss: expected string not found, nothing changed', file=sys.stderr)
    sys.exit(1)
p.write_text(updated)
" "$CURRENT_VERSION" "$NEW_VERSION" || fail "failed to bump packaging/windows-installer.iss"

echo "Bumped core/version.py and packaging/windows-installer.iss to $NEW_VERSION"

git add -A

# Defense in depth: .gitignore already excludes these, but a script that
# commits unattended shouldn't rely on that alone -- refuse to proceed if
# anything sensitive somehow made it into the staged set.
BLOCKED_PATTERN='(^|/)(\.env|secrets\.enc|\.secrets\.key|credentials\.json|.*\.pem|.*\.db)$'
STAGED=$(git diff --cached --name-only)
if echo "$STAGED" | grep -qE "$BLOCKED_PATTERN"; then
    git reset
    fail "refusing to commit -- a sensitive-looking file was staged: $(echo "$STAGED" | grep -E "$BLOCKED_PATTERN")"
fi

if [ -z "$STAGED" ]; then
    fail "nothing staged to commit (not even the version bump) -- something's wrong, aborting"
fi
echo "Staging:"
echo "$STAGED" | sed 's/^/  /'

git commit -m "Release $TAG"
git tag "$TAG"
git push origin "$BRANCH"
git push origin "$TAG"
echo "Pushed $BRANCH and tag $TAG -- CI should pick this up now."

# --- 3. wait for GitHub Actions to build + publish --------------------------

echo "Waiting for the CI run to appear..."
RUN_ID=""
for _ in $(seq 1 20); do
    RUN_ID=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/actions/runs?event=push&per_page=5" | python3 -c "
import json, sys
target = sys.argv[1]
data = json.load(sys.stdin)
for r in data.get('workflow_runs', []):
    if r.get('head_branch') == target:
        print(r['id'])
        break
" "$TAG")
    [ -n "$RUN_ID" ] && break
    sleep 10
done
[ -n "$RUN_ID" ] || fail "no CI run appeared for tag $TAG after 200s -- check the Actions tab manually"
echo "CI run: https://github.com/$GITHUB_REPO/actions/runs/$RUN_ID"

echo "Waiting for it to finish (this builds Windows + macOS, can take 5-15 minutes)..."
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
[ -n "$CONCLUSION" ] || fail "CI run didn't finish within 30 minutes -- check it manually: https://github.com/$GITHUB_REPO/actions/runs/$RUN_ID"

echo "CI conclusion: $CONCLUSION"
echo "--- per-job status ---"
curl -s "https://api.github.com/repos/$GITHUB_REPO/actions/runs/$RUN_ID/jobs" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for j in data.get('jobs', []):
    print(f\"{j['name']:10s} -> {j['status']} / {j['conclusion']}\")
"

if [ "$CONCLUSION" != "success" ]; then
    fail "CI did not succeed for $TAG (conclusion: $CONCLUSION) -- see https://github.com/$GITHUB_REPO/actions/runs/$RUN_ID"
fi

# --- 4. confirm the release actually has assets attached --------------------

echo "--- verifying the published release ---"
RELEASE_JSON=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest")
RELEASE_TAG=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))")
ASSET_COUNT=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('assets',[])))")
echo "Latest release tag: $RELEASE_TAG ($ASSET_COUNT asset(s))"

if [ "$RELEASE_TAG" != "$TAG" ] || [ "$ASSET_COUNT" -lt 1 ]; then
    fail "release published but not usable: expected tag $TAG with assets, got '$RELEASE_TAG' with $ASSET_COUNT asset(s)"
fi

echo "=== SUCCESS: $TAG is live with $ASSET_COUNT asset(s) attached ==="
notify "Aegis $TAG released" "Build succeeded, $ASSET_COUNT asset(s) published. Older installs can now self-update."
echo "Log saved to: $LOG_FILE"
read -r -p "Done -- press Enter to close this window."
