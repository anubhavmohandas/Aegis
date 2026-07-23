"""
Self-update: checks GitHub Releases for a newer Aegis version and, once the
user explicitly confirms, downloads and installs it in place.

Only ever runs from an explicit user click ("Check for Updates" /
"Download & Install" in the dashboard's Settings page) -- never automatically
or silently, since this replaces the running application's own files.

These are UNSIGNED builds (see packaging/PACKAGING.md and the note in
CHANGELOG.md about where v2.0.x actually sits). A freshly
installed update is exactly as unsigned as a freshly downloaded one, so
macOS Gatekeeper may still require right-click -> Open on first launch after
an update, same as a first-ever install.

VERIFIED: the check/compare/download logic and the macOS install path (this
runs on real macOS hardware in this repo's dev environment). NOT VERIFIED ON
REAL WINDOWS HARDWARE: the Windows install path (silent Inno Setup install
over a running app) -- implemented per Inno Setup's documented
CloseApplications/AppMutex behavior, but per this project's own standard
(see ADR-008 in docs/DECISIONS.md), treat it as unconfirmed until it's
actually run on a Windows machine.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.error import URLError

import certifi

from .version import __version__

logger = logging.getLogger("aegis.updater")

GITHUB_REPO = "anubhavmohandas/Aegis"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

# Confirmed bug: urllib's plain ssl.create_default_context() has ZERO trust
# anchors on some Python installs (verified on a real venv here -- a fresh
# `ssl.create_default_context().cert_store_stats()` reported {'x509': 0, ...}).
# That's a widely-known gotcha for python.org/Homebrew macOS Pythons that
# never had the OS's root certs wired in, and there's no equivalent of
# "Install Certificates.command" available inside a packaged, non-interactive
# app -- every self-update check failed CERTIFICATE_VERIFY_FAILED and (before
# the check_failed distinction above) silently read as "you're up to date."
# certifi is already an install dependency (pulled in by anthropic/openai's
# httpx), so use its CA bundle explicitly instead of trusting the platform
# default to have one.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


class UpdateError(Exception):
    pass


def _parse_version(v: str) -> tuple:
    """'2.0.1-alpha' -> ((2, 0, 1), 'alpha'). A missing pre-release tag sorts
    HIGHEST ('\\uffff') so '2.0.0' (final) correctly counts as newer than
    '2.0.0-alpha' -- a bare tuple/string compare would get this backwards."""
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?", v.strip())
    if not m:
        return ((0, 0, 0), "")
    major, minor, patch, pre = m.groups()
    return ((int(major), int(minor), int(patch)), pre or "￿")


def is_newer(remote: str, local: str = __version__) -> bool:
    return _parse_version(remote) > _parse_version(local)


def _pick_asset(assets: list[dict]) -> dict | None:
    system = platform.system()
    for asset in assets:
        name = asset.get("name", "").lower()
        if system == "Darwin" and name.endswith(".dmg"):
            return asset
        if system == "Windows" and name.endswith(".exe") and "setup" in name:
            return asset
    return None


def check_for_update(timeout: int = 10) -> dict | None:
    """Returns {version, notes, download_url, asset_name} if a newer release
    is published for this platform, or None if there genuinely isn't one.

    Raises UpdateError if the check itself couldn't complete (network down,
    TLS/cert failure, GitHub unreachable, malformed response) -- this used to
    be swallowed into the same `None` as "no update," which meant a broken
    check and a healthy up-to-date install were indistinguishable to the
    user (the dashboard always said "you're on the latest version," even
    when it had never successfully asked). The caller (dashboard/server.py's
    check_update()) catches this and reports it as a failed check, not a
    verified "you're current.\""""
    req = urllib.request.Request(
        RELEASES_API, headers={"Accept": "application/vnd.github+json", "User-Agent": "Aegis-updater"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as resp:
            data = json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError) as e:
        logger.warning("Update check failed: %s", e)
        raise UpdateError(str(e)) from e

    tag = data.get("tag_name", "")
    if not tag or not is_newer(tag):
        return None

    asset = _pick_asset(data.get("assets", []))
    if asset is None:
        logger.warning("Newer release %s exists but has no downloadable asset for %s",
                        tag, platform.system())
        return None

    return {
        "version": tag.lstrip("v"),
        "notes": _trim_notes(data.get("body", "") or ""),
        "download_url": asset["browser_download_url"],
        "asset_name": asset["name"],
    }


def _trim_notes(body: str, limit: int = 400) -> str:
    """GitHub's `generate_release_notes: true` (see .github/workflows/build.yml)
    produces a full commit-by-commit changelog -- fine on the Releases page,
    way too much for a compact "what's new" card in Settings. Cuts at the
    last line break before `limit` so it doesn't end mid-sentence."""
    body = body.strip()
    if len(body) <= limit:
        return body
    cut = body.rfind("\n", 0, limit)
    if cut < limit // 2:  # no reasonable line break -- just hard-cut
        cut = limit
    return body[:cut].rstrip() + "…"


_ASSET_URL_PREFIX = f"https://github.com/{GITHUB_REPO}/releases/download/"


def download_update(download_url: str, asset_name: str) -> Path:
    # Confirmed bug: dashboard/server.py's /api/update/install used to hand
    # whatever download_url/asset_name it received in the POST body straight
    # to this function -- since that's a plain authenticated API call, not a
    # value this module fetched itself, anything that can reach the endpoint
    # with a valid session (malware running as the same user, a stolen
    # session cookie, a future auth-bypass regression) could point Aegis's
    # self-updater at an arbitrary URL and have the result *executed* as if
    # it were a real release, or use a crafted asset_name like
    # "../../../Library/LaunchAgents/x" to write outside the temp directory.
    # server.py's install_update() now independently re-verifies against a
    # fresh check_for_update() call before ever getting here, but this
    # function guards the same two things again on its own -- defense in
    # depth, not reliant on the caller having done it right.
    safe_name = Path(asset_name).name
    if not safe_name or safe_name != asset_name:
        raise UpdateError(f"refusing to save update asset with an unsafe name: {asset_name!r}")
    if not download_url.startswith(_ASSET_URL_PREFIX):
        raise UpdateError(f"refusing to download update from an unexpected URL: {download_url!r}")

    dest_dir = Path(tempfile.mkdtemp(prefix="aegis-update-"))
    dest = dest_dir / safe_name
    req = urllib.request.Request(download_url, headers={"User-Agent": "Aegis-updater"})
    with urllib.request.urlopen(req, timeout=120, context=_SSL_CONTEXT) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)
    return dest


def _current_app_bundle_macos() -> Path:
    exe = Path(sys.executable).resolve()  # .../Aegis.app/Contents/MacOS/Aegis
    for parent in exe.parents:
        if parent.suffix == ".app":
            return parent
    raise UpdateError(f"Could not locate the .app bundle above {exe}")


def _install_macos(installer_path: Path) -> None:
    """Spawns a detached shell script that waits for this process to exit
    (can't replace our own running app bundle out from under ourselves),
    mounts the DMG, swaps /Applications/Aegis.app, relaunches, and cleans up
    after itself -- then this function returns and the caller quits."""
    app_path = _current_app_bundle_macos()
    new_app_path = app_path.with_name(app_path.name + ".new")
    bak_app_path = app_path.with_name(app_path.name + ".bak")
    pid = os.getpid()
    q = shlex.quote
    # Confirmed bug: this used to `rm -rf` the live app bundle BEFORE `cp -R`
    # of the replacement -- if the copy failed partway (disk full,
    # permissions, DMG unmounted early), the old app was already gone with
    # nothing to fall back to and no automatic recovery. Now the new bundle
    # is built fully alongside the old one first (old app untouched the
    # whole time), and the swap itself is two `mv`s (fast, same-volume
    # renames) with an explicit rollback if the second one fails.
    script = f"""#!/bin/bash
set -e
while kill -0 {pid} 2>/dev/null; do sleep 0.5; done
MOUNT_DIR=$(mktemp -d)
hdiutil attach {q(str(installer_path))} -nobrowse -quiet -mountpoint "$MOUNT_DIR"
SRC_APP=$(find "$MOUNT_DIR" -maxdepth 1 -iname "*.app" | head -n1)
if [ -z "$SRC_APP" ]; then
    hdiutil detach "$MOUNT_DIR" -quiet || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
    exit 1
fi
rm -rf {q(str(new_app_path))} {q(str(bak_app_path))}
if ! cp -R "$SRC_APP" {q(str(new_app_path))}; then
    rm -rf {q(str(new_app_path))}
    hdiutil detach "$MOUNT_DIR" -quiet || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
    exit 1
fi
hdiutil detach "$MOUNT_DIR" -quiet || true
rmdir "$MOUNT_DIR" 2>/dev/null || true
mv {q(str(app_path))} {q(str(bak_app_path))}
if mv {q(str(new_app_path))} {q(str(app_path))}; then
    rm -rf {q(str(bak_app_path))}
else
    mv {q(str(bak_app_path))} {q(str(app_path))}
    rm -rf {q(str(new_app_path))}
    exit 1
fi
open {q(str(app_path))}
rm -f {q(str(installer_path))}
rm -- "$0"
"""
    script_path = installer_path.parent / "aegis_update_installer.sh"
    script_path.write_text(script)
    script_path.chmod(0o755)
    subprocess.Popen(
        ["/bin/bash", str(script_path)],
        start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _install_windows(installer_path: Path) -> None:
    # /VERYSILENT + /SUPPRESSMSGBOXES: no UI, no blocking dialogs.
    # /NORESTART: never trigger a reboot prompt.
    # CloseApplications/RestartApplications (windows-installer.iss [Setup])
    # is what lets Inno Setup close this very process mid-install and
    # relaunch it after -- without that, installing over a running .exe
    # would just fail with a file-in-use error.
    subprocess.Popen(
        [str(installer_path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
    )


def install_update(installer_path: Path, on_quit) -> None:
    """Kicks off a detached, platform-specific installer, then calls
    on_quit() so THIS process actually exits and releases the files/ports
    the installer is waiting on. Treat this call as terminal -- nothing
    after it in the caller runs on the happy path."""
    system = platform.system()
    if system == "Darwin":
        _install_macos(installer_path)
    elif system == "Windows":
        _install_windows(installer_path)
    else:
        raise UpdateError(f"Self-update isn't implemented for {system}")
    on_quit()
