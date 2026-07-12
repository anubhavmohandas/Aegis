"""
Self-update: checks GitHub Releases for a newer Aegis version and, once the
user explicitly confirms, downloads and installs it in place.

Only ever runs from an explicit user click ("Check for Updates" /
"Download & Install" in the dashboard's Settings page) -- never automatically
or silently, since this replaces the running application's own files.

This is an UNSIGNED alpha build (see packaging/PACKAGING.md). A freshly
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
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.error import URLError

from .version import __version__

logger = logging.getLogger("aegis.updater")

GITHUB_REPO = "anubhavmohandas/Aegis"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


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
    is published for this platform, else None. Never raises for "no
    update"/network conditions -- this runs off a UI button click, and a
    transient network blip must read as "no update found," not a crash."""
    req = urllib.request.Request(
        RELEASES_API, headers={"Accept": "application/vnd.github+json", "User-Agent": "Aegis-updater"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError) as e:
        logger.warning("Update check failed: %s", e)
        return None

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


def download_update(download_url: str, asset_name: str) -> Path:
    dest_dir = Path(tempfile.mkdtemp(prefix="aegis-update-"))
    dest = dest_dir / asset_name
    req = urllib.request.Request(download_url, headers={"User-Agent": "Aegis-updater"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
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
    pid = os.getpid()
    q = shlex.quote
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
rm -rf {q(str(app_path))}
cp -R "$SRC_APP" {q(str(app_path))}
hdiutil detach "$MOUNT_DIR" -quiet || true
rmdir "$MOUNT_DIR" 2>/dev/null || true
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
