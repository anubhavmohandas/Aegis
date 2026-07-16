"""
Local pre-filter that decides whether an event needs an AI call at all.

WHY THIS IS AN ALLOWLIST YOU CONFIGURE, NOT A BUILT-IN "KNOWN SAFE" DATABASE:

A hardcoded "these process names are always safe" list is a classic malware
masquerade vector -- e.g. treating "svchost.exe" as automatically safe is
exactly wrong, since svchost.exe impersonation is a real technique. Baking in
a global safe-list would make Aegis *less* trustworthy, not more: it would
create false confidence in exactly the cases an attacker is most likely to
exploit.

Instead, this engine only skips the AI call for items YOU explicitly added to
your own config (trusted_process_names / trusted_process_hashes /
trusted_usb_ids in config.yaml) -- e.g. your own dev tools that fire
constantly. That's an opt-in reduction of noise for things you already know
about, not a security judgment made on your behalf. Everything else still
goes to the AI, and every event -- gated or not -- is still written to the
database and the flat log.

NAME-BASED TRUST vs HASH-BASED TRUST -- read this before relying on either:

trusted_process_names matches on filename only ("notepad.exe"). That's trivial
to spoof -- literally rename any binary. trusted_process_hashes matches on the
sha256 of the file on disk at the path the collector reported, which is much
harder to spoof (an attacker would need to either replace the trusted file at
that exact path, which is a much bigger ask than a filename match, or find a
sha256 collision, which isn't practically feasible). Prefer hash-based trust
over name-based trust when you can -- name-based is kept only because it's
zero-setup and still meaningfully cuts noise for obviously-benign, high-
frequency local tools.

CAVEAT, STATED PLAINLY: hash computation here reads the file at
`exe`/`executable_path` from event.details at evaluation time -- i.e. AFTER
the process already started. On Windows in particular, some processes lock
their own executable file while running, which can make the read fail
(handled below by falling through to "not trusted" rather than crashing).
This hashing path has NOT been run against real Windows or macOS processes
yet -- it's implemented and unit-testable against files on disk, but whether
file-locking behavior actually blocks reads in practice on either OS is an
open question pending real-hardware testing, same as everything else in this
codebase that hasn't been run outside the dev sandbox.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from core.events import EventCategory, MonitorEvent

logger = logging.getLogger("aegis.rule_engine")

# Cap how much of a file we'll hash in one go so a multi-GB binary can't stall
# the dispatcher thread -- this is a noise-reduction feature, not a security
# gate, so a hash that took multiple seconds to compute would be defeating
# its own purpose (the whole point is fast, cheap allowlisting).
_HASH_READ_LIMIT_BYTES = 200 * 1024 * 1024  # 200MB

# THE ONE BUILT-IN SUPPRESSION, AND WHY IT DOESN'T CONTRADICT THE ALLOWLIST
# PHILOSOPHY ABOVE: binaries under /System/ on a SIP-enabled Mac cannot be
# modified or replaced even with root access -- System Integrity Protection
# enforces that at the kernel level. So "the executable's real path is under
# /System/" is an integrity property of the file, not a name match an attacker
# can spoof by calling their payload "mdworker". This is what makes it safe to
# skip the AI call for the constant stream of Apple platform noise (mdworker,
# XPC service helpers, /System/Applications apps) that otherwise dominates the
# timeline and the AI bill.
#
# DELIBERATELY NOT COVERED: /usr/bin, /usr/sbin, /bin, /sbin. Those are also
# SIP-protected, but they're exactly living-off-the-land territory -- osascript,
# curl, nc, python3, the shells. The binary being genuine Apple software says
# nothing about whether its *invocation* is benign, and narrating those
# invocations is Aegis's whole job. Only /System/ (GUI apps, daemons, framework
# helpers -- things a user or launchd starts, not things an attacker scripts
# with) gets suppressed.
_SIP_PLATFORM_PREFIX = "/System/"


def _sip_enabled() -> bool:
    """One-shot check at RuleEngine construction. If SIP is disabled (or the
    check itself fails), the /System/ path stops being tamper-proof and the
    platform-binary suppression must not run -- fail toward more AI calls,
    never toward silent suppression."""
    if sys.platform != "darwin":
        return False
    try:
        out = subprocess.run(["csrutil", "status"], capture_output=True, text=True, timeout=5)
        return "enabled" in out.stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass
class RuleVerdict:
    skip_ai: bool
    canned_explanation: str | None = None
    reason: str = ""


def _sha256_of(path: str) -> str | None:
    try:
        p = Path(path)
        if not p.is_file():
            return None
        h = hashlib.sha256()
        read = 0
        with open(p, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
                read += len(chunk)
                if read >= _HASH_READ_LIMIT_BYTES:
                    logger.warning("Hash read limit hit for %s -- treating as unhashable, not trusted", path)
                    return None
        return h.hexdigest()
    except (OSError, PermissionError) as e:
        # Locked/permission-denied/vanished-before-we-could-read-it -- all of
        # these mean "can't verify," which must resolve to "not trusted," not
        # to an exception that takes down the dispatcher thread.
        logger.debug("Could not hash %s for trust check: %s", path, e)
        return None


class RuleEngine:
    def __init__(self, trusted_process_names: list[str] | None = None,
                 trusted_usb_ids: list[str] | None = None,
                 trusted_process_hashes: list[str] | None = None):
        # Normalize to lowercase for case-insensitive matching (Windows paths
        # especially are inconsistent about casing).
        self.trusted_process_names = {p.lower() for p in (trusted_process_names or [])}
        self.trusted_usb_ids = {u.lower() for u in (trusted_usb_ids or [])}
        self.trusted_process_hashes = {h.lower() for h in (trusted_process_hashes or [])}
        self.suppress_platform_binaries = _sip_enabled()

    def evaluate(self, event: MonitorEvent) -> RuleVerdict:
        if event.category == EventCategory.PROCESS_STARTED:
            name = str(event.details.get("image_name") or event.details.get("name") or "").lower()

            if self.trusted_process_hashes:
                exe_path = str(event.details.get("exe") or event.details.get("executable_path") or "")
                if exe_path:
                    digest = _sha256_of(exe_path)
                    if digest and digest.lower() in self.trusted_process_hashes:
                        # Confirmed bug: this hash was computed and used for the
                        # match but never written back into event.details --
                        # core/events.py's ProcessDetails TypedDict documents
                        # `sha256` as "present if the rule engine's hash check
                        # computed one," but it never actually was. The event
                        # persisted to the DB for a hash-matched process (whose
                        # own canned_explanation literally cites "its sha256
                        # matches...") carried no sha256, so the audit trail
                        # couldn't show what value was actually matched.
                        event.details["sha256"] = digest
                        return RuleVerdict(
                            skip_ai=True,
                            canned_explanation=f"{name or exe_path} started. Its sha256 matches your "
                                                f"trusted-hash list (config.yaml) -- harder to spoof than "
                                                f"a name match, so this wasn't sent to the AI explainer.",
                            reason="user_trusted_process_hash",
                        )

            if name and name in self.trusted_process_names:
                return RuleVerdict(
                    skip_ai=True,
                    canned_explanation=f"{name} started. This is on your trusted-process list "
                                        f"(config.yaml), so this wasn't sent to the AI explainer.",
                    reason="user_trusted_process",
                )

            if self.suppress_platform_binaries:
                exe_path = str(event.details.get("exe") or event.details.get("executable_path") or "")
                if exe_path:
                    try:
                        # resolve() first so /tmp/evil/../../System/... or a
                        # symlink named like a system path can't fake the prefix.
                        resolved = str(Path(exe_path).resolve())
                    except OSError:
                        resolved = ""
                    if resolved.startswith(_SIP_PLATFORM_PREFIX):
                        return RuleVerdict(
                            skip_ai=True,
                            canned_explanation=(
                                f"{name or resolved} started from {resolved}. That location is "
                                f"protected by macOS System Integrity Protection -- the file "
                                f"cannot be modified or replaced, even with administrator access "
                                f"-- so this is genuine Apple system software behaving normally. "
                                f"Expected activity; not sent to the AI explainer."
                            ),
                            reason="os_platform_binary",
                        )

        if event.category in (EventCategory.USB_CONNECTED, EventCategory.USB_REMOVED):
            device_id = str(event.details.get("device_id") or event.details.get("serial_num") or "").lower()
            if device_id and device_id in self.trusted_usb_ids:
                return RuleVerdict(
                    skip_ai=True,
                    canned_explanation=f"USB device event for a device on your trusted-device list "
                                        f"(config.yaml). Not sent to the AI explainer.",
                    reason="user_trusted_usb",
                )

        return RuleVerdict(skip_ai=False)


if __name__ == "__main__":
    # Self-check for the platform-binary suppression branch. Forces the SIP
    # flag both ways so it runs identically on a SIP-disabled Mac or on CI.
    engine = RuleEngine()
    engine.suppress_platform_binaries = True
    mk = lambda exe: MonitorEvent(category=EventCategory.PROCESS_STARTED,
                                  summary="t", details={"name": "x", "exe": exe}, source="process")
    assert engine.evaluate(mk("/System/Library/CoreServices/mdworker")).reason == "os_platform_binary"
    assert engine.evaluate(mk("/System/Library/../Library/x")).reason == "os_platform_binary"  # resolve() normalizes
    assert not engine.evaluate(mk("/tmp/../System/Library/x")).skip_ai  # /tmp is a symlink: resolves to /private/System
    assert not engine.evaluate(mk("/usr/bin/osascript")).skip_ai      # LOLBins always reach the AI
    assert not engine.evaluate(mk("/tmp/System/payload")).skip_ai     # prefix must be the real root
    assert not engine.evaluate(mk("")).skip_ai
    engine.suppress_platform_binaries = False
    assert not engine.evaluate(mk("/System/Library/CoreServices/mdworker")).skip_ai  # SIP off -> no suppression
    print("rule_engine self-check: OK")
