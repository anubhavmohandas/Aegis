"""
Local, deterministic severity classification -- runs BEFORE the AI call, not
instead of it. Levels: "low" | "medium" | "high" | "critical".

WHY THIS IS SEPARATE FROM `confidence` (see events.py): confidence answers
"how sure are we we detected this correctly" (real-time vs polled).
Severity answers "how concerning is this event, assuming we detected it
correctly." Conflating the two would mean a real-time detection of something
harmless reads as more alarming than a polled detection of something
dangerous, which is backwards. They're tracked independently and both shown
in the UI.

DESIGN PRINCIPLE: default to "medium," never "low," for anything this engine
doesn't have a specific reason to downgrade. An unrecognized event getting
silently classified as low-severity is exactly the failure mode that made
the rule engine an opt-in allowlist instead of a built-in "safe" list (see
rule_engine.py) -- the same reasoning applies here. Only two things can push
severity down: (1) the user's own trusted-item list, or (2) a startup-item
*removal* event, which is inherently less actionable than an addition.

Only two things push severity up beyond the category baseline, both
well-established, boring heuristics from real EDR products, not guesses:
  - A new process executing from a temp/downloads-style path.
  - A new/modified file in a watched folder that IS executable code -- by
    extension, or by its magic bytes when the extension says otherwise (see
    executable_kind), so renaming a Mach-O binary to invoice.pdf doesn't hide it.
These are heuristics, not verdicts -- they raise the number in the UI, they
don't block anything or make a decision for the user.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.events import EventCategory, MonitorEvent
from core.rule_engine import RuleVerdict, is_system_binary

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# Binaries that live in a SIP-protected system directory but whose INVOCATION
# is the interesting part -- the living-off-the-land set. Being genuine Apple
# software says nothing about what someone is using them for, so these hold at
# the category baseline while their neighbours (ioreg, pmset, system_profiler,
# tail...) drop to low. This is an *un*safe-list, not a safe-list: an unknown
# name is not on it and therefore does NOT get the downgrade-blocking
# treatment... it gets the downgrade only by proving its path is SIP-protected.
_LOLBIN_NAMES = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "osascript", "python", "python3", "perl", "ruby", "php", "tclsh",
    "sudo", "security", "dscl", "launchctl", "openssl", "base64", "xattr",
    "screencapture", "csrutil", "spctl",
}
# occam: shells (zsh/bash/sh) are deliberately NOT in that set -- they fire on
# every terminal command and would keep the timeline at a wall of medium. The
# signal that separates "user typed a command" from "browser spawned a shell"
# is the PARENT process, not the shell itself; add parent-name lineage to
# details and gate on that if shell abuse ever needs to surface here.

_CATEGORY_BASELINE = {
    EventCategory.PROCESS_STARTED: "medium",
    EventCategory.USB_CONNECTED: "medium",
    EventCategory.USB_REMOVED: "low",
    EventCategory.STARTUP_ITEM_ADDED: "high",       # persistence mechanisms are a classic malware behavior
    EventCategory.STARTUP_ITEM_REMOVED: "medium",   # could be innocuous cleanup, or something disabling security tooling -- not assumed safe
    EventCategory.FILE_CREATED: "low",
    EventCategory.FILE_MODIFIED: "low",
    EventCategory.FILE_DELETED: "low",
    EventCategory.FILE_MOVED: "low",
    EventCategory.SESSION_LOCKED: "low",       # informational boundary markers
    EventCategory.SESSION_UNLOCKED: "low",
    EventCategory.MONITORING_GAP: "high",      # Aegis was blind for a while -- worth surfacing
    EventCategory.TAMPER_ATTEMPT: "high",      # a wrong password on a protected action
    EventCategory.TAMPER_EVIDENCE: "critical", # repeated failures -> evidence captured
}

_SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/downloads/", "\\downloads\\",
)

_EXECUTABLE_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dll", ".sh", ".command",
)

# The half of the check that a rename cannot defeat. The extension list catches
# `payload.exe`; this catches the same Mach-O binary saved as `invoice.pdf` --
# which on macOS is the more realistic drop, because native Mach-O executables
# carry NO extension at all and so never matched anything in the list above.
#
# Longest-prefix concerns don't arise: these are all distinct 2- and 4-byte
# leaders, and the first match wins.
_EXECUTABLE_MAGIC = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"#!", "script"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),   # 64-bit little-endian -- the modern default
    (b"\xce\xfa\xed\xfe", "Mach-O"),   # 32-bit little-endian
    (b"\xfe\xed\xfa\xcf", "Mach-O"),   # 64-bit big-endian
    (b"\xfe\xed\xfa\xce", "Mach-O"),   # 32-bit big-endian
    # CAFEBABE is a Mach-O universal binary AND a Java .class. No attempt is
    # made to tell them apart: both are compiled code landing in a folder the
    # user watches, which is the thing being flagged.
    (b"\xca\xfe\xba\xbe", "universal binary or Java class"),
    (b"\xbe\xba\xfe\xca", "universal binary"),
)


def _magic_bytes(path: str) -> bytes:
    """First 4 bytes of `path`, or b"" if it can't be read as a regular file.

    Every failure returns b"" on purpose. The file may already be gone (a
    create-then-delete race is normal in a watched folder), sit on a volume
    that just disconnected, or simply not be readable by this user. None of
    those are evidence of anything, and the extension check runs regardless --
    content sniffing only ever ADDS detections, it can never remove one.
    """
    try:
        if not Path(path).is_file():
            return b""   # missing, a directory, or a socket/FIFO/device node
        # O_NONBLOCK is load-bearing, not decoration: opening a FIFO for reading
        # BLOCKS until a writer appears, and this runs inline on the single
        # dispatcher thread -- a named pipe swapped in behind the is_file()
        # check would stall all event processing, for every collector, forever.
        # Windows has no O_NONBLOCK, hence the getattr.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            return os.read(fd, 4)
        finally:
            os.close(fd)
    except OSError:
        return b""


def executable_kind(path: str) -> str | None:
    """What kind of executable `path` is (".exe", "Mach-O", ...), or None.

    Shared with core/signals.py so that "is this an executable drop" has exactly
    one answer -- the severity number and the drawer's explanation of that
    number must never be able to disagree about it.
    """
    if not path:
        return None
    ext = next((e for e in _EXECUTABLE_EXTENSIONS if path.lower().endswith(e)), None)
    if ext:
        return ext   # no file read needed, and still works once the file is deleted
    magic = _magic_bytes(path)
    return next((name for sig, name in _EXECUTABLE_MAGIC if magic.startswith(sig)), None)


def _bump(level: str, steps: int = 1) -> str:
    idx = SEVERITY_ORDER.index(level)
    return SEVERITY_ORDER[min(idx + steps, len(SEVERITY_ORDER) - 1)]


class SeverityEngine:
    def evaluate(self, event: MonitorEvent, rule_verdict: RuleVerdict | None = None) -> str:
        if rule_verdict is not None and rule_verdict.skip_ai:
            # Either the user explicitly told Aegis about this item, or it's a
            # SIP-protected /System/ binary (see rule_engine.py's
            # os_platform_binary rule) -- downgrade, but never silently drop
            # it from the timeline (dispatcher still persists it, just with
            # lower urgency and no AI call).
            return "low"

        level = _CATEGORY_BASELINE.get(event.category, "medium")

        if event.category == EventCategory.PROCESS_STARTED:
            raw_path = str(
                event.details.get("exe")
                or event.details.get("executable_path")
                or event.details.get("image_name")
                or ""
            )
            path = raw_path.lower()
            if any(frag in path for frag in _SUSPICIOUS_PATH_FRAGMENTS):
                level = _bump(level)
            elif is_system_binary(raw_path):
                # The third thing that can push severity down, and the only one
                # based on an integrity property rather than user configuration:
                # the file is in a directory the kernel will not let anyone
                # modify. Routine OS housekeeping (ioreg, pmset, biomesyncd,
                # system_profiler) is what actually dominates the timeline, and
                # scoring all of it identically to an unknown binary is what
                # made every row read "medium" -- a severity that never varies
                # carries no information at all. Note the elif: a suspicious
                # path never gets quietly downgraded by this branch.
                name = str(event.details.get("image_name") or event.details.get("name") or "").lower()
                if name not in _LOLBIN_NAMES:
                    level = "low"

        if event.category in (EventCategory.FILE_CREATED, EventCategory.FILE_MODIFIED):
            if self._note_executable(event, str(event.details.get("path", ""))):
                level = _bump(level, steps=2)  # low -> high: an executable dropped in a watched folder is worth surfacing

        if event.category == EventCategory.FILE_MOVED:
            # Check the DESTINATION name, not the source. This is the specific
            # evasion on_moved was added to catch: drop "payload.txt" (fires
            # on_created, extension check finds nothing suspicious), then
            # rename it to "payload.exe" (only on_moved fires -- if this checked
            # src_path instead of dest_path, the rename to an executable
            # extension would go completely unclassified).
            if self._note_executable(event, str(event.details.get("dest_path", ""))):
                level = _bump(level, steps=2)

        return level

    @staticmethod
    def _note_executable(event: MonitorEvent, path: str) -> str | None:
        """Classify `path`, and RECORD the answer on the event.

        Recorded rather than left to be recomputed, because core/signals.py
        derives the drawer's explanation on every dashboard read -- long after
        the file may have been deleted, replaced, or unmounted. Sniffing content
        there would put a disk read on every poll of every visible row, and
        would let the drawer say "not executable" underneath a severity this
        engine raised for precisely the opposite reason. Detected once, here,
        while the file still exists; stored in details_json by _persist.
        """
        kind = executable_kind(path)
        if kind:
            event.details["exec_kind"] = kind
        return kind


if __name__ == "__main__":
    # Self-check for the system-binary downgrade -- the branch that decides
    # whether the timeline says anything at all or just repeats "medium".
    # Forces the SIP flag on so it runs the same on Linux CI or a SIP-off Mac.
    import core.rule_engine as _re

    _re._sip_ok = lambda: True  # type: ignore[assignment]

    engine = SeverityEngine()
    proc = lambda name, exe: MonitorEvent(category=EventCategory.PROCESS_STARTED,
                                          summary="t", details={"name": name, "exe": exe},
                                          source="process")

    assert engine.evaluate(proc("ioreg", "/usr/sbin/ioreg")) == "low"
    assert engine.evaluate(proc("biomesyncd", "/usr/libexec/biomesyncd")) == "low"
    assert engine.evaluate(proc("zsh", "/bin/zsh")) == "low"
    assert engine.evaluate(proc("curl", "/usr/bin/curl")) == "medium"       # LOLBin holds
    assert engine.evaluate(proc("osascript", "/usr/bin/osascript")) == "medium"
    assert engine.evaluate(proc("payload", "/Users/me/payload")) == "medium"  # unknown stays medium
    # A system-tool NAME outside a system path must not earn the downgrade,
    # and the suspicious-path bump must still win outright.
    assert engine.evaluate(proc("ioreg", "/Users/me/Downloads/ioreg")) == "high"
    assert engine.evaluate(proc("ioreg", "/tmp/ioreg")) == "high"
    assert engine.evaluate(proc("ioreg", "")) == "medium"
    # Downgrades and bumps for other categories are untouched.
    assert engine.evaluate(MonitorEvent(category=EventCategory.STARTUP_ITEM_ADDED, summary="t",
                                        details={}, source="startup")) == "high"
    assert engine.evaluate(proc("anything", "/usr/bin/anything"),
                           RuleVerdict(skip_ai=True)) == "low"
    print("severity_engine self-check: OK")
