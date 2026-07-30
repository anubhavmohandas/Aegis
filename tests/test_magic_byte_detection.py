"""Runnable self-check: executable detection survives a lying file extension.

THE GAP THIS CLOSES: detection used to be extension-only, so a Mach-O binary
saved as `invoice.pdf` scored the same as a text file -- and on macOS that is
the realistic drop, because native Mach-O executables carry NO extension at
all and never matched anything in _EXECUTABLE_EXTENSIONS to begin with.

Three properties are asserted, and all three have teeth:

  1. Content beats the name. A real Mach-O/ELF/PE/script is flagged whatever
     it is called, and a genuine PDF is not flagged just for sitting nearby.

  2. The verdict is RECORDED at detection time (details["exec_kind"]), not
     recomputed on read. core/signals.py annotates every visible row on every
     dashboard poll, so re-sniffing there would put a disk read in the poll
     loop and -- worse -- would let the drawer say "not executable" under a
     severity the engine raised for exactly the opposite reason, once the file
     was deleted. Rows written before exec_kind existed must still explain
     themselves via the extension fallback.

  3. Reading the file cannot hang the dispatcher. Every collector feeds one
     thread; opening a FIFO for read blocks until a writer appears, so a named
     pipe dropped in a watched folder would otherwise stall ALL monitoring.

No framework: `python tests/test_magic_byte_detection.py`.
"""
import os
import signal
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.events import EventCategory, MonitorEvent
from core.severity_engine import SeverityEngine, executable_kind
from core.signals import signals_for

tmp = Path(tempfile.mkdtemp(prefix="aegis-magic-"))


def write(name: str, data: bytes) -> str:
    p = tmp / name
    p.write_bytes(data)
    return str(p)


# --- 1. content beats the name ---------------------------------------------
MACH_O_64_LE = b"\xcf\xfa\xed\xfe"
MACH_O_32_LE = b"\xce\xfa\xed\xfe"
MACH_O_64_BE = b"\xfe\xed\xfa\xcf"
MACH_O_32_BE = b"\xfe\xed\xfa\xce"
FAT_BINARY = b"\xca\xfe\xba\xbe"

for label, magic in (("64le", MACH_O_64_LE), ("32le", MACH_O_32_LE),
                     ("64be", MACH_O_64_BE), ("32be", MACH_O_32_BE)):
    path = write(f"invoice-{label}.pdf", magic + b"\x00" * 64)
    assert executable_kind(path) == "Mach-O", f"{label} Mach-O disguised as .pdf went undetected"

assert executable_kind(write("fat.pdf", FAT_BINARY + b"\x00" * 64)) is not None
assert executable_kind(write("linux.jpg", b"\x7fELF" + b"\x00" * 64)) == "ELF"
assert executable_kind(write("windows.docx", b"MZ\x90\x00" + b"\x00" * 64)) == "PE"
assert executable_kind(write("notes.txt", b"#!/bin/sh\necho hi\n")) == "script"

# A genuine PDF must not be swept up by proximity to the above.
assert executable_kind(write("real.pdf", b"%PDF-1.4\ntrailer\n")) is None
assert executable_kind(write("empty.pdf", b"")) is None

# Extension still decides without ever touching the disk -- which is what keeps
# this working for a file that has already been deleted.
assert executable_kind(str(tmp / "gone-forever.exe")) == ".exe"
assert executable_kind(str(tmp / "gone-forever.pdf")) is None
assert executable_kind(str(tmp)) is None, "a directory is not an executable"
assert executable_kind("") is None

# --- 2. the verdict is recorded once, at detection time ---------------------
engine = SeverityEngine()


def classify(details, category=EventCategory.FILE_CREATED):
    ev = MonitorEvent(category=category, summary="File created", details=dict(details),
                      source="folder", confidence="certain")
    return engine.evaluate(ev), ev.details


disguised = str(tmp / "invoice-64le.pdf")
level, details = classify({"path": disguised})
assert level == "high", f"a disguised Mach-O must be surfaced, got {level}"
assert details["exec_kind"] == "Mach-O", "the verdict must be stored for the drawer to reuse"

level, details = classify({"path": str(tmp / "real.pdf")})
assert level == "low" and "exec_kind" not in details, "a real PDF must stay low and unannotated"

# The rename evasion, now caught on content rather than on the new extension.
level, details = classify({"path": str(tmp / "a.txt"), "dest_path": disguised},
                          category=EventCategory.FILE_MOVED)
assert level == "high" and details["exec_kind"] == "Mach-O", \
    "renaming a Mach-O to .pdf must be caught on the destination's CONTENT"


def drop_signal(details):
    codes = {"executable_drop", "not_executable"}
    return next(s for s in signals_for({"source": "folder", "category": "file_created",
                                        "confidence": "certain", "details": details})
                if s["code"] in codes)

# The drawer reads the stored verdict...
s = drop_signal({"path": disguised, "exec_kind": "Mach-O"})
assert s["code"] == "executable_drop" and s["ext"] == "Mach-O"

# ...and keeps reading it after the file is gone, which is the whole point of
# storing it. Deleting the file must not flip the drawer to "not executable".
os.remove(disguised)
s = drop_signal({"path": disguised, "exec_kind": "Mach-O"})
assert s["code"] == "executable_drop", "a deleted file must not un-explain its own severity"

# Rows persisted before exec_kind existed still fall back to the extension.
s = drop_signal({"path": "/Users/me/Downloads/setup.exe"})
assert s["code"] == "executable_drop" and s["ext"] == ".exe", "legacy rows must keep working"
s = drop_signal({"path": "/Users/me/Downloads/notes.pdf"})
assert s["code"] == "not_executable"

# --- 3. reading cannot hang the dispatcher ---------------------------------
if hasattr(os, "mkfifo"):
    fifo = tmp / "pipe"
    os.mkfifo(fifo)

    def _hung(*_):
        raise AssertionError(
            "opening a FIFO blocked -- a named pipe in a watched folder would "
            "stall every collector, since all events share one dispatcher thread")

    signal.signal(signal.SIGALRM, _hung)
    signal.alarm(5)
    try:
        assert executable_kind(str(fifo)) is None
    finally:
        signal.alarm(0)

print("ok: disguised executables are caught, recorded once, and cannot hang the dispatcher")
