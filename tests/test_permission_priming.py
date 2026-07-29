"""Runnable self-check: permissions are asked for at launch, and camera only
when webcam evidence is actually enabled.

The bug this pins: TCC prompts fired lazily, on first use -- so Camera and
Screen Recording were requested from inside a tamper capture, mid-incident,
right after someone typed a wrong password. core/permissions.prime() moves
them to startup.

Both halves matter and both fail silently. Prime too little and the prompt is
back at incident time; prime unconditionally and a security app demands the
camera for a feature the user deliberately left switched off.

No framework: `python tests/test_permission_priming.py`.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.permissions as perms  # noqa: E402

real_prime_folders = perms._prime_folders          # kept for the failure test below

calls = []
perms._prime_folders = lambda folders: calls.append(("folders", list(folders)))
perms._prime_screen_recording = lambda: calls.append(("screen", None))
perms._prime_camera = lambda: calls.append(("camera", None))
perms.platform = SimpleNamespace(system=lambda: "Darwin")   # module-local, not the real platform


def _prime(**kw):
    calls.clear()
    cfg = {"watched_folders": ["/tmp"], "tamper_evidence_screenshot": True,
           "tamper_evidence_webcam": False, **kw}
    perms.prime(SimpleNamespace(**cfg))
    return [name for name, _ in calls]


# Default config: folders + screenshot primed, camera left alone.
assert _prime() == ["folders", "screen"], calls
assert calls[0] == ("folders", ["/tmp"]), calls

# Webcam evidence on -> camera asked at startup too.
assert _prime(tamper_evidence_webcam=True) == ["folders", "screen", "camera"], calls

# Screenshot evidence off -> no Screen Recording prompt.
assert _prime(tamper_evidence_screenshot=False) == ["folders"], calls

# Non-macOS: nothing at all (Windows/Linux have no TCC to pre-answer).
perms.platform = SimpleNamespace(system=lambda: "Windows")
assert _prime(tamper_evidence_webcam=True) == [], calls
perms.platform = SimpleNamespace(system=lambda: "Darwin")

# A missing or unreadable folder must not take startup down with it.
real_prime_folders(["/definitely/not/a/real/folder", "/private/var/root"])   # no raise

print("OK -- permissions primed at launch; camera only when webcam evidence is on")
