"""
Standalone pywintrace isolation probe. NO Aegis imports -- if this script
receives zero events, Aegis is innocent and the problem is between Windows,
pywintrace, and the subscription itself.

Run from an elevated (Administrator) terminal, inside the venv:

    python windows\\etw_probe.py

What it does, per stage:
  Stage A: Microsoft-Windows-Kernel-Process, any_keywords=0x10, level 4
           (exactly what Aegis uses)
  Stage B: same provider, any_keywords=0xFFFFFFFFFFFFFFFF, level 5
           (maximally permissive -- only runs if Stage A got nothing)

During each stage it spawns a few short-lived child processes to guarantee
ProcessStart events exist, then reports three independent signals:
  1. callback events received      (the full pipeline works)
  2. kernel-side session counters  (is Windows writing events into the
     session buffers at all? BuffersWritten/EventsLost from ControlTrace)
  3. consumer thread liveness      (pywintrace swallows ProcessTrace()
     failures -- a dead thread here means the consumer died silently)

Interpreting results:
  A gets events            -> pywintrace + subscription fine; bug is in how
                              Aegis wires/logs it.
  A silent, B gets events  -> keyword/level nuance on this Windows build.
  Both silent, buffers written, consumer alive -> delivery/parse problem
                              inside pywintrace's consumer.
  Both silent, no buffers written -> provider enable is ineffective on this
                              build; pywintrace 0.2.0 viability is in doubt.
  Consumer thread dead     -> ProcessTrace() failed silently; that's the bug.
"""

import ctypes
import logging
import platform
import subprocess
import sys
import time

# Surface pywintrace's internal logger -- it logs parse errors and callback
# exceptions that are otherwise swallowed.
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

try:
    from etw import ETW, ProviderInfo
    from etw.GUID import GUID
except ImportError as e:
    sys.exit(f"pywintrace not importable: {e}")

KERNEL_PROCESS = "Microsoft-Windows-Kernel-Process"
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

WATCH_SECONDS = 8
CHILD_SPAWNS = 3


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def spawn_children():
    """Guarantee ProcessStart events exist while the trace is running."""
    for i in range(CHILD_SPAWNS):
        subprocess.run(["cmd", "/c", "ver"], capture_output=True)
        print(f"    spawned child process {i + 1}/{CHILD_SPAWNS} (cmd /c ver)")
        time.sleep(0.5)


def query_session_counters(trace):
    """Kernel-side truth: has Windows written anything into this session?"""
    try:
        props = trace.query()
        return {
            "BuffersWritten": getattr(props, "BuffersWritten", "?"),
            "EventsLost": getattr(props, "EventsLost", "?"),
            "RealTimeBuffersLost": getattr(props, "RealTimeBuffersLost", "?"),
            "NumberOfBuffers": getattr(props, "NumberOfBuffers", "?"),
        }
    except Exception as e:
        return {"query failed": repr(e)}


def run_stage(label, any_keywords, level):
    print(f"\n=== Stage {label}: any_keywords={any_keywords:#x}, level={level} "
          f"({WATCH_SECONDS}s watch) ===")

    events = []

    def callback(event_tuple):
        try:
            event_id, payload = event_tuple
        except Exception:
            event_id, payload = "?", event_tuple
        events.append(event_id)
        if len(events) <= 3:
            print(f"    EVENT id={event_id} keys={list(payload) if isinstance(payload, dict) else type(payload)}")
            print(f"      payload={payload!r}"[:600])

    provider = ProviderInfo(
        KERNEL_PROCESS,
        GUID(KERNEL_PROCESS_GUID),
        level,
        any_keywords=any_keywords,
    )
    trace = ETW(session_name=f"AegisEtwProbe{label}",
                providers=[provider],
                event_callback=callback)
    trace.start()
    print("    session started")

    spawn_children()
    time.sleep(max(0, WATCH_SECONDS - CHILD_SPAWNS * 0.5))

    counters = query_session_counters(trace)
    consumer_alive = trace.consumer.process_thread.is_alive()
    consumer_ended = trace.consumer.end_capture.is_set()

    trace.stop()

    print(f"\n  Stage {label} results:")
    print(f"    callback events received : {len(events)}")
    print(f"    event ids seen           : {sorted(set(events))[:10]}")
    print(f"    session counters         : {counters}")
    print(f"    consumer thread alive    : {consumer_alive}"
          f"{'' if consumer_alive else '  <-- ProcessTrace() died silently!'}")
    print(f"    consumer end flag set    : {consumer_ended}")
    return len(events)


def main():
    print(f"python     : {sys.version.split()[0]}")
    print(f"windows    : {platform.platform()}")
    try:
        from importlib.metadata import version
        print(f"pywintrace : {version('pywintrace')}")
    except Exception:
        print("pywintrace : version unknown")
    print(f"admin      : {is_admin()}")

    if not is_admin():
        sys.exit("Not elevated -- run from an Administrator terminal. Aborting.")

    got = run_stage("A", any_keywords=0x10, level=4)

    if got == 0:
        print("\nStage A silent -- escalating to maximally permissive subscription.")
        got_b = run_stage("B", any_keywords=0xFFFFFFFFFFFFFFFF, level=5)
        if got_b == 0:
            print("\nVERDICT: pywintrace received nothing from this provider even "
                  "fully permissive. Aegis is innocent. Check the counters above: "
                  "if BuffersWritten stayed ~0, the provider enable itself is "
                  "ineffective on this build; if buffers were written but no "
                  "callbacks fired, the consumer/delivery path is broken.")
        else:
            print("\nVERDICT: events flow with permissive settings but not with "
                  "0x10/level-4. Keyword/level handling differs on this build -- "
                  "adjust Aegis's ProviderInfo accordingly.")
    else:
        print("\nVERDICT: pywintrace works with Aegis's exact settings. The bug "
              "is in Aegis's integration (wiring/logging), not the subscription.")


if __name__ == "__main__":
    main()
