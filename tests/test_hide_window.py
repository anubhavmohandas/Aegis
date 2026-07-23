"""Regression test for the Hide Window crash.

Hiding the window aborted the whole app (SIGABRT), silently ending monitoring:
the block handed to addOperationWithBlock_ returned the BOOL from
setActivationPolicy_, and PyObjC types those blocks as `void` -- depythonifying
the result raised, and a Python exception escaping a block becomes an uncaught
Obj-C exception. So the two invariants worth pinning are: the block returns
None, and it never lets an exception escape.

Runs on any platform: AppKit is stubbed, so nothing here touches Cocoa.
"""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import desktop_app


class _FakeQueue:
    def __init__(self):
        self.block = None

    def addOperationWithBlock_(self, block):
        self.block = block


def _stub_appkit(queue):
    mod = types.ModuleType("AppKit")
    mod.NSOperationQueue = types.SimpleNamespace(mainQueue=lambda: queue)
    sys.modules["AppKit"] = mod


def test_main_thread_block_is_void_and_swallows_errors():
    queue = _FakeQueue()
    _stub_appkit(queue)

    # 1. A callable returning a value (setActivationPolicy_ returns BOOL) must
    #    not make the block return it -- that return value is what aborted.
    desktop_app._run_on_main_thread(lambda: True)
    assert queue.block() is None

    # 2. A raising callable must not propagate out of the block.
    desktop_app._run_on_main_thread(lambda: 1 / 0)
    assert queue.block() is None

    # 3. The real payload discards the BOOL.
    calls = []
    app = types.SimpleNamespace(setActivationPolicy_=lambda p: calls.append(p) or True)
    assert desktop_app._set_policy(app, 1) is None
    assert calls == [1]


def test_hide_window_survives_a_broken_window():
    class _Boom:
        def hide(self):
            raise RuntimeError("no window")

    desktop_app._hide_window(_Boom())      # must not raise: a crash here = monitoring outage
    desktop_app._show_window(_Boom())


if __name__ == "__main__":
    test_main_thread_block_is_void_and_swallows_errors()
    test_hide_window_survives_a_broken_window()
    print("ok")
