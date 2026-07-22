"""Self-check for the desktop_app quit gate (Occam: one runnable check for the
security branch that vetoes a window close). Run: python test_quit_gate.py"""
import desktop_app as d


def test_veto_when_unauthorized():
    d._quit_authorized = False
    d._authorize_action = lambda *a, **k: False        # cancelled / wrong password
    assert d._on_closing() is False                    # MUST veto the close


def test_allow_when_password_ok():
    d._quit_authorized = False
    d._authorize_action = lambda *a, **k: True         # correct password
    assert d._on_closing() is None                     # allow the close


def test_allow_when_preauthorized_without_prompting():
    d._quit_authorized = True
    def _must_not_prompt(*a, **k):
        raise AssertionError("closing gate must not re-prompt when already authorized")
    d._authorize_action = _must_not_prompt
    assert d._on_closing() is None                     # flag short-circuits


def test_fail_closed_on_error():
    d._quit_authorized = False
    def _boom(*a, **k):
        raise RuntimeError("gate blew up")
    d._authorize_action = _boom
    assert d._on_closing() is False                    # error MUST veto, not bypass


if __name__ == "__main__":
    test_veto_when_unauthorized()
    test_allow_when_password_ok()
    test_allow_when_preauthorized_without_prompting()
    test_fail_closed_on_error()
    print("quit gate OK")
