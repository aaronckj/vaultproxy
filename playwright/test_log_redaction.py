"""Regression guard: agent.py must NEVER log the password value.

Captures stdout/stderr during a simulated stdin protocol round-trip with a
fill action and greps for the test password fixture. If it leaks, the test
fails loudly.

This is an isolated unit test of the I/O envelope — it does NOT spawn a real
browser. Playwright is mocked via sys.modules.
"""

import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock

PASSWORD_FIXTURE = "T3stPassWord!XYZ-FixtureNoLeak-2026"


def _make_fake_playwright():
    """Construct a minimal sync_playwright stand-in that lets agent.py reach
    its stdin loop without crashing."""
    page = MagicMock()
    page.fill = MagicMock(return_value=None)
    page.url = "https://example.com/login"
    page.content = MagicMock(return_value="<html><body>OK</body></html>")
    browser = MagicMock()
    browser.new_page = MagicMock(return_value=page)
    browser.close = MagicMock(return_value=None)
    p_obj = MagicMock()
    p_obj.chromium.launch = MagicMock(return_value=browser)
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=p_obj)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


def test_agent_does_not_log_password_on_fill():
    """Drive agent.py's stdin loop with a fill action carrying the password
    fixture. Capture stdout/stderr. Assert the fixture is absent."""
    fake_pw = _make_fake_playwright()
    sys.modules["playwright"] = MagicMock()
    sys.modules["playwright.sync_api"] = MagicMock(sync_playwright=lambda: fake_pw)

    # Drive stdin with one fill action then close.
    cmds = [
        json.dumps({"action": "fill", "selector": "input[type=password]", "value": PASSWORD_FIXTURE}) + "\n",
        json.dumps({"action": "close"}) + "\n",
    ]
    sys.stdin = io.StringIO("".join(cmds))

    # Import (or re-import) agent.py and run main().
    import importlib
    import importlib.util
    import os

    spec = importlib.util.spec_from_file_location(
        "agent_under_test",
        os.path.join(os.path.dirname(__file__), "agent.py"),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        spec.loader.exec_module(mod)
        mod.main()

    combined = out.getvalue() + err.getvalue()
    assert PASSWORD_FIXTURE not in combined, (
        f"LEAK: password fixture appeared in output: {combined[-500:]!r}"
    )
    # Also confirm the success replies are present, so we know the fill
    # actually executed (and the test isn't trivially passing on a no-op).
    assert '"status": "ok"' in combined
