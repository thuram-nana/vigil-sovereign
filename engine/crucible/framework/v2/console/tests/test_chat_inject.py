"""B1 — add a message to a running engagement (mid-run steering). The load-bearing correctness property:
the console's ``engage_instruct`` must enqueue to the SAME base the running engine drains from, or the
message is written but never read. The engine drains ``instructions.drain(slug, base=config.base_dir)``,
and the launcher pins ``--base-dir _live_base()`` — so ``engage_instruct`` enqueues with that same base.

Also: the enqueue is advisory + fail-closed (unsafe slug / empty text refused, never a traceback).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions
from framework.v2.console import sessions


@pytest.fixture(autouse=True)
def _live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    yield tmp_path


def test_engage_instruct_enqueues_to_the_shared_live_base():
    out = actions.engage_instruct("eng-1", "also check the password-reset flow")
    assert out["ok"] is True and out.get("seq") is not None and out.get("slug") == "eng-1"
    # enqueue lands in _live_base(); the SEPARATE launcher-pin test proves the engine drains from that same
    # base (config.base_dir == --base-dir == _live_base()), closing the loop.
    from vigil_integration.live.instructions import drain
    got = drain("eng-1", base=actions._live_base())
    assert got == ["also check the password-reset flow"], "the message did not reach the shared base"


def test_engage_instruct_reports_running_truthfully(monkeypatch):
    """RED-PEN BLOCK-1: never claim delivery to a run that isn't alive. `running` reflects whether a run
    with this slug is actually alive to drain the message."""
    # no running run → ok, but running=False (UI then says "queued, applied on resume", not "it steers")
    out = actions.engage_instruct("eng-x", "steer me")
    assert out["ok"] is True and out["running"] is False
    # a live run for the slug → running=True
    monkeypatch.setattr(actions, "_slug_has_running_run", lambda slug, **k: True)
    out2 = actions.engage_instruct("eng-x", "steer me again")
    assert out2["ok"] is True and out2["running"] is True


def test_launcher_pins_base_dir_to_the_live_base(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/opt/vigil/bin/vigil")
    monkeypatch.setattr(sessions, "connections_of", lambda sid: [])
    cmd = actions._integration_engage_cmd("http://127.0.0.1/", "eng-1", "sess-A", "standard")
    assert "--base-dir" in cmd, "the agentic run must pin --base-dir so its instruction queue is findable"
    assert cmd[cmd.index("--base-dir") + 1] == actions._live_base(), "engage_instruct + the run must share a base"


def test_engage_instruct_is_fail_closed():
    assert actions.engage_instruct("../evil", "x")["ok"] is False          # unsafe slug
    assert actions.engage_instruct("eng-1", "   ")["ok"] is False           # empty text
    # a valid one still works afterward (fail-closed, not fail-broken)
    assert actions.engage_instruct("eng-1", "real guidance")["ok"] is True


def test_two_messages_drain_in_order():
    actions.engage_instruct("eng-2", "first")
    actions.engage_instruct("eng-2", "second")
    from vigil_integration.live.instructions import drain
    assert drain("eng-2", base=actions._live_base()) == ["first", "second"]
