"""
Tests for the gated LogSourceSensor (defender.logsource) — offline log ingestion behind the
W1.4 fail-closed tool seam.

It is Tier-1, no entitlement, no egress, and names no host in its args, so ``invoke_tool``'s
gate chain reduces to the engagement KILL-SWITCH: a tripped switch REFUSES the read (nothing is
parsed), a missing file degrades cleanly, and it mints nothing into the world-model.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolRegistry
from framework.v2.agents.tools.invoker import invoke_tool
from framework.v2.common import paths as _paths
from framework.v2.defender.logsource import LogSourceSensor


def _registry() -> ToolRegistry:
    r = ToolRegistry()
    r.register(LogSourceSensor())
    return r


def test_run_reads_a_file_and_returns_events(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("<38>Oct 11 22:14:15 web01 sshd[1]: Failed password user=admin\n", encoding="utf-8")
    res = LogSourceSensor().run({"log": str(log)}, ToolContext(slug="alpha"))
    assert res.ok
    assert res.output["count"] == 1
    assert res.output["events"][0]["fields"]["user"] == "admin"


def test_run_missing_arg_is_clean_failure() -> None:
    assert not LogSourceSensor().run({}, ToolContext(slug="alpha")).ok


def test_run_nonexistent_file_is_clean_failure() -> None:
    res = LogSourceSensor().run({"log": "/no/such/file.log"}, ToolContext(slug="alpha"))
    assert not res.ok and "not found" in (res.note or "")


def test_normalize_mints_nothing() -> None:
    # defensive log events do not enter the attack world-model (prove-don't-guess)
    res = LogSourceSensor().run({"log": "/no/such"}, ToolContext(slug="alpha"))
    assert LogSourceSensor().normalize(res, ToolContext(slug="alpha"), seq=1) == []


def test_invoke_tool_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # point the kill-switch at a tmp path that does NOT exist -> switch is CLEAR
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: tmp_path / "targets" / s / ".halt")
    log = tmp_path / "alerts.cef"
    log.write_text("CEF:0|V|P|1|100|worm|10|src=10.0.0.1\n", encoding="utf-8")
    res = invoke_tool(_registry(), "log_source", {"log": str(log)}, ToolContext(slug="alpha"))
    assert res.ok and not res.refused
    assert res.output["count"] == 1


def test_invoke_tool_refuses_when_killswitch_tripped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    halt = tmp_path / "targets" / "alpha" / ".halt"
    halt.parent.mkdir(parents=True, exist_ok=True)
    halt.write_text('{"slug": "alpha", "reason": "operator stop"}', encoding="utf-8")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: tmp_path / "targets" / s / ".halt")

    log = tmp_path / "auth.log"
    log.write_text("<38>Oct 11 22:14:15 h app: user=admin\n", encoding="utf-8")
    res = invoke_tool(_registry(), "log_source", {"log": str(log)}, ToolContext(slug="alpha"))
    # the read was REFUSED before it ran — nothing parsed, gate recorded
    assert res.refused and res.gate == "kill-switch" and not res.ok
    assert not res.output
