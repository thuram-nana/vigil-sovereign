"""Per-tool token budgets: charge/rollover, warn+throttle (never block), operator-editable limits
(not hard-coded), output clamp, tool tagging, and the fail-open safety property (metering never breaks
a caller)."""
from __future__ import annotations

import json

import pytest

from vigil_core import token_budget as tb


@pytest.fixture()
def store(tmp_path, monkeypatch):
    p = tmp_path / "token-budgets.json"
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_FILE", str(p))
    # flatten the throttle so the "delay is bounded/nonzero" assertions don't sleep for real
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_THROTTLE_BASE_S", "0.0")
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_MAX_THROTTLE_S", "0.0")
    # reload module-level throttle constants under the flattened env
    import importlib
    importlib.reload(tb)
    yield p
    importlib.reload(tb)          # restore defaults for other tests


def test_record_accumulates_and_persists(store):
    tb.record("chat", 100)
    tb.record("chat", 250)
    st = tb.status("chat")
    assert st.used == 350
    # persisted to the shared file
    data = json.loads(store.read_text())
    assert data["usage"]["used"]["chat"] == 350


def test_daily_rollover_resets_usage_but_keeps_limits(store):
    day1 = 1_000_000.0                       # some fixed epoch
    day2 = day1 + 86_400 * 2                 # +2 days
    tb.set_tool("engine", limit=500)
    tb.record("engine", 400, now=day1)
    assert tb.status("engine", now=day1).used == 400
    # next day: usage resets, the operator's limit persists
    st2 = tb.status("engine", now=day2)
    assert st2.used == 0
    assert st2.limit == 500


def test_levels_ok_warn_over(store):
    tb.set_tool("terminal", limit=1000, warn_frac=0.8, mode="throttle")
    assert tb.status("terminal").level == "ok"
    tb.record("terminal", 850)
    assert tb.status("terminal").level == "warn"      # >= 80%
    tb.record("terminal", 300)                         # now 1150 / 1000
    over = tb.status("terminal")
    assert over.level == "over"
    assert over.warn is True


def test_warn_and_throttle_never_block(store):
    # Even far over budget, the throttle delay is BOUNDED (here flattened to 0 by the fixture) and
    # reserve() never signals a refusal — there is no "deny" path in the API at all.
    tb.set_tool("chat", limit=10, mode="throttle")
    tb.record("chat", 10_000)                          # 1000x over
    st = tb.reserve("chat")
    assert st.level == "over"
    assert st.throttle_delay_s == 0.0                  # flattened; the point is it returns a NUMBER, not a veto
    assert not hasattr(st, "allowed") and not hasattr(st, "denied")


def test_throttle_delay_is_bounded_and_ramps(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_FILE", str(tmp_path / "b.json"))
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_THROTTLE_BASE_S", "1.0")
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_MAX_THROTTLE_S", "3.0")
    import importlib
    importlib.reload(tb)
    try:
        tb.set_tool("engine", limit=100, mode="throttle")
        tb.record("engine", 100)                       # exactly at limit -> frac 1.0 -> base delay
        assert tb.status("engine").throttle_delay_s == pytest.approx(1.0)
        tb.record("engine", 10_000)                    # massively over -> capped at MAX
        assert tb.status("engine").throttle_delay_s == 3.0
        # mode "warn" never throttles; mode "off" never warns or throttles
        tb.set_tool("engine", mode="warn")
        assert tb.status("engine").throttle_delay_s == 0.0
        assert tb.status("engine").warn is True
        tb.set_tool("engine", mode="off")
        assert tb.status("engine").warn is False
        assert tb.status("engine").throttle_delay_s == 0.0
    finally:
        importlib.reload(tb)


def test_limits_are_operator_editable_not_hardcoded(store):
    # a call site names only the tool; the limit comes from the store the UI writes, over the default.
    default_limit = tb.DEFAULT_TOOLS["chat"].default_limit
    assert tb.status("chat").limit == default_limit
    tb.set_tool("chat", limit=42)
    assert tb.status("chat").limit == 42               # operator override wins immediately
    # a tool the operator invented (not in the registry) is honored too
    tb.set_tool("my_custom_api", limit=7, mode="warn")
    assert tb.status("my_custom_api").limit == 7
    assert any(s.tool == "my_custom_api" for s in tb.list_status())


def test_set_tool_rejects_bad_mode(store):
    with pytest.raises(ValueError):
        tb.set_tool("chat", mode="block")              # never-block: "block" is not a valid mode


def test_clamp_output_caps_a_single_call(store):
    tb.set_tool("terminal", output_max=1000)
    assert tb.clamp_output("terminal", 50_000) == 1000     # clamped down
    assert tb.clamp_output("terminal", 200) == 200         # under the ceiling: unchanged
    assert tb.clamp_output("terminal", 0) == 1             # at least 1


def test_list_status_covers_registry(store):
    tools = {s.tool for s in tb.list_status()}
    for t in ("engine", "chat", "vulnfeed", "recon"):
        assert t in tools


def test_using_tool_contextvar(store):
    assert tb.current_tool() == "engine"               # default
    with tb.using_tool("chat"):
        assert tb.current_tool() == "chat"
    assert tb.current_tool() == "engine"               # restored


def test_metering_never_raises_on_a_broken_store(tmp_path, monkeypatch):
    # point the store at a path that cannot be created (a file where a directory must go)
    bad = tmp_path / "afile"
    bad.write_text("x")
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_FILE", str(bad / "nested" / "budgets.json"))
    import importlib
    importlib.reload(tb)
    try:
        # none of these may raise — the caller must always be able to proceed
        st = tb.record("chat", 100)
        assert st.used >= 0
        assert tb.reserve("chat").throttle_delay_s == 0.0
        assert tb.clamp_output("chat", 10_000) in (10_000, tb.DEFAULT_TOOLS["chat"].default_output_max)
        assert isinstance(tb.list_status(), list)
    finally:
        importlib.reload(tb)
