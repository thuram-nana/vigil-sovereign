"""H4b-B — the REAL producer persists a CAPABILITY-annotated proposal (and never breaks if the join fails).

Slice H4b-A gave ``proposal_document`` an optional capabilities map; slice H4b-B wires the PRODUCER so a
``vigil engage --brain hexstrike`` run actually persists that annotation. ``engine_think.BrainThink._persist``
now computes real rows via ``live.capability_join.resolve(probe_host=True)`` (function-local import, FATAL-2)
and folds them into ``{tool -> {status, reason}}`` for ``proposal_document`` — so the Brain-decision panel
shows WHY each proposed tool can or cannot run.

FAIL-SOFT is load-bearing: if ``resolve()`` raises (a probe/registry hiccup) the proposal is STILL persisted,
just UNANNOTATED — a panel-data hiccup must never sink the run.

Runs in the OFFENSE leg (needs both ``vigil_integration`` and ``framework``); skips cleanly in the sovereign
leg.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("framework")  # offense leg only

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain

TARGET = "http://127.0.0.1/"


def _drive(rd: Path, *, target: str = TARGET, objective: str = "comprehensive") -> list[str]:
    """Drive BrainThink EXACTLY as `vigil engage --brain hexstrike` constructs it, to exhaustion.
    Returns the ordered tool names it proposed (for the panel-parity check)."""
    bt = BrainThink(HexstrikeBrain(), target=target, objective=objective, proposal_out=rd)
    state = SimpleNamespace(objective=target)
    tools: list[str] = []
    for _ in range(64):
        dec = bt(state)
        tc = getattr(dec, "tool", None)
        if tc is None:
            break
        tools.append(tc.tool_name)
    assert tools, "the brain proposed no steps — fixture/brain broken"
    return tools


def _read(rd: Path) -> dict:
    art = rd / "brain-proposal.json"
    assert art.is_file(), "BrainThink did not persist brain-proposal.json"
    return json.loads(art.read_text(encoding="utf-8"))


def test_persisted_proposal_is_capability_annotated(tmp_path):
    rd = tmp_path / "A"
    proposed = _drive(rd)
    doc = _read(rd)

    steps = doc["steps"]
    # every step carries a capability with a non-empty status + reason field present
    for s in steps:
        assert "capability" in s, s
        cap = s["capability"]
        assert cap.get("status"), ("statusless capability", s)
        assert "reason" in cap, ("capability missing reason key", s)

    by_tool = {s["tool"]: s for s in steps}
    assert "sqlmap" in by_tool, "the comprehensive web chain should include sqlmap"
    sqlmap_cap = by_tool["sqlmap"]["capability"]
    assert sqlmap_cap["status"] == "BLOCKED", sqlmap_cap
    assert "excluded" in (sqlmap_cap["reason"] or ""), sqlmap_cap

    # panel parity (test_brain_proposal_panel invariant): the persisted chain's tool order == what was driven
    assert [s["tool"] for s in steps] == proposed, ([s["tool"] for s in steps], proposed)
    # and the per-step render fields the panel reads are still all present
    for s in steps:
        assert {"tool", "priority", "danger", "effectiveness", "params"} <= set(s), s


def test_negative_control_the_join_was_really_consumed_not_a_constant(tmp_path):
    """If the annotation were a hard-coded constant, every step would share one status. The real join over
    the committed catalogue + a live probe yields at least two distinct statuses for the web chain (sqlmap
    is BLOCKED-excluded, and a builder-less proposable tool like katana is UNAVAILABLE) — host-independent."""
    rd = tmp_path / "B"
    _drive(rd)
    doc = _read(rd)
    statuses = {s["capability"]["status"] for s in doc["steps"]}
    assert len(statuses) > 1, ("annotation looks constant — the join was not consumed", statuses)


def test_fail_soft_a_resolve_error_persists_the_proposal_unannotated(tmp_path, monkeypatch):
    """A resolve() failure must NOT sink persistence: the proposal is still written, just unannotated
    (no step carries a 'capability' key — proposal_document's default None path)."""
    import vigil_integration.live.capability_join as cj

    def _boom(*a, **k):
        raise RuntimeError("simulated probe/registry failure")

    monkeypatch.setattr(cj, "resolve", _boom)

    rd = tmp_path / "C"
    proposed = _drive(rd)          # must not raise despite resolve() blowing up
    doc = _read(rd)                # the file must still exist
    steps = doc["steps"]
    assert [s["tool"] for s in steps] == proposed, "the chain must persist intact when the join fails"
    assert all("capability" not in s for s in steps), (
        "a resolve() failure must leave the proposal UNANNOTATED, never partially/failed-annotated"
    )
