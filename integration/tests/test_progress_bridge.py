"""W6c — the offense child's progress bridge: WARDEN blocks and Strix graph activity reach the console's
live process box via ``$VIGIL_PROOF_RUN_DIR/progress.jsonl`` (the file ``/api/events?run=`` already tails).

The invariants under test:
  * a block is SURFACED (gate + what was refused + why + fatal), so "blocked by WARDEN, because X" is visible;
  * surfacing is BEST-EFFORT — a feed failure never breaks the run, and never turns a block into an allow;
  * an ALLOWED call emits nothing (negative control — the box must not show a phantom block);
  * the Strix summary leaks no agent ids/names/metadata — only a status histogram.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from vigil_integration.progress import append_progress, strix_graph_event
from vigil_integration.warden_gate import WardenDenied, WardenGateHooks

ENV = "VIGIL_PROOF_RUN_DIR"


def _stub(table):
    return lambda name: table.get(name, "A3")


class _FakeTool:
    def __init__(self, name):
        self.name = name


def _lines(d):
    p = os.path.join(str(d), "progress.jsonl")
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


# --- append_progress: writes, and fails SILENTLY ---------------------------------------------------
def test_append_progress_writes_one_json_line_per_event(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    assert append_progress({"event": "a", "n": 1}) is True
    assert append_progress({"event": "b"}) is True
    got = _lines(tmp_path)
    assert [g["event"] for g in got] == ["a", "b"], "appends must not truncate a prior line"
    assert got[0]["n"] == 1


def test_append_progress_is_a_silent_noop_without_a_run_dir(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert append_progress({"event": "a"}) is False          # no console run dir → nothing to feed
    monkeypatch.setenv(ENV, str(tmp_path / "does-not-exist"))
    assert append_progress({"event": "a"}) is False          # unwritable path → silent, no raise


def test_append_progress_rejects_non_mappings_and_oversized_payloads(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    assert append_progress("not-a-mapping") is False         # type: ignore[arg-type]
    assert append_progress({"event": "big", "blob": "x" * 40000}) is False   # dropped, not torn
    assert _lines(tmp_path) == []


# --- WARDEN blocks are surfaced -------------------------------------------------------------------
def test_warden_hard_deny_is_surfaced_as_a_fatal_block(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"rm_rf": "A3"}), denylist=["rm_rf"])
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("rm_rf")))
    (ev,) = _lines(tmp_path)
    assert ev["event"] == "warden.block" and ev["gate"] == "warden"
    assert ev["action_refused"] == "rm_rf"
    assert ev["fatal"] is True                      # a hard class deny never runs
    assert ev["reason"], "a block with no reason tells the operator nothing"


def test_warden_queue_block_is_surfaced_as_non_fatal(tmp_path, monkeypatch):
    """A QUEUE block (no approval authority) is approvable — it must NOT read as a fatal deny."""
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}))   # no approver → fail-safe block
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))
    (ev,) = _lines(tmp_path)
    assert ev["action_refused"] == "exec_command" and ev["outcome"] == "queue"
    assert ev["fatal"] is False
    assert "authority" in ev["reason"]


def test_warden_denied_by_approver_is_surfaced(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}), approver=lambda *_a: False)
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))
    (ev,) = _lines(tmp_path)
    assert ev["event"] == "warden.block" and ev["action_refused"] == "exec_command"


# --- NEGATIVE CONTROLS: no phantom blocks, and the feed never weakens the gate ---------------------
def test_an_allowed_call_emits_no_block(tmp_path, monkeypatch):
    """The box must never show a block for a call that RAN — the phantom-block negative control."""
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"http.get": "A0"}), floor="A1", ceiling="A1")
    asyncio.run(hooks.on_tool_start(None, None, _FakeTool("http.get")))   # auto → no raise
    assert _lines(tmp_path) == []


def test_an_approved_call_emits_no_block(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, str(tmp_path))
    hooks = WardenGateHooks(classify=_stub({"exec_command": "A3"}), approver=lambda *_a: True)
    asyncio.run(hooks.on_tool_start(None, None, _FakeTool("exec_command")))   # owner-approved → ran
    assert _lines(tmp_path) == []


def test_a_broken_feed_still_blocks(tmp_path, monkeypatch):
    """FAIL-SAFE: if surfacing the block raises, the BLOCK still happens. Telemetry must never be able to
    turn a refusal into an allow."""
    monkeypatch.setenv(ENV, str(tmp_path))
    import vigil_integration.warden_gate as wg

    def _boom(*_a, **_k):
        raise OSError("feed exploded")

    monkeypatch.setattr(wg, "append_progress", _boom)
    hooks = WardenGateHooks(classify=_stub({"rm_rf": "A3"}), denylist=["rm_rf"])
    with pytest.raises(WardenDenied):        # still refused
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("rm_rf")))


def test_no_run_dir_means_no_feed_but_still_blocks(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    hooks = WardenGateHooks(classify=_stub({"rm_rf": "A3"}), denylist=["rm_rf"])
    with pytest.raises(WardenDenied):
        asyncio.run(hooks.on_tool_start(None, None, _FakeTool("rm_rf")))


# --- Strix graph summary: a histogram, never identities -------------------------------------------
def test_strix_graph_event_is_a_histogram_only():
    snap = {"statuses": {"a1": "running", "a2": "running", "a3": "done"},
            "names": {"a1": "sqli-hunter"}, "metadata": {"a1": {"secret": "s3cret"}}}
    ev = strix_graph_event(snap)
    assert ev == {"event": "strix.graph", "agents": 3, "statuses": {"running": 2, "done": 1}}
    blob = json.dumps(ev)
    assert "sqli-hunter" not in blob and "s3cret" not in blob and "a1" not in blob


def test_strix_graph_event_handles_empty_and_junk():
    assert strix_graph_event(None) is None
    assert strix_graph_event({}) is None
    assert strix_graph_event({"statuses": "not-a-map"}) is None      # type: ignore[arg-type]
    assert strix_graph_event({"statuses": {}}) == {"event": "strix.graph", "agents": 0, "statuses": {}}
