"""vigil_core.live_graph — the customer-safe agent-GRAPH + rich-activity seam (offense emits, sovereign reads).

Invariants a false-green would break:
  * the graph is a DETERMINISTIC FOLD over the recorded rows — a node/edge can only exist if a real row produced
    it (no fabricated node, no invented edge);
  * HONEST emptiness — a quiet trail yields an EMPTY graph (not a fake heartbeat);
  * customer-safe BY CONSTRUCTION — an off-allowlist node/kind is DROPPED, an unknown agent role NORMALISES to the
    generic ``agent`` node, and an injected extra key never surfaces (a leak is impossible even via a hostile line);
  * incremental + replay — a ``since`` cursor delivers only new rows; ``since=-1`` is the full stream; a cursor
    beyond a reset file resyncs from the start;
  * per-node filter — ``node=`` returns only that node's rows (what the UI does on selection);
  * fail-closed — a missing / corrupt / oversized file reads as empty, never raises.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from vigil_core import live_graph as lg


def _seed(base: str, slug: str = "eng1") -> None:
    lg.emit(base, slug, "phase:preflight", "phase", ts=1.0, ref=1, status="started")
    lg.emit(base, slug, "agent:recon", "observation", ts=1.5, ref=5, from_node="phase:preflight", edge="attach")
    lg.emit(base, slug, "phase:scan", "phase", ts=2.0, ref=2, status="started",
            from_node="phase:preflight", edge="sequence")
    lg.emit(base, slug, "agent:exploit", "tool_call", ts=2.5, ref=10, from_node="agent:recon", edge="delegation")
    lg.emit(base, slug, "agent:exploit", "finding", ts=3.0, ref=11, from_node="phase:scan",
            edge="attach", verified=True)
    lg.emit(base, slug, "phase:scan", "phase", ts=3.5, ref=3, status="completed")


def test_graph_is_a_fold_over_real_rows_with_status_counts_and_edges():
    base = tempfile.mkdtemp()
    _seed(base)
    g = lg.graph(base, "eng1")
    nodes = {n["id"]: n for n in g["nodes"]}
    # exactly the nodes that posted — nothing invented
    assert set(nodes) == {"phase:preflight", "phase:scan", "agent:recon", "agent:exploit"}
    assert nodes["phase:scan"]["status"] == "done"                 # latest lifecycle status (completed) wins
    assert nodes["phase:preflight"]["status"] == "running"         # only 'started' seen
    assert nodes["agent:exploit"]["events"] == 2 and nodes["agent:exploit"]["verified"] == 1
    assert nodes["agent:recon"]["group"] == "recon" and nodes["agent:exploit"]["group"] == "exploit"
    assert nodes["agent:exploit"]["first_ref"] == 10              # provenance anchor = the earliest spine ref
    edges = {(e["src"], e["dst"], e["kind"]) for e in g["edges"]}
    assert ("phase:preflight", "phase:scan", "sequence") in edges   # the phase backbone, in real order
    assert ("agent:recon", "agent:exploit", "delegation") in edges  # recorded parent->child delegation
    assert ("phase:scan", "agent:exploit", "attach") in edges       # agent active during the stage
    assert g["generation"] == 6 and g["cursor"] == 5


def test_a_quiet_trail_reads_as_empty_never_a_fabricated_graph():
    base = tempfile.mkdtemp()
    g = lg.graph(base, "never-emitted")
    assert g == {"nodes": [], "edges": [], "generation": 0, "cursor": -1}
    assert lg.read(base, "never-emitted") == []


def test_off_allowlist_node_or_kind_is_dropped_and_unknown_role_normalises():
    base = tempfile.mkdtemp()
    lg.emit(base, "eng1", "phase:EXFIL", "phase", ts=1.0, ref=1, status="started")   # bad stage -> dropped at emit
    lg.emit(base, "eng1", "agent:exploit", "pwn", ts=2.0, ref=2)                      # bad kind  -> dropped at emit
    lg.emit(base, "eng1", "agent:top-secret-xyz", "observation", ts=3.0, ref=3)       # unknown role -> agent:agent
    rows = lg.read(base, "eng1")
    assert [r["node"] for r in rows] == ["agent:agent"]
    assert [r["kind"] for r in rows] == ["observation"]
    # even a hostile line written DIRECTLY into the file is dropped/normalised + its extra key never surfaces
    p = Path(base) / "eng1.graph.jsonl"
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": 9.0, "node": "agent:exploit", "kind": "finding",
                             "secret": "not-a-real-secret-marker", "ref": 7}) + "\n")
        fh.write(json.dumps({"ts": 9.0, "node": "phase:../../etc", "kind": "phase"}) + "\n")  # path-ish -> dropped
    rows = lg.read(base, "eng1")
    assert all(set(r.keys()) == {"seq", "ts", "node", "role", "label", "kind", "status", "ref", "verified"}
               for r in rows)
    assert not any("secret" in r for r in rows)
    assert "phase:../../etc" not in [r["node"] for r in rows]


def test_incremental_cursor_and_full_replay_and_node_filter():
    base = tempfile.mkdtemp()
    _seed(base)
    full = lg.read(base, "eng1", since=-1)
    assert [r["seq"] for r in full] == [0, 1, 2, 3, 4, 5]               # since=-1 is the whole recorded stream (replay)
    assert [r["seq"] for r in lg.read(base, "eng1", since=4)] == [5]    # incremental: only rows after the cursor
    assert lg.read(base, "eng1", since=5) == []
    only = lg.read(base, "eng1", node="agent:exploit")
    assert [r["seq"] for r in only] == [3, 4] and all(r["node"] == "agent:exploit" for r in only)
    # the verified finding row carries the oracle-verified label (payload-derived, never free text)
    fin = [r for r in full if r["kind"] == "finding"][0]
    assert fin["verified"] is True and fin["label"] == "Confirmed a finding (oracle-verified)"


def test_cursor_beyond_a_reset_file_resyncs_from_the_start():
    base = tempfile.mkdtemp()
    _seed(base)
    cur = lg.graph(base, "eng1")["cursor"]
    lg.reset(base, "eng1")                                             # a new run begins — fresh trail
    lg.emit(base, "eng1", "phase:preflight", "phase", ts=10.0, ref=1, status="started")
    # a stale cursor (past the now-shorter file) resyncs to the start rather than returning nothing
    assert [r["seq"] for r in lg.read(base, "eng1", since=cur)] == [0]
    assert [n["id"] for n in lg.graph(base, "eng1")["nodes"]] == ["phase:preflight"]


def test_fail_closed_on_corrupt_and_oversized_lines():
    base = tempfile.mkdtemp()
    p = Path(base) / "eng1.graph.jsonl"
    p.write_text("not json\n" + json.dumps({"node": "agent:recon", "kind": "observation", "ts": 1.0, "ref": 1})
                 + "\n" + ("x" * 400) + "\n", encoding="utf-8")
    rows = lg.read(base, "eng1")
    assert [r["node"] for r in rows] == ["agent:recon"]               # the garbage + oversized lines are skipped
    assert lg.graph(base, "eng1")["nodes"][0]["id"] == "agent:recon"


def test_unsafe_slug_is_fail_closed():
    base = tempfile.mkdtemp()
    for bad in ("../escape", "a/b", ".hidden", ""):
        lg.emit(base, bad, "agent:recon", "observation", ts=1.0, ref=1)   # never writes outside the seam
        assert lg.read(base, bad) == []
        assert lg.graph(base, bad)["nodes"] == []
