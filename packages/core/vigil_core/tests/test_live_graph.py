"""vigil_core.live_graph — the customer-safe agent-GRAPH + rich-activity seam (offense emits, sovereign reads).

Invariants a false-green would break:
  * the graph is a DETERMINISTIC FOLD over the recorded rows — a node/edge can only exist if a real row produced
    it (no fabricated node, no invented edge);
  * HONEST emptiness — a quiet trail yields an EMPTY graph (not a fake heartbeat);
  * customer-safe BY CONSTRUCTION — an off-allowlist node/kind is DROPPED, an unknown agent role NORMALISES to the
    generic ``agent`` node, and an injected extra key never surfaces (a leak is impossible even via a hostile line);
  * incremental + replay — a ``since`` cursor delivers only new rows; ``since=-1`` is the full stream; a cursor
    beyond a reset file resyncs from the start;
  * generation/epoch — reset() bumps a deterministic monotone epoch so a relaunch of the reused slug is
    detectable; a stale cursor from a prior generation never returns a suffix of a new run as a continuation;
  * per-node filter — ``node=`` returns only that node's rows (what the UI does on selection);
  * fail-closed + BOUNDED — a missing / corrupt file reads as empty; an OVERSIZED seam (over the total byte /
    line ceiling) reads as empty too, so the fold is never unbounded; never raises.
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
    assert g == {"nodes": [], "edges": [], "generation": 0, "epoch": 0, "cursor": -1}
    assert lg.read(base, "never-emitted") == []
    assert lg.epoch(base, "never-emitted") == 0                    # no run has reset this seam yet


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


def test_reset_bumps_the_generation_epoch_so_a_longer_new_run_is_never_spliced_onto_a_stale_cursor():
    # Finding 2: `seq` restarts at 0 on every reset()/relaunch of the reused (org, host) slug. The only
    # in-reader recovery (`since >= len(rows)` resync) catches ONLY a reset that left the file SHORTER than a
    # stale cursor. When the NEW run has already written MORE rows than the cursor, read(since=old_cursor)
    # returns a SUFFIX of the new run — which a client would wrongly append onto the prior run. The GENERATION
    # epoch is the signal that lets the client detect the relaunch and resync from seq 0 instead.
    base = tempfile.mkdtemp()
    for i in range(3):                                                 # run 1: a short trail a viewer follows to its end
        lg.emit(base, "eng1", "agent:recon", "observation", ts=float(i), ref=i + 1)
    old_epoch = lg.epoch(base, "eng1")
    old_cursor = lg.graph(base, "eng1")["cursor"]
    assert old_cursor == 2
    run1_refs = {r["ref"] for r in lg.read(base, "eng1", since=-1)}
    assert run1_refs == {1, 2, 3}

    lg.reset(base, "eng1")                                            # run 2 on the SAME slug: the epoch is bumped
    new_epoch = lg.epoch(base, "eng1")
    assert new_epoch != old_epoch                                    # (a) the relaunch is DETECTABLE by the client
    for i in range(6):                                               # a LONGER run than the viewer's stale cursor
        lg.emit(base, "eng1", "agent:exploit", "result", ts=float(100 + i), ref=500 + i)

    g = lg.graph(base, "eng1")
    assert g["epoch"] == new_epoch and g["epoch"] != old_epoch       # graph() surfaces the new generation to resync on
    full_new = lg.read(base, "eng1", since=-1)
    assert [r["seq"] for r in full_new] == [0, 1, 2, 3, 4, 5]        # (b) from seq 0 -> ONLY the new run
    assert all(r["ref"] not in run1_refs for r in full_new)          # NONE of run 1's rows survive the reset
    # the seam cannot know a given viewer's epoch, so a stale cursor DOES fetch a suffix — but it is a suffix of
    # the NEW run (never a continuation of run 1), and the changed epoch is what tells the client to drop it.
    suffix = lg.read(base, "eng1", since=old_cursor)
    assert suffix and all(r["ref"] >= 500 for r in suffix)
    assert not any(r["ref"] in run1_refs for r in suffix)            # read(since=old_cursor) returns NO prior-run rows


def test_generation_epoch_is_deterministic_and_monotone_no_wall_clock():
    # determinism (byte-identical replay): the same sequence of resets yields the SAME epoch sequence — it is a
    # persisted monotone counter, never a wall-clock or RNG value.
    def _run(seed_base):
        seq = []
        for _ in range(4):
            lg.reset(seed_base, "eng1")
            seq.append(lg.epoch(seed_base, "eng1"))
        return seq
    a = _run(tempfile.mkdtemp())
    b = _run(tempfile.mkdtemp())
    assert a == [1, 2, 3, 4] == b                                    # monotone from 1, identical across replays


def test_oversized_seam_reads_as_empty_fail_closed():
    # Finding 3: _read_rows must bound the TOTAL bytes / lines it parses, honouring "an oversized file reads as
    # empty" — so neither read() nor graph() can fold an unbounded file.
    base = tempfile.mkdtemp()
    row = json.dumps({"node": "agent:recon", "kind": "observation", "ts": 1.0, "ref": 1}) + "\n"

    # (1) too many LINES -> empty (fail-closed); nothing above the ceiling is parsed.
    p = Path(base) / "eng1.graph.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for _ in range(lg._MAX_TOTAL_LINES + 1):
            fh.write(row)
    assert lg.read(base, "eng1") == []
    assert lg.graph(base, "eng1")["nodes"] == []

    # (2) too many BYTES -> empty (checked via stat BEFORE any bytes are read; an oversized file is never loaded).
    q = Path(base) / "eng2.graph.jsonl"
    q.write_text("x" * (lg._MAX_TOTAL_BYTES + 1), encoding="utf-8")
    assert lg.read(base, "eng2") == []
    assert lg.graph(base, "eng2")["nodes"] == []

    # (3) a seam comfortably UNDER both bounds still parses normally — the guard never breaks ordinary operation.
    r = Path(base) / "eng3.graph.jsonl"
    with r.open("w", encoding="utf-8") as fh:
        for _ in range(10):
            fh.write(row)
    assert len(lg.read(base, "eng3")) == 10
    assert lg.graph(base, "eng3")["nodes"][0]["id"] == "agent:recon"


def test_unsafe_slug_is_fail_closed():
    base = tempfile.mkdtemp()
    for bad in ("../escape", "a/b", ".hidden", ""):
        lg.emit(base, bad, "agent:recon", "observation", ts=1.0, ref=1)   # never writes outside the seam
        assert lg.read(base, bad) == []
        assert lg.graph(base, bad)["nodes"] == []
        assert lg.epoch(base, bad) == 0                               # an unsafe slug yields no epoch either
