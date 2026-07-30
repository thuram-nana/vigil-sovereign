"""
F2 — the permanent, operator-managed engagement SESSION registry (console.sessions) + its API/route wiring.

Doctrine under test:
  * a session is a first-class object: create / rename / soft-delete (reversible tombstone) / hard-delete
    (out of history) — and NEITHER delete ever touches the append-only spine or a FACT;
  * the ordering coordinate is a MONOTONIC per-registry seq (not wallclock), since F3/F4 make it the
    per-session graph coordinate;
  * path safety: an unsafe/traversal id is refused (rename/delete raise ValueError → the server maps to
    404; create returns a clean error) — a URL-derived id can never escape the sessions dir;
  * names are sanitised (control chars dropped, length-capped) — no envfile/log/JSON injection;
  * legacy chat transcripts (predating the registry) are adopted read-only so old chats still list + open;
  * the registry mints no fact and authorizes nothing.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import api, sessions


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the whole live plane (sessions + chats) + the run store at tmp."""
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    return tmp_path


# ---- CRUD + monotonic seq ---------------------------------------------------

def test_create_rename_softdelete_harddelete_roundtrip():
    c = sessions.create_session(name="AWS audit", kind="engagement")
    assert c["ok"] and c["session"]["name"] == "AWS audit" and c["session"]["kind"] == "engagement"
    sid = c["session"]["id"]

    r = sessions.rename_session(sid, "AWS prod audit")
    assert r["ok"] and r["session"]["name"] == "AWS prod audit"

    soft = sessions.delete_session(sid)
    assert soft["deleted"] == "soft"
    assert all(s["id"] != sid for s in sessions.list_sessions()["sessions"])        # hidden
    assert any(s["id"] == sid for s in sessions.list_sessions(include_deleted=True)["sessions"])

    hard = sessions.delete_session(sid, hard=True)
    assert hard["deleted"] == "hard"
    assert sessions.get_session(sid).get("error")                                    # gone entirely


def test_ordering_coordinate_is_monotonic_seq_not_wallclock():
    a = sessions.create_session(name="a")["session"]
    b = sessions.create_session(name="b")["session"]
    assert isinstance(a["created_seq"], int) and b["created_seq"] == a["created_seq"] + 1
    # a rename bumps updated_seq monotonically (strictly greater than the create seq)
    ren = sessions.rename_session(a["id"], "a2")["session"]
    assert ren["updated_seq"] > b["created_seq"]


def test_link_run_dedupes_and_promotes_chat_to_mixed():
    s = sessions.ensure_session("chat-1", kind="chat")
    assert s["kind"] == "chat"
    sessions.link_run("chat-1", "20260101-000000-001", slug="web")
    sessions.link_run("chat-1", "20260101-000000-001")            # duplicate → ignored
    got = sessions.get_session("chat-1")["session"]
    assert got["run_ids"] == ["20260101-000000-001"] and got["slug"] == "web"
    assert got["kind"] == "mixed"                                 # a chat that gained a run


# ---- path safety + name sanitisation ---------------------------------------

@pytest.mark.parametrize("bad", ["../etc", "a/b", "..", ".", "x\x00y"])
def test_unsafe_id_is_refused(bad):
    # rename/delete RAISE (server → 404); create returns a clean error. Never a traversal, never a 500.
    with pytest.raises(ValueError):
        sessions.rename_session(bad, "x")
    with pytest.raises(ValueError):
        sessions.delete_session(bad)
    assert sessions.create_session(session_id=bad).get("error")


def test_name_is_sanitised():
    c = sessions.create_session(name="  hi\nthere\tx" + "z" * 500)["session"]
    assert "\n" not in c["name"] and "\t" not in c["name"]
    assert len(c["name"]) <= 200


def test_unknown_kind_refused():
    assert sessions.create_session(name="x", kind="wizardry").get("error")


# ---- F4: session connect / disconnect (directional, consented, read-time) ---

def test_connect_is_directional_and_disconnect_re_isolates():
    a = sessions.create_session(name="A")["session"]["id"]
    b = sessions.create_session(name="B")["session"]["id"]
    r = sessions.connect_session(a, b)
    assert r["ok"] and r["session"]["connections"] == [b]
    assert sessions.connections_of(a) == [b]
    assert sessions.connections_of(b) == []            # DIRECTIONAL: B does not read A
    # disconnect re-isolates instantly (it was only a read-time scope entry — nothing of B was copied in)
    d = sessions.disconnect_session(a, b)
    assert d["ok"] and d["session"]["connections"] == []
    assert sessions.connections_of(a) == []


def test_connections_of_drops_a_tampered_entry():
    # Defense in depth: connections flow into a `vigil engage --connect <id>` argv token, so
    # connections_of must NOT trust that connect_session was the only writer. A tampered/legacy record
    # holding an unsafe id (path traversal, an injected flag) is dropped, never emitted onto the argv.
    a = sessions.create_session(name="A")["session"]["id"]
    good = sessions.create_session(name="B")["session"]["id"]
    sessions.connect_session(a, good)
    rec = sessions._read(a)
    rec["connections"] = ["../../etc/passwd", "--scope=0.0.0.0/0", good]   # two hostile ids + one valid
    sessions._write(rec)
    assert sessions.connections_of(a) == [good]                            # only the safe id survives


def test_connect_refuses_self_unknown_and_caps():
    a = sessions.create_session(name="A")["session"]["id"]
    assert sessions.connect_session(a, a).get("error")             # no self-connect
    assert sessions.connect_session(a, "nonexistent-xyz").get("error")   # unknown target
    # idempotent (a repeat connect does not duplicate)
    b = sessions.create_session(name="B")["session"]["id"]
    sessions.connect_session(a, b)
    assert sessions.connect_session(a, b)["session"]["connections"] == [b]
    # bounded
    for i in range(sessions._MAX_CONNECTIONS + 5):
        sessions.connect_session(a, sessions.create_session(name=f"C{i}")["session"]["id"])
    assert len(sessions.connections_of(a)) <= sessions._MAX_CONNECTIONS


def test_concurrent_connects_do_not_lose_updates():
    # F4 mutators run under the F2 _LOCK; concurrent connects to the SAME session must all persist.
    a = sessions.create_session(name="A")["session"]["id"]
    targets = [sessions.create_session(name=f"T{i}")["session"]["id"] for i in range(20)]
    errors: list = []
    barrier = threading.Barrier(len(targets))

    def _w(t: str) -> None:
        try:
            barrier.wait()
            sessions.connect_session(a, t)
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=_w, args=(t,)) for t in targets]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=20)
    assert not errors
    assert set(sessions.connections_of(a)) == set(targets)      # every concurrent connect persisted


@pytest.mark.parametrize("bad", ["../etc", "a/b", ".."])
def test_connect_unsafe_id_raises(bad):
    a = sessions.create_session(name="A")["session"]["id"]
    with pytest.raises(ValueError):
        sessions.connect_session(a, bad)
    with pytest.raises(ValueError):
        sessions.connect_session(bad, a)
    with pytest.raises(ValueError):
        sessions.disconnect_session(a, bad)


# ---- concurrency negative control (the console is a ThreadingHTTPServer) ----

def test_concurrent_creates_are_unique_monotonic_and_lossless():
    # RED-PEN control (F2 BLOCK-1): N handler threads each create a session simultaneously. Because the
    # ordering coordinate becomes the F3/F4 graph coordinate, every create must succeed, yield a UNIQUE
    # id + a UNIQUE, strictly-increasing created_seq, raise NOTHING, and lose NO record.
    n = 60
    results: list = []
    errors: list = []
    barrier = threading.Barrier(n)

    def _worker(i: int) -> None:
        try:
            barrier.wait()                              # release all threads at once → max contention
            results.append(sessions.create_session(name=f"s{i}"))
        except Exception as e:  # noqa: BLE001 — any raise is a failure of the control
            errors.append(repr(e))

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert not errors, f"a create raised under contention: {errors[:3]}"
    assert len(results) == n and all(r.get("ok") for r in results)
    ids = [r["session"]["id"] for r in results]
    seqs = [r["session"]["created_seq"] for r in results]
    assert len(set(ids)) == n, "duplicate session ids under concurrency"
    assert len(set(seqs)) == n, "duplicate created_seq under concurrency (corrupts the graph coordinate)"
    # every record actually persisted (no silent loss) and the seqs form a contiguous strictly-monotonic run
    persisted = sessions.list_sessions()["sessions"]
    assert len({s["id"] for s in persisted} & set(ids)) == n, "records lost under concurrency"
    assert sorted(seqs) == list(range(min(seqs), min(seqs) + n)), "seq not gap-free monotonic"


def test_next_seq_is_unique_under_threads():
    got: list = []
    barrier = threading.Barrier(40)

    def _w() -> None:
        barrier.wait()
        got.append(sessions._next_seq())

    ts = [threading.Thread(target=_w) for _ in range(40)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=20)
    assert len(got) == 40 and len(set(got)) == 40    # every value distinct (serialised counter)


# ---- legacy chat adoption (read-only) --------------------------------------

def test_legacy_chat_is_adopted_read_only(_isolate):
    chats = Path(_isolate) / "live" / "chats"
    chats.mkdir(parents=True, exist_ok=True)
    (chats / "oldchat.jsonl").write_text(
        json.dumps({"role": "user", "text": "test my api"}) + "\n"
        + json.dumps({"role": "assistant", "text": "ok"}) + "\n", encoding="utf-8")
    rows = sessions.list_sessions()["sessions"]
    row = next((s for s in rows if s["id"] == "oldchat"), None)
    assert row is not None and row["kind"] == "chat" and row["name"] == "test my api" and row.get("legacy")
    # it opens too (synthesized, not persisted)
    got = sessions.get_session("oldchat")
    assert got["ok"] and got["session"]["kind"] == "chat"
    # no session.json was written for it (read-only adoption)
    assert not (Path(_isolate) / "live" / "sessions" / "oldchat" / "session.json").exists()


# ---- API surface ------------------------------------------------------------

def test_api_sessions_list_and_detail():
    c = sessions.create_session(name="net posture", kind="engagement")["session"]
    sessions.link_run(c["id"], "20260101-000000-009", slug="net")
    lst = api.sessions_list()
    assert any(s["id"] == c["id"] for s in lst["sessions"])
    detail = api.session_detail(c["id"])
    assert detail["session"]["id"] == c["id"]
    assert [r["run_id"] for r in detail["runs"]] == ["20260101-000000-009"]
    # an unsafe id raises (do_GET maps to 404); an unknown id is a clean error body
    with pytest.raises(ValueError):
        api.session_detail("../secret")
    assert api.session_detail("nope-nonexistent").get("error")


# ---- F3: per-session GRAPH partition (a pure, ONE-WAY projection of the signed spine) ---------------

from dataclasses import dataclass  # noqa: E402
from typing import Any, Optional  # noqa: E402

from framework.v2.agents import blackboard as bb_mod  # noqa: E402
from framework.v2.graph.store import project_events  # noqa: E402


@dataclass
class _Ev:
    """Duck-typed to a BlackboardEventRow (the projection consumes the shape, never imports the class).
    ``posted_at`` is a wallclock the projection MUST ignore."""
    id: int
    engagement_id: int
    kind: str
    agent_name: str
    payload: dict
    parent_id: Optional[int] = None
    supersedes_id: Optional[int] = None
    posted_at: str = "IGNORED-WALLCLOCK"


class _FakeBlackboard:
    """A stand-in spine: records every read so a test can assert the FULL audit history is projected."""
    def __init__(self, by_slug: dict[str, list]) -> None:
        self._by = by_slug
        self.reads: list[tuple[str, bool]] = []

    def read(self, *, engagement: str, include_superseded: bool = False, limit: int = 1000, **_: Any):
        self.reads.append((str(engagement), bool(include_superseded)))
        return list(self._by.get(str(engagement), []))

    def close(self) -> None:
        pass


def _seed_spine(monkeypatch, by_slug: dict[str, list]) -> _FakeBlackboard:
    fake = _FakeBlackboard(by_slug)
    monkeypatch.setattr(bb_mod, "open_blackboard", lambda **kw: fake)
    return fake


_SPINE = [
    _Ev(1, 7, "recon", "scout", {"host": "t"}),
    _Ev(2, 7, "hypothesis", "planner", {"h": "sqli"}, parent_id=1),
    _Ev(3, 7, "hypothesis", "planner", {"h": "sqli-2"}, parent_id=1, supersedes_id=2),
]


def test_project_session_graph_is_a_pure_one_way_spine_projection(monkeypatch):
    fake = _seed_spine(monkeypatch, {"acme": _SPINE})
    sid = sessions.create_session(name="acme audit", kind="engagement")["session"]["id"]
    sessions.link_run(sid, "20260101-000000-001", slug="acme")

    res = sessions.project_session_graph(sid)
    assert res["ok"] and res["partition"] == sid and res["engagements"] == ["acme"]
    assert res["backend"] == "EmbeddedGraphStore"          # embedded is the DEFAULT backend (no Neo4j needed)

    # the partition is EXACTLY project_events over the session's spine — a pure function of the events.
    pure = project_events(_SPINE)
    view = sessions.session_graph(sid, project=False)
    assert view["nodes"] == pure["nodes"] and view["edges"] == pure["edges"]
    assert res["nodes"] == len(pure["nodes"]) and res["edges"] == len(pure["edges"])
    # the supersedes edge is present ⇒ the FULL audit history was read (include_superseded=True)
    assert ("acme", True) in fake.reads
    assert any(e["rel"] == "supersedes" for e in view["edges"])


def test_partition_projection_is_deterministic_and_wallclock_free(monkeypatch, _isolate):
    _seed_spine(monkeypatch, {"acme": _SPINE})
    sid = sessions.create_session(name="a")["session"]["id"]
    sessions.link_run(sid, "20260101-000000-002", slug="acme")

    part = Path(_isolate) / "live" / "graph" / (sid + ".json")
    sessions.project_session_graph(sid)
    first = part.read_bytes()
    # mutate the ignored wallclock, reproject → byte-identical partition on disk
    _SPINE[0].posted_at = "a-totally-different-time"
    sessions.project_session_graph(sid)
    assert part.read_bytes() == first
    _SPINE[0].posted_at = "IGNORED-WALLCLOCK"


def test_session_graph_exposes_no_authority_readback(monkeypatch):
    """The one-way invariant at the sessions layer: the graph view returns ONLY nodes/edges/partition — no
    tier/grant/authority is ever readable back out, and the module exposes no such surface."""
    _seed_spine(monkeypatch, {"acme": _SPINE})
    sid = sessions.create_session(name="a")["session"]["id"]
    sessions.link_run(sid, "20260101-000000-003", slug="acme")
    view = sessions.session_graph(sid)
    assert set(view) == {"partition", "nodes", "edges"}
    forbidden = {"grant", "promote", "authorize", "set_tier", "mint", "confirm", "certify"}
    assert forbidden.isdisjoint(set(dir(sessions)))


def test_link_run_projects_the_partition(monkeypatch):
    _seed_spine(monkeypatch, {"acme": _SPINE})
    sid = sessions.create_session(name="a")["session"]["id"]
    # before any run the partition is empty; linking a run projects it best-effort
    assert sessions.session_graph(sid, project=False)["nodes"] == []
    sessions.link_run(sid, "20260101-000000-004", slug="acme")
    assert len(sessions.session_graph(sid, project=False)["nodes"]) == len(project_events(_SPINE)["nodes"])


def test_hard_delete_drops_the_graph_partition(monkeypatch):
    _seed_spine(monkeypatch, {"acme": _SPINE})
    sid = sessions.create_session(name="a")["session"]["id"]
    sessions.link_run(sid, "20260101-000000-005", slug="acme")
    sessions.project_session_graph(sid)
    assert sid in sessions._open_graph_store().partitions()
    sessions.delete_session(sid, hard=True)
    assert sid not in sessions._open_graph_store().partitions()   # rebuildable projection dropped
    assert sessions.session_graph(sid, project=False)["nodes"] == []


def test_open_threads_are_the_non_terminal_runs(monkeypatch, _isolate):
    _seed_spine(monkeypatch, {"acme": _SPINE})
    sid = sessions.create_session(name="a")["session"]["id"]
    # two runs: one finished, one still running (an open thread)
    for rid, status in (("20260101-000000-006", "done"), ("20260101-000000-007", "running")):
        rd = actions_mod.run_dir(rid)
        rd.mkdir(parents=True, exist_ok=True)
        (rd / "meta.json").write_text(json.dumps({"slug": "acme", "status": status, "target": "127.0.0.1"}),
                                      encoding="utf-8")
        sessions.link_run(sid, rid, slug="acme")
    threads = sessions.open_threads(sid)
    assert [t["run_id"] for t in threads] == ["20260101-000000-007"]
    assert threads[0]["status"] == "running"


def test_project_unknown_session_is_a_clean_error(monkeypatch):
    _seed_spine(monkeypatch, {})
    assert sessions.project_session_graph("nope-nonexistent").get("error")
    with pytest.raises(ValueError):
        sessions.project_session_graph("../escape")


def test_neo4j_optin_falls_safe_to_the_embedded_default(monkeypatch):
    """Opting into the OPTIONAL Neo4j backend (with creds present) must NEVER crash and must fall SAFE to the
    embedded default — Neo4jGraphStore is a documented scaffold today, and Neo4j is never required to run."""
    monkeypatch.setenv("VIGIL_GRAPH_BACKEND", "neo4j")
    monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7687")
    monkeypatch.setenv("NEO4J_USERNAME", "neo4j")
    monkeypatch.setenv("NEO4J_PASSWORD", "sealed-by-the-broker")
    assert type(sessions._open_graph_store()).__name__ == "EmbeddedGraphStore"
