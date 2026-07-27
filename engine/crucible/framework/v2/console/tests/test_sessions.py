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
