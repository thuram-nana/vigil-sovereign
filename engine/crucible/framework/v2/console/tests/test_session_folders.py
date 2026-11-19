"""Session FOLDERS (``VIGIL_SESSION_FOLDERS``, default-OFF): operator organisation of chats and sessions.

Pins, in order:
  1. OFF is byte-identical — no ``folder_id`` on any sessions payload, and every folder route answers exactly
     as an unknown route does (for a direct token-holder; a per-user proxy role hits the same 404 because the
     routes are RBAC-mapped at the session tier, as every flag-gated console route is).
  2. Folder CRUD — ids only ever registry-minted from the monotonic seq, names sanitised + unique
     case-insensitively, a listing sorted by name.
  3. Filing — file / move / unfile; filing is NOT activity (a filed chat keeps its place in the recent order).
  4. Fail-closed input — unknown folder / session, a deleted session, and unsafe ids (exact match, no
     normalisation) are refused.
  5. Deleting a folder NEVER deletes a session; every member is unfiled, other folders are untouched.
  6. Legacy chats — filing one adopts it into the registry with its title, as renaming/linking it would.
  7. Persistence — a 0600 index beside ``.seq`` under the 0700 registry dir, atomic (no temp left), never
     mistaken for a session; a corrupt index reads as empty and foreign ids are dropped.
  8. Concurrency (the console is a ThreadingHTTPServer) — concurrent creates/filings lose nothing.
  9. The HTTP surface end to end, OFF and ON.
"""

from __future__ import annotations

import json
import stat
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import server, sessions

from .conftest import AUTH_HEADERS

#: the exact public session keys before folders existed — OFF must emit precisely these
PRE_FOLDERS_KEYS = {"id", "name", "kind", "run_ids", "slug", "connections", "model", "deleted",
                    "created_seq", "updated_seq", "updated"}


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    monkeypatch.delenv("VIGIL_SESSION_FOLDERS", raising=False)
    yield


@pytest.fixture
def on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_SESSION_FOLDERS", "1")
    yield


def _legacy_chat(tmp_path: Path, chat_id: str, first_line: str) -> None:
    """A chat transcript the registry has not adopted (predates it)."""
    d = tmp_path / "live" / "chats"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{chat_id}.jsonl").write_text(json.dumps({"role": "user", "text": first_line}) + "\n",
                                        encoding="utf-8")


# ---- 1. OFF is byte-identical ------------------------------------------------------------------------

def test_off_by_default_and_no_payload_carries_folder_id(tmp_path):
    assert not sessions.folders_enabled()
    s = sessions.create_session(name="alpha", kind="chat")["session"]
    assert set(s) == PRE_FOLDERS_KEYS
    _legacy_chat(tmp_path, "legacychat1", "hello there")
    rows = sessions.list_sessions()["sessions"]
    assert {r["id"] for r in rows} == {s["id"], "legacychat1"}
    assert all("folder_id" not in r for r in rows)


@pytest.mark.parametrize("val", ["", "0", "false", "off", "no", "nope", "2"])
def test_non_affirmative_values_keep_it_off(monkeypatch, val):
    monkeypatch.setenv("VIGIL_SESSION_FOLDERS", val)
    assert not sessions.folders_enabled()


@pytest.mark.parametrize("val", ["1", "true", "YES", " on ", "enabled"])
def test_affirmative_values_turn_it_on(monkeypatch, val):
    monkeypatch.setenv("VIGIL_SESSION_FOLDERS", val)
    assert sessions.folders_enabled()


def test_on_every_sessions_row_carries_folder_id(on, tmp_path):
    s = sessions.create_session(name="alpha", kind="chat")["session"]
    assert set(s) == PRE_FOLDERS_KEYS | {"folder_id"} and s["folder_id"] == ""
    _legacy_chat(tmp_path, "legacychat1", "hello")
    rows = {r["id"]: r for r in sessions.list_sessions()["sessions"]}
    assert rows[s["id"]]["folder_id"] == "" and rows["legacychat1"]["folder_id"] == ""


# ---- 2. folder CRUD ----------------------------------------------------------------------------------

def test_create_rename_delete_roundtrip_sorted_and_on_disk(on):
    b = sessions.create_folder("beta")["folder"]
    a = sessions.create_folder("Alpha")["folder"]
    assert a["id"].startswith("fld-") and b["id"].startswith("fld-") and a["id"] != b["id"]
    assert [f["name"] for f in sessions.list_folders()["folders"]] == ["Alpha", "beta"]   # by name, any case
    on_disk = json.loads(sessions._folders_path().read_text(encoding="utf-8"))
    assert {f["id"] for f in on_disk["folders"]} == {a["id"], b["id"]}
    r = sessions.rename_folder(b["id"], "Zeta")
    assert r["ok"] and r["folder"]["name"] == "Zeta" and r["folder"]["updated_seq"] > b["updated_seq"]
    assert sessions.delete_folder(a["id"]) == {"ok": True, "deleted": a["id"], "unfiled": 0}
    assert [f["id"] for f in sessions.list_folders()["folders"]] == [b["id"]]


def test_folder_ids_come_from_the_monotonic_registry_seq(on):
    nums = [int(sessions.create_folder(f"f{i}")["folder"]["id"].split("-")[1]) for i in range(5)]
    assert nums == sorted(nums) and len(set(nums)) == 5


def test_names_are_sanitised_required_and_unique_case_insensitively(on):
    assert sessions.create_folder("").get("error")
    assert sessions.create_folder("   \t ").get("error")
    f = sessions.create_folder("  Clients\x00\n  ")["folder"]
    assert f["name"] == "Clients"                                          # control chars stripped, trimmed
    assert sessions.create_folder("clients").get("error")                  # duplicate, different case
    assert sessions.create_folder("x" * 500)["folder"]["name"] == "x" * sessions._MAX_NAME
    other = sessions.create_folder("Other")["folder"]
    assert sessions.rename_folder(other["id"], "CLIENTS").get("error")     # rename into a taken name
    assert sessions.rename_folder(f["id"], "CLIENTS")["folder"]["name"] == "CLIENTS"   # own name, new case
    assert sessions.rename_folder(f["id"], " ").get("error")
    assert "no such folder" in sessions.rename_folder("fld-999", "x")["error"]


def test_folder_cap(on, monkeypatch):
    monkeypatch.setattr(sessions, "_MAX_FOLDERS", 2)
    assert sessions.create_folder("a").get("ok") and sessions.create_folder("b").get("ok")
    assert "limit" in sessions.create_folder("c")["error"]


# ---- 3. filing ---------------------------------------------------------------------------------------

def test_file_move_unfile_and_filing_is_not_activity(on):
    s = sessions.create_session(name="work", kind="chat")["session"]
    f1 = sessions.create_folder("one")["folder"]
    f2 = sessions.create_folder("two")["folder"]
    r = sessions.set_session_folder(s["id"], f1["id"])
    assert r["ok"] and r["session"]["folder_id"] == f1["id"]
    assert (r["session"]["updated_seq"], r["session"]["updated"]) == (s["updated_seq"], s["updated"])
    assert sessions.set_session_folder(s["id"], f2["id"])["session"]["folder_id"] == f2["id"]
    assert sessions.set_session_folder(s["id"], "")["session"]["folder_id"] == ""
    assert "folder_id" not in json.loads(sessions._session_path(s["id"]).read_text(encoding="utf-8"))


# ---- 4. fail-closed input ----------------------------------------------------------------------------

def test_filing_fails_closed(on):
    s = sessions.create_session(name="work", kind="chat")["session"]
    assert "no such folder" in sessions.set_session_folder(s["id"], "fld-999")["error"]
    f = sessions.create_folder("one")["folder"]
    assert "no such session" in sessions.set_session_folder("not-a-session", f["id"])["error"]
    sessions.delete_session(s["id"])                                       # soft tombstone
    assert "deleted" in sessions.set_session_folder(s["id"], f["id"])["error"]


@pytest.mark.parametrize("bad", ["../x", "fld-0", "fld-01", "FLD-1", "fld-1/..", "fld-", "fld-1 x",
                                 "fld-" + "9" * 19, "fld-1\n", " fld-1", "x" * 300])
def test_unsafe_folder_ids_raise(on, bad):
    s = sessions.create_session(name="w", kind="chat")["session"]
    with pytest.raises(ValueError):
        sessions.rename_folder(bad, "n")
    with pytest.raises(ValueError):
        sessions.delete_folder(bad)
    with pytest.raises(ValueError):
        sessions.set_session_folder(s["id"], bad)


# ---- 5. delete never deletes a session ---------------------------------------------------------------

def test_delete_folder_unfiles_every_member_and_keeps_every_session(on):
    f = sessions.create_folder("proj")["folder"]
    keep = sessions.create_folder("keep")["folder"]
    a = sessions.create_session(name="a", kind="chat")["session"]
    b = sessions.create_session(name="b", kind="engagement")["session"]
    c = sessions.create_session(name="c", kind="chat")["session"]
    for sid in (a["id"], b["id"]):
        sessions.set_session_folder(sid, f["id"])
    sessions.set_session_folder(c["id"], keep["id"])
    sessions.delete_session(b["id"])                       # a soft-deleted member is unfiled too
    assert sessions.delete_folder(f["id"]) == {"ok": True, "deleted": f["id"], "unfiled": 2}
    listed = {s["id"]: s for s in sessions.list_sessions(include_deleted=True)["sessions"]}
    assert {a["id"], b["id"], c["id"]} <= set(listed)      # nothing deleted
    assert listed[a["id"]]["folder_id"] == "" and listed[b["id"]]["folder_id"] == ""
    assert listed[c["id"]]["folder_id"] == keep["id"]      # another folder's member untouched
    assert "no such folder" in sessions.delete_folder(f["id"])["error"]


def test_a_dangling_folder_id_never_breaks_a_read_and_is_recoverable(on):
    s = sessions.create_session(name="w", kind="chat")["session"]
    rec = json.loads(sessions._session_path(s["id"]).read_text(encoding="utf-8"))
    rec["folder_id"] = "fld-424242"                        # names a folder that does not exist
    sessions._write(rec)
    row = {r["id"]: r for r in sessions.list_sessions()["sessions"]}[s["id"]]
    assert row["folder_id"] == "fld-424242"                # surfaced as-is; the UI renders it unfiled
    f = sessions.create_folder("real")["folder"]
    assert sessions.set_session_folder(s["id"], f["id"])["session"]["folder_id"] == f["id"]


# ---- 6. legacy chats ---------------------------------------------------------------------------------

def test_filing_a_legacy_chat_adopts_it_with_its_title(on, tmp_path):
    _legacy_chat(tmp_path, "oldchat", "how do I scan my staging site")
    assert sessions._read("oldchat") is None
    f = sessions.create_folder("Staging")["folder"]
    r = sessions.set_session_folder("oldchat", f["id"])
    assert r["ok"] and r["session"]["kind"] == "chat" and r["session"]["folder_id"] == f["id"]
    assert r["session"]["name"] == "how do I scan my staging site"
    assert sessions._read("oldchat")["folder_id"] == f["id"]


# ---- 7. persistence ----------------------------------------------------------------------------------

def test_index_is_private_atomic_and_never_listed_as_a_session(on):
    sessions.create_folder("one")
    p = sessions._folders_path()
    assert p.name == ".folders.json" and p.parent == sessions._sessions_dir()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    assert not [x for x in p.parent.iterdir() if x.name.startswith(".folders.") and x.name.endswith(".tmp")]
    assert sessions.list_sessions()["sessions"] == []      # the index is not a session


def test_a_corrupt_index_reads_as_empty_and_drops_foreign_ids(on):
    p = sessions._folders_path()
    p.write_text("{not json", encoding="utf-8")
    assert sessions.list_folders() == {"folders": []}
    p.write_text(json.dumps({"folders": [{"id": "../evil", "name": "x"}, {"id": "fld-7", "name": "ok"}, "junk"]}),
                 encoding="utf-8")
    assert [f["id"] for f in sessions.list_folders()["folders"]] == ["fld-7"]


# ---- 8. concurrency ----------------------------------------------------------------------------------

def test_concurrent_creates_are_unique_and_lossless(on):
    n, out, errs = 24, [], []

    def worker(i: int) -> None:
        try:
            out.append(sessions.create_folder(f"folder-{i}")["folder"]["id"])
        except Exception as e:  # noqa: BLE001 — surfaced by the assertion below
            errs.append(e)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs and len(out) == n and len(set(out)) == n
    assert len(sessions.list_folders()["folders"]) == n


def test_concurrent_filing_then_delete_loses_no_session(on):
    f = sessions.create_folder("busy")["folder"]
    ids = [sessions.create_session(name=f"s{i}", kind="chat")["session"]["id"] for i in range(16)]
    ts = [threading.Thread(target=sessions.set_session_folder, args=(sid, f["id"])) for sid in ids]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    rows = {r["id"]: r for r in sessions.list_sessions()["sessions"]}
    assert all(rows[sid]["folder_id"] == f["id"] for sid in ids)
    assert sessions.delete_folder(f["id"])["unfiled"] == len(ids)
    rows = {r["id"]: r for r in sessions.list_sessions()["sessions"]}
    assert set(ids) <= set(rows) and all(rows[sid]["folder_id"] == "" for sid in ids)


# ---- 9. the HTTP surface -----------------------------------------------------------------------------

FOLDER_POSTS = ("/api/folder/create", "/api/folder/rename", "/api/folder/delete", "/api/session/folder")


@contextmanager
def _running():
    httpd = server.serve(host="127.0.0.1", port=0)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _call(req: urllib.request.Request):
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def _get(url: str):
    return _call(urllib.request.Request(url, headers=AUTH_HEADERS))


def _post(url: str, body: dict):
    req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode("utf-8"))
    req.add_header("X-Requested-With", "vigil-ui")           # the console's CSRF header
    req.add_header("Content-Type", "application/json")
    for k, v in AUTH_HEADERS.items():
        req.add_header(k, v)
    return _call(req)


def test_http_off_every_folder_route_is_the_unknown_route_response(tmp_path):
    with _running() as base:
        unknown_get = _get(base + "/api/definitely-not-a-route")
        unknown_post = _post(base + "/api/definitely-not-a-route", {})
        assert unknown_get[0] == 404 and unknown_post[0] == 404
        assert _get(base + "/api/folders") == unknown_get
        for path in FOLDER_POSTS:
            assert _post(base + path, {"name": "x", "id": "fld-1", "folder_id": "fld-1"}) == unknown_post, path
        st, body = _get(base + "/api/sessions")
        assert st == 200 and all("folder_id" not in s for s in body["sessions"])
    assert not (tmp_path / "live" / "sessions" / ".folders.json").exists()   # no side effect while off


def test_http_on_full_roundtrip(on):
    s = sessions.create_session(name="client chat", kind="chat")["session"]
    with _running() as base:
        st, made = _post(base + "/api/folder/create", {"name": "Clients"})
        assert st == 200 and made["ok"]
        fid = made["folder"]["id"]
        assert _get(base + "/api/folders") == (200, {"folders": [made["folder"]]})
        st, dup = _post(base + "/api/folder/create", {"name": "clients"})
        assert st == 200 and "already exists" in dup["error"]          # a refusal is an honest error body
        st, filed = _post(base + "/api/session/folder", {"id": s["id"], "folder_id": fid})
        assert st == 200 and filed["session"]["folder_id"] == fid
        st, listed = _get(base + "/api/sessions")
        assert {r["id"]: r for r in listed["sessions"]}[s["id"]]["folder_id"] == fid
        st, ren = _post(base + "/api/folder/rename", {"id": fid, "name": "Key clients"})
        assert st == 200 and ren["folder"]["name"] == "Key clients"
        st, gone = _post(base + "/api/folder/delete", {"id": fid})
        assert st == 200 and gone == {"ok": True, "deleted": fid, "unfiled": 1}
        st, listed = _get(base + "/api/sessions")
        assert {r["id"]: r for r in listed["sessions"]}[s["id"]]["folder_id"] == ""
        assert _get(base + "/api/folders") == (200, {"folders": []})


def test_http_on_unsafe_ids_are_an_honest_404_not_a_500(on):
    s = sessions.create_session(name="w", kind="chat")["session"]
    with _running() as base:
        assert _post(base + "/api/folder/rename", {"id": "../etc", "name": "x"})[0] == 404
        assert _post(base + "/api/folder/delete", {"id": "fld-01"})[0] == 404
        assert _post(base + "/api/session/folder", {"id": s["id"], "folder_id": "nope"})[0] == 404
        assert _post(base + "/api/session/folder", {"id": "../../x", "folder_id": ""})[0] == 404
