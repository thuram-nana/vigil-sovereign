"""Spine store integrity at the line level.

  * append refuses a tail whose last record does not carry the highest seq in the active segment (a duplicated
    or reordered line there would make the next record fork below the true tip);
  * verify() flags a duplicated or out-of-order seq anywhere in the spine;
  * every reader refuses a manifest whose segments are not one contiguous run;
  * a record with no canonical form (a lone surrogate — no append can write one) is reported as tampered by
    verify_record, SpineStore.verify, the live tailer (which keeps advancing), dedup and `/api/record`, never a
    crash;
  * a line of the wrong shape is skipped by every reader, but a complete, chained line whose payload is not a JSON
    object is a RECORD (read, verified, chained from) that its consumers fail closed on — never skipped.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_spine_store_integrity.py
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from sigil.reuse.chain import _entry_hash
from sigil.spine.store import SpineError, SpineStore
from sigil.spine.tail import SpineTailer
from sigil.spine.verify import verify_record


def _add(s: SpineStore, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        s.append(kind="message", source="t", actor="u", payload={"text": f"m{i}"})


def _legacy(tmp_path, n=10) -> SpineStore:
    s = SpineStore(tmp_path / "spine.jsonl")
    _add(s, n)
    return s


def _segmented(tmp_path, per=3, sealed=3) -> SpineStore:
    """`sealed` sealed segments of `per` records each, then an active one holding `per` more."""
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    for k in range(sealed):
        _add(s, per, k * per)
        s.rotate()
    _add(s, per, sealed * per)
    return s


def _line_of(s: SpineStore, seq: int) -> bytes:
    for p in s._segments_in_order():
        for raw in p.read_bytes().splitlines(keepends=True):
            if raw.strip() and json.loads(raw)["seq"] == seq:
                return raw
    raise AssertionError(seq)


def _write_raw(path: Path, lines: list[bytes]) -> None:
    path.write_bytes(b"".join(lines))


def _checked(s: SpineStore):
    from sigil.spine import store as store_mod
    return store_mod._TAIL_CHECKED[str(s._active.resolve())]


class _AnotherProcess:
    """Run writes as ANOTHER process would: this process's checked-tail progress does not see them."""

    def __enter__(self):
        from sigil.spine import store as store_mod
        self.saved = dict(store_mod._TAIL_CHECKED)

    def __exit__(self, *exc):
        from sigil.spine import store as store_mod
        store_mod._TAIL_CHECKED.clear()
        store_mod._TAIL_CHECKED.update(self.saved)


# ---- append refuses a non-monotonic tail -----------------------------------------------------------------------

@pytest.mark.parametrize("copied", [(3,), (3, 4), (9,)])       # an older line, an older run, the tip again
def test_append_refuses_a_tail_that_is_not_the_highest_seq(tmp_path, copied):
    s = _legacy(tmp_path)
    with s._active.open("ab") as f:
        for q in copied:
            f.write(_line_of(s, q))
    before = s._active.read_bytes()
    for store in (s, SpineStore(tmp_path / "spine.jsonl")):       # this store, and a fresh process's
        with pytest.raises(SpineError, match="not above every earlier record"):
            store.append(kind="message", source="t", actor="u", payload={"text": "engage"})
        with pytest.raises(SpineError, match="not above every earlier record"):
            store.append_many([{"kind": "message", "source": "t", "actor": "u", "payload": {"text": "x"}}])
    assert s._active.read_bytes() == before, "a refused append wrote bytes"


def test_append_refuses_an_older_line_in_a_freshly_rotated_active(tmp_path):
    s = _segmented(tmp_path)
    s.rotate()                                                      # active is empty, first seq 12
    with s._active.open("ab") as f:
        f.write(_line_of(s, 4))
    with pytest.raises(SpineError, match="not above every earlier record"):
        SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_appends_from_two_stores_on_one_spine_interleave(tmp_path):
    a = _legacy(tmp_path, 2)
    b = SpineStore(tmp_path / "spine.jsonl")
    for i in range(12):
        if i % 3:
            a.append(kind="message", source="t", actor="u", payload={"text": f"i{i}"})
        else:
            with _AnotherProcess():                                 # a peer process's append
                b.append(kind="message", source="t", actor="u", payload={"text": f"i{i}"})
    b.append_many([{"kind": "message", "source": "t", "actor": "u", "payload": {"text": "batch"}}] * 3)
    a.append(kind="message", source="t", actor="u", payload={"text": "last"})
    assert [r.seq for r in a.iter_records()] == list(range(18))
    assert a.verify()[0]


def test_append_rechecks_a_spine_that_was_reset_and_regrew(tmp_path):
    a = _legacy(tmp_path, 5)
    with _AnotherProcess():
        b = SpineStore(tmp_path / "spine.jsonl")
        b.reset()
        _add(b, 9)                                                  # past `a`'s checked bytes, different records
    assert a.append(kind="message", source="t", actor="u", payload={"text": "after"}) == 9
    assert a.verify()[0]


def _fixed(s, payloads):
    for t in payloads:
        s.append(kind="message", source="t", actor="u", payload={"text": t}, ts="2026-01-01T00:00:00Z")


def test_append_rechecks_a_same_size_rewrite_under_it(tmp_path):
    """Another process rewrites the active segment to EXACTLY the size this store last checked, ending in a copied
    older line: the size alone must not pass for "nothing new" — the tail record must be the one checked."""
    a = SpineStore(tmp_path / "spine.jsonl")
    _fixed(a, [f"m{i}" for i in range(6)])
    size = a._active.stat().st_size
    with _AnotherProcess():
        b = SpineStore(tmp_path / "spine.jsonl")
        b.reset()
        _fixed(b, [f"n{i}" for i in range(5)])
        with b._active.open("ab") as f:
            f.write(_line_of(b, 2))
    assert a._active.stat().st_size == size                         # the precondition this test is about
    with pytest.raises(SpineError, match="not above every earlier record"):
        a.append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_append_rechecks_an_in_place_same_size_rewrite_of_its_tail(tmp_path):
    """The SAME file (same inode) is rewritten in place to exactly the size this store last checked, its last line
    replaced by a copy of an older one: the same file at the same size is not "nothing new" — the tail record must
    still be the one checked."""
    a = SpineStore(tmp_path / "spine.jsonl")
    _fixed(a, [f"m{i}" for i in range(6)])
    p = a._active
    st = p.stat()
    lines = p.read_bytes().splitlines(keepends=True)
    with p.open("r+b") as f:                                        # in place: no new file
        f.write(b"".join(lines[:5] + [lines[2]]))
    assert (p.stat().st_ino, p.stat().st_size) == (st.st_ino, st.st_size)   # the precondition this test is about
    with pytest.raises(SpineError, match="not above every earlier record"):
        a.append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_append_rechecks_a_replacement_file_that_ends_in_the_record_it_checked(tmp_path):
    """The active segment is REPLACED by a new file of exactly the checked size that still ends in the very record
    this store checked, with a copy of that record earlier in it: a different file is re-checked from its start."""
    import os
    a = SpineStore(tmp_path / "spine.jsonl")
    _fixed(a, [f"m{i}" for i in range(6)])
    p = a._active
    st = p.stat()
    lines = p.read_bytes().splitlines(keepends=True)
    tmp = p.with_name(p.name + ".new")
    tmp.write_bytes(b"".join(lines[:3] + [lines[5]] + lines[4:]))  # seq 5 at line 3, and again as the tail
    os.replace(tmp, p)
    assert p.stat().st_ino != st.st_ino and p.stat().st_size == st.st_size
    assert p.read_bytes().splitlines(keepends=True)[-1] == lines[-1]
    with pytest.raises(SpineError, match="not above every earlier record"):
        a.append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_append_rechecks_a_longer_rewrite_from_its_start(tmp_path):
    """Another process resets the spine and writes FEWER, LONGER records past this store's checked offset: the
    bytes after that offset are not a continuation, so the segment is re-checked from its start (no false refusal
    from this store's stale high-water)."""
    a = SpineStore(tmp_path / "spine.jsonl")
    _fixed(a, [f"m{i}" for i in range(20)])
    with _AnotherProcess():
        b = SpineStore(tmp_path / "spine.jsonl")
        b.reset()
        _fixed(b, ["y" * 2000 for _ in range(5)])
    assert a._active.stat().st_size > _checked(a)[1]
    assert a.append(kind="message", source="t", actor="u", payload={"text": "after"}) == 5
    assert a.verify()[0]


def test_append_rechecks_a_rewrite_that_ends_on_a_record_boundary(tmp_path):
    """The rewrite has a record boundary exactly at this store's checked offset, but a different record before it:
    that is not a continuation, so the high-water from the old content must not be applied to the new one."""
    a = SpineStore(tmp_path / "spine.jsonl")
    _fixed(a, [f"a{i}" for i in range(10)])                         # 10 equal lines, seqs 0..9
    lx = a._active.stat().st_size // 10
    with _AnotherProcess():
        b = SpineStore(tmp_path / "spine.jsonl")
        b.reset()
        _fixed(b, ["b" * (2 + lx) for _ in range(6)])               # 6 lines of exactly 2*lx: a boundary at 10*lx
    assert b._active.stat().st_size == 12 * lx and _checked(a)[1] == 10 * lx
    assert a.append(kind="message", source="t", actor="u", payload={"text": "after"}) == 6


def test_append_after_a_torn_tail_still_works(tmp_path):
    s = _legacy(tmp_path, 4)
    with s._active.open("ab") as f:
        f.write(b'{"seq": 4, "scope": "torn')
    assert s.append(kind="message", source="t", actor="u", payload={"text": "ok"}) == 4
    assert s.verify()[0]


# ---- verify() flags duplicate / out-of-order seqs -----------------------------------------------------------------

def _dup_at_end(p: Path, lines):
    _write_raw(p, lines + [lines[3]])


def _dup_in_middle(p: Path, lines):
    _write_raw(p, lines[:6] + [lines[3]] + lines[6:])


def _swapped(p: Path, lines):
    _write_raw(p, lines[:4] + [lines[5], lines[4]] + lines[6:])


def _dup_of_last(p: Path, lines):
    _write_raw(p, lines + [lines[-1]])


@pytest.mark.parametrize("tamper", [_dup_at_end, _dup_in_middle, _swapped, _dup_of_last])
def test_verify_flags_a_duplicated_or_reordered_line(tmp_path, tamper):
    s = _legacy(tmp_path)
    assert s.verify()[0]
    p = s._active
    tamper(p, p.read_bytes().splitlines(keepends=True))
    ok, why = SpineStore(tmp_path / "spine.jsonl").verify()
    assert ok is False and "duplicated or reordered" in why


def test_verify_flags_a_line_duplicated_across_segments(tmp_path):
    s = _segmented(tmp_path)
    with s._active.open("ab") as f:
        f.write(_line_of(s, 2))                                     # a sealed segment's record, again at the end
    ok, why = SpineStore(tmp_path / "spine.jsonl").verify()
    assert ok is False and "duplicated or reordered" in why


# ---- every reader refuses a manifest that is not one contiguous run -----------------------------------------------

def _omit_middle(m):
    sealed = [g for g in m["segments"] if g["sealed"]]
    m["segments"].remove(sealed[1])


def _omit_last_sealed(m):
    sealed = [g for g in m["segments"] if g["sealed"]]
    m["segments"].remove(sealed[-1])


def _two_unsealed(m):
    next(g for g in m["segments"] if g["sealed"] and g["first_seq"] == 3)["sealed"] = False


def _overlapping(m):
    g = dict(next(g for g in m["segments"] if g["sealed"] and g["first_seq"] == 3))
    m["segments"].append(dict(g, id=99))


def _wrong_link(m):
    next(g for g in m["segments"] if g["sealed"] and g["first_seq"] == 3)["first_prev_hash"] = "0" * 64


def _extra_unsealed(m):
    act = next(g for g in m["segments"] if not g["sealed"])
    m["segments"].append(dict(act, id=98, file=act["file"].replace(".jsonl", "-b.jsonl")))


def _sealed_without_last(m):
    next(g for g in m["segments"] if g["sealed"] and g["first_seq"] == 3)["last_seq"] = None


def _shifted_first_seq(m):
    next(g for g in m["segments"] if g["sealed"] and g["first_seq"] == 3)["first_seq"] = 4


def _unsealed_in_the_middle(m):
    """Exactly one unsealed segment, but it is not the last one."""
    next(g for g in m["segments"] if g["sealed"] and g["first_seq"] == 3)["sealed"] = False
    next(g for g in m["segments"] if g["first_seq"] == 9)["sealed"] = True


@pytest.mark.parametrize("edit", [_omit_middle, _omit_last_sealed, _two_unsealed, _extra_unsealed, _overlapping,
                                  _wrong_link, _sealed_without_last, _shifted_first_seq, _unsealed_in_the_middle])
def test_every_reader_refuses_a_manifest_that_is_not_a_contiguous_run(tmp_path, edit):
    s = _segmented(tmp_path)
    tip = list(s.iter_records())[-1]
    mp = s._layout.manifest_path
    m = json.loads(mp.read_text())
    edit(m)
    mp.write_text(json.dumps(m))
    for g in m["segments"]:
        (mp.parent / g["file"]).touch()                             # every named file exists: only the run is wrong
    fresh = SpineStore(tmp_path / "spine.jsonl")
    for read in (lambda: list(fresh.iter_records()), fresh.count, lambda: fresh.get(10), fresh.verify):
        with pytest.raises(SpineError, match="not a contiguous segment run"):
            read()
    assert fresh.tail_after(tip.seq, tip.entry_hash) is None        # the fold cache's tail path: undecidable


def test_a_contiguous_manifest_reads_as_before(tmp_path):
    s = _segmented(tmp_path)
    s.compact()                                                     # gzip the sealed segments (codec/file move)
    fresh = SpineStore(tmp_path / "spine.jsonl")
    assert [r.seq for r in fresh.iter_records()] == list(range(12)) and fresh.verify()[0]


# ---- a record with no canonical form is reported, never a crash ---------------------------------------------------

def _append_surrogate_record(s: SpineStore) -> int:
    """A well-chained line whose payload holds a lone surrogate (as a JSON escape) — what a tampered line looks
    like; no append can write one (it has no canonical bytes to digest)."""
    tip = s._read_last_entry()
    seq = tip.seq + 1
    cert = "c" * 64
    rec = {"seq": seq, "scope": "sigil", "kind": "message", "source": "t", "actor": "u",
           "payload": {"text": "bad \ud800 text"}, "parent_id": None, "supersedes_id": None,
           "ts": "2026-01-01T00:00:00Z", "cert_digest": cert, "prev_hash": tip.entry_hash,
           "entry_hash": _entry_hash(seq, tip.entry_hash, cert), "schema_version": 1}
    with s._active.open("ab") as f:
        f.write((json.dumps(rec) + "\n").encode("ascii"))
    return seq


def test_verify_record_reports_a_record_with_no_canonical_form(tmp_path):
    s = _legacy(tmp_path, 3)
    seq = _append_surrogate_record(s)
    ok, why = verify_record(SpineStore(tmp_path / "spine.jsonl").get(seq))
    assert ok is False and "not canonicalisable" in why


def test_store_verify_reports_a_record_with_no_canonical_form(tmp_path):
    s = _legacy(tmp_path, 3)
    _append_surrogate_record(s)
    ok, why = SpineStore(tmp_path / "spine.jsonl").verify()
    assert ok is False and "not canonicalisable" in why


def test_verify_record_reports_a_chain_field_with_no_canonical_form(tmp_path):
    s = _legacy(tmp_path, 3)
    lines = s._active.read_bytes().splitlines(keepends=True)
    rec = json.loads(lines[-1])
    rec["prev_hash"] = "\ud800"                                    # binding still holds; the derivation cannot run
    lines[-1] = (json.dumps(rec) + "\n").encode("ascii")
    _write_raw(s._active, lines)
    ok, why = verify_record(SpineStore(tmp_path / "spine.jsonl").get(2))
    assert ok is False and "not canonicalisable" in why


def test_the_tailer_flags_it_and_keeps_advancing(tmp_path):
    s = _legacy(tmp_path, 3)
    t = SpineTailer(SpineStore(tmp_path / "spine.jsonl"), since_seq=2)
    seq = _append_surrogate_record(s)
    evs = t.poll()
    assert [e["seq"] for e in evs] == [seq] and evs[0]["integrity_ok"] is False
    assert "not canonicalisable" in evs[0]["integrity_reason"]
    assert t.cursor == seq and t.poll() == []
    s2 = SpineStore(tmp_path / "spine.jsonl")
    nxt = s2.append(kind="message", source="t", actor="u", payload={"text": "after"})
    assert [e["seq"] for e in t.poll()] == [nxt]


def test_the_tailer_flags_a_record_it_cannot_verify_and_keeps_advancing(tmp_path, monkeypatch):
    import sigil.spine.tail as tail_mod
    s = _legacy(tmp_path, 3)
    t = SpineTailer(SpineStore(tmp_path / "spine.jsonl"), since_seq=0)

    def boom(r):
        raise RuntimeError("verifier failure")

    monkeypatch.setattr(tail_mod, "verify_record", boom)
    evs = t.poll()
    assert [e["seq"] for e in evs] == [1, 2] and not any(e["integrity_ok"] for e in evs)
    assert "could not be verified" in evs[0]["integrity_reason"] and t.cursor == 2


def test_dedup_skips_a_record_with_no_canonical_form(tmp_path):
    s = _legacy(tmp_path, 3)
    seq = _append_surrogate_record(s)
    s2 = SpineStore(tmp_path / "spine.jsonl")
    assert s2.append(kind="message", source="t", actor="u", payload={"text": "m1"}, dedup=True) == 1
    assert s2.append(kind="message", source="t", actor="u", payload={"text": "new"}, dedup=True) == seq + 1


def test_api_record_reports_it(tmp_path):
    from sigil.ui.server import build_server
    s = _legacy(tmp_path, 3)
    seq = _append_surrogate_record(s)
    srv = build_server(token="test-secret-token-xyz", port=0, spine_path=str(tmp_path / "spine.jsonl"))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/record/{seq}",
                                     headers={"X-SIGIL-Token": "test-secret-token-xyz"})
        with urllib.request.urlopen(req, timeout=5) as r:
            code, body = r.status, json.loads(r.read())
    finally:
        srv.shutdown()
    assert code == 200 and body["integrity_ok"] is False and "not canonicalisable" in body["integrity_reason"]
    assert body["payload"]["text"] == "bad \ud800 text"


def _serve(tmp_path):
    from sigil.ui.server import build_server
    srv = build_server(token="test-secret-token-xyz", port=0, spine_path=str(tmp_path / "spine.jsonl"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _first_events(port, path, n=1):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    body = ""
    with urllib.request.urlopen(req, timeout=5) as r:
        while body.count("data: ") < n:
            chunk = r.read1(4000)
            if not chunk:                                           # the stream ended (a crashed handler)
                break
            body += chunk.decode("utf-8")
    return [json.loads(ln[len("data: "):]) for ln in body.splitlines() if ln.startswith("data: ")]


def test_the_live_stream_carries_it(tmp_path):
    s = _legacy(tmp_path, 3)
    seq = _append_surrogate_record(s)
    srv, port = _serve(tmp_path)
    try:
        evs = _first_events(port, f"/api/stream?token=test-secret-token-xyz&since={seq - 1}")
    finally:
        srv.shutdown()
    assert evs[0]["seq"] == seq and evs[0]["integrity_ok"] is False


def test_the_hud_stream_carries_a_lone_surrogate(tmp_path):
    import os

    from sigil.voice.hud_status import status_path
    s = _legacy(tmp_path, 1)
    tip = s._read_last_entry()
    rec = {"seq": 1, "scope": "sigil", "kind": "event", "source": "voice", "actor": "OWNER",
           "payload": {"signal": "sigil.nav", "screen_id": "x\ud800"}, "parent_id": None, "supersedes_id": None,
           "ts": "2026-01-01T00:00:00Z", "cert_digest": "c" * 64, "prev_hash": tip.entry_hash,
           "entry_hash": _entry_hash(1, tip.entry_hash, "c" * 64), "schema_version": 1}
    with s._active.open("ab") as f:
        f.write((json.dumps(rec) + "\n").encode("ascii"))
    status_path().write_text('{"state": "listening", "transcript": "t\\ud800", "feedback": ""}', encoding="utf-8")
    srv, port = _serve(tmp_path)
    try:
        evs = _first_events(port, "/api/sigil/hud?token=test-secret-token-xyz&since=0", n=2)
    finally:
        srv.shutdown()
        try:
            os.unlink(status_path())
        except OSError:
            pass
    assert {"t": "nav", "screen_id": "x\ud800", "seq": 1} in evs
    assert {"t": "state", "state": "listening", "transcript": "t\ud800", "feedback": ""} in evs


def test_the_cockpit_json_encoder_round_trips_a_lone_surrogate():
    from sigil.ui.server import _json_bytes
    obj = {"t": "a\ud800b", "ok": "ünïcode"}
    raw = _json_bytes(obj)
    assert json.loads(raw) == obj and "ünïcode".encode("utf-8") in raw


# ---- review fold: one record rule, the seam, the seal, the per-process checkpoint --------------------------------

def test_a_duplicate_seq_key_cannot_hide_an_older_tail(tmp_path):
    """The check reads a line exactly as the readers do: a rewritten line carrying a second `seq` key (JSON keeps the
    last) still counts as the record the readers yield."""
    s = _legacy(tmp_path)
    lines = s._active.read_bytes().splitlines(keepends=True)
    for i in range(3, 10):
        lines[i] = b'{"seq": 0, ' + lines[i][1:]
    lines.append(lines[3])
    _write_raw(s._active, lines)
    with pytest.raises(SpineError, match="not above every earlier record"):
        SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_an_append_after_a_rotation_refuses_a_sealed_tail_that_is_not_the_recorded_boundary(tmp_path):
    s = _segmented(tmp_path)
    s.rotate()                                                      # the active is empty: the seam decides
    sealed = sorted(s._layout.segments_dir.glob("seg-*.jsonl"))[-2]
    with sealed.open("ab") as f:
        f.write(_line_of(s, 4))
    with pytest.raises(SpineError, match="not at the boundary the manifest records"):
        SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_an_append_after_a_rotation_refuses_a_sealed_tail_with_the_boundary_seq_but_another_hash(tmp_path):
    s = _segmented(tmp_path)
    s.rotate()                                                      # the active is empty: the seam decides
    sealed = sorted(s._layout.segments_dir.glob("seg-*.jsonl"))[-2]
    lines = sealed.read_bytes().splitlines(keepends=True)
    rec = json.loads(lines[-1])
    rec["entry_hash"] = "0" * 64                                    # the boundary's seq, not its hash
    _write_raw(sealed, lines[:-1] + [(json.dumps(rec) + "\n").encode()])
    with pytest.raises(SpineError, match="not at the boundary the manifest records"):
        SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_a_rotation_refuses_to_seal_a_tail_an_append_would_refuse(tmp_path):
    s = _segmented(tmp_path)
    with s._active.open("ab") as f:
        f.write(_line_of(s, 4))
    gen = s.generation()
    with pytest.raises(SpineError, match="not above every earlier record"):
        SpineStore(tmp_path / "spine.jsonl").rotate()
    assert s.generation() == gen, "the segment was sealed"


def _with_line(s: SpineStore, at: int, raw: bytes):
    lines = s._active.read_bytes().splitlines(keepends=True)
    lines.insert(at, raw)
    _write_raw(s._active, lines)


def test_a_line_the_readers_skip_never_blocks_an_append(tmp_path):
    s = _legacy(tmp_path)
    _with_line(s, 5, b'{"seq": 999999, "note": "not a record"}\n')
    fresh = SpineStore(tmp_path / "spine.jsonl")
    assert fresh.verify()[0]
    assert fresh.append(kind="message", source="t", actor="u", payload={"text": "x"}) == 10
    assert fresh.verify()[0]


@pytest.mark.parametrize("field,value", [("seq", "3"), ("seq", 3.0), ("seq", True), ("kind", ["message"]),
                                         ("schema_version", "x"), ("parent_id", "1"), ("ts", 5)])
def test_a_line_of_the_wrong_shape_is_skipped_by_every_reader_never_a_crash(tmp_path, field, value):
    s = _legacy(tmp_path, 6)
    rec = json.loads(_line_of(s, 3))
    rec[field] = value
    _with_line(s, 6, (json.dumps(rec) + "\n").encode())           # a wrong-shape copy of seq 3, at the end
    fresh = SpineStore(tmp_path / "spine.jsonl")
    assert [r.seq for r in fresh.iter_records()] == list(range(6))
    assert fresh.get(3).seq == 3 and fresh.count() == 6 and fresh.verify()[0]
    t = SpineTailer(fresh, since_seq=2)
    assert [e["seq"] for e in t.poll()] == [3, 4, 5]
    two = fresh.get(2)
    assert [r.seq for r in fresh.tail_after(two.seq, two.entry_hash)] == [3, 4, 5]      # the fold cache's tail path
    assert fresh.append(kind="message", source="t", actor="u", payload={"text": "x"}) == 6   # not chained from it


def write_chained_line(s: SpineStore, payload, *, kind="event", source="t", actor="u",
                       ts="2026-01-01T00:00:00Z") -> int:
    """Write, by hand, a complete line that continues the chain exactly as `append` would (seq + 1, prev_hash = the
    tip's entry_hash, the real cert_digest and entry_hash) but whose payload is `payload` — the only way to put a
    payload that is not a JSON object on the spine, since `append` refuses one. Returns its seq."""
    from sigil.config import SCOPE
    from sigil.reuse import ChainEntry, append_entry, digest_payload
    fresh = SpineStore(s.path)
    recs = list(fresh.iter_records())
    prior = [ChainEntry(seq=r.seq, prev_hash=r.prev_hash, cert_digest=r.cert_digest, entry_hash=r.entry_hash)
             for r in recs[-1:]]                                    # none: the genesis record
    content = {"scope": SCOPE, "kind": kind, "source": source, "actor": actor, "payload": payload,
               "parent_id": None, "supersedes_id": None}
    entry = append_entry(prior, digest_payload(content))
    rec = {"seq": entry.seq, **content, "ts": ts, "cert_digest": entry.cert_digest, "prev_hash": entry.prev_hash,
           "entry_hash": entry.entry_hash, "schema_version": 1}
    seq = entry.seq
    with fresh._active.open("ab") as f:
        f.write((json.dumps(rec) + "\n").encode())
    return seq


_chained = write_chained_line


@pytest.mark.parametrize("payload", [["not", "a", "dict"], "text", 5, True])
def test_a_chained_line_whose_payload_is_not_an_object_is_a_record(tmp_path, payload):
    """Not a malformed line: every reader yields it, the chain verifies through it, the tail path returns it and the
    next append chains from it — its consumers then fail closed on it (test_fold_cache_latches,
    test_fold_cache_authority)."""
    s = _legacy(tmp_path, 6)
    _chained(s, payload)
    fresh = SpineStore(tmp_path / "spine.jsonl")
    assert [r.seq for r in fresh.iter_records()] == list(range(7))
    assert fresh.get(6).payload == payload and fresh.count() == 7 and fresh.verify()[0]
    five = fresh.get(5)
    assert [r.seq for r in fresh.tail_after(five.seq, five.entry_hash)] == [6]
    tip = fresh.get(6)
    assert SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u",
                                                       payload={"text": "x"}) == 7
    after = SpineStore(tmp_path / "spine.jsonl")
    assert after.get(7).prev_hash == tip.entry_hash and after.verify()[0]


def test_a_copy_of_a_record_with_a_payload_that_is_not_an_object_is_a_duplicate_seq(tmp_path):
    """A copy of seq 3 whose payload is not a JSON object, at the end: it is a record, so it is a duplicated seq —
    verify() reports it and append refuses to chain from it, never steps over it."""
    s = _legacy(tmp_path, 6)
    rec = json.loads(_line_of(s, 3))
    rec["payload"] = ["not", "a", "dict"]
    _with_line(s, 6, (json.dumps(rec) + "\n").encode())
    fresh = SpineStore(tmp_path / "spine.jsonl")
    assert [r.seq for r in fresh.iter_records()] == list(range(6))
    ok, why = fresh.verify()
    assert ok is False and "duplicated or reordered" in why
    with pytest.raises(SpineError, match="not above every earlier record"):
        fresh.append(kind="message", source="t", actor="u", payload={"text": "x"})


_NOT_OBJECTS = [["not", "a", "dict"], "text", 5, True, None, ()]


def _lock_forbidden(monkeypatch):
    """Fail the test if the write path takes the spine lock (the refusal must come before any lock)."""
    from sigil.spine import store as store_mod

    def taken(*a, **kw):
        raise AssertionError("the spine lock was taken")

    monkeypatch.setattr(store_mod, "spine_lock", taken)


@pytest.mark.parametrize("payload", _NOT_OBJECTS)
def test_append_refuses_a_payload_that_is_not_an_object_before_any_lock(tmp_path, monkeypatch, payload):
    s = _legacy(tmp_path, 3)
    before = s._active.read_bytes()
    _lock_forbidden(monkeypatch)
    for dedup in (False, True):
        with pytest.raises(SpineError, match="payload is not a JSON object"):
            s.append(kind="message", source="t", actor="u", payload=payload, dedup=dedup)
    monkeypatch.undo()
    assert s._active.read_bytes() == before
    assert s.append(kind="message", source="t", actor="u", payload={"text": "ok"}) == 3     # not a lost seq


@pytest.mark.parametrize("payload", _NOT_OBJECTS)
def test_append_many_refuses_a_batch_with_a_payload_that_is_not_an_object_before_any_lock(tmp_path, monkeypatch,
                                                                                           payload):
    s = _legacy(tmp_path, 3)
    before = s._active.read_bytes()
    _lock_forbidden(monkeypatch)
    good = {"kind": "message", "source": "t", "actor": "u", "payload": {"text": "ok"}}
    with pytest.raises(SpineError, match=r"spec\[1\] payload is not a JSON object"):
        s.append_many([good, dict(good, payload=payload), good])
    assert s._active.read_bytes() == before


def test_a_coalesced_append_with_a_payload_that_is_not_an_object_fails_only_its_owner(tmp_path, monkeypatch):
    """With group commit on, the refusal comes before the append joins a batch: it never reaches the leader's
    append_many, so the appends batched with it are written."""
    s = _legacy(tmp_path, 3)
    s._group_commit_coalesce = True
    joined = []
    real = SpineStore._append_coalesced

    def coalesced(self, spec):
        joined.append(spec["payload"])
        return real(self, spec)

    monkeypatch.setattr(SpineStore, "_append_coalesced", coalesced)
    with pytest.raises(SpineError, match="payload is not a JSON object"):
        s.append(kind="message", source="t", actor="u", payload=["not", "a", "dict"])
    assert joined == []
    out, errs = [], []

    def ok(i):
        try:
            out.append(s.append(kind="event", source="t", actor="u", payload={"n": i}))
        except Exception as e:  # noqa: BLE001 — recorded
            errs.append(e)

    def bad():
        try:
            s.append(kind="event", source="t", actor="u", payload=["x"])
        except SpineError as e:
            errs.append(e)

    ts = [threading.Thread(target=ok, args=(i,)) for i in range(6)] + [threading.Thread(target=bad)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    assert sorted(out) == list(range(3, 9)) and len(errs) == 1 and isinstance(errs[0], SpineError)
    assert ["x"] not in joined and SpineStore(tmp_path / "spine.jsonl").verify()[0]


def test_verify_record_reports_a_kind_that_is_not_a_string():
    from types import SimpleNamespace
    rec = SimpleNamespace(seq=1, kind=["message"], scope="sigil", source="t", actor="u", payload={},
                          parent_id=None, supersedes_id=None, cert_digest="c", prev_hash="p", entry_hash="e")
    ok, why = verify_record(rec)
    assert ok is False and "unknown kind" in why


def test_a_verify_pass_that_is_restarted_still_sees_a_duplicate(tmp_path, monkeypatch):
    s = _segmented(tmp_path)
    sealed = sorted(s._layout.segments_dir.glob("seg-*.jsonl"))[1]
    lines = sealed.read_bytes().splitlines(keepends=True)
    _write_raw(sealed, lines[:1] + [lines[0]] + lines[1:])          # seq 3 twice in a sealed segment
    fresh = SpineStore(tmp_path / "spine.jsonl")
    fresh.get(5)                                                    # build the index (last offset of seq 3 wins)
    real = fresh._open_segment
    state = {"raised": False}

    def flaky(p):
        if p == sealed and not state["raised"]:
            state["raised"] = True
            raise FileNotFoundError(p)                              # a compaction moved it under the pass
        return real(p)

    monkeypatch.setattr(fresh, "_open_segment", flaky)
    ok, why = fresh.verify()
    assert state["raised"] and ok is False and "duplicated or reordered" in why


def test_an_append_refuses_a_manifest_that_is_not_a_contiguous_run(tmp_path):
    s = _segmented(tmp_path)
    mp = s._layout.manifest_path
    m = json.loads(mp.read_text())
    _omit_middle(m)
    mp.write_text(json.dumps(m))
    with pytest.raises(SpineError, match="not a contiguous segment run"):
        SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u", payload={"text": "x"})


def test_two_segments_naming_one_file_are_not_a_contiguous_run(tmp_path):
    s = _segmented(tmp_path)
    mp = s._layout.manifest_path
    m = json.loads(mp.read_text())
    sealed = sorted((g for g in m["segments"] if g["sealed"]), key=lambda g: g["first_seq"])
    sealed[1]["file"] = sealed[0]["file"]
    mp.write_text(json.dumps(m))
    with pytest.raises(SpineError, match="two segments name the same file"):
        list(SpineStore(tmp_path / "spine.jsonl").iter_records())


def test_a_fresh_store_per_request_does_not_re_read_the_active_segment(tmp_path, monkeypatch):
    from sigil.spine import store as store_mod
    _legacy(tmp_path, 50)
    reads: list = []
    real = store_mod._lines_between

    def counting(path, start, end, **kw):
        reads.append((start, end))
        return real(path, start, end, **kw)

    monkeypatch.setattr(store_mod, "_lines_between", counting)
    for i in range(5):                                              # five requests, five stores, one process
        SpineStore(tmp_path / "spine.jsonl").append(kind="message", source="t", actor="u", payload={"text": f"{i}"})
    assert reads == [], "a store of this process re-read bytes this process had already checked"


def test_the_check_streams_lines_across_chunk_boundaries(tmp_path):
    from sigil.spine import store as store_mod
    p = tmp_path / "f"
    p.write_bytes(b"aaaa\nbb\n\ncccccc\nd\n")
    assert list(store_mod._lines_between(p, 0, p.stat().st_size, chunk=3)) == [b"aaaa", b"bb", b"cccccc", b"d"]
    assert list(store_mod._lines_between(p, 5, 8, chunk=2)) == [b"bb"]
