"""Spine store integrity at the line level.

  * append refuses a tail whose last record does not carry the highest seq in the active segment (a duplicated
    or reordered line there would make the next record fork below the true tip);
  * verify() flags a duplicated or out-of-order seq anywhere in the spine;
  * every reader refuses a manifest whose segments are not one contiguous run;
  * a record with no canonical form (a lone surrogate — no append can write one) is reported as tampered by
    verify_record, SpineStore.verify, the live tailer (which keeps advancing), dedup and `/api/record`, never a
    crash.

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


# ---- append refuses a non-monotonic tail -----------------------------------------------------------------------

@pytest.mark.parametrize("copied", [(3,), (3, 4)])
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
        (a if i % 3 else b).append(kind="message", source="t", actor="u", payload={"text": f"i{i}"})
    b.append_many([{"kind": "message", "source": "t", "actor": "u", "payload": {"text": "batch"}}] * 3)
    a.append(kind="message", source="t", actor="u", payload={"text": "last"})
    assert [r.seq for r in a.iter_records()] == list(range(18))
    assert a.verify()[0]


def test_append_rechecks_a_spine_that_was_reset_and_regrew(tmp_path):
    a = _legacy(tmp_path, 5)
    b = SpineStore(tmp_path / "spine.jsonl")
    b.reset()
    _add(b, 9)                                                      # past `a`'s checked bytes, different records
    assert a.append(kind="message", source="t", actor="u", payload={"text": "after"}) == 9
    assert a.verify()[0]


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


@pytest.mark.parametrize("tamper", [_dup_at_end, _dup_in_middle, _swapped])
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


@pytest.mark.parametrize("edit", [_omit_middle, _omit_last_sealed, _two_unsealed, _overlapping, _wrong_link])
def test_every_reader_refuses_a_manifest_that_is_not_a_contiguous_run(tmp_path, edit):
    s = _segmented(tmp_path)
    mp = s._layout.manifest_path
    m = json.loads(mp.read_text())
    edit(m)
    mp.write_text(json.dumps(m))
    fresh = SpineStore(tmp_path / "spine.jsonl")
    for read in (lambda: list(fresh.iter_records()), fresh.count, lambda: fresh.get(10), fresh.verify):
        with pytest.raises(SpineError, match="not a contiguous segment run"):
            read()


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


def test_the_cockpit_json_encoder_round_trips_a_lone_surrogate():
    from sigil.ui.server import _json_bytes
    obj = {"t": "a\ud800b", "ok": "ünïcode"}
    raw = _json_bytes(obj)
    assert json.loads(raw) == obj and "ünïcode".encode("utf-8") in raw
