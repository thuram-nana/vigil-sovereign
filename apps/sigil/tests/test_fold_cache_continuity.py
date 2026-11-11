"""Front C S0 — the verified fold cache never caches a read that is not CONTIGUOUS.

Every record a cached fold folds must chain from the one before it (`seq == prev + 1`, `prev_hash ==` the previous
`entry_hash`; the first record after an anchor chains from the anchor). Without that check one bad read was cached for
the life of the process — the entry anchored PAST the hole, so every later read was missing the record:

  * a TORN READ: `SpineStore.iter_records` reads to the live end of a segment another process is appending to; a
    half-written line is skipped as malformed and the NEXT record is yielded (no attacker needed);
  * a STALE seq index persisted as the `.idx` sidecar (a long-lived store that indexed a segment before a live
    rollback writes its stale offsets when the segment is sealed) — or a planted one;
  * a DUPLICATE-seq line after the anchor (the seq index is last-wins, the full scan first-wins).

Each test drives the real scenario and requires the cached answer to EQUAL the flag-OFF full fold on the same bytes.
"""
from __future__ import annotations

import itertools
import json
import shutil
from types import SimpleNamespace

import pytest

from sigil.governor import customers as cu
from sigil.governor import fold_read
from sigil.governor import key_history as kh
from sigil.governor import killswitch as ks
from sigil.governor import wallet as wal
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine import store as store_mod
from sigil.spine.manifest import read_manifest
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
PUB = OWNER.public_key_b64
FLAG = "VIGIL_FOLD_CACHE_ENABLED"
_issue = itertools.count(1)


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    fold_cache.clear_all()
    ks._STATE_CACHE.clear()
    yield
    fold_cache.clear_all()


def _full(monkeypatch, read):
    """`read()` with the cache OFF (the unchanged full verified fold), then the flag restored."""
    monkeypatch.setenv(FLAG, "")
    ks._STATE_CACHE.clear()
    try:
        return read()
    finally:
        monkeypatch.setenv(FLAG, "1")


def _noise(s, i, pad=0):
    s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": i, "pad": "x" * pad})


# ======================================================================================================
# 1. a torn read during a cold build (no attacker)
# ======================================================================================================
def _wallet(path, key=OWNER):
    return WalletRegistry(SpineStore(path), owner_key=key, trusted_pubkey=PUB)


def test_a_cold_build_racing_an_append_never_caches_a_balance_missing_a_debit(tmp_path, monkeypatch):
    """Deterministic replay of the interleaving a stress run hits for real: the build's fold pass meets another
    writer's half-written record at EOF; before its next read the rest of that record and one more land. The read
    skips the two halves and yields the NEXT record — a 40-credit debit is missing from that pass."""
    path = str(tmp_path / "spine.jsonl")
    w = _wallet(path)
    w.grant("org_a", 100, "topup", entry_id="g1", issued_at=1.0)
    w.debit("org_a", 1, entry_id="d1", issued_at=2.0)
    size0 = (tmp_path / "spine.jsonl").stat().st_size
    twin = tmp_path / "twin" / "spine.jsonl"                 # the other writer's bytes, with real chain hashes
    twin.parent.mkdir()
    shutil.copy(path, twin)
    tw = _wallet(str(twin))
    tw.debit("org_a", 40, entry_id="d2", issued_at=3.0)
    tw.debit("org_a", 1, entry_id="d3", issued_at=4.0)
    tail = twin.read_bytes()[size0:]
    cut = tail.index(b"\n") // 2

    def raw_append(b):
        with open(path, "ab") as f:
            f.write(b)

    real_resolver = kh.key_resolver_with_horizon

    def resolver_then_half_a_record(store, *, current):
        out = real_resolver(store, current=current)
        raw_append(tail[:cut])
        return out

    state = {"done": False}
    real_warning = store_mod._log.warning

    def warning(msg, *a, **k):
        if "malformed line during iter_records" in msg and not state["done"]:
            state["done"] = True
            raw_append(tail[cut:])
        return real_warning(msg, *a, **k)

    monkeypatch.setattr(kh, "key_resolver_with_horizon", resolver_then_half_a_record)
    monkeypatch.setattr(store_mod._log, "warning", warning)
    first = _wallet(path, key=None).balance("org_a")         # the cold build (a fresh store, as a request)
    assert state["done"], "the interleaving was exercised"
    monkeypatch.setattr(kh, "key_resolver_with_horizon", real_resolver)
    monkeypatch.setattr(store_mod._log, "warning", real_warning)

    assert SpineStore(path).verify()[0]
    assert first.available == 58, "the torn pass is never answered from: the full fold re-reads the spine"
    assert not wal._WALLET_FOLD._entries, "nothing was cached from the torn pass"
    cached = [_wallet(path, key=None).balance("org_a").available for _ in range(5)]
    assert cached == [58] * 5
    assert _full(monkeypatch, lambda: _wallet(path, key=None).balance("org_a").available) == 58
    _wallet(path).debit("org_a", 5, entry_id="d4", issued_at=5.0)
    assert _wallet(path, key=None).balance("org_a").available == 53
    res = fold_read.audit_with(lambda: _wallet(path, key=None).balance("org_a"))
    assert [r["status"] for r in res] == ["match"]


# ======================================================================================================
# 2. a stale or planted `.idx` sidecar on the indexed catch-up path
# ======================================================================================================
def _plant_sidecar(seg_path, hide_seq):
    """A size-matching sidecar whose first offset is right (all `_load_sidecar` checks) and whose offset for
    `hide_seq` points at the NEXT line — written with file-write access only, the spine bytes untouched."""
    offs, size = [], 0
    for raw in seg_path.read_bytes().splitlines(keepends=True):
        offs.append((json.loads(raw)["seq"], size))
        size += len(raw)
    by_seq = dict(offs)
    offsets = [by_seq.get(seq + 1, size) if seq == hide_seq else off for seq, off in offs]
    idx = seg_path.with_name(seg_path.name + ".idx")
    idx.write_text(json.dumps({"v": 1, "first_seq": offs[0][0], "seg_bytes": size, "offsets": offsets}))


def test_a_planted_sidecar_cannot_hide_a_kill_switch_engage(tmp_path, monkeypatch):
    p = tmp_path / "spine.jsonl"
    w = SpineStore(p, seg_max_bytes=0, seg_max_records=6)    # the engage itself trips the seal
    w.migrate()
    for i in range(5):
        _noise(w, i)
    reader = lambda: ks.KillSwitch(SpineStore(p), owner_key=OWNER, trusted_pubkey=PUB)  # noqa: E731
    assert reader().is_engaged() is False                    # warm: anchor = seq 4
    assert ks.KillSwitch(w, owner_key=OWNER, trusted_pubkey=PUB).engage(by="owner", reason="panic") == 5
    seg0 = w._layout.seg_path(read_manifest(w._layout).sealed_in_order()[0])
    _plant_sidecar(seg0, hide_seq=5)
    assert SpineStore(p).verify()[0]
    assert reader().is_engaged() is True
    assert _full(monkeypatch, lambda: reader().is_engaged()) is True
    _noise(w, 99)
    assert reader().is_engaged() is True


def test_a_planted_sidecar_cannot_hide_a_customer_revocation(tmp_path, monkeypatch):
    p = tmp_path / "spine.jsonl"
    w = SpineStore(p, seg_max_bytes=0, seg_max_records=0)
    w.migrate()
    wreg = cu.CustomerRegistry(w, owner_key=OWNER, trusted_pubkey=PUB)
    for i in range(4):
        wreg.create(f"user{i}@example.com", issued_at=float(next(_issue)))
    reader = lambda: cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=PUB)  # noqa: E731
    victim = reader().by_email("user2@example.com")
    assert victim is not None
    tip = list(SpineStore(p).iter_records())[-1].seq
    wreg.revoke(victim.username)
    _noise(w, 0)
    assert w.rotate()
    _plant_sidecar(w._layout.seg_path(read_manifest(w._layout).sealed_in_order()[0]), hide_seq=tip + 1)
    assert SpineStore(p).verify()[0]
    assert reader().by_email("user2@example.com") is None
    assert _full(monkeypatch, lambda: reader().by_email("user2@example.com")) is None


def test_a_stale_sidecar_left_by_a_live_rollback_cannot_hide_an_engage(tmp_path, monkeypatch):
    """No attacker: a long-lived store indexed the active segment, the spine was rolled back to a backup under it
    and regrown, and on the seal that store persisted its stale offsets as the sidecar every fresh store loads."""
    p = tmp_path / "spine.jsonl"
    w = SpineStore(p, seg_max_bytes=0, seg_max_records=0)
    w.migrate()
    for i in range(4):
        _noise(w, i)
    active = w._layout.seg_path(read_manifest(w._layout).active())
    backup = active.read_bytes()
    daemon = SpineStore(p)
    for i in range(4, 8):
        _noise(w, i, pad=600)
    assert daemon.get(7) is not None
    active.write_bytes(backup)                               # the live rollback
    w2 = SpineStore(p, seg_max_bytes=0, seg_max_records=0)
    reader = lambda: ks.KillSwitch(SpineStore(p), owner_key=OWNER, trusted_pubkey=PUB)  # noqa: E731
    _noise(w2, 100)
    assert reader().is_engaged() is False
    assert ks.KillSwitch(w2, owner_key=OWNER, trusted_pubkey=PUB).engage(by="owner", reason="panic") == 5
    for i in range(101, 112):
        _noise(w2, i, pad=300)
    assert w2.rotate()
    assert daemon.get(2) is not None                         # the daemon reconciles -> writes the stale .idx
    seg0 = w._layout.seg_path(read_manifest(w._layout).sealed_in_order()[0])
    assert seg0.with_name(seg0.name + ".idx").exists()
    assert SpineStore(p).verify()[0]
    assert reader().is_engaged() is True
    assert _full(monkeypatch, lambda: reader().is_engaged()) is True


# ======================================================================================================
# 3. a duplicate-seq line after the anchor
# ======================================================================================================
def test_an_appended_duplicate_seq_line_cannot_hide_an_engage(tmp_path, monkeypatch):
    p = tmp_path / "spine.jsonl"
    w = SpineStore(p)
    for i in range(3):
        _noise(w, i)
    reader = lambda: ks.KillSwitch(SpineStore(p), owner_key=OWNER, trusted_pubkey=PUB)  # noqa: E731
    assert reader().is_engaged() is False                    # warm: anchor = seq 2
    assert ks.KillSwitch(w, owner_key=OWNER, trusted_pubkey=PUB).engage(by="owner", reason="panic") == 3
    _noise(w, 9)
    dup = json.loads(p.read_bytes().splitlines()[0])
    dup["seq"] = 3                                           # an old line re-stamped seq 3, APPENDED
    with open(p, "ab") as f:
        f.write((json.dumps(dup) + "\n").encode())
    full = _full(monkeypatch, lambda: reader().is_engaged())
    assert full is True and reader().is_engaged() is full


# ======================================================================================================
# 4. the guards themselves, on a store whose reads are scripted
# ======================================================================================================
def _rec(seq, prev, h, kind="event", payload=None):
    return SimpleNamespace(seq=seq, prev_hash=prev, entry_hash=h, kind=kind, payload=payload or {})


class _Scripted:
    """A store whose `iter_records` returns a scripted list (no index, no tail fast path)."""

    def __init__(self, path, recs):
        self.path, self.recs = path, list(recs)

    def iter_records(self, *, since_seq=-1):
        return iter([r for r in self.recs if r.seq > since_seq])

    def get(self, seq):
        return next((r for r in self.recs if r.seq == seq), None)


def _counting_cache(name):
    def step(state, r, ctx):
        state.append(r.seq)
    return fold_cache.FoldCache(name, step=step)


def _build():
    return [], None, -1, float("inf")


CHAIN = [_rec(0, "g", "h0"), _rec(1, "h0", "h1"), _rec(2, "h1", "h2"), _rec(3, "h2", "h3")]


@pytest.mark.parametrize("label,recs", [
    ("a skipped record", [CHAIN[0], CHAIN[1], CHAIN[3]]),
    ("a repeated seq", [CHAIN[0], CHAIN[1], _rec(1, "h0", "h1"), CHAIN[2]]),
    ("a record that does not link from its predecessor", [CHAIN[0], CHAIN[1], _rec(2, "zz", "h2")]),
])
def test_a_rebuild_over_a_non_contiguous_read_raises_and_caches_nothing(tmp_path, label, recs):
    c = _counting_cache(f"test.cont.rebuild.{label}")
    with pytest.raises(fold_cache.FoldDiscontinuity):
        c.read(_Scripted(tmp_path, recs), ("k",), build=_build, reader=list)
    assert not c._entries, label


def test_a_contiguous_rebuild_is_cached(tmp_path):
    c = _counting_cache("test.cont.ok")
    assert c.read(_Scripted(tmp_path, CHAIN), ("k",), build=_build, reader=list) == [0, 1, 2, 3]
    assert len(c._entries) == 1


@pytest.mark.parametrize("label,more", [
    ("the next record skips a seq", [_rec(5, "h4", "h5")]),
    ("the next record does not link from the anchor", [_rec(4, "zz", "h4")]),
])
def test_a_catch_up_that_does_not_chain_from_the_anchor_rebuilds(tmp_path, label, more):
    c = _counting_cache(f"test.cont.catchup.{label}")
    s = _Scripted(tmp_path, CHAIN)
    assert c.read(s, ("k",), build=_build, reader=list) == [0, 1, 2, 3]
    s.recs = CHAIN + more                                    # the anchor (seq 3, h3) still holds
    with pytest.raises(fold_cache.FoldDiscontinuity):
        c.read(s, ("k",), build=_build, reader=list)         # the catch-up refuses; the rebuild meets the same gap
    assert not c._entries


def test_the_read_path_answers_uncached_on_a_discontinuity(tmp_path, monkeypatch):
    c = _counting_cache("test.cont.readpath")

    def seed(snap):
        return [], -1

    out = fold_read.cached_unsigned_read(c, _Scripted(tmp_path, [CHAIN[0], CHAIN[2]]), seed=seed, reader=list)
    assert out is fold_read.UNCACHED
    assert fold_read.cached_unsigned_read(c, _Scripted(tmp_path, CHAIN), seed=seed, reader=list) == [0, 1, 2, 3]


def test_the_audit_skips_a_non_contiguous_fresh_fold(tmp_path):
    c = _counting_cache("test.cont.audit")
    s = _Scripted(tmp_path, CHAIN)
    c.read(s, ("k",), build=_build, reader=list)
    s.recs = [CHAIN[0], CHAIN[2], CHAIN[3]]                  # the audit's own fresh read is torn
    rep = c.audit(s, ("k",), build=_build)
    assert rep["status"] == "skipped" and "not contiguous" in rep["reason"]
    s.recs = CHAIN
    assert c.audit(s, ("k",), build=_build)["status"] == "match"


def test_the_resolver_horizon_stops_at_the_first_non_contiguous_record(tmp_path):
    """A history record a torn scan may have missed sits ABOVE the horizon, so the build that folds it is not
    cached (the resolver might not reflect that rotation)."""
    s = _Scripted(tmp_path, [CHAIN[0], CHAIN[1], CHAIN[3], _rec(4, "h3", "h4")])
    _res, horizon = kh.key_resolver_with_horizon(s, current=PUB)
    assert horizon == 1
    _res, horizon = kh.key_resolver_with_horizon(_Scripted(tmp_path, CHAIN), current=PUB)
    assert horizon == 3
    _res, horizon = kh.key_resolver_with_horizon(_Scripted(tmp_path, []), current=PUB)
    assert horizon == -1


class _WithTip(_Scripted):
    """As `_Scripted`, plus the tip the store read from disk when opened (`next_seq`)."""

    def __init__(self, path, recs, tip):
        super().__init__(path, recs)
        self.next_seq = tip + 1


def test_a_rebuild_that_ends_below_the_stores_tip_raises(tmp_path):
    """The tail hidden by a stale / planted index: the read ends early, every record it did yield chains."""
    c = _counting_cache("test.cont.tip.rebuild")
    with pytest.raises(fold_cache.FoldDiscontinuity, match="below the tip"):
        c.read(_WithTip(tmp_path, CHAIN[:3], tip=3), ("k",), build=_build, reader=list)
    assert not c._entries
    assert c.read(_WithTip(tmp_path, CHAIN, tip=3), ("k",), build=_build, reader=list) == [0, 1, 2, 3]


def test_a_catch_up_that_ends_below_the_stores_tip_rebuilds(tmp_path):
    c = _counting_cache("test.cont.tip.catchup")
    assert c.read(_WithTip(tmp_path, CHAIN, tip=3), ("k",), build=_build, reader=list) == [0, 1, 2, 3]
    grown = CHAIN + [_rec(4, "h3", "h4"), _rec(5, "h4", "h5")]
    hiding = _WithTip(tmp_path, grown, tip=5)
    hiding.iter_records = lambda *, since_seq=-1: iter([r for r in grown if since_seq < r.seq < 5])  # tail hidden
    with pytest.raises(fold_cache.FoldDiscontinuity):
        c.read(hiding, ("k",), build=_build, reader=list)
    assert c.read(_WithTip(tmp_path, grown, tip=5), ("k",), build=_build, reader=list) == [0, 1, 2, 3, 4, 5]


def test_a_tip_from_a_store_that_has_none_is_not_checked(tmp_path):
    c = _counting_cache("test.cont.tip.none")
    s = _Scripted(tmp_path, CHAIN[:2])
    s.next_seq = "not a seq"
    assert c.read(s, ("k",), build=_build, reader=list) == [0, 1]


def test_a_seeded_read_must_start_right_after_its_seed(tmp_path):
    c = _counting_cache("test.cont.seeded")

    def seeded():
        return [], None, 1, float("inf")                     # the seed covers [0..1]; the read must start at seq 2

    with pytest.raises(fold_cache.FoldDiscontinuity, match="starts at seq 3"):
        c.read(_Scripted(tmp_path, [CHAIN[3]]), ("k",), build=seeded, reader=list)
    assert c.read(_Scripted(tmp_path, CHAIN), ("k",), build=seeded, reader=list) == [2, 3]


def test_a_tail_fast_path_delta_that_ends_below_the_stores_tip_rebuilds(tmp_path):
    """`tail_after` is trusted for the delta after the anchor; a delta that stops short of the tip the store read
    from disk is never folded into the entry."""
    c = _counting_cache("test.cont.tip.tail")
    grown = CHAIN + [_rec(4, "h3", "h4"), _rec(5, "h4", "h5")]
    s = _WithTip(tmp_path, CHAIN, tip=3)
    assert c.read(s, ("k",), build=_build, reader=list) == [0, 1, 2, 3]
    short = _WithTip(tmp_path, grown, tip=5)
    short.tail_after = lambda seq, h: [r for r in grown if seq < r.seq < 5]          # a short delta
    assert c.read(short, ("k",), build=_build, reader=list) == [0, 1, 2, 3, 4, 5]   # rebuilt from the full read
    ok = _WithTip(tmp_path, grown, tip=5)
    ok.tail_after = lambda seq, h: [r for r in grown if r.seq > seq]
    assert c.read(ok, ("k",), build=_build, reader=list) == [0, 1, 2, 3, 4, 5]


def test_the_audit_skips_when_its_catch_up_read_is_not_contiguous(tmp_path):
    """The audit's fresh fold can lag the entry (appends land between the two); the read that brings it up to the
    entry's seq is held to the same continuity rule."""
    c = _counting_cache("test.cont.audit.catchup")
    grown = CHAIN + [_rec(4, "h3", "h4"), _rec(5, "h4", "h5")]
    s = _Scripted(tmp_path, grown)
    c.read(s, ("k",), build=_build, reader=list)
    # 1st read: the fresh fold reaches seq 1; 2nd: the entry's own catch-up (nothing new); 3rd: the fresh fold's
    # catch-up to the entry's seq 5 — which skips seq 2
    reads = iter([CHAIN[:2], grown, [grown[3], grown[4], grown[5]]])
    s.iter_records = lambda *, since_seq=-1: iter([r for r in next(reads, grown) if r.seq > since_seq])
    s.tail_after = None
    rep = c.audit(s, ("k",), build=_build)
    assert rep["status"] == "skipped" and "not contiguous" in rep["reason"], rep


def test_the_resolver_horizon_stops_at_a_record_that_does_not_link(tmp_path):
    s = _Scripted(tmp_path, [CHAIN[0], CHAIN[1], _rec(2, "zz", "h2"), _rec(3, "h2", "h3")])
    assert kh.key_resolver_with_horizon(s, current=PUB)[1] == 1


# ======================================================================================================
# 5. a LOST segment: a warm read fails closed exactly as the full fold does (invariant 15)
# ======================================================================================================
def _customers_on_two_segments(tmp_path):
    p = tmp_path / "spine.jsonl"
    w = SpineStore(p, seg_max_bytes=0, seg_max_records=0)
    w.migrate()
    wreg = cu.CustomerRegistry(w, owner_key=OWNER, trusted_pubkey=PUB)
    for i in range(4):
        wreg.create(f"user{i}@example.com", issued_at=float(next(_issue)))
    assert w.rotate()
    return p, w, wreg


def _cust(p):
    return cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=PUB)


def test_a_warm_read_over_a_lost_sealed_segment_raises_like_the_full_fold(tmp_path, monkeypatch):
    p, w, wreg = _customers_on_two_segments(tmp_path)
    for i in range(4, 8):
        wreg.create(f"user{i}@example.com", issued_at=float(next(_issue)))
    assert _cust(p).by_email("user1@example.com") is not None             # warm; anchor in the active segment
    w._layout.seg_path(read_manifest(w._layout).sealed_in_order()[0]).unlink()
    with pytest.raises(store_mod.SpineError, match="missing segment"):
        _full(monkeypatch, lambda: _cust(p).by_email("user1@example.com"))
    with pytest.raises(store_mod.SpineError, match="missing segment"):
        _cust(p).by_email("user1@example.com")


def test_a_warm_read_over_a_lost_active_segment_raises_like_the_full_fold(tmp_path, monkeypatch):
    """The anchor at the seam (the last record of the sealed segment): a missing ACTIVE file is not "empty, so the
    anchor is the tip" — a revoke that landed in it would be missed."""
    p, w, wreg = _customers_on_two_segments(tmp_path)
    assert _cust(p).by_email("user1@example.com") is not None
    victim = _cust(p).by_email("user2@example.com")
    wreg.revoke(victim.username)
    w._layout.seg_path(read_manifest(w._layout).active()).unlink()
    with pytest.raises(store_mod.SpineError, match="missing segment"):
        _full(monkeypatch, lambda: _cust(p).by_email("user2@example.com"))
    with pytest.raises(store_mod.SpineError, match="missing segment"):
        _cust(p).by_email("user2@example.com")


@pytest.mark.parametrize("which", ["active", "sealed", "the segments directory"])
def test_tail_after_is_undecidable_when_a_segment_is_missing(tmp_path, which):
    p = tmp_path / "spine.jsonl"
    w = SpineStore(p, seg_max_bytes=0, seg_max_records=0)
    w.migrate()
    for i in range(4):
        _noise(w, i)
    assert w.rotate()
    anchor = list(SpineStore(p).iter_records())[-1]
    for i in range(3):
        _noise(w, 10 + i)
    m = read_manifest(w._layout)
    assert len(SpineStore(p).tail_after(anchor.seq, anchor.entry_hash)) == 3      # control
    probe = SpineStore(p)                                    # opened (tip read) before the loss
    if which == "the segments directory":
        shutil.rmtree(w._layout.segments_dir)
    else:
        w._layout.seg_path(m.active() if which == "active" else m.sealed_in_order()[0]).unlink()
    assert probe.tail_after(anchor.seq, anchor.entry_hash) is None


def test_an_audit_whose_fresh_fold_raises_discards_the_entry(tmp_path):
    """The full fold raises on this spine now, so the warm entry must not keep answering after the audit saw it."""
    c = _counting_cache("test.cont.audit.raises")
    s = _Scripted(tmp_path, CHAIN)
    assert c.read(s, ("k",), build=_build, reader=list) == [0, 1, 2, 3]

    def broken(*, since_seq=-1):
        raise store_mod.SpineError("references a missing segment")

    s.iter_records = broken
    with pytest.raises(store_mod.SpineError):
        c.audit(s, ("k",), build=_build)
    assert not c._entries
    with pytest.raises(store_mod.SpineError):
        c.read(s, ("k",), build=_build, reader=list)
