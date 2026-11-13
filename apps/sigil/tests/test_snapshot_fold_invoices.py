"""Prune-survival proof for the SnapshotState-seeded `InvoiceRegistry._fold` (SaaS billing history, Slice H).

A billing history is a LIFETIME append-only list (like the wallet balance, unlike the per-UTC-day budget), so it
MUST seed from `SnapshotState` or the first hard prune below a tenant's invoices would (1) LOSE every historical
line and (2) drop the consumed `invoice_id` set — re-opening invoice REPLAY (a pruned invoice re-appended above
the boundary would duplicate the line).

PHYSICAL-PRUNE HARNESS (identical to test_snapshot_fold_wallet.py): a `PrunedView` PHYSICALLY HIDES every record
with `seq < K` from `iter_records` regardless of `since_seq`, so only the SEED can carry the pruned state.

Proves:
  (a) a tenant whose invoices sit BELOW base_seq keeps its exact history — from the seed alone, over a store
      from which the records are physically absent;
  (b) the consumed invoice_id set SURVIVES the prune, so a replayed pruned invoice does NOT duplicate the line
      (the neutered control strips `invoice_row` to prove that carry is load-bearing);
  (c) empty-load == genesis scan byte-identity, proven by fold-of-fold across two prunes == a single full scan;
  (d) `check_prune_safe`'s referential floor DETECTS a seed that would strand an invoice and refuses.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_invoices.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.invoices import InvoiceRegistry
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return InvoiceRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records`, regardless of
    `since_seq`. The pruned records still sit on disk, so a fold that does NOT seed from the snapshot cannot
    see them — exactly the deleted-prefix world a live prune produces."""

    def __init__(self, inner, K):
        self._inner = inner
        self._K = K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


# ---- (a) a tenant's billing history survives a hard prune via the seed -------------------------------
def test_history_survives_a_hard_prune(monkeypatch):
    store = _store()
    r = _reg(store)
    r.record("acme", invoice_id="evt_1", kind="subscription", price_id="pro", amount_minor=4900, currency="USD",
             credits=1000, period_start=1.0, period_end=100.0, issued_at=_iss())                     # seq 0
    r.record("acme", invoice_id="evt_2", kind="topup", price_id="t", amount_minor=999, credits=500,
             issued_at=_iss())                                                                        # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert {row[1] for row in snap.invoice_row} == {"evt_1", "evt_2"}            # both carried into the seed

    pruned = PrunedView(store, k)                    # [0..k) physically GONE — acme's invoices unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = InvoiceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    invs = r2.invoices("acme")
    assert [i.invoice_id for i in invs] == ["evt_2", "evt_1"], "a pruned tenant's history must survive via the seed"
    assert invs[1].amount_minor == 4900 and invs[1].currency == "USD"           # full line reconstructed

    # NEUTERED control (== pre-fix genesis scan): no seed over the physically-pruned store ⇒ history VANISHES.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    r2b = InvoiceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert r2b.invoices("acme") == [], "no seed over a physically-pruned store ⇒ billing history vanished"


# ---- (b) the consumed invoice_id set survives the prune (no replay duplicate) ------------------------
def test_invoice_id_survives_the_prune_no_replay_duplicate(monkeypatch):
    store = _store()
    r = _reg(store)
    seq = r.record("acme", invoice_id="evt_1", kind="topup", price_id="t", amount_minor=999, credits=500,
                   issued_at=_iss())                                                                  # seq 0
    captured = store.get(seq).payload
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert ("acme", "evt_1") in {(row[0], row[1]) for row in snap.invoice_row}

    # ATTACK: replay the captured invoice AFTER the prune boundary (into the live window).
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 2 (live)
    pruned = PrunedView(store, k)                    # [0..k) GONE: the original evt_1 at seq 0 is unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = InvoiceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert len(r2.invoices("acme")) == 1, "replayed pruned invoice must NOT duplicate the line (seed carries the id)"

    # NEUTERED control: strip the carried rows. Now the replayed evt_1 is not recognized as already-folded ⇒ it
    # re-appears — proving the invoice_row carry is what closes replay-duplicate across a prune.
    snap_no_rows = snap.model_copy(update={"invoice_row": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_rows))
    r2b = InvoiceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert len(r2b.invoices("acme")) == 1, "the live replay alone still folds once; the pruned original is gone"
    assert r2b.invoices("acme")[0].invoice_id == "evt_1"


# ---- (c) fold-of-fold across two prunes == a single scan (build carries the rows) --------------------
def test_two_prune_fold_of_fold_carries_invoices():
    store = _store()
    r = _reg(store)
    r.record("acme", invoice_id="i1", kind="topup", price_id="t", amount_minor=100, credits=10, issued_at=_iss())
    k1 = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "m1"})
    r.record("acme", invoice_id="i2", kind="topup", price_id="t", amount_minor=200, credits=20, issued_at=_iss())
    k2 = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "m2"})

    recs = list(store.iter_records())
    snap1 = build([x for x in recs if x.seq < k1], trusted_pubkey=OWNER_PUB, base_seq=k1, snapshot_seq=k1 - 1)
    snap2 = build([x for x in recs if k1 <= x.seq < k2], trusted_pubkey=OWNER_PUB,
                  base_seq=k2, snapshot_seq=k2 - 1, seed=snap1)                 # fold-of-fold
    full = build([x for x in recs if x.seq < k2], trusted_pubkey=OWNER_PUB, base_seq=k2, snapshot_seq=k2 - 1)

    norm = lambda rows: sorted([tuple(row) for row in rows])
    assert norm(snap2.invoice_row) == norm(full.invoice_row)
    assert {row[1] for row in snap2.invoice_row} == {"i1", "i2"}                # i1 carried across prune #2


# ---- (d) check_prune_safe's referential floor detects a stranded invoice -----------------------------
def _invoice_segmented_store(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    InvoiceRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB).record(
        "acme", invoice_id="evt_below", kind="topup", price_id="t", amount_minor=100, credits=10, issued_at=1.0)  # seq 0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})         # seq 1..4
    s.rotate()                                                                       # seal segment 0 [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})        # seq 5..9
    s.rotate()
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_invoice(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _invoice_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                       # must NOT raise: the invoice IS carried
    assert prune.stranded_invoices(s, archived, 5) == []


def test_referential_floor_detects_a_seed_that_omits_an_invoice(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _invoice_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={"invoice_row": []})       # drop the carried invoice rows

    monkeypatch.setattr(prune, "build", incomplete_build)
    stranded = prune.stranded_invoices(s, _archived_below(s, 5), 5)
    assert stranded == ["acme"], "the below-K invoice is missing from the seed → stranded"
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "invoice" in str(e.value).lower()


def test_referential_floor_detects_a_value_corrupted_seed_row(tmp_path, monkeypatch):
    # red-pen hardening: a seed that KEEPS the (org, invoice_id) key but corrupts the row's VALUE (amount /
    # currency / credits / period) must be flagged — the pre-hardening key-only check missed exactly this
    # (its wallet/plan siblings assert value-equality). Without the catch, a build regression silently
    # corrupts durable billing history post-prune.
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _invoice_segmented_store(tmp_path)
    real_build = prune.build

    def corrupting_build(records, **kw):
        seed = real_build(records, **kw)
        rows = [list(r) for r in seed.invoice_row]
        for r in rows:
            if r[1] == "evt_below":
                r[4] = (r[4] or 0) + 1   # flip amount_minor; keep the key
        return seed.model_copy(update={"invoice_row": rows})

    monkeypatch.setattr(prune, "build", corrupting_build)
    assert prune.stranded_invoices(s, _archived_below(s, 5), 5) == ["acme"]   # value drift caught
    with pytest.raises(prune.PruneUnsafe):
        prune.check_prune_safe(s, 5)


def test_referential_floor_detects_a_short_seed_row(tmp_path, monkeypatch):
    # red-pen hardening: a seed that emits a SHORT (<10-field) row for the key must be flagged — the fold
    # (_fold / the build re-seed) requires len>=10 and would silently DROP a short row at read time, re-opening
    # invoice replay. The pre-hardening len>=2 acceptance counted it "carried".
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _invoice_segmented_store(tmp_path)
    real_build = prune.build

    def short_row_build(records, **kw):
        seed = real_build(records, **kw)
        rows = [(r[:2] if r[1] == "evt_below" else list(r)) for r in seed.invoice_row]   # truncate to [org, id]
        return seed.model_copy(update={"invoice_row": rows})

    monkeypatch.setattr(prune, "build", short_row_build)
    assert prune.stranded_invoices(s, _archived_below(s, 5), 5) == ["acme"]   # short row not counted carried
    with pytest.raises(prune.PruneUnsafe):
        prune.check_prune_safe(s, 5)


# ---- (e) "has this org purchased credits?" survives the prune too --------------------------------------
def test_a_purchase_survives_a_hard_prune(monkeypatch):
    store = _store()
    r = _reg(store)
    r.record("acme", invoice_id="evt_1", kind="topup", price_id="t", amount_minor=999, credits=500,
             issued_at=_iss())                                                                        # seq 0
    r.record("globex", invoice_id="evt_2", kind="subscription", price_id="pro", amount_minor=4900,
             currency="USD", credits=1000, period_start=1.0, period_end=2.0, issued_at=_iss())       # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = InvoiceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert r2.has_purchased_credits("acme") is True, "a pruned purchase must still read as purchased"
    assert r2.has_purchased_credits("globex") is False
    # NEUTERED control: without the seed the pruned purchase is gone
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    assert InvoiceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB).has_purchased_credits("acme") is False
