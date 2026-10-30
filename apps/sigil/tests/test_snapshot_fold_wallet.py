"""Prune-survival proof for the SnapshotState-seeded `WalletRegistry._fold` (SaaS credit wallet).

A wallet balance is a LIFETIME running total (unlike `governor/budget.py`, a per-UTC-day window that needs no
seed because the prune retention invariant keeps today live). So the wallet MUST seed from `SnapshotState` or
the first hard prune below a tenant's grants would (1) ZERO their balance and (2) drop the consumed-`entry_id`
set — re-opening grant REPLAY (a pruned grant re-appended above the boundary would re-credit).

PHYSICAL-PRUNE HARNESS (identical to tests/test_snapshot_fold_accounts.py): the survival + replay tests read
through a `PrunedView` that PHYSICALLY HIDES every record with `seq < K` from `iter_records` REGARDLESS of
`since_seq`, so only the SEED can carry the pruned state.

MUTATION-VERIFIED: reverting the wallet fold to a genesis scan (no seed) fails the survival + split tests;
dropping ONLY the carried `wallet_seen` set re-opens replay-recredit (the dedicated neutered control below).

  (a) a tenant whose grants/debits sit BELOW base_seq keeps its exact balance — from the seed alone, over a
      store from which the records are physically absent;
  (b) the consumed `entry_id` set SURVIVES the prune, so a replayed pruned grant does NOT re-credit (the
      neutered control strips ONLY `wallet_seen` to prove that carry is load-bearing, not the balance carry);
  (c) empty-load == genesis scan byte-identity, proven by split == full with the prefix physically absent;
  (d) `check_prune_safe`'s referential floor DETECTS a seed that would strand a tenant wallet and refuses.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_wallet.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.wallet import CREDIT_GRANT_SIGNAL, WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return WalletRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records`, regardless of
    `since_seq`. The pruned records still sit on disk in the inner store, so a fold that does NOT seed from the
    snapshot cannot see them — exactly the deleted-prefix world a live prune produces."""

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


# ---- (a) a tenant's balance survives a hard prune via the seed ---------------------------------------
def test_balance_survives_a_hard_prune(monkeypatch):
    store = _store()
    w = _reg(store)
    w.grant("acme", 100, "trial", issued_at=_iss(), entry_id="g1")                                 # seq 0
    w.debit("acme", 30, engagement_id="eng1", issued_at=_iss(), entry_id="d1")                      # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.wallet_granted_map().get("acme") == 100
    assert snap.wallet_debited_map().get("acme") == 30

    pruned = PrunedView(store, k)                    # [0..k) physically GONE — acme's grant+debit unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    w2 = WalletRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert w2.available("acme") == 70, "a pruned tenant's balance must survive via the seed"

    # NEUTERED control (== pre-fix genesis scan): no seed over the physically-pruned store ⇒ balance ZEROED.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    w2b = WalletRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert w2b.available("acme") == 0, "no seed over a physically-pruned store ⇒ balance vanished"


# ---- (b) the consumed entry_id set survives the prune (no replay re-credit) ---------------------------
def test_seen_set_survives_the_prune_no_replay_recredit(monkeypatch):
    store = _store()
    w = _reg(store)
    grant_seq = w.grant("acme", 100, "topup", issued_at=_iss(), entry_id="g1")    # seq 0
    captured = store.get(grant_seq).payload                  # the genuine owner-signed grant
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.wallet_granted_map().get("acme") == 100
    assert ("acme", "g1") in snap.wallet_seen_set()          # the idempotency key is carried

    # ATTACK: replay the captured grant AFTER the prune boundary (into the live window).
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 2 (live)
    pruned = PrunedView(store, k)                    # [0..k) GONE: the original g1 at seq 0 is unreadable

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    w2 = WalletRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert w2.available("acme") == 100, "replayed pruned grant must NOT re-credit (seed seen-set)"

    # NEUTERED control: carry the BALANCE but strip ONLY the seen-set. Now the replayed g1 is not recognized
    # as already-counted ⇒ it re-credits to 200 — proving the seen-set carry (not the balance carry) is what
    # closes replay-recredit across a prune.
    snap_no_seen = snap.model_copy(update={"wallet_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    w2b = WalletRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert w2b.available("acme") == 200, "dropping the seen-set ⇒ the replayed pruned grant re-credits"


# ---- (c) empty-load == genesis scan, proven by split == full == known-correct ------------------------
def _populate(store):
    """Prefix [0..K) carries a seed-only tenant + a tenant that is extended live; live [K..T) adds more + a
    live-only tenant + a forged grant that must be ignored. Returns the split seq K."""
    w = _reg(store)
    # ---- prefix [0..K) ----
    w.grant("seeded", 100, "trial", issued_at=_iss(), entry_id="gs")       # seed-only tenant
    w.grant("mixed", 50, "topup", issued_at=_iss(), entry_id="gm1")        # extended live
    w.debit("mixed", 20, engagement_id="e", issued_at=_iss(), entry_id="dm1")
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    # ---- live [K..T) ----
    w.grant("mixed", 30, "topup", issued_at=_iss(), entry_id="gm2")
    w.grant("live", 200, "trial", issued_at=_iss(), entry_id="gl")         # live-only tenant
    w.debit("live", 10, engagement_id="e", issued_at=_iss(), entry_id="dl")
    core = {"signal": CREDIT_GRANT_SIGNAL, "org_id": "seeded", "entry_id": "evil", "credits": 9999,
            "kind": "topup", "source_ref": "", "issued_at": 9_999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    return k


_EXPECTED = {"seeded": 100, "mixed": 60, "live": 190}      # available per tenant


def _avail_map(reg):
    return {b.org_id: b.available for b in reg.balances()}


def test_wallet_empty_load_matches_known_correct():
    store = _store()
    _populate(store)
    assert SnapshotState.load(store).base_seq == 0            # no prune -> empty identity (genesis scan)
    assert _avail_map(_reg(store)) == _EXPECTED
    assert _reg(store).available("seeded") == 100             # forged +9999 grant stayed inert


def test_split_fold_equals_full_scan_with_prefix_physically_absent(monkeypatch):
    store = _store()
    k = _populate(store)
    full = _avail_map(_reg(store))
    assert full == _EXPECTED

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.wallet_granted_map().get("seeded") == 100
    assert snap.trusted_pubkey == OWNER_PUB                   # consumer takes the fold (non-bypass) path

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    split = _avail_map(WalletRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB))
    assert split == full, f"wallet fold != scan over a physically-pruned store\n full={full}\n split={split}"

    # NEUTERED (== pre-fix): no seed over the pruned store ⇒ the seed-only 'seeded' tenant vanishes.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    split_neutered = _avail_map(WalletRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB))
    assert split_neutered != full and "seeded" not in split_neutered


# ---- (d) check_prune_safe referential floor ----------------------------------------------------------
def _wallet_segmented_store(tmp_path):
    """A migrated store with TWO sealed segments (so K=5 is a valid boundary) — a tenant's grant + debit sit
    at seq 0..1, inside the segment a prune at K=5 would archive+delete."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    w.grant("acme", 100, "trial", issued_at=1.0, entry_id="g1")                      # seq 0
    w.debit("acme", 25, engagement_id="e", issued_at=2.0, entry_id="d1")             # seq 1
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})         # seq 2..4
    s.rotate()                                                                       # seal segment 0 [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})        # seq 5..9
    s.rotate()                                                                       # seal segment 1 [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})        # a live tail
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_wallet(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _wallet_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                       # must NOT raise: acme's wallet IS carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_wallets(s, archived, 5) == []    # detector empty on a complete seed
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = build(below, trusted_pubkey=OWNER_PUB, base_seq=5, snapshot_seq=-1)
    assert seed.wallet_granted_map().get("acme") == 100 and seed.wallet_debited_map().get("acme") == 25


def test_referential_floor_detects_a_seed_that_omits_a_wallet(tmp_path, monkeypatch):
    """REAL positive control: if build()/the seed ever DROPPED a tenant's below-K wallet state, the floor must
    DETECT it (non-empty) and refuse, not silently zero the balance / re-open replay. Simulated by making
    build() emit a seed with 'acme' stripped; the detector still folds the REAL below-K records (acme present)
    so it genuinely finds it missing from the seed."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _wallet_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "wallet_granted": [r for r in seed.wallet_granted if r[0] != "acme"],
            "wallet_debited": [r for r in seed.wallet_debited if r[0] != "acme"],
            "wallet_seen": [r for r in seed.wallet_seen if r[0] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_active_wallets(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "acme" in msg and "wallet" in msg


def test_check_prune_safe_reraises_a_nonempty_wallet_floor_wiring_only(tmp_path, monkeypatch):
    """Pure WIRING check: check_prune_safe re-raises PruneUnsafe when the wallet detector reports a non-empty
    stranded list. The detector's real substance is covered by the positive control above."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _wallet_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_wallets", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost-tenant" in str(e.value)
