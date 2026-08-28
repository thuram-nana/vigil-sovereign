"""Prune-survival proof for the SnapshotState-seeded `AccountsRegistry._fold` (hard-prune Slice S2).

The accounts fold used to be a GENESIS scan with NO snapshot seed, so a hard prune below the first
`governor.account` grant would SILENTLY vanish an active account (`resolve()`→None, dropped from
`accounts()`) AND reset the per-username anti-replay high-water (re-opening the LWW replay-resurrection
HIGH). This slice seeds the fold from `SnapshotState`, mirroring promotion/killswitch/capability.

PHYSICAL-PRUNE HARNESS (this is the substance the red-pen required): the survival + high-water tests read
through a `PrunedView` wrapper that PHYSICALLY HIDES every record with `seq < K` from `iter_records`
REGARDLESS of `since_seq` — i.e. `[0..K)` is gone as if deleted. Windowing alone (relying on `_fold`'s
`since = base_seq - 1`) is NOT enough: the records still sit on disk, so a pre-S2 genesis scan (`since=-1`)
would just re-read the "pruned" grant and pass. Under `PrunedView`, only the SEED can carry the pruned state.

MUTATION-VERIFIED: reverting `AccountsRegistry._fold` to its exact pre-S2 body (`since=-1`, no snapshot
seed — the code this slice fixes) makes `test_active_account_survives_a_hard_prune` AND
`test_high_water_survives_the_prune_no_replay_resurrection` FAIL under this harness (alice no longer
resolves; the replayed grant resurrects bob). Each test also carries an inline NEUTERED control
(`SnapshotState.load` → the empty identity) that reproduces the pre-S2 behaviour without a source edit, so
the seed is proven load-bearing from inside the test itself.

  (a) an active account whose only grant sits BELOW base_seq STILL resolves + appears in accounts() — from
      the seed alone, over a store from which the grant is physically absent;
  (b) the per-username high-water SURVIVES the prune (the seq that SET it is physically pruned away), so a
      replayed old owner-signed `active` grant for a revoked user does NOT resurrect it;
  (c) the empty-identity load path (no prune) leaves `_fold` BYTE-IDENTICAL to the genesis scan, proven by
      split == full == known-correct with the prefix PHYSICALLY absent from the split store;
  (d) `check_prune_safe`'s referential floor DETECTS a seed that would strand an active account (real
      positive control: a build that omits the account) and refuses.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest tests/test_snapshot_fold_accounts.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor import accounts as acc
from sigil.governor.accounts import AccountsRegistry
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()

# Strictly-increasing DETERMINISTIC issued_at for each owner-signed grant (the anti-replay high-water).
# NEVER time.time(): two grants inside one tick would collide and the second would refuse itself as a replay.
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return AccountsRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records` (as if `[0..K)`
    were deleted), REGARDLESS of the caller's `since_seq`. The pruned records still sit on disk in the inner
    store, so a fold that does NOT seed from the snapshot cannot see them — exactly the deleted-prefix world a
    live prune produces. `_fold` reaches the store only via `iter_records` (and `SnapshotState.load`, which
    the tests monkeypatch)."""

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


# ---- (a) an active account whose only grant is PHYSICALLY PRUNED survives via the seed ----------------
def test_active_account_survives_a_hard_prune(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create("alice", "operator", bearer_token="alice-bearer-xxxxxxxxxxxx", issued_at=5.0)   # seq 0
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed carries alice: active state + the high-water + the cred fields to rebuild the Account
    assert snap.account_state_map().get("alice") == "active"
    assert snap.account_issued_map().get("alice") == 5.0
    assert any(row[0] == "alice" for row in snap.account_cred)

    pruned = PrunedView(store, k)                    # [0..k) physically GONE — alice's grant is not readable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    p = reg2.resolve("alice-bearer-xxxxxxxxxxxx")
    assert p is not None and p.role == "operator", "a pruned active account must survive via the seed (resolve)"
    assert "alice" in {a.username for a in reg2.accounts()}, "…and appear in accounts() too"

    # NEUTERED control (== the pre-S2 genesis scan): with the seed removed, alice is GONE — proving the seed
    # is load-bearing, not that the record was merely still on disk.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.resolve("alice-bearer-xxxxxxxxxxxx") is None, "no seed over a physically-pruned store ⇒ vanished"
    assert "alice" not in {a.username for a in reg2b.accounts()}


# ---- (a2) a KEYED account (bound user_pubkey) survives a prune WITH its key (S2xS3 seed integration) --
def test_a_keyed_account_survives_a_prune_with_its_user_pubkey(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create("carol", "operator", bearer_token="carol-bearer-zzzzzzzzzzzz", issued_at=5.0)   # seq 0
    upk = generate_keypair().public_key_b64
    reg.enroll_pubkey("carol", upk, issued_at=6.0)                                              # seq 1 (keyed grant)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed's account_cred row carries carol's user_pubkey as the 5th field — a KEYED grant (8-field core)
    # is verified with the conditional core in build(), not dropped, and its key is preserved.
    row = next(r for r in snap.account_cred if r[0] == "carol")
    assert len(row) >= 5 and row[4] == upk, "the snapshot seed must carry the bound user_pubkey"

    pruned = PrunedView(store, k)                    # both grants physically GONE
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    carol = next(a for a in reg2.accounts() if a.username == "carol")
    assert carol.user_pubkey == upk, "a KEYED account pruned below base_seq must keep its user_pubkey via the seed"

    # NEUTERED control: without the seed, carol vanishes entirely (proving the seed carries the key).
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert "carol" not in {a.username for a in reg2b.accounts()}


# ---- (a3) an EXPIRING account survives a prune WITH its absolute deadline (Slice 1a TTL seed carry) ---
def test_an_expiring_account_survives_a_prune_with_its_deadline(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create("erin", "operator", bearer_token="erin-bearer-wwwwwwwwwwww",
               issued_at=5.0, ttl_seconds=3600)                                                 # seq 0 → exp 3605
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed's account_cred row carries erin's absolute deadline as the 8th field (index 7)
    row = next(r for r in snap.account_cred if r[0] == "erin")
    assert len(row) >= 8 and row[7] == 3605.0, "the snapshot seed must carry the absolute deadline"

    pruned = PrunedView(store, k)                    # erin's grant physically GONE
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    erin = next(a for a in reg2.accounts() if a.username == "erin")
    assert erin.expires_at == 3605.0, "a pruned expiring account must keep its deadline via the seed"
    assert reg2.resolve("erin-bearer-wwwwwwwwwwww", now=3600.0) is not None    # still enforces: valid before…
    assert reg2.resolve("erin-bearer-wwwwwwwwwwww", now=3605.0) is None        # …denied after, from the seed

    # NEUTERED control: strip ONLY the 8th seed field. Erin still SURVIVES the prune (via her other seed
    # fields) but SILENTLY becomes never-expiring — the exact downgrade the carry prevents. This proves the
    # expires_at carry (not just the account carry) is load-bearing.
    snap_no_exp = snap.model_copy(update={"account_cred": [list(r[:7]) for r in snap.account_cred]})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_exp))
    reg2b = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    erin_b = next(a for a in reg2b.accounts() if a.username == "erin")
    assert erin_b.expires_at is None, "dropping the 8th seed field silently makes a pruned account never-expire"
    assert reg2b.resolve("erin-bearer-wwwwwwwwwwww", now=1e18) is not None      # the silent downgrade, made visible


# ---- (b) the per-username high-water SURVIVES the prune (no replay resurrection) ----------------------
def test_high_water_survives_the_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    reg = _reg(store)
    create_seq = reg.create("bob", "operator", bearer_token="bob-bearer-yyyyyyyyyyyy", issued_at=5.0)  # seq 0
    captured = store.get(create_seq).payload                 # the genuine owner-signed active grant
    reg.revoke("bob")                                        # seq 1 -> bob revoked
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed keeps bob REVOKED and PRESERVES the high-water (5.0) though bob is not active — the anti-replay
    # floor that MUST cross the prune. The seqs that SET the high-water (0 and 1) are pruned away below.
    assert snap.account_state_map().get("bob") == "revoked"
    assert snap.account_issued_map().get("bob") == 5.0

    # ATTACK: replay the captured owner-signed active grant AFTER the prune boundary (into the live window).
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 3 (live)
    pruned = PrunedView(store, k)                    # [0..k) GONE: bob's create AND revoke are unreadable

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.resolve("bob-bearer-yyyyyyyyyyyy") is None, "replayed grant must NOT resurrect (seed high-water)"
    assert "bob" not in {a.username for a in reg2.accounts()}, "…nor via accounts()"

    # NEUTERED control (== pre-S2): with the seed removed the high-water resets to -inf, so the replayed grant
    # (issued_at 5.0 > -inf) RESURRECTS bob — the exact LWW replay HIGH this slice closes.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.resolve("bob-bearer-yyyyyyyyyyyy") is not None, "no seed ⇒ high-water lost ⇒ replay resurrects"


# ---- (c) empty-identity load == genesis scan, proven by split == full == known-correct ---------------
_TOK = {"seeded": "seeded-tok-000000000000", "regrant": "regrant-new-11111111", "live": "live-tok-222222222"}


def _populate(store):
    """Crafted history: prefix [0..K) carries grants that MATTER downstream; live [K..T) overrides/extends
    them + a forged grant that must be ignored. Returns the split seq K."""
    reg = _reg(store)
    # ---- prefix [0..K) ----
    reg.create("seeded", "operator", bearer_token=_TOK["seeded"], issued_at=_iss())   # never touched -> seed-only
    reg.create("revlive", "operator", bearer_token="revlive-tok-33333333", issued_at=_iss())  # revoked live
    reg.create("regrant", "operator", bearer_token="regrant-old-44444444", issued_at=_iss())  # re-granted live
    reg.revoke("regrant")                                                             # revoked in the prefix
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    # ---- live [K..T) ----
    reg.revoke("revlive")                                                             # LWW: overrides prefix grant
    reg.create("regrant", "viewer", bearer_token=_TOK["regrant"], issued_at=_iss())   # LWW: overrides the revoke
    reg.create("live", "analyst", bearer_token=_TOK["live"], issued_at=_iss())        # live-only grant
    # a forged (attacker-signed) active grant -> fail-closed, changes nothing
    core = {"signal": acc.SIGNAL, "username": "evil", "role": "operator", "cred_hash": "h", "cred_salt": "s",
            "state": "active", "issued_at": 9_999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    return k


_EXPECTED = {"seeded": "operator", "regrant": "viewer", "live": "analyst"}   # the currently-active accounts


def test_identity_empty_load_matches_known_correct():
    """Byte-identity of the empty-load path: with NO prune, load() is the empty identity and _fold is a full
    genesis scan == the pre-S2 semantics (passes under fix AND pre-S2, which is exactly the byte-identity
    contract). Mutation-sensitivity for the SURVIVAL property lives in the physical-prune tests above."""
    store = _store()
    _populate(store)
    assert SnapshotState.load(store).base_seq == 0                # no prune -> the empty identity (genesis scan)
    got = {a.username: a.role for a in _reg(store).accounts()}
    assert got == _EXPECTED
    assert _reg(store).resolve(_TOK["seeded"]).role == "operator"
    assert _reg(store).resolve("regrant-old-44444444") is None   # the old (revoked) bearer stays dead


def test_split_fold_equals_full_scan_with_prefix_physically_absent(monkeypatch):
    """fold([0..K)) + fold([K..T]) == scan([0..T]), with [0..K) PHYSICALLY absent from the split store. The
    'seeded' account (granted only in the prefix) is reachable in `split` ONLY via the seed, so this is
    mutation-sensitive: pre-S2 (no seed) drops 'seeded' from split and the equality FAILS."""
    store = _store()
    k = _populate(store)

    # full = the real (empty-load) genesis scan over the WHOLE store — the ground truth
    full = {a.username: a.role for a in _reg(store).accounts()}
    assert full == _EXPECTED

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    sm = snap.account_state_map()
    assert sm.get("seeded") == "active" and sm.get("revlive") == "active" and sm.get("regrant") == "revoked"
    assert snap.trusted_pubkey == OWNER_PUB                       # so the consumer takes the fold (non-bypass) path

    pruned = PrunedView(store, k)                                 # [0..k) physically gone
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    split = {a.username: a.role
             for a in AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB).accounts()}
    assert split == full, f"fold != scan over a physically-pruned store\n full={full}\n split={split}"
    # resolve() honors the seed too: the seed-only 'seeded' account authenticates from the seed alone.
    reg_pruned = AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg_pruned.resolve(_TOK["seeded"]).role == "operator"

    # NEUTERED control (== pre-S2): no seed over the pruned store ⇒ 'seeded' vanishes ⇒ split != full.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    split_neutered = {a.username: a.role
                      for a in AccountsRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB).accounts()}
    assert split_neutered != full and "seeded" not in split_neutered


# ---- (d) check_prune_safe referential floor ----------------------------------------------------------
def _account_segmented_store(tmp_path):
    """A migrated store with TWO sealed segments (so K=5 is a valid boundary) — an owner-signed active
    account grant sits at seq 0, inside the segment that a prune at K=5 would archive+delete."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    AccountsRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB).create(
        "alice", "operator", bearer_token="alice-bearer-zzzzzzzzzzzz", issued_at=1.0)   # seq 0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})            # seq 1..4
    s.rotate()                                                                          # seal segment 0 [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})           # seq 5..9
    s.rotate()                                                                          # seal segment 1 [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})           # a live tail
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_active_account(tmp_path, monkeypatch):
    """Happy path: the detector is EMPTY when the seed carries every verified-active account below K, so
    check_prune_safe returns the archive set without raising."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _account_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                       # must NOT raise: alice IS carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_accounts(s, archived, 5) == []   # detector empty on a complete seed
    # the seed genuinely carries alice as active (survival proof at the seed level)
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = build(below, trusted_pubkey=OWNER_PUB, base_seq=5, snapshot_seq=-1)
    assert seed.account_state_map().get("alice") == "active"


def test_referential_floor_detects_a_seed_that_omits_an_active_account(tmp_path, monkeypatch):
    """A1 REAL positive control (not just the re-raise wiring): if build()/the seed ever DROPPED an active
    account whose only grant is below K — a seed/build regression — the referential floor must DETECT it
    (non-empty) and refuse, not silently prune the account away. We simulate the regression by making
    build() emit a seed with 'alice' stripped; the detector still folds the REAL below-K records (alice
    active) so it genuinely finds her missing from the seed."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _account_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "account_state": [r for r in seed.account_state if r[0] != "alice"],
            "account_issued": [r for r in seed.account_issued if r[0] != "alice"],
            "account_cred": [r for r in seed.account_cred if r[0] != "alice"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    # the detector genuinely returns the stranded account (real diff: active={alice} minus carried={})
    assert prune.stranded_active_accounts(s, _archived_below(s, 5), 5) == ["alice"]
    # …and check_prune_safe refuses the prune, fail-closed.
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "alice" in msg


def test_check_prune_safe_reraises_a_nonempty_floor_wiring_only(tmp_path, monkeypatch):
    """Pure WIRING check: check_prune_safe re-raises PruneUnsafe when the detector reports a non-empty
    stranded list (mirrors test_referential_floor_blocks_open_workflow). The detector's real substance is
    covered by test_referential_floor_detects_a_seed_that_omits_an_active_account above."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _account_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_accounts", lambda store, archived, K: ["ghost"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost" in str(e.value)
