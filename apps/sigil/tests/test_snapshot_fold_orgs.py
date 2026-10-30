"""Prune-survival proof for the SnapshotState-seeded `OrgRegistry._fold_orgs` / `._fold_memberships`
(enterprise-identity HIGH).

The org + membership folds USED to be a GENESIS scan with NO snapshot seed (unlike `accounts._fold`), so a
hard prune below the first `governor.org` / `governor.org_membership` grant would SILENTLY vanish an active
org/membership (`org()`/`membership_role()`→None, dropped from `orgs()`/`memberships()`) AND reset the
per-org / per-(org_id, username) anti-replay high-water — re-opening the LWW replay-RESURRECTION HIGH (a
captured owner-signed `active` grant for a revoked org/member becomes replayable again). This slice seeds the
folds from `SnapshotState` exactly as `accounts._fold` does (snapshot.py grew `org_*` / `membership_*` rows),
and `spine.prune` refuses any prune that would strand an active org/membership the seed does not carry.

PHYSICAL-PRUNE HARNESS (identical to tests/test_snapshot_fold_accounts.py — the substance the red-pen
requires): the survival + high-water tests read through a `PrunedView` wrapper that PHYSICALLY HIDES every
record with `seq < K` from `iter_records` REGARDLESS of `since_seq` — i.e. `[0..K)` is gone as if deleted.
Windowing alone (relying on the fold's `since = base_seq - 1`) is NOT enough: the records still sit on disk,
so a pre-fix genesis scan (`since=-1`) would just re-read the "pruned" grant and pass. Under `PrunedView`,
only the SEED can carry the pruned state.

MUTATION-VERIFIED: reverting `_fold_orgs`/`_fold_memberships` to a genesis scan (`since=-1`, no snapshot
seed — the code this slice fixes) makes `test_active_org_survives_a_hard_prune`,
`test_active_membership_survives_a_hard_prune`, and the two high-water tests FAIL under this harness (the
entity no longer resolves; the replayed grant resurrects it). Each test also carries an inline NEUTERED
control (`SnapshotState.load` → the empty identity) that reproduces the pre-fix behaviour without a source
edit, so the seed is proven load-bearing from inside the test itself.

  (a) an active org/membership whose only grant sits BELOW base_seq STILL resolves + appears in the list —
      from the seed alone, over a store from which the grant is physically absent;
  (b) the per-org / per-(org_id, username) high-water SURVIVES the prune (the seq that SET it is physically
      pruned away), so a replayed old owner-signed `active` grant for a revoked entity does NOT resurrect it;
  (c) the empty-identity load path (no prune) leaves the folds BYTE-IDENTICAL to the genesis scan, proven by
      split == full == known-correct with the prefix PHYSICALLY absent from the split store;
  (d) `check_prune_safe`'s referential floor DETECTS a seed that would strand an active org OR an active
      membership (real positive control: a build that omits it) and refuses.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_orgs.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.orgs import MEMBERSHIP_SIGNAL, ORG_SIGNAL, OrgRegistry
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
    return OrgRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records` (as if `[0..K)`
    were deleted), REGARDLESS of the caller's `since_seq`. The pruned records still sit on disk in the inner
    store, so a fold that does NOT seed from the snapshot cannot see them — exactly the deleted-prefix world a
    live prune produces. The folds reach the store only via `iter_records` (and `SnapshotState.load`, which
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


# ---- (a) an active ORG whose only grant is PHYSICALLY PRUNED survives via the seed -------------------
def test_active_org_survives_a_hard_prune(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create_org("acme", "Acme Corp", owner="owner", issued_at=5.0)                              # seq 0
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed carries acme: active state + the per-org high-water + the row to rebuild the Org
    assert snap.org_state_map().get("acme") == "active"
    assert snap.org_issued_map().get("acme") == 5.0
    assert any(row[0] == "acme" for row in snap.org_row)

    pruned = PrunedView(store, k)                    # [0..k) physically GONE — acme's grant is not readable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    o = reg2.org("acme")
    assert o is not None and o.name == "Acme Corp" and o.state == "active", \
        "a pruned active org must survive via the seed (org())"
    assert "acme" in {x.org_id for x in reg2.orgs()}, "…and appear in orgs() too"

    # NEUTERED control (== the pre-fix genesis scan): with the seed removed, acme is GONE — proving the seed
    # is load-bearing, not that the record was merely still on disk.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.org("acme") is None, "no seed over a physically-pruned store ⇒ vanished"
    assert "acme" not in {x.org_id for x in reg2b.orgs()}


# ---- (a2) an active MEMBERSHIP whose only grant is PHYSICALLY PRUNED survives via the seed -----------
def test_active_membership_survives_a_hard_prune(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create_org("acme", "Acme", owner="owner", issued_at=5.0)                                   # seq 0
    reg.grant_membership("acme", "alice", "analyst", issued_at=6.0)                                 # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed carries BOTH the org (so the tenant is admissible) AND the membership + its per-pair high-water
    assert snap.org_state_map().get("acme") == "active"
    assert snap.membership_state_map().get(("acme", "alice")) == "active"
    assert snap.membership_issued_map().get(("acme", "alice")) == 6.0
    assert any(row[0] == "acme" and row[1] == "alice" for row in snap.membership_row)

    pruned = PrunedView(store, k)                    # [0..k) physically GONE — both grants unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.membership_role("alice", "acme") == "analyst", \
        "a pruned active membership must survive via the seed (membership_role)"
    assert "alice" in {m.username for m in reg2.memberships("acme")}, "…and appear in memberships() too"
    assert reg2.org_role_can("alice", "acme", "read") is True, "…and admit through org_role_can"

    # NEUTERED control (== pre-fix): with the seed removed, the membership is GONE.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.membership_role("alice", "acme") is None, "no seed over a physically-pruned store ⇒ vanished"
    assert "alice" not in {m.username for m in reg2b.memberships("acme")}


# ---- (b) the per-ORG high-water SURVIVES the prune (no replay resurrection) ---------------------------
def test_org_high_water_survives_the_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    reg = _reg(store)
    create_seq = reg.create_org("acme", "Acme", owner="owner", issued_at=5.0)   # seq 0
    captured = store.get(create_seq).payload                 # the genuine owner-signed active grant
    reg.revoke_org("acme")                                   # seq 1 -> acme revoked
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed keeps acme REVOKED and PRESERVES the per-org high-water (5.0) though acme is not active — the
    # anti-replay floor that MUST cross the prune. The seqs that SET the high-water (0 and 1) are pruned below.
    assert snap.org_state_map().get("acme") == "revoked"
    assert snap.org_issued_map().get("acme") == 5.0

    # ATTACK: replay the captured owner-signed active grant AFTER the prune boundary (into the live window).
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 3 (live)
    pruned = PrunedView(store, k)                    # [0..k) GONE: acme's create AND revoke are unreadable

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.org("acme") is None, "replayed grant must NOT resurrect the org (seed high-water)"
    assert "acme" not in {x.org_id for x in reg2.orgs()}, "…nor via orgs()"

    # NEUTERED control (== pre-fix): with the seed removed the high-water resets to -inf, so the replayed
    # grant (issued_at 5.0 > -inf) RESURRECTS acme — the exact LWW replay HIGH this slice closes.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.org("acme") is not None, "no seed ⇒ per-org high-water lost ⇒ replay resurrects"


# ---- (b2) the per-(org_id, username) high-water SURVIVES the prune (no replay resurrection) -----------
def test_membership_high_water_survives_the_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create_org("acme", "Acme", owner="owner", issued_at=5.0)                 # seq 0 (org stays active)
    grant_seq = reg.grant_membership("acme", "bob", "operator", issued_at=6.0)   # seq 1
    captured = store.get(grant_seq).payload                  # the genuine owner-signed active membership grant
    reg.revoke_membership("acme", "bob")                     # seq 2 -> bob's membership revoked
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 3

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed keeps the org active AND bob's membership REVOKED with its per-pair high-water (6.0) preserved.
    assert snap.org_state_map().get("acme") == "active"
    assert snap.membership_state_map().get(("acme", "bob")) == "revoked"
    assert snap.membership_issued_map().get(("acme", "bob")) == 6.0

    # ATTACK: replay the captured owner-signed active MEMBERSHIP grant after the prune boundary.
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 4 (live)
    pruned = PrunedView(store, k)                    # [0..k) GONE: org create + grant + revoke all unreadable

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    # assert on the membership fold DIRECTLY (membership_role also gates on the org being active, which the
    # seed carries either way — the point here is the membership high-water, isolated).
    assert ("acme", "bob") not in reg2._fold_memberships(), \
        "replayed grant must NOT resurrect the membership (seed per-pair high-water)"
    assert "bob" not in {m.username for m in reg2.memberships("acme")}
    assert reg2.membership_role("bob", "acme") is None       # …and the gated read agrees

    # NEUTERED control (== pre-fix): with the seed removed the per-pair high-water resets to -inf, so the
    # replayed grant (6.0 > -inf) RESURRECTS bob's membership. (The org also vanishes without the seed, so we
    # prove resurrection on the un-gated membership fold, which does NOT depend on org state.)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert ("acme", "bob") in reg2b._fold_memberships(), \
        "no seed ⇒ per-pair high-water lost ⇒ replay resurrects the membership"


# ---- (c) empty-identity load == genesis scan, proven by split == full == known-correct ---------------
def _populate(store):
    """Crafted history: prefix [0..K) carries org + membership grants that MATTER downstream; live [K..T)
    overrides/extends them + a forged grant that must be ignored. Returns the split seq K."""
    reg = _reg(store)
    # ---- prefix [0..K) ----
    reg.create_org("seeded", "Seeded", owner="owner", issued_at=_iss())    # never touched -> seed-only org
    reg.grant_membership("seeded", "sm", "analyst", issued_at=_iss())      # seed-only membership (org active)
    reg.create_org("revlive", "RevLive", owner="owner", issued_at=_iss())  # revoked live
    reg.create_org("regrant", "Old", owner="owner", issued_at=_iss())      # re-granted live
    reg.revoke_org("regrant")                                             # revoked in the prefix
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    # ---- live [K..T) ----
    reg.revoke_org("revlive")                                             # LWW: overrides the prefix grant
    reg.create_org("regrant", "New", owner="owner", issued_at=_iss())      # LWW: overrides the revoke
    reg.create_org("live", "Live", owner="owner", issued_at=_iss())        # live-only org
    reg.grant_membership("live", "lm", "viewer", issued_at=_iss())         # live-only membership
    # a forged (attacker-signed) active org grant -> fail-closed, changes nothing
    core = {"signal": ORG_SIGNAL, "org_id": "evil", "name": "Evil", "owner": "owner",
            "state": "active", "issued_at": 9_999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    # a forged (attacker-signed) active membership grant -> fail-closed too
    mcore = {"signal": MEMBERSHIP_SIGNAL, "org_id": "seeded", "username": "evilm", "role": "operator",
             "state": "active", "issued_at": 9_999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(mcore, ATTACKER)})
    return k


_EXPECTED_ORGS = {"seeded": "Seeded", "regrant": "New", "live": "Live"}       # currently-active orgs by name
_EXPECTED_MEMS = {("seeded", "sm"): "analyst", ("live", "lm"): "viewer"}      # currently-active memberships


def _org_name_map(reg):
    return {o.org_id: o.name for o in reg.orgs()}


def _mem_role_map(reg):
    return {(m.org_id, m.username): m.role for m in reg.memberships()}


def test_org_identity_empty_load_matches_known_correct():
    """Byte-identity of the empty-load path: with NO prune, load() is the empty identity and the folds are a
    full genesis scan == the pre-fix semantics (passes under fix AND pre-fix, which is exactly the
    byte-identity contract). Mutation-sensitivity for the SURVIVAL property lives in the physical-prune tests
    above."""
    store = _store()
    _populate(store)
    assert SnapshotState.load(store).base_seq == 0                # no prune -> the empty identity (genesis scan)
    reg = _reg(store)
    assert _org_name_map(reg) == _EXPECTED_ORGS
    assert _mem_role_map(reg) == _EXPECTED_MEMS
    assert reg.org("evil") is None                                # the forged org grant stays inert
    assert reg.membership_role("evilm", "seeded") is None         # …and the forged membership grant


def test_split_fold_equals_full_scan_with_prefix_physically_absent(monkeypatch):
    """fold([0..K)) + fold([K..T]) == scan([0..T]), with [0..K) PHYSICALLY absent from the split store. The
    'seeded' org + its 'sm' membership (granted only in the prefix) are reachable in `split` ONLY via the
    seed, so this is mutation-sensitive: pre-fix (no seed) drops them from split and the equality FAILS."""
    store = _store()
    k = _populate(store)

    # full = the real (empty-load) genesis scan over the WHOLE store — the ground truth
    full_orgs = _org_name_map(_reg(store))
    full_mems = _mem_role_map(_reg(store))
    assert full_orgs == _EXPECTED_ORGS and full_mems == _EXPECTED_MEMS

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    osm = snap.org_state_map()
    assert osm.get("seeded") == "active" and osm.get("revlive") == "active" and osm.get("regrant") == "revoked"
    assert snap.membership_state_map().get(("seeded", "sm")) == "active"
    assert snap.trusted_pubkey == OWNER_PUB                        # so the consumer takes the fold (non-bypass) path

    pruned = PrunedView(store, k)                                  # [0..k) physically gone
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg_split = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    split_orgs = _org_name_map(reg_split)
    split_mems = _mem_role_map(reg_split)
    assert split_orgs == full_orgs, f"org fold != scan over a physically-pruned store\n full={full_orgs}\n split={split_orgs}"
    assert split_mems == full_mems, f"membership fold != scan over a physically-pruned store\n full={full_mems}\n split={split_mems}"

    # NEUTERED control (== pre-fix): no seed over the pruned store ⇒ the seed-only org + membership vanish.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg_neutered = OrgRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    split_neutered_orgs = _org_name_map(reg_neutered)
    split_neutered_mems = _mem_role_map(reg_neutered)
    assert split_neutered_orgs != full_orgs and "seeded" not in split_neutered_orgs
    assert split_neutered_mems != full_mems and ("seeded", "sm") not in split_neutered_mems


# ---- (d) check_prune_safe referential floor ----------------------------------------------------------
def _org_segmented_store(tmp_path):
    """A migrated store with TWO sealed segments (so K=5 is a valid boundary) — an owner-signed active org
    grant sits at seq 0 and an owner-signed active membership at seq 1, inside the segment a prune at K=5
    would archive+delete."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    reg = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    reg.create_org("acme", "Acme", owner="owner", issued_at=1.0)                     # seq 0
    reg.grant_membership("acme", "alice", "operator", issued_at=2.0)                 # seq 1
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


def test_check_prune_safe_allows_a_carried_active_org_and_membership(tmp_path, monkeypatch):
    """Happy path: the detector is EMPTY when the seed carries every verified-active org + membership below K,
    so check_prune_safe returns the archive set without raising."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _org_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                       # must NOT raise: acme + alice ARE carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_org_entities(s, archived, 5) == ([], [])   # detector empty on a complete seed
    # the seed genuinely carries acme active + alice@acme active (survival proof at the seed level)
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = build(below, trusted_pubkey=OWNER_PUB, base_seq=5, snapshot_seq=-1)
    assert seed.org_state_map().get("acme") == "active"
    assert seed.membership_state_map().get(("acme", "alice")) == "active"


def test_referential_floor_detects_a_seed_that_omits_an_active_org(tmp_path, monkeypatch):
    """REAL positive control (not just the re-raise wiring): if build()/the seed ever DROPPED an active org
    whose only grant is below K — a seed/build regression — the referential floor must DETECT it (non-empty)
    and refuse, not silently prune the org away. We simulate the regression by making build() emit a seed with
    'acme' stripped; the detector still folds the REAL below-K records (acme active) so it genuinely finds it
    missing from the seed."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _org_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "org_state": [r for r in seed.org_state if r[0] != "acme"],
            "org_issued": [r for r in seed.org_issued if r[0] != "acme"],
            "org_row": [r for r in seed.org_row if r[0] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    stranded_orgs, _ = prune.stranded_active_org_entities(s, _archived_below(s, 5), 5)
    assert stranded_orgs == ["acme"]                             # real diff: active={acme} minus carried={}
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "acme" in msg and "org" in msg


def test_referential_floor_detects_a_seed_that_omits_an_active_membership(tmp_path, monkeypatch):
    """The SAME positive control for an active MEMBERSHIP whose only grant is below K: a seed that drops it
    must be DETECTED and refused (membership strings are reported as `username@org_id`)."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _org_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "membership_state": [r for r in seed.membership_state if (r[0], r[1]) != ("acme", "alice")],
            "membership_issued": [r for r in seed.membership_issued if (r[0], r[1]) != ("acme", "alice")],
            "membership_row": [r for r in seed.membership_row if (r[0], r[1]) != ("acme", "alice")],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    _, stranded_mems = prune.stranded_active_org_entities(s, _archived_below(s, 5), 5)
    assert stranded_mems == ["alice@acme"]                       # real diff: active={alice@acme} minus carried={}
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "alice@acme" in msg and "membership" in msg


def test_check_prune_safe_reraises_a_nonempty_org_floor_wiring_only(tmp_path, monkeypatch):
    """Pure WIRING check: check_prune_safe re-raises PruneUnsafe when the org-entity detector reports a
    non-empty stranded list — for an org AND (separately) for a membership. The detector's real substance is
    covered by the two positive-control tests above."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _org_segmented_store(tmp_path)

    monkeypatch.setattr(prune, "stranded_active_org_entities", lambda store, archived, K: (["ghost-org"], []))
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost-org" in str(e.value)

    monkeypatch.setattr(prune, "stranded_active_org_entities", lambda store, archived, K: ([], ["ghost@org"]))
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost@org" in str(e.value)
