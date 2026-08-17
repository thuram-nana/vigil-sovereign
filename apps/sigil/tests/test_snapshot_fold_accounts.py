"""Prune-survival proof for the SnapshotState-seeded `AccountsRegistry._fold` (hard-prune Slice S2).

The accounts fold used to be a GENESIS scan with NO snapshot seed, so a hard prune below the first
`governor.account` grant would SILENTLY vanish an active account (`resolve()`→None, dropped from
`accounts()`) AND reset the per-username anti-replay high-water (re-opening the LWW replay-resurrection
HIGH). This slice seeds the fold from `SnapshotState` (per-username LWW state + high-water + the cred fields
to rebuild an active `Account`), mirroring promotion/killswitch/capability. This file pins:

  (a) an active account whose only grant sits BELOW base_seq STILL resolves + appears in accounts() — seeded,
      not dropped (simulated by building a snapshot with base_seq ABOVE the grant, then windowing it out);
  (b) the per-username high-water SURVIVES the prune, so a replayed old owner-signed `active` grant for a
      revoked user does NOT resurrect it;
  (c) the empty-identity load path (no prune shipped) leaves `_fold` BYTE-IDENTICAL to the genesis scan —
      proven by the split == full == known-correct equivalence (fold([0..K)) + fold([K..T]) == scan([0..T]));
  (d) `check_prune_safe` refuses a prune that would strand an active account's only grant.

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


# ---- (a) an active account whose only grant is PRUNED survives via the seed -------------------------
def test_active_account_survives_a_hard_prune(monkeypatch):
    store = _store()
    reg = _reg(store)
    reg.create("alice", "operator", bearer_token="alice-bearer-xxxxxxxxxxxx", issued_at=5.0)   # seq 0
    # a marker marks the split boundary K — build a snapshot with base_seq ABOVE alice's grant (a prune past it)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)

    # the seed carries alice: active state + the high-water + the cred fields to rebuild the Account
    assert snap.account_state_map().get("alice") == "active"
    assert snap.account_issued_map().get("alice") == 5.0
    assert any(row[0] == "alice" for row in snap.account_cred)

    # with the grant PRUNED (load() returns the snapshot => the fold windows [K..T], skipping seq 0), alice
    # STILL resolves and lists — from the seed alone. Dropping the seed would make both fail (the guard below).
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = _reg(store)
    p = reg2.resolve("alice-bearer-xxxxxxxxxxxx")
    assert p is not None and p.role == "operator", "a pruned active account must survive via the seed (resolve)"
    assert "alice" in {a.username for a in reg2.accounts()}, "…and appear in accounts() too"


# ---- (b) the per-username high-water SURVIVES the prune (no replay resurrection) --------------------
def test_high_water_survives_the_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    reg = _reg(store)
    create_seq = reg.create("bob", "operator", bearer_token="bob-bearer-yyyyyyyyyyyy", issued_at=5.0)  # seq 0
    captured = store.get(create_seq).payload                 # the genuine owner-signed active grant
    reg.revoke("bob")                                        # seq 1 -> bob revoked
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the seed keeps bob REVOKED and PRESERVES the high-water (5.0) even though bob is not active — this is the
    # anti-replay floor that must cross the prune.
    assert snap.account_state_map().get("bob") == "revoked"
    assert snap.account_issued_map().get("bob") == 5.0

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    # ATTACK: replay the captured owner-signed active grant AFTER the prune boundary (into the live window).
    # Its issued_at (5.0) <= the SEEDED high-water (5.0) => ignored. Without the seed the floor would be -inf
    # and this replay would resurrect bob.
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    reg2 = _reg(store)
    assert reg2.resolve("bob-bearer-yyyyyyyyyyyy") is None, "replayed grant must NOT resurrect (resolve path)"
    assert "bob" not in {a.username for a in reg2.accounts()}, "…nor via accounts()"


# ---- (c) empty-identity load == genesis scan, proven by split == full == known-correct --------------
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
    store = _store()
    _populate(store)
    assert SnapshotState.load(store).base_seq == 0                # no prune -> the empty identity (genesis scan)
    got = {a.username: a.role for a in _reg(store).accounts()}
    assert got == _EXPECTED
    assert _reg(store).resolve(_TOK["seeded"]).role == "operator"
    assert _reg(store).resolve("regrant-old-44444444") is None   # the old (revoked) bearer stays dead


def test_split_fold_equals_full_scan(monkeypatch):
    store = _store()
    k = _populate(store)

    # full = the real (empty-load) genesis scan over the WHOLE store
    full = {a.username: a.role for a in _reg(store).accounts()}

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    # the prefix snapshot is NON-TRIVIAL: it carries the load-bearing state
    sm = snap.account_state_map()
    assert sm.get("seeded") == "active"      # the discriminator lives ONLY in the prefix
    assert sm.get("revlive") == "active"     # (overridden live)
    assert sm.get("regrant") == "revoked"    # (overridden live)
    assert snap.trusted_pubkey == OWNER_PUB  # so the consumer takes the fold (non-bypass) path

    # seed the synthetic prefix + fold ONLY the live window [K..T] from the SAME store
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    split = {a.username: a.role for a in _reg(store).accounts()}

    assert split == full, f"fold != scan\n full={full}\n split={split}"
    # both equal the independently-known-correct table (no green-wash: "seeded" active proves the seed was
    # actually consumed — dropping it would make "seeded" absent in split while full keeps it).
    assert full == _EXPECTED
    # resolve() honors the seed too: the seed-only account authenticates from the seed alone.
    assert _reg(store).resolve(_TOK["seeded"]).role == "operator"


# ---- (d) check_prune_safe refuses a prune that would strand an active account's only grant ----------
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


def test_check_prune_safe_allows_a_carried_active_account(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _account_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                       # must NOT raise: alice IS carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_accounts(s, archived, 5) == []   # nothing stranded
    # the seed genuinely carries alice as active (survival proof at the seed level)
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = build(below, trusted_pubkey=OWNER_PUB, base_seq=5, snapshot_seq=-1)
    assert seed.account_state_map().get("alice") == "active"


def test_check_prune_safe_refuses_a_stranded_active_account(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _account_segmented_store(tmp_path)
    # force the referential-floor detector to report a stranded active account (the fold-carry regression the
    # guard exists to catch) — mirrors test_referential_floor_blocks_open_workflow monkeypatching the floor.
    monkeypatch.setattr(prune, "stranded_active_accounts", lambda store, archived, K: ["alice"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "alice" in msg
