"""Front C S0b — `OrgRegistry` (orgs + memberships, the two folds behind every `admit_customer`) on the
verified incremental fold cache, through the shared `governor/fold_read.cached_read` path.

The cache may change only HOW the folds are read. Every test compares the cached answers with the registry's
own unchanged full folds (`_fold_orgs` / `_fold_memberships`) over the same spine, and fails if a cached read
silently fell back to them. The generic trust-model cases (chain anchor, key rotation, genesis repin, build
race, faults, concurrency) are proven once on the shared substrate in `test_fold_cache_customers.py`; here:

  * seeded randomized equivalence over every org/membership op, incl. the revoke-org cascade, re-creation of a
    revoked org (no member resurrected), replays, forged / unsigned grants and a second store instance;
  * O(new records): a warm `admit_customer` verifies ZERO signatures; k appends cost exactly k;
  * ONE cache entry serves both folds;
  * a seeded hard prune keeps the pruned org, member and their high-waters;
  * a rollback under the live process rebuilds;
  * flag OFF: the cache is never consulted.
"""
from __future__ import annotations

import itertools
import random
import shutil

import pytest

from sigil.governor import orgs as og
from sigil.governor.authn import signed_payload
from sigil.governor.orgs import OrgRegistry
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotError, SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()
_issue = itertools.count(1)
ORG_IDS = ["acme", "globex", "initech"]
USERS = ["alice", "bob", "carol", "dave"]
ROLES = ["viewer", "analyst", "operator", "org_admin"]
PERMS = [None, "read", "queue_proposal", "run_engagement", "manage_billing", "offense_authority"]


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


def _reg(store):
    return OrgRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


@pytest.fixture
def no_full_fold(monkeypatch):
    calls = {"n": 0}
    for name in ("_fold_orgs", "_fold_memberships"):
        real = getattr(OrgRegistry, name)

        def spy(self, _real=real):
            calls["n"] += 1
            return _real(self)

        monkeypatch.setattr(OrgRegistry, name, spy)
    return calls


def _full_answers(reg, org_ids=ORG_IDS, users=USERS):
    orgs = reg._fold_orgs()
    mems = reg._fold_memberships()

    def role(u, o):
        if o not in orgs:
            return None
        m = mems.get((o, u))
        return m.role if m is not None else None

    return {
        "orgs": [orgs[o] for o in sorted(orgs)],
        "org": {o: orgs.get(o) for o in org_ids + ["nope"]},
        "memberships": [mems[k] for k in sorted(mems)],
        "memberships_of": {o: [mems[k] for k in sorted(k for k in mems if k[0] == o)] for o in org_ids + ["nope"]},
        "role": {(u, o): role(u, o) for u in users for o in org_ids},
        "admit": {(u, o, p): og.role_can(role(u, o), p) for u in users for o in org_ids for p in PERMS},
    }


def _cached_answers(reg, org_ids=ORG_IDS, users=USERS):
    return {
        "orgs": reg.orgs(),
        "org": {o: reg.org(o) for o in org_ids + ["nope"]},
        "memberships": reg.memberships(),
        "memberships_of": {o: reg.memberships(o) for o in org_ids + ["nope"]},
        "role": {(u, o): reg.membership_role(u, o) for u in users for o in org_ids},
        "admit": {(u, o, p): reg.admit_customer(username=u, org_id=o, permission=p)
                  for u in users for o in org_ids for p in PERMS},
    }


def _assert_equivalent(reg, no_full_fold=None):
    before = no_full_fold["n"] if no_full_fold is not None else 0
    got = _cached_answers(reg)
    if no_full_fold is not None:
        assert no_full_fold["n"] == before, "a cached read fell back to a full fold"
    assert got == _full_answers(reg)


def _fails_closed_both_ways(monkeypatch, *reads):
    """Every read RAISES `SnapshotError`, with the fold cache ON and OFF alike (never an answer from an empty start)."""
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        for read in reads:
            with pytest.raises(SnapshotError, match="does not succeed"):
                read()
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")


@pytest.mark.parametrize("seed", [11, 12, 13, 14])
def test_randomized_equivalence_with_the_full_folds(tmp_path, seed, no_full_fold):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store, other = SpineStore(path), SpineStore(path)
    reg, reg_other = _reg(store), _reg(other)
    captured: list = []
    for step in range(110):
        op = rng.choice(["create", "grant", "grant", "revoke_m", "revoke_org", "replay", "forged", "unsigned",
                         "noise", "other_grant"])
        o, u = rng.choice(ORG_IDS), rng.choice(USERS)
        if op == "create":
            seq = reg.create_org(o, f"{o} inc", owner="owner", issued_at=_iss())
            captured.append(store.get(seq).payload)
        elif op in ("grant", "other_grant"):
            r = reg if op == "grant" else reg_other
            if reg._fold_orgs().get(o) is not None:
                seq = r.grant_membership(o, u, rng.choice(ROLES), issued_at=_iss())
                captured.append(store.get(seq).payload)
        elif op == "revoke_m":
            reg.revoke_membership(o, u)
        elif op == "revoke_org":
            reg.revoke_org(o)                                 # cascades every current membership
        elif op == "replay" and captured:
            store.append(kind="event", source="governor", actor="WARDEN", payload=rng.choice(captured))
        elif op == "forged":
            core = {"signal": og.MEMBERSHIP_SIGNAL, "org_id": o, "username": u, "role": "operator",
                    "state": "active", "issued_at": _iss() + 1e6}
            store.append(kind="event", source="governor", actor="WARDEN", payload=signed_payload(core, ATTACKER))
        elif op == "unsigned":
            store.append(kind="event", source="governor", actor="WARDEN",
                         payload={"signal": og.ORG_SIGNAL, "org_id": o, "name": "x", "owner": "owner",
                                  "state": "active", "issued_at": _iss() + 1e6})
        else:
            store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": step})
        _assert_equivalent(reg, no_full_fold)
    assert og._ORGS_FOLD._entries


def test_recreating_a_revoked_org_resurrects_no_member(tmp_path, no_full_fold):
    reg = _reg(SpineStore(str(tmp_path / "spine.jsonl")))
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    assert reg.membership_role("alice", "acme") == "operator"          # warm
    reg.revoke_org("acme")
    reg.create_org("acme", "Acme again", owner="owner", issued_at=_iss())
    _assert_equivalent(reg, no_full_fold)
    assert reg.membership_role("alice", "acme") is None
    assert reg.org("acme").name == "Acme again"


def test_a_warm_admission_verifies_no_signature_and_appends_cost_one_each(tmp_path, monkeypatch):
    reg = _reg(SpineStore(str(tmp_path / "spine.jsonl")))
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    for i in range(20):
        reg.grant_membership("acme", f"user{i}", "analyst", issued_at=_iss())
    fold_cache.clear_all()                     # each grant's org() check already warmed it: start cold
    count = {"n": 0}
    real = og.verify_signed

    def counting(*a, **kw):
        count["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(og, "verify_signed", counting)
    assert reg.admit_customer(username="user3", org_id="acme", permission="read")
    assert count["n"] == 21                                            # cold: 1 org + 20 memberships, once
    count["n"] = 0
    for _ in range(5):
        assert reg.admit_customer(username="user7", org_id="acme", permission="read")
        assert reg.membership_role("user19", "acme") == "analyst"
    assert count["n"] == 0, "a warm admission must not re-verify any signature"
    reg.grant_membership("acme", "late", "viewer", issued_at=_iss())
    reg.grant_membership("acme", "later", "viewer", issued_at=_iss())
    assert reg.membership_role("later", "acme") == "viewer"
    assert count["n"] == 2
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    count["n"] = 0
    assert reg.membership_role("later", "acme") == "viewer"
    assert count["n"] == 1 + 22, "control: OFF re-verifies the org and all 22 membership grants"


def test_one_entry_serves_both_folds(tmp_path):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    reg.grant_membership("acme", "alice", "viewer", issued_at=_iss())
    reg.orgs()
    reg.memberships()
    reg.membership_role("alice", "acme")
    assert len(og._ORGS_FOLD._entries) == 1


class _PrunedView:
    def __init__(self, inner):
        self._inner, self.K, self.path = inner, 0, inner.path

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self.K:
                yield r

    def get(self, seq):
        return self._inner.get(seq) if seq >= self.K else None

    def append(self, **kw):
        return self._inner.append(**kw)


def test_a_seeded_prune_keeps_the_pruned_org_member_and_high_waters(tmp_path, monkeypatch, no_full_fold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    reg = _reg(view)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    g = reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    reg.create_org("globex", "Globex", owner="owner", issued_at=_iss())
    b = reg.grant_membership("globex", "bob", "analyst", issued_at=_iss())
    captured_b = store.get(b).payload
    reg.revoke_membership("globex", "bob")
    assert reg.membership_role("alice", "acme") == "operator"             # warm, unpruned
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=OWNER_PUB, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured_b)   # live replay
    reg.grant_membership("acme", "carol", "viewer", issued_at=_iss())
    _assert_equivalent(reg, no_full_fold)
    assert g < k and reg.membership_role("alice", "acme") == "operator", "the seed carries the pruned member"
    assert reg.membership_role("bob", "globex") is None, "the seeded high-water refuses the replay"
    assert reg.membership_role("carol", "acme") == "viewer"


def test_a_rollback_under_the_live_process_rebuilds(tmp_path, no_full_fold):
    path = tmp_path / "spine.jsonl"
    reg = _reg(SpineStore(str(path)))
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    shutil.copy(path, tmp_path / "backup.jsonl")
    reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    reg.grant_membership("acme", "bob", "operator", issued_at=_iss())
    assert reg.membership_role("bob", "acme") == "operator"
    shutil.copy(tmp_path / "backup.jsonl", path)
    reg2 = _reg(SpineStore(str(path)))
    reg2.grant_membership("acme", "carol", "viewer", issued_at=_iss())
    reg2.grant_membership("acme", "dave", "viewer", issued_at=_iss())
    _assert_equivalent(reg2, no_full_fold)
    assert reg2.membership_role("bob", "acme") is None and reg2.membership_role("dave", "acme") == "viewer"


def test_a_raw_org_revoke_without_the_cascade_strips_every_member(tmp_path, no_full_fold):
    """A safe-direction org revoke appended WITHOUT the membership cascade (any unsigned revoke is honoured):
    the members' grants stay active in the membership fold, but a revoked org admits no one."""
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    reg = _reg(store)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    assert reg.membership_role("alice", "acme") == "operator"           # warm
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={"signal": og.ORG_SIGNAL, "org_id": "acme", "name": "", "owner": "",
                          "state": "revoked", "issued_at": 0.0})
    _assert_equivalent(reg, no_full_fold)
    assert reg.memberships("acme"), "no cascade: the membership grant itself is still active"
    assert reg.membership_role("alice", "acme") is None
    assert not reg.admit_customer(username="alice", org_id="acme", permission="read")


def test_a_foreign_key_reader_of_a_pruned_snapshot_fails_closed(tmp_path, monkeypatch):
    """A PRUNED snapshot folded under a key the reader's owner-key succession does not reach (a swapped key, a
    re-genesis) is never trusted, and an empty start over the deleted prefix is not an answer either: every read
    fails CLOSED, cached and uncached alike."""
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    reg = _reg(view)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=OWNER_PUB, base_seq=k,
                 snapshot_seq=k - 1)
    assert snap.membership_row and snap.org_row, "the snapshot carries the rows a foreign reader must never see"
    new_owner = generate_keypair()
    reader = OrgRegistry(view, owner_key=new_owner, trusted_pubkey=new_owner.public_key_b64)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    _fails_closed_both_ways(monkeypatch, lambda: reader.org("acme"), reader.memberships,
                            lambda: reader.membership_role("alice", "acme"))


@pytest.mark.parametrize("value", ["", "0", "off"])
def test_flag_off_never_consults_the_cache(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("the fold cache was consulted with the flag OFF")

    monkeypatch.setattr(og._ORGS_FOLD, "read", boom)
    reg = _reg(SpineStore(str(tmp_path / "spine.jsonl")))
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    assert reg.admit_customer(username="alice", org_id="acme", permission="read")
    assert [o.org_id for o in reg.orgs()] == ["acme"] and len(reg.memberships("acme")) == 1
    reg.revoke_org("acme")
    assert reg.membership_role("alice", "acme") is None


def test_memberships_of_a_non_str_org_is_empty_like_the_full_fold(tmp_path):
    reg = _reg(SpineStore(str(tmp_path / "spine.jsonl")))
    reg.create_org("acme", "Acme", owner="owner", issued_at=_iss())
    reg.grant_membership("acme", "alice", "operator", issued_at=_iss())
    for odd in (5, ["acme"], ("acme",), ""):
        assert reg.memberships(odd) == []
