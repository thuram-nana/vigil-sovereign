"""Slice E1 — the owner-signed CUSTOMER identity namespace (`governor.customer`), DISJOINT from accounts.

Load-bearing invariants (a false-green is an account-takeover / cross-plane-privilege path):
  * owner-signed create → the customer resolves by username + email; verify_login matches only the real
    password and is constant-time w.r.t. existence (unknown email → None via the decoy);
  * PLANE ISOLATION: a customer grant never appears in the operator `AccountsRegistry` fold, and an
    operator account never appears in the customer fold (disjoint signal — the critic's E2/mint findings);
  * a forged/unsigned customer grant is INERT; set_password rotates the hash; revoke drops the customer;
  * the per-username LWW high-water refuses a replayed owner-signed `active` grant (no resurrection);
  * HARD-PRUNE: an active customer whose only grant is physically pruned SURVIVES via the SnapshotState
    seed, its high-water survives (a replayed grant cannot resurrect a revoked customer), and
    `check_prune_safe` refuses a seed that would strand an active customer. Each prune test carries a
    NEUTERED control (empty seed) reproducing the pre-seed failure, proving the seed load-bearing.
"""
import itertools
import tempfile

import pytest

from sigil.governor import customers as cust
from sigil.governor.accounts import AccountsRegistry
from sigil.governor.authn import signed_payload
from sigil.governor.customers import CustomerRegistry
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
    return CustomerRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


# ---- core identity -----------------------------------------------------------------------------------
def test_create_resolve_and_verify_login():
    reg = _reg(_store())
    u, _ = reg.create("alice@acme.com", password="customer-pw-123", issued_at=5.0)
    assert u.startswith("cust_")
    acct = reg.customer(u)
    assert acct is not None and acct.email == "alice@acme.com" and acct.password_hash
    assert reg.by_email("ALICE@acme.com") is not None, "by_email normalizes case"
    # verify_login: right password matches; wrong password + unknown email both fail (decoy, constant-time)
    assert reg.verify_login("alice@acme.com", "customer-pw-123") is not None
    assert reg.verify_login("alice@acme.com", "wrong") is None
    assert reg.verify_login("nobody@acme.com", "customer-pw-123") is None


def test_set_password_rotates_and_revoke_drops():
    store = _store()
    reg = _reg(store)
    u, _ = reg.create("bob@acme.com", password="first-password-1", issued_at=_iss())
    reg.set_password(u, "second-password-2", issued_at=_iss())
    assert reg.verify_login("bob@acme.com", "first-password-1") is None       # old password no longer valid
    assert reg.verify_login("bob@acme.com", "second-password-2") is not None    # new one works
    reg.revoke(u)
    assert reg.customer(u) is None and reg.by_email("bob@acme.com") is None


def test_email_uniqueness_helper_and_oidc_only_customer():
    reg = _reg(_store())
    u, _ = reg.create("carol@acme.com", password=None, issued_at=_iss())        # OIDC/passkey-only (no password)
    assert reg.by_email("carol@acme.com").username == u
    assert reg.verify_login("carol@acme.com", "anything") is None, "a passwordless customer never logs in by pw"


# ---- plane isolation (the disjoint-signal structural guard) ------------------------------------------
def test_customer_and_operator_folds_are_disjoint():
    store = _store()
    custs = _reg(store)
    accts = AccountsRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    cu, _ = custs.create("dave@acme.com", password="customer-pw-999", issued_at=_iss())
    accts.create("operator_dave", "operator", bearer_token="op-bearer-xxxxxxxxxxxx", issued_at=_iss())
    # the operator account is NOT in the customer fold, and the customer is NOT in the operator fold
    assert "operator_dave" not in {c.username for c in custs.customers()}
    assert cu not in {a.username for a in accts.accounts()}
    # a customer never resolves as an operator principal (no shared bearer space either)
    assert accts.resolve("op-bearer-xxxxxxxxxxxx") is not None          # the operator's own bearer still works
    assert custs.by_email("operator_dave") is None


def test_forged_customer_grant_is_inert():
    store = _store()
    reg = _reg(store)
    # an attacker-signed active customer grant (wrong key) must NOT verify in the fold → no such customer
    core = {"signal": cust.SIGNAL, "username": "cust_evil", "email": "evil@acme.com",
            "state": "active", "issued_at": 9999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    assert reg.customer("cust_evil") is None
    assert reg.by_email("evil@acme.com") is None


def test_replay_resurrection_refused_in_the_live_fold():
    store = _store()
    reg = _reg(store)
    u, create_seq = reg.create("erin@acme.com", password="customer-pw-777", issued_at=5.0)
    captured = store.get(create_seq).payload                 # the genuine owner-signed active grant
    reg.revoke(u)
    assert reg.customer(u) is None
    # ATTACK: replay the captured active grant — its issued_at (5.0) <= the per-username high-water (5.0),
    # so the fold IGNORES it and the customer stays revoked (the LWW replay-resurrection guard).
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg.customer(u) is None, "a replayed owner-signed active grant must NOT resurrect a revoked customer"


# ---- hard-prune survival (PrunedView harness, mirrors test_snapshot_fold_accounts) -------------------
class PrunedView:
    """A real hard prune: physically hide every record with seq < K from iter_records regardless of
    since_seq (as if [0..K) were deleted). Only the snapshot SEED can carry the pruned state."""

    def __init__(self, inner, K):
        self._inner, self._K = inner, K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


def test_active_customer_survives_a_hard_prune(monkeypatch):
    store = _store()
    reg = _reg(store)
    u, _ = reg.create("frank@acme.com", password="customer-pw-555", issued_at=5.0)       # seq 0
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.customer_state_map().get(u) == "active"
    assert snap.customer_issued_map().get(u) == 5.0
    assert any(row[0] == u for row in snap.customer_cred)

    pruned = PrunedView(store, k)                            # [0..k) physically GONE
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = CustomerRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.customer(u) is not None and reg2.customer(u).email == "frank@acme.com"
    assert reg2.verify_login("frank@acme.com", "customer-pw-555") is not None, "pruned customer still logs in via seed"

    # NEUTERED control (== pre-seed genesis scan): no seed over the pruned store ⇒ the customer vanishes.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = CustomerRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.customer(u) is None, "no seed over a physically-pruned store ⇒ vanished (seed is load-bearing)"


def test_high_water_survives_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    reg = _reg(store)
    u, create_seq = reg.create("gina@acme.com", password="customer-pw-444", issued_at=5.0)   # seq 0
    captured = store.get(create_seq).payload
    reg.revoke(u)                                                                            # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.customer_state_map().get(u) == "revoked"
    assert snap.customer_issued_map().get(u) == 5.0          # the high-water that MUST cross the prune

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 3 (live) — the replay
    pruned = PrunedView(store, k)                            # [0..k) GONE: create AND revoke unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = CustomerRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.customer(u) is None, "replayed grant must NOT resurrect (seed high-water refuses it)"

    # NEUTERED control (== pre-seed): high-water lost ⇒ replayed grant (5.0 > -inf) RESURRECTS.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = CustomerRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.customer(u) is not None, "no seed ⇒ high-water lost ⇒ replay resurrects (the HIGH this closes)"


# ---- check_prune_safe referential floor for customers ------------------------------------------------
def _customer_segmented_store(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB).create(
        "hank@acme.com", password="customer-pw-222", issued_at=1.0)                 # seq 0
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


def test_check_prune_safe_allows_a_carried_active_customer(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _customer_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                       # must NOT raise: hank IS carried
    assert prune.stranded_active_customers(s, archived, 5) == []


def test_referential_floor_detects_a_seed_that_omits_an_active_customer(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _customer_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "customer_state": [r for r in seed.customer_state if not str(r[0]).startswith("cust_")],
            "customer_issued": [r for r in seed.customer_issued if not str(r[0]).startswith("cust_")],
            "customer_cred": [r for r in seed.customer_cred if not str(r[0]).startswith("cust_")],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    stranded = prune.stranded_active_customers(s, _archived_below(s, 5), 5)
    assert stranded and all(u.startswith("cust_") for u in stranded)     # the real active customer, missing from seed
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "customer" in str(e.value).lower()
