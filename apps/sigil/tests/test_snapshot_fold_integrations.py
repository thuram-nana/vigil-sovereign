"""Prune-survival proof for the SnapshotState-seeded `IntegrationBindingRegistry._fold` (DevSecOps integrations).

The customer-integration binding fold (`governor.customer_integration`) used to be a GENESIS scan with NO
snapshot seed, so a hard prune below the first owner-signed `active` binding record would:

  * STRANDING (availability): SILENTLY vanish an active Slack/Jira/Linear binding (`active_for_org` -> [],
    `get` -> None) — deliveries of confirmed findings silently stop to a still-authorized integration; and
  * REVOKE-RESURRECTION (the security half): reset the per-(org_id, binding_id) anti-replay high-water, so a
    captured/replayed owner-signed `active` record for a binding the owner REVOKED re-applies above K
    (freshness passes because the high-water is gone) — re-activating a revoked integration and re-enabling
    egress of confirmed findings + evidence through a sealed credential the owner retired.

This slice seeds the fold from `SnapshotState` (v14 grew `customer_integration_*` rows) exactly as
`asset_ownership._fold_proofs` / `customer_credentials._fold` do, and `spine.prune` refuses any prune that
would strand an active binding the seed does not carry.

PHYSICAL-PRUNE HARNESS (identical to tests/test_snapshot_fold_ownership.py): a `PrunedView` physically hides
every record with `seq < K` from `iter_records` regardless of `since_seq`, so only the SEED can carry the
pruned state. Each test also carries an inline NEUTERED control (`SnapshotState.load` -> the empty identity)
that reproduces the pre-fix genesis-scan behaviour from inside the test, proving the seed is load-bearing.
"""
import itertools
import tempfile

import pytest

from sigil.governor import customer_integrations as ci
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

_SEAL = "c2VhbGVkLXdlYmhvb2s="   # a non-empty (fake-sealed) secret; the plaintext never reaches the spine

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _integrations_on(monkeypatch):
    """`configure` is flag-gated (default-off, fail-closed); turn the layer ON for these fold tests."""
    monkeypatch.setenv("VIGIL_CUSTOMER_INTEGRATIONS", "1")
    yield


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return ci.IntegrationBindingRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _configure(store, org, binding, *, now):
    """Owner-sign an active Slack-webhook binding for (org, binding); issued_at = now."""
    _reg(store).configure(org, binding, provider=ci.PROVIDER_SLACK, mode=ci.SLACK_WEBHOOK,
                          sealed_secret=_SEAL, issued_at=now)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records`."""
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


# ---- (a) an active BINDING whose only config is PHYSICALLY PRUNED survives via the seed (no stranding) ----
def test_active_binding_survives_a_hard_prune(monkeypatch):
    store = _store()
    _configure(store, "acme", "slk1", now=5.0)                       # active binding at seq0 (issued 5.0)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.customer_integration_state_map().get(("acme", "slk1")) == "active"
    assert snap.customer_integration_issued_map().get(("acme", "slk1")) == 5.0
    assert any(row[0] == "acme" and row[1] == "slk1" for row in snap.customer_integration_row)

    pruned = PrunedView(store, k)                                    # [0..k) GONE — the binding config is unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = ci.IntegrationBindingRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    b = reg2.get("acme", "slk1")
    assert b is not None, "a pruned active binding must survive via the seed (no stranding)"
    assert b.provider == ci.PROVIDER_SLACK and b.sealed_secret == _SEAL and b.issued_at == 5.0
    assert [x.binding_id for x in reg2.active_for_org("acme")] == ["slk1"]

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = ci.IntegrationBindingRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.get("acme", "slk1") is None, "no seed over a physically-pruned store ⇒ binding stranded (vanished)"


# ---- (b) the per-(org,binding) high-water SURVIVES the prune (no revoke-resurrection) --------------------
def test_binding_high_water_survives_the_prune_no_revoke_resurrection(monkeypatch):
    store = _store()
    _configure(store, "acme", "slk1", now=5.0)                       # active binding at seq0 (issued 5.0)
    captured = next(r.payload for r in store.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == ci._BINDING_SIGNAL
                    and r.payload.get("state") == "active")
    _reg(store).remove("acme", "slk1")                               # owner REVOKES the binding
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.customer_integration_state_map().get(("acme", "slk1")) == "revoked"
    assert snap.customer_integration_issued_map().get(("acme", "slk1")) == 5.0   # high-water preserved though revoked

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay the active grant
    pruned = PrunedView(store, k)                                    # configure + revoke are both pruned away
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = ci.IntegrationBindingRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2.get("acme", "slk1") is None, "replayed active record must NOT resurrect a revoked binding (seed hw)"
    assert reg2.active_for_org("acme") == []

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = ci.IntegrationBindingRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.get("acme", "slk1") is not None, "no seed ⇒ high-water lost ⇒ the replayed grant resurrects"


# ---- (c) empty-identity load == genesis scan (byte-identity of the no-prune path) -----------------------
def test_binding_empty_load_matches_genesis():
    store = _store()
    _configure(store, "acme", "slk1", now=_iss())
    _configure(store, "acme", "jira1", now=_iss())
    _reg(store).remove("acme", "jira1")                              # revoked live
    assert SnapshotState.load(store).base_seq == 0                  # no prune -> empty identity (genesis scan)
    reg = _reg(store)
    assert reg.get("acme", "slk1") is not None
    assert reg.get("acme", "jira1") is None                         # revoked
    assert [b.binding_id for b in reg.active_for_org("acme")] == ["slk1"]


# ---- (d) check_prune_safe referential floor ------------------------------------------------------------
def _binding_segmented_store(tmp_path):
    """A migrated store: an owner-signed active integration binding sits in segment 0 [0..5), which a prune at
    K=5 archives+deletes; the seed must carry it or the floor refuses."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _configure(s, "acme", "slk1", now=1.0)                           # active binding at seq0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})          # seq 1..4
    s.rotate()                                                                        # seal segment 0 [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})         # seq 5..9
    s.rotate()                                                                        # seal segment 1 [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})         # a live tail
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_active_binding(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _binding_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                          # must NOT raise: the binding IS carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_integration_bindings(s, archived, 5) == []   # detector empty on a complete seed


def test_referential_floor_detects_a_seed_that_omits_an_active_binding(tmp_path, monkeypatch):
    """Positive control: if build()/the seed ever DROPPED an active binding whose only config is below K, the
    floor must DETECT it (non-empty) and refuse — not silently prune the binding away (stranding it)."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _binding_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "customer_integration_state": [r for r in seed.customer_integration_state
                                           if (r[0], r[1]) != ("acme", "slk1")],
            "customer_integration_issued": [r for r in seed.customer_integration_issued
                                            if (r[0], r[1]) != ("acme", "slk1")],
            "customer_integration_row": [r for r in seed.customer_integration_row
                                         if (r[0], r[1]) != ("acme", "slk1")],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    stranded = prune.stranded_active_integration_bindings(s, _archived_below(s, 5), 5)
    assert stranded == ["slk1@acme"]                                # real diff: active minus carried={}
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "slk1@acme" in msg and "integration binding" in msg


def test_check_prune_safe_reraises_a_nonempty_binding_floor_wiring_only(tmp_path, monkeypatch):
    """Pure wiring check: check_prune_safe re-raises PruneUnsafe when the binding detector reports non-empty."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _binding_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_integration_bindings", lambda store, archived, K: ["ghost@org"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost@org" in str(e.value)
