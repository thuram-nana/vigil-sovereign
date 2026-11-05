"""AEGIS-SaaS AE-0 — the sovereign MonitoringAuthorityRegistry (owner-signed defensive-monitoring grants).

Invariants pinned here:
  * a grant REQUIRES a current ownership proof for the EXACT (org, host) and never outlives it (clamped);
  * default mode is OBSERVE; an unknown mode is refused; a forged/unsigned/wrong-key grant is inert;
  * revoke is the safe direction (honored unsigned); a captured grant cannot resurrect a revoked one;
  * the decision read is DEFAULT-DENY: other org / other host / outside window / ownership lapsed → None;
  * HARD-PRUNE durable: an active grant whose only record is pruned survives via the v6 snapshot seed, its
    high-water survives (no replay resurrection), and the prune tripwire refuses a seed that drops it.
"""
import itertools
import tempfile

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import (
    MODE_BLOCK,
    MODE_OBSERVE,
    SIGNAL,
    MonitoringAuthorityRegistry,
)
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _ma(store, key=OWNER):
    return MonitoringAuthorityRegistry(store, owner_key=key, trusted_pubkey=OP)


def _prove(store, org, host, *, now, ttl=1e12):
    reg = AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OP)
    ch = reg.issue_challenge(org, host, issued_at=now)
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)


# ---- grant semantics ------------------------------------------------------------------------------
def test_grant_requires_current_ownership_proof_for_the_exact_pair():
    s = _store()
    with pytest.raises(ValueError, match="ownership"):
        _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=100.0, now=1.0)
    _prove(s, "acme", "apme.cm", now=1.0)
    with pytest.raises(ValueError, match="ownership"):                       # other org, same host
        _ma(s).grant("beta", "apme.cm", not_before=0.0, not_after=100.0, now=2.0)
    with pytest.raises(ValueError, match="ownership"):                       # same org, other host
        _ma(s).grant("acme", "www.apme.cm", not_before=0.0, not_after=100.0, now=2.0)
    g = _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=100.0, now=2.0)
    assert g.mode == MODE_OBSERVE                                           # default OBSERVE


def test_grant_is_clamped_to_the_ownership_proof_expiry():
    s = _store()
    _prove(s, "acme", "apme.cm", now=10.0, ttl=50.0)                        # proof expires at 60
    g = _ma(s).grant("acme", "apme.cm", not_before=10.0, not_after=1000.0, now=11.0)
    assert g.not_after == 60.0
    with pytest.raises(ValueError):                                          # window starts after proof ends
        _ma(s).grant("acme", "apme.cm", not_before=70.0, not_after=80.0, now=12.0)


def test_bad_mode_window_and_missing_key_refused():
    s = _store()
    _prove(s, "acme", "apme.cm", now=1.0)
    with pytest.raises(ValueError):
        _ma(s).grant("acme", "apme.cm", mode="enforce", not_before=0.0, not_after=10.0, now=2.0)
    with pytest.raises(ValueError):
        _ma(s).grant("acme", "apme.cm", not_before=10.0, not_after=10.0, now=2.0)
    with pytest.raises(ValueError):
        _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=1e9, now=2.0)    # > max single-grant span
    with pytest.raises(ValueError):
        _ma(s, key=None).grant("acme", "apme.cm", not_before=0.0, not_after=10.0, now=2.0)


def test_forged_grant_is_inert():
    s = _store()
    _prove(s, "acme", "apme.cm", now=1.0)
    MonitoringAuthorityRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP).grant(
        "acme", "apme.cm", mode=MODE_BLOCK, not_before=0.0, not_after=100.0, now=2.0)
    assert _ma(s).grant_for("acme", "apme.cm") is None
    assert _ma(s).active_at("acme", "apme.cm", now=5.0) is None


def test_active_at_is_default_deny():
    s = _store()
    _prove(s, "acme", "apme.cm", now=1.0)
    _ma(s).grant("acme", "apme.cm", mode=MODE_BLOCK, not_before=10.0, not_after=20.0, now=2.0)
    r = _ma(s)
    assert r.active_at("acme", "apme.cm", now=15.0).mode == MODE_BLOCK
    assert r.active_at("acme", "apme.cm", now=9.0) is None                   # not yet valid
    assert r.active_at("acme", "apme.cm", now=20.0) is None                  # expired (half-open window)
    assert r.active_at("beta", "apme.cm", now=15.0) is None                  # other tenant
    assert r.active_at("acme", "x.apme.cm", now=15.0) is None                # no subdomain inheritance


def test_ownership_revoke_makes_grant_inert_immediately():
    s = _store()
    _prove(s, "acme", "apme.cm", now=1.0)
    _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=100.0, now=2.0)
    AssetOwnershipRegistry(s, owner_key=OWNER, trusted_pubkey=OP).revoke_proof("acme", "apme.cm")
    assert _ma(s).grant_for("acme", "apme.cm") is not None                   # record still there...
    assert _ma(s).active_at("acme", "apme.cm", now=5.0) is None              # ...but no longer authorizes


def test_revoke_and_no_replay_resurrection():
    s = _store()
    _prove(s, "acme", "apme.cm", now=1.0)
    _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=100.0, now=2.0)
    captured = next(r.payload for r in s.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == SIGNAL)
    MonitoringAuthorityRegistry(s, owner_key=None, trusted_pubkey=OP).revoke("acme", "apme.cm")  # unsigned OK
    assert _ma(s).grant_for("acme", "apme.cm") is None
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert _ma(s).grant_for("acme", "apme.cm") is None, "a replayed grant must not resurrect a revoked one"
    g = _ma(s).grant("acme", "apme.cm", mode=MODE_BLOCK, not_before=0.0, not_after=100.0, now=50.0)  # fresh re-grant
    assert _ma(s).active_at("acme", "apme.cm", now=60.0).mode == g.mode == MODE_BLOCK


def test_revoke_org_revokes_only_that_org():
    s = _store()
    for org, host in (("acme", "a.cm"), ("acme", "b.cm"), ("beta", "c.cm")):
        _prove(s, org, host, now=1.0)
        _ma(s).grant(org, host, not_before=0.0, not_after=100.0, now=2.0)
    _ma(s).revoke_org("acme")
    assert _ma(s).grants("acme") == []
    assert [g.host for g in _ma(s).grants("beta")] == ["c.cm"]


# ---- hard-prune durability --------------------------------------------------------------------------
class PrunedView:
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


def test_active_grant_and_high_water_survive_a_hard_prune(monkeypatch):
    s = _store()
    _prove(s, "acme", "apme.cm", now=5.0)
    _ma(s).grant("acme", "apme.cm", mode=MODE_BLOCK, not_before=0.0, not_after=1e7, now=6.0)
    k = s.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    snap = build([r for r in s.iter_records() if r.seq < k], trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert snap.monitoring_authority_state_map()[("acme", "apme.cm")] == "active"
    assert snap.monitoring_authority_issued_map()[("acme", "apme.cm")] == 6.0
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, st: snap))
    r2 = MonitoringAuthorityRegistry(PrunedView(s, k), owner_key=OWNER, trusted_pubkey=OP)
    g = r2.grant_for("acme", "apme.cm")
    assert g is not None and g.mode == MODE_BLOCK, "a pruned active grant must survive via the seed"
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, st: SnapshotState.empty()))
    assert MonitoringAuthorityRegistry(PrunedView(s, k), owner_key=OWNER, trusted_pubkey=OP).grant_for(
        "acme", "apme.cm") is None, "neutered control: no seed ⇒ vanished"


def test_revoked_high_water_survives_prune_no_replay(monkeypatch):
    s = _store()
    _prove(s, "acme", "apme.cm", now=5.0)
    _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=1e7, now=6.0)
    captured = next(r.payload for r in s.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == SIGNAL)
    _ma(s).revoke("acme", "apme.cm")
    k = s.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    snap = build([r for r in s.iter_records() if r.seq < k], trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert snap.monitoring_authority_state_map()[("acme", "apme.cm")] == "revoked"
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, st: snap))
    assert MonitoringAuthorityRegistry(PrunedView(s, k), owner_key=OWNER, trusted_pubkey=OP).grant_for(
        "acme", "apme.cm") is None
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, st: SnapshotState.empty()))
    assert MonitoringAuthorityRegistry(PrunedView(s, k), owner_key=OWNER, trusted_pubkey=OP).grant_for(
        "acme", "apme.cm") is not None, "neutered control: no seed ⇒ replay resurrects"


def _segmented(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _prove(s, "acme", "apme.cm", now=1.0)                                     # seq 0,1
    _ma(s).grant("acme", "apme.cm", not_before=0.0, not_after=1e7, now=2.0)   # seq 2
    for _ in range(2):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})  # seq 3,4
    s.rotate()
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_prune_allows_a_carried_grant(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert prune.stranded_active_monitoring_authorities(s, archived, 5) == []


def test_tripwire_detects_a_seed_that_drops_an_active_grant(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    real = prune.build

    def drop(records, **kw):
        seed = real(records, **kw)
        return seed.model_copy(update={
            "monitoring_authority_state": [], "monitoring_authority_issued": [], "monitoring_authority_row": []})

    monkeypatch.setattr(prune, "build", drop)
    assert prune.stranded_active_monitoring_authorities(s, _archived_below(s, 5), 5) == ["apme.cm@acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "monitoring authorit" in str(e.value) and "apme.cm@acme" in str(e.value)


def test_check_prune_safe_wires_the_monitoring_tripwire(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_monitoring_authorities", lambda st, a, K: ["ghost@org"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "ghost@org" in str(e.value)
