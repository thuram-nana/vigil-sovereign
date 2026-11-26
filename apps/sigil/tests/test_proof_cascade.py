"""Slice AS-2l — PROOF CASCADE on org decommission (the resurrection guard for the asset layer).

`orgs.OrgRegistry.revoke_org` already cascade-revokes an org's memberships and monitoring authorities so a
re-created org_id cannot inherit the decommissioned org's members or monitoring grants. This slice closes the
remaining resurrection hole: ASSET-OWNERSHIP PROOFS. `asset_ownership.has_current_proof` gates ONLY on the
proof fold (never on whether the org is active), so without a cascade a `revoke_org`->`create_org` on the SAME
org_id would silently restore every prior proven host in the new incarnation.

Load-bearing invariants (a false-green here would let a re-created org inherit a decommissioned org's proofs —
the exact ownership-resurrection the slice closes):
  * revoke_org revokes EVERY active ownership proof of the org (all its hosts);
  * a RE-CREATED org_id starts with NO proofs (the acceptance), and re-proving still works with a fresh grant;
  * the cascade is TENANT-SCOPED: revoking org A never touches org B's proofs;
  * NEGATIVE CONTROL (anti-replay): a proof revoked by the cascade is NOT resurrectable by replaying the
    captured owner-signed ACTIVE proof grant (per-(org_id, host) LWW high-water);
  * NEGATIVE CONTROL (fail-safe partial cascade): if the cascade raises partway, the org revoke has ALREADY
    landed (fail-safe ordering — the tenant admits no one), the proofs it did revoke stay durably revoked, and
    re-running completes it idempotently — no completed decommission leaves a resurrectable proof;
  * ROBUSTNESS: a single corrupt folded proof (a host the binding check would reject, reachable only via a
    direct owner-signed append) cannot abort the cascade — it is revoked by its RAW folded host;
  * DETERMINISM: the cascade carries a FIXED issued_at 0.0 (no wallclock / RNG on the revoke path);
  * SAFE DIRECTION: the cascade revoke is honored even unsigned (fixed issued_at 0.0).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor import asset_ownership as ao
from sigil.governor.asset_ownership import (
    PROOF_SIGNAL,
    AssetOwnershipRegistry,
    METHOD_DNS_TXT,
    expected_marker,
)
from sigil.governor.orgs import OrgRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store() -> SpineStore:
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _orgs(store: SpineStore) -> OrgRegistry:
    return OrgRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _own(store: SpineStore) -> AssetOwnershipRegistry:
    return AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _prove(own: AssetOwnershipRegistry, org_id: str, host: str, *, now: float = 100.0) -> None:
    """Record a real owner-signed ownership proof for (org_id, host) via the deterministic verdict."""
    ch = own.issue_challenge(org_id, host, issued_at=_issue())
    own.verify_and_record(org_id, host, method=METHOD_DNS_TXT, observed=[expected_marker(ch.token)], now=now)


# --- the cascade: revoke_org removes every proof of the org ----------------------------------------

def test_revoke_org_cascades_every_proof_of_the_org():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    for h in ("apme.cm", "beta.cm", "gamma.cm"):
        _prove(own, "acme", h)
    assert own.proven_hosts("acme", now=150.0) == ["apme.cm", "beta.cm", "gamma.cm"]

    orgs.revoke_org("acme")

    # every proof is gone — no active proof record, nothing proven.
    assert own.proven_hosts("acme", now=150.0) == []
    for h in ("apme.cm", "beta.cm", "gamma.cm"):
        assert own.proof("acme", h) is None
        assert own.has_current_proof("acme", h, now=150.0) is False


def test_revoke_org_with_no_proofs_is_a_noop():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("empty", "Empty", owner="owner", issued_at=_issue())
    # no proofs recorded -> the cascade appends nothing and returns an empty list.
    assert own.revoke_org("empty") == []


# --- the acceptance: a RE-CREATED org starts with no proofs (no resurrection) -----------------------

def test_recreated_org_has_no_proofs_then_reproving_works():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")
    assert own.has_current_proof("acme", "apme.cm", now=150.0) is True

    orgs.revoke_org("acme")                                   # decommission (cascades the proof)
    orgs.create_org("acme", "Acme-reborn", owner="owner", issued_at=_issue())  # supported reactivation

    # THE ACCEPTANCE: the re-created org does NOT inherit the decommissioned org's proofs.
    assert own.proven_hosts("acme", now=150.0) == []
    assert own.has_current_proof("acme", "apme.cm", now=150.0) is False

    # ...and a FRESH owner-signed verify-and-record re-proves cleanly (reactivation is not a dead end).
    _prove(own, "acme", "apme.cm", now=300.0)
    assert own.proven_hosts("acme", now=350.0) == ["apme.cm"]


# --- tenant isolation: the cascade is strictly per-org ---------------------------------------------

def test_proof_cascade_is_tenant_scoped():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    orgs.create_org("globex", "Globex", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")
    _prove(own, "globex", "glx.cm")

    orgs.revoke_org("acme")

    assert own.proof("acme", "apme.cm") is None               # revoked org's proof gone
    assert own.has_current_proof("globex", "glx.cm", now=150.0) is True   # other tenant untouched


# --- NEGATIVE CONTROL: a revoked proof is NOT resurrectable by replaying the signed active grant ----

def test_revoked_proof_not_resurrectable_by_replay():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")

    # capture the OWNER-SIGNED active proof grant exactly as it sits on the spine (an attacker's capture).
    captured = None
    for r in s.iter_records():
        p = r.payload
        if isinstance(p, dict) and p.get("signal") == PROOF_SIGNAL and p.get("host") == "apme.cm" \
                and p.get("state") == "active":
            captured = dict(p)
    assert captured is not None

    orgs.revoke_org("acme")
    assert own.proof("acme", "apme.cm") is None

    # Replay the captured active grant. A non-core field (`reason`) is altered so the spine does not simply
    # dedup it — this forces a REAL fold of the replayed grant, which the per-(org,host) high-water refuses
    # (its issued_at <= the high-water already consumed), so the proof STAYS revoked. The signature is still
    # valid (the authenticated core is byte-identical) — authenticity is not the guard here, freshness is.
    replay = dict(captured)
    replay["reason"] = "attacker replay of a captured owner-signed proof"
    s.append(kind="event", source="governor", actor="WARDEN", payload=replay)

    assert own.proof("acme", "apme.cm") is None               # NOT resurrected
    assert own.has_current_proof("acme", "apme.cm", now=150.0) is False


# --- NEGATIVE CONTROL: a partial / failed cascade leaves the org revoked and is idempotently completed

def test_partial_cascade_is_failsafe_and_idempotently_completed(monkeypatch):
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")     # sorts first
    _prove(own, "acme", "beta.cm")     # sorts second -> make the cascade blow up HERE

    real = AssetOwnershipRegistry._append_revoked_proof

    def _boom(self, org_id, host):
        if host == "beta.cm":
            raise RuntimeError("simulated crash mid-cascade")
        return real(self, org_id, host)

    monkeypatch.setattr(AssetOwnershipRegistry, "_append_revoked_proof", _boom)

    with pytest.raises(RuntimeError):
        orgs.revoke_org("acme")

    # FAIL-SAFE ordering: the ORG revoke landed FIRST, before the proof cascade crashed, so the tenant admits
    # no one regardless of the cascade outcome.
    assert orgs.org("acme") is None
    # the proof the cascade DID reach is durably revoked; the one it did not is still active (a partial).
    assert own.proof("acme", "apme.cm") is None
    assert own.proof("acme", "beta.cm") is not None

    # Recovery: with the fault gone, re-running the cascade is idempotent and completes it — no completed
    # decommission leaves a stale proof. (`apme.cm`'s re-revoke merely re-revokes; `beta.cm` is now revoked.)
    monkeypatch.setattr(AssetOwnershipRegistry, "_append_revoked_proof", real)
    own.revoke_org("acme")
    assert own.proven_hosts("acme", now=150.0) == []
    assert own.proof("acme", "beta.cm") is None


# --- NEGATIVE CONTROL: a PRECEDING cascade raising must NOT skip the proof cascade (isolation) -------

def test_proof_cascade_runs_even_when_monitoring_cascade_raises(monkeypatch):
    """CASCADE ISOLATION (AS-2l red-pen MEDIUM): `revoke_org` runs the membership, monitoring-authority and
    proof cascades. The monitoring-authority cascade is NOT itself fail-safe (its `revoke` unpublishes to the
    edge, which can raise). Without isolation it ran sequentially BEFORE the proof cascade with no try/except,
    so a raising monitoring cascade SKIPPED the proof cascade entirely — leaving the org's ownership proofs
    ACTIVE, which a re-created org_id would inherit (defeating the slice's whole anti-replay guarantee on
    exactly the partial-failure path the cascade exists to handle).

    This injects a crash into the monitoring-authority cascade (which runs BEFORE the proof cascade) and
    asserts the PROOF cascade STILL ran (the proof is revoked) AND the overall call still SURFACES the failure
    (an aggregated raise), rather than silently swallowing it. Mutation-sensitive: with the pre-fix sequential
    code the proof cascade is skipped and `own.proof("acme", "apme.cm")` stays non-None, failing below."""
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")
    assert own.has_current_proof("acme", "apme.cm", now=150.0) is True

    # make the monitoring-authority cascade (which lands BEFORE the proof cascade) blow up.
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry

    real_revoke_org = MonitoringAuthorityRegistry.revoke_org

    def _boom(self, org_id):
        raise RuntimeError("simulated monitoring-authority cascade crash")

    monkeypatch.setattr(MonitoringAuthorityRegistry, "revoke_org", _boom)

    # the call still SURFACES the failure (aggregated raise) rather than swallowing it...
    with pytest.raises(RuntimeError):
        orgs.revoke_org("acme")

    # ...BUT the proof cascade ran anyway (it is no longer gated on the preceding cascade succeeding):
    assert own.proof("acme", "apme.cm") is None
    assert own.has_current_proof("acme", "apme.cm", now=150.0) is False
    # the org revoke landed FIRST (fail-safe ordering), so the tenant admits no one regardless.
    assert orgs.org("acme") is None

    # Recovery: with the fault gone, re-running the (now complete) decommission is an idempotent no-op in
    # effect — the monitoring cascade finishes and the proof stays revoked.
    monkeypatch.setattr(MonitoringAuthorityRegistry, "revoke_org", real_revoke_org)
    orgs.revoke_org("acme")
    assert own.proof("acme", "apme.cm") is None


# --- ROBUSTNESS: a corrupt folded proof cannot abort the cascade (revoked by raw folded host) -------

def test_cascade_not_aborted_by_a_corrupt_folded_proof():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")

    # Inject a CORRUPT active proof whose host the binding-time `_check_host` would reject (a space), reachable
    # only by a direct owner-signed append (the public API refuses it). It folds as active (valid signature,
    # fresh issued_at), so it is in the set the cascade must clear.
    bad_host = "bad host.cm"
    from sigil.governor.authn import signed_payload
    core = {"signal": PROOF_SIGNAL, "org_id": "acme", "host": bad_host, "method": METHOD_DNS_TXT,
            "token_sha256": "deadbeef", "verified_at": 10.0, "expires_at": 1e18, "state": "active",
            "issued_at": 10.0}
    payload = {**signed_payload(core, OWNER), "by": "owner", "requested_by": "owner", "tier": "A0",
               "decision": "auto", "reason": "hand-signed corrupt proof (test)"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert ("acme", bad_host) in own._fold_proofs()           # it really is an active folded proof

    # The cascade must NOT raise on the corrupt host (it revokes by RAW folded host, no re-validation) and
    # must clear BOTH the valid and the corrupt proof.
    orgs.revoke_org("acme")
    assert own.proof("acme", "apme.cm") is None
    assert ("acme", bad_host) not in own._fold_proofs()


# --- DETERMINISM: the cascade revoke carries a fixed issued_at 0.0 (no wallclock / RNG) -------------

def test_cascade_revoke_is_deterministic_fixed_issued_at():
    s = _store()
    orgs, own = _orgs(s), _own(s)
    orgs.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(own, "acme", "apme.cm")

    n0 = sum(1 for _ in s.iter_records())
    orgs.revoke_org("acme")                                   # takes NO `now` argument on the proof path
    new = list(s.iter_records())[n0:]

    proof_revokes = [r.payload for r in new
                     if isinstance(r.payload, dict) and r.payload.get("signal") == PROOF_SIGNAL]
    assert len(proof_revokes) == 1
    assert proof_revokes[0]["state"] == "revoked"
    assert proof_revokes[0]["issued_at"] == 0.0               # fixed bottom, never a clock read


# --- SAFE DIRECTION: the cascade revoke is honored even when UNSIGNED --------------------------------

def test_cascade_revoke_honored_even_unsigned():
    s = _store()
    _orgs(s).create_org("acme", "Acme", owner="owner", issued_at=_issue())
    _prove(_own(s), "acme", "apme.cm")

    # a pure-read registry (owner_key=None) signs nothing, yet its safe-direction org cascade still revokes.
    unsigned = AssetOwnershipRegistry(s, owner_key=None, trusted_pubkey=OP)
    unsigned.revoke_org("acme")
    assert _own(s).proof("acme", "apme.cm") is None
