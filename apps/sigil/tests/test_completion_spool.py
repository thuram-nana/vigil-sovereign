"""K4-5b — the SOVEREIGN settle-drain of the engagement-completion seam.

Drives the REAL path: reserve → publish lease → a keyless governance-signed completion signal on the settle
spool → ``CompletionSpoolWatcher.drain()`` verifies it against the owner-signed OFFENSE_GOVERNANCE_ROLE
delegation and calls the idempotent ``settle_launch``. Pins the money invariants:
  * a COMPLETED signal settles net-spend == reserved (flat-per-run, no refund) + tombstones the lease;
  * a CANCELED signal settles consumed=0 (full refund);
  * a FORGED (wrong-key) / out-of-scope / nonce-mismatched signal is REJECTED — nothing settled;
  * a bad delegation refuses the whole drain at construction (no settle under an un-owner-delegated key);
  * a byte-identical replay is deduped (defence over settle_launch's own (slug,nonce) idempotency).

Sovereign leg (the drain is owner-side; the envelope is built here with vigil_core + the integration
producer, both framework-free): PYTHONPATH=apps/sigil:integration.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, generate_keypair
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reserve(store, *, units=30, credits=100):
    """Seat a member + wallet credits + ownership proof + a customer authority, then reserve + PUBLISH a lease.
    Returns (owner_keypair, reserve_result)."""
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return owner, r


def _gov_and_delegation(owner):
    """A governance keypair + an owner-signed OFFENSE_GOVERNANCE_ROLE delegation scoped to the cust_ slug."""
    gov = generate_keypair()
    slug = _customer_slug()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=slug, not_after=9_000_000_000)
    return gov, deleg


def _customer_slug():
    from sigil.ui.target_authorization import _customer_slug as cs
    return cs(ORG, HOST)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _drain(store, spool, owner, deleg, *, scope=None):
    import os
    return CompletionSpoolWatcher(
        store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
        scope=scope if scope is not None else _customer_slug(),
        base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: NOW).drain()


def test_completed_settles_full_consumption_and_tombstones(monkeypatch):
    import os
    s = _store()
    owner, r = _reserve(s)
    assert _avail(s) == 70                                   # 30 of 100 reserved (held)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    assert _avail(s) == 70                                   # flat-per-run: full reserved consumed, NO refund
    base = os.environ["VIGIL_BASE_DIR"]
    assert is_lease_settled(base, r["slug"], r["nonce"]) is True   # settle tombstoned + marked (K4-1)
    assert read_credit_lease(base, r["slug"]) is None


def test_canceled_settles_full_refund(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    assert _drain(s, spool, owner, deleg)["settled"] == 1
    assert _avail(s) == 100                                  # canceled → consumed 0 → full refund


def test_forged_wrong_key_signal_is_rejected_nothing_settled(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)             # the delegation trusts gov...
    attacker = generate_keypair()
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", attacker.private_key_b64)], spool_dir=spool)   # ...but ATTACKER signed
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 0 and out["rejected"] == 1
    assert _avail(s) == 70                                   # unchanged — no settle, credits still held


def test_nonce_mismatch_is_rejected(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce="a-different-nonce", outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 0 and out["rejected"] == 1      # a completion for another launch can't settle this one
    assert _avail(s) == 70


def test_replay_is_deduped_no_double_settle(monkeypatch):
    from pathlib import Path
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    env_path = emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                                      signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    text = Path(env_path).read_text(encoding="utf-8")        # capture the exact bytes BEFORE the drain moves it
    assert _drain(s, spool, owner, deleg)["settled"] == 1
    assert _avail(s) == 100
    # replay the SAME envelope bytes under a fresh incoming name → deduped on sha256(text), not re-settled
    (Path(spool, "incoming") / "replay.json").write_text(text, encoding="utf-8")
    out2 = _drain(s, spool, owner, deleg)
    assert out2["deduped"] == 1 and out2["settled"] == 0
    assert _avail(s) == 100                                  # no double refund


def test_bad_delegation_refuses_the_whole_drain(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    attacker = generate_keypair()
    with pytest.raises(ValueError):                          # delegation not signed by THIS owner → refuse at construction
        CompletionSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), owner_pubkey=attacker.public_key_b64,
                               delegation=deleg, scope=_customer_slug())
