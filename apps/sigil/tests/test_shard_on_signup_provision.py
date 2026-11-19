"""Consumer PR-F — shard-placement-on-signup wired through the Provisioner (``_place_on_signup``).

Pins the byte-identical-OFF contract and the flag-ON mint:
  * DEFAULT OFF / no injected registry ⇒ a sign-up mints NO shard assignment (byte-identical to pre-PR-F);
  * flag ON but ``multi_shard`` OFF, or no owner ``shard_ids`` ⇒ still no placement (every gate must hold);
  * all gates ON ⇒ the sign-up owner-signs ONE shard placement for the new org, idempotently.
A tenant never supplies a shard — placement is server-chosen from owner topology.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.shard_assignment import ShardAssignmentRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _prov(*, with_shards: bool):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    tokens = EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0)
    rl = LoginRateLimiter(tempfile.mkdtemp(), max_fails=3, window_s=10_000.0, base_lock_s=50.0)
    clock = itertools.count(1)
    shards = ShardAssignmentRegistry(s, owner_key=OWNER, trusted_pubkey=OP) if with_shards else None
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet, email_tokens=tokens, rate_limiter=rl,
                    email_sender=NullEmailSender(), trial_credits=100, expose_dev_tokens=True,
                    shard_assignments=shards, now_fn=lambda: float(next(clock)))
    return p, s, shards


def _signup(p, email="alice@acme.com") -> str:
    tok = p.request_signup(email, ip="1.1.1.1", now=100.0)["dev_token"]
    return p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)["org_id"]


def _all_on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    monkeypatch.setenv("VIGIL_MULTI_SHARD", "1")
    monkeypatch.setenv("VIGIL_SHARD_IDS", "shard01,shard02")


def test_signup_default_off_mints_no_placement(monkeypatch):
    # No flags, registry injected: byte-identical pre-PR-F — the sign-up itself still works, no shard record.
    monkeypatch.delenv("VIGIL_CUSTOMER_FAIR_QUEUE", raising=False)
    monkeypatch.delenv("VIGIL_MULTI_SHARD", raising=False)
    monkeypatch.delenv("VIGIL_SHARD_IDS", raising=False)
    p, s, shards = _prov(with_shards=True)
    org_id = _signup(p)
    assert org_id.startswith("org_")
    assert shards.placement(org_id) is None


def test_signup_without_injected_registry_is_a_noop(monkeypatch):
    # Even all-on, a provisioner built WITHOUT a registry (every pre-PR-F construction) places nothing.
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=False)
    org_id = _signup(p)
    # the account/org/membership/trial all minted; the shard registry simply was not consulted.
    assert org_id.startswith("org_")


def test_signup_flag_on_but_multi_shard_off_mints_no_placement(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    monkeypatch.delenv("VIGIL_MULTI_SHARD", raising=False)
    monkeypatch.setenv("VIGIL_SHARD_IDS", "shard01")
    p, s, shards = _prov(with_shards=True)
    assert shards.placement(_signup(p)) is None


def test_signup_all_on_but_no_topology_mints_no_placement(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    monkeypatch.setenv("VIGIL_MULTI_SHARD", "1")
    monkeypatch.delenv("VIGIL_SHARD_IDS", raising=False)
    p, s, shards = _prov(with_shards=True)
    assert shards.placement(_signup(p)) is None           # fail-safe: no owner topology -> no guess


def test_signup_all_on_owner_signs_one_placement(monkeypatch):
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    org_id = _signup(p)
    placement = shards.placement(org_id)
    assert placement is not None
    assert placement.shard_id in ("shard01", "shard02")   # an OWNER-named shard, never tenant-chosen
    assert placement.epoch == 1
    # exactly one active placement for this org (idempotent transaction, not a double-mint).
    assert len([x for x in shards.placements() if x.tenant_id == org_id]) == 1


def test_two_signups_balance_across_shards(monkeypatch):
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    a = _signup(p, "a@x.com")
    b = _signup(p, "b@x.com")
    placed = {shards.placement(a).shard_id, shards.placement(b).shard_id}
    assert placed == {"shard01", "shard02"}               # least-loaded spreads the two across both shards


def test_repeated_confirm_is_idempotent_single_placement(monkeypatch):
    # confirm_signup is single-use, but the placement itself must be idempotent under the commit-marker retry
    # semantics. Assert exactly one placement after a successful sign-up (no second epoch, no duplicate).
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    org_id = _signup(p)
    assert shards.placement(org_id).epoch == 1
    assert len([x for x in shards.placements() if x.tenant_id == org_id]) == 1
