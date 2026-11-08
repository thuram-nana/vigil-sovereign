"""NTF-3 (completion_spool leg) — a verified settle PROJECTS a tenant-scoped ``assessment_outcome`` record.

The gap this closes: a governance-signed engagement-completion drove BILLING settle only — a COMPLETED run
with zero findings, and a FAILED run (credits refunded), left the tenant with NOTHING to see. The settle
drain now appends an advisory, tenant-scoped ``assessment_outcome`` spine record on a FRESH settle, surfaced
by the customer notification centre. These tests pin the load-bearing guarantees of the write leg:

  * a verified COMPLETED settle appends EXACTLY ONE record, org_id/slug/nonce taken from the VERIFIED
    owner-signed lease (never the signal body), outcome from the gov-verified completion, and NO amount;
  * a verified FAILED settle appends one with outcome=failed;
  * an ALREADY-SETTLED re-drive (a second completion for a (slug, nonce) whose marker is already settled)
    appends NO second record — the fresh-settle guard (action == "launch_settled") is load-bearing;
  * a record-append failure NEITHER breaks NOR doubles the settle — the settle commits, the drain does not
    reject/crash, and the money outcome is unchanged (best-effort, strictly separate from the settle decision).

Sovereign leg (the drain is owner-side; the envelope is built with vigil_core + the integration producer,
both framework-free): PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.
"""
from __future__ import annotations

import itertools
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, generate_keypair
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease, write_credit_lease

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _customer_slug(org=ORG, host=HOST):
    from sigil.ui.target_authorization import _customer_slug as cs
    return cs(org, host)


def _reserve(store, *, units=30, credits=100):
    """Seat a member + wallet credits + ownership proof + a customer authority, then reserve + PUBLISH a
    lease. Returns (owner_keypair, reserve_result)."""
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


def _gov_and_delegation(owner, *, not_after=9_000_000_000):
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=_customer_slug(), not_after=not_after)
    return gov, deleg


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _watcher(store, spool, owner, deleg):
    return CompletionSpoolWatcher(
        store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
        scope=_customer_slug(), base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: NOW)


def _outcome_records(store):
    return [r.payload for r in store.iter_records() if getattr(r, "kind", None) == "assessment_outcome"]


def test_completed_settle_appends_exactly_one_tenant_bound_outcome_record():
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _watcher(s, spool, owner, deleg).drain()
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    recs = _outcome_records(s)
    assert len(recs) == 1, recs
    p = recs[0]
    # org_id + slug + nonce are the VERIFIED owner-signed lease's, not the signal body; outcome from the signal
    assert p["org_id"] == ORG
    assert p["engagement_slug"] == r["slug"] == _customer_slug()
    assert p["outcome"] == "completed"
    assert p["nonce"] == r["nonce"]
    assert "ts" in p
    # MONEY DOCTRINE: the record is advisory — it carries NO amount / price / units figure
    assert not ({"amount", "price", "units", "units_reserved", "consumed", "refund"} & set(p))
    assert _avail(s) == 70                                   # flat-per-run completed: full consumed, no refund


def test_failed_settle_appends_one_outcome_failed():
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="failed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _watcher(s, spool, owner, deleg).drain()
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    recs = _outcome_records(s)
    assert len(recs) == 1 and recs[0]["outcome"] == "failed" and recs[0]["org_id"] == ORG
    assert _avail(s) == 100                                  # failed → consumed 0 → full refund


def test_already_settled_redrive_appends_no_second_record():
    # IDEMPOTENCY (the fresh-settle guard is load-bearing). First COMPLETED settle tombstones the lease + marks
    # (slug, nonce) settled and appends ONE record. We then re-write the lease bundle to the seam so a second
    # drain finds a LIVE lease but an ALREADY-SETTLED marker -> settle_launch returns launch_already_settled
    # (NOT launch_settled). The outcome record must NOT be appended a second time: an append on an
    # already-settled no-op would double a tenant's "assessment completed" record.
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    base = os.environ["VIGIL_BASE_DIR"]
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    assert _watcher(s, spool, owner, deleg).drain() == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}
    assert len(_outcome_records(s)) == 1
    assert is_lease_settled(base, r["slug"], r["nonce"]) is True
    assert read_credit_lease(base, r["slug"]) is None       # tombstoned by the first settle
    # resurrect the lease bundle on the seam (bypassing publish_lease's settled-guard) so the re-drive reaches
    # settle_launch with a live lease + an already-settled marker
    signed = SignedCreditLaunchLease.model_validate(r["lease"])
    write_credit_lease(base, r["slug"], signed, _owner_root(owner))
    assert read_credit_lease(base, r["slug"]) is not None
    # a SECOND completion for the SAME (slug, nonce) — a different outcome gives different bytes (not sha256-
    # deduped), so it reaches _settle_one and settle_launch returns launch_already_settled
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="failed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    _watcher(s, spool, owner, deleg).drain()
    assert len(_outcome_records(s)) == 1, "an already-settled re-drive must append NO second outcome record"
    assert _avail(s) == 70                                   # no double settle: still consumed-in-full, no refund


def test_record_append_failure_neither_breaks_nor_doubles_the_settle(monkeypatch):
    # BEST-EFFORT + STRICTLY SEPARATE: inject a store/append error for the assessment_outcome kind ONLY. The
    # settle (which committed BEFORE the record block) must still succeed — the drain does NOT reject/crash and
    # the money outcome is unchanged — and nothing is doubled (the envelope is archived, never re-driven).
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    real_append = s.append

    def _boom_append(*a, **k):
        if k.get("kind") == "assessment_outcome":
            raise RuntimeError("injected assessment_outcome append failure")
        return real_append(*a, **k)

    monkeypatch.setattr(s, "append", _boom_append)
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _watcher(s, spool, owner, deleg).drain()
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out   # settle NOT broken by the append
    assert _outcome_records(s) == []                         # the failed append was swallowed (no record)
    assert _avail(s) == 70                                   # the settle committed correctly (consumed in full)
    assert is_lease_settled(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"]) is True
    # and the envelope was archived as handled, not left to re-drive (no double settle) — a re-drain is a no-op
    monkeypatch.setattr(s, "append", real_append)
    out2 = _watcher(s, spool, owner, deleg).drain()
    assert out2 == {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0}, out2
    assert _outcome_records(s) == [] and _avail(s) == 70
