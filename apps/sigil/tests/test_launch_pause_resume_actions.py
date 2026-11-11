"""pause/resume PR-4b — the CUSTOMER pause/resume ACTIONS (the slice that RECORDS a pause, OFF inert).

``LaunchGate.pause_launch``/``resume_launch`` record/clear the ``(slug, nonce)`` pause marker UNDER the spine
lock (the PR-1 caller-serialization); ``provision.launch_pause``/``launch_resume`` gate them
(``customer_pause_resume_enabled`` default-OFF + ``admit_customer(run_engagement)`` + tenant-bind + step-up,
identical to ``launch_cancel``/``launch_start``).

The money-safety the recorded marker drives — HELD at every window (queued / in-flight / gate→arm) → RE-ADMITS
on resume → settles EXACTLY once, never stranded / double-charged / free-run — is the already-merged PR-2..PR-4a
plumbing, proven over this SAME ``is_lease_paused`` marker by
``integration/tests/test_launch_pause_redrive_gate.py`` (gate + runner) and
``test_engage_worker_pause_redrive.py`` (worker). The two planes cannot co-load (FATAL-2), so THIS test proves
the sovereign PRODUCER records/clears exactly that marker, gated + tenant-bound + settled-safe + idempotent, and
that a pause/resume cycle never breaks the single-settle invariant — so the composition is money-safe end to end.

Runs with the integration PYTHONPATH (the authority broker + add_customer_target + credit_lease_pause live
across the seam), mirroring test_launch_gate.py.

Mutation-verify targets (each neuter reds a NAMED test here):
  * pause_launch skips record_lease_pause            -> test_pause_launch_records_the_marker_resume_clears_it
  * drop the expect_org_id tenant-bind on pause      -> test_pause_is_tenant_bound
  * drop the settled refusal in pause_launch         -> test_pause_refuses_a_settled_lease
  * drop the customer_pause_resume_enabled flag gate -> test_launch_pause_is_denied_when_the_flag_is_off
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, role="operator", credits=100, now=1000.0):
    """Seat a member (``operator`` HAS run_engagement) + wallet credits + ownership proof + a minted
    EngagementAuthority — enough for reserve_launch to mint a verifiable lease (copied from test_launch_gate)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", role, issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=1e12)
    r = add_customer_target(host, org_id=org, store=store, now=now)
    assert r["ok"], r


def _gate(store):
    from sigil.ui.launch_gate import LaunchGate
    return LaunchGate(store)


def _paused(slug, nonce):
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    return is_lease_paused(os.environ["VIGIL_BASE_DIR"], slug, nonce)


def _reserve(store, *, org="org_a", host="apme.cm"):
    from vigil_core import SignedCreditLaunchLease
    _setup(store, org, host)
    r = _gate(store).reserve_launch(requester="u", org_id=org, host=host, units=10, now=2000.0)
    assert r["ok"], r
    doc = SignedCreditLaunchLease.model_validate(r["lease"]).document
    return r["lease"], r["slug"], str(doc.nonce)


# ---------------------------------------------------------------- LaunchGate producer (the marker) ----
def test_pause_launch_records_the_marker_resume_clears_it():
    s = _store()
    lease, slug, nonce = _reserve(s)
    assert not _paused(slug, nonce)                                   # default: not paused (feature was inert)
    out = _gate(s).pause_launch(signed_lease=lease, expect_org_id="org_a")
    assert out["ok"] and out["action"] == "launch_paused" and out["slug"] == slug and out["nonce"] == nonce
    assert _paused(slug, nonce)                                       # HELD: the exact marker PR-2..PR-4a check is set
    out2 = _gate(s).resume_launch(signed_lease=lease, expect_org_id="org_a")
    assert out2["ok"] and out2["action"] == "launch_resumed"
    assert not _paused(slug, nonce)                                   # RE-ADMITS: marker cleared → the held launch re-arms


def test_pause_is_tenant_bound():
    s = _store()
    lease, slug, nonce = _reserve(s)
    out = _gate(s).pause_launch(signed_lease=lease, expect_org_id="org_evil")
    assert not out["ok"] and "different org" in out["error"]
    assert not _paused(slug, nonce)                                   # a cross-tenant pause records NOTHING
    # resume is tenant-bound too
    assert not _gate(s).resume_launch(signed_lease=lease, expect_org_id="org_evil")["ok"]


def test_pause_refuses_a_settled_lease():
    s = _store()
    lease, slug, nonce = _reserve(s)
    assert _gate(s).settle_launch(signed_lease=lease, consumed_units=0, now=3000.0, expect_org_id="org_a")["ok"]
    out = _gate(s).pause_launch(signed_lease=lease, expect_org_id="org_a")
    assert not out["ok"] and "settled" in out["error"]               # a settled lease is no longer a runnable launch
    assert not _paused(slug, nonce)


def test_pause_and_resume_are_idempotent():
    s = _store()
    lease, slug, nonce = _reserve(s)
    g = _gate(s)
    assert g.pause_launch(signed_lease=lease, expect_org_id="org_a")["ok"]
    assert g.pause_launch(signed_lease=lease, expect_org_id="org_a")["ok"]    # re-pause: no-op
    assert _paused(slug, nonce)
    assert g.resume_launch(signed_lease=lease, expect_org_id="org_a")["ok"]
    assert g.resume_launch(signed_lease=lease, expect_org_id="org_a")["ok"]   # re-resume: no-op
    assert not _paused(slug, nonce)


def test_a_pause_resume_cycle_does_not_break_single_settle():
    # MONEY-SAFETY: a pause/resume cycle never double-settles or free-runs — the lease settles EXACTLY once
    # (second settle is the idempotent no-op), and pausing moves NO money (availability unchanged by pause).
    from sigil.governor.wallet import WalletRegistry
    s = _store()
    lease, slug, nonce = _reserve(s)
    g = _gate(s)
    avail_after_reserve = WalletRegistry(s).available("org_a")
    assert g.pause_launch(signed_lease=lease, expect_org_id="org_a")["ok"]
    assert WalletRegistry(s).available("org_a") == avail_after_reserve     # pause moved no money
    assert g.resume_launch(signed_lease=lease, expect_org_id="org_a")["ok"]
    first = g.settle_launch(signed_lease=lease, consumed_units=10, now=3000.0, expect_org_id="org_a")
    assert first["ok"] and first["net_spend"] == 10
    second = g.settle_launch(signed_lease=lease, consumed_units=10, now=4000.0, expect_org_id="org_a")
    assert second["ok"] and second["action"] == "launch_already_settled"  # idempotent: never a second charge/refund


# ---------------------------------------------------------------- provision gates (flag / admit / step-up)
def _provisioner(monkeypatch):
    """A minimal Provisioner (mirror test_customer_stepup._prov). The signup-default admin is an ``org_admin``
    WITHOUT run_engagement (billing != testing), so a pause attempt is refused by ADMIT once the flag is on."""
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.reuse import generate_keypair
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    owner = generate_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    orgs = OrgRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=orgs,
        wallet=WalletRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    admin, org = "cust_admin000000000000001", "org_pr4b"
    custs.create("admin@acme.com", issued_at=1.0, password="password-xyz", username=admin)
    orgs.create_org(org, "Acme", owner=admin, issued_at=2.0)
    orgs.grant_membership(org, admin, "org_admin", issued_at=3.0)
    return p, admin, org


def test_launch_pause_is_denied_when_the_flag_is_off(monkeypatch):
    # DEFAULT-OFF: the action is refused BEFORE any admit/lease work — the whole pause substrate stays inert.
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.delenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", raising=False)
    p, admin, org = _provisioner(monkeypatch)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.launch_pause(admin, org, None)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.launch_resume(admin, org, None)


def test_launch_pause_flag_on_refuses_a_non_run_engagement_requester(monkeypatch):
    # Flag ON, but an org_admin without run_engagement is refused by ADMIT (billing != testing) — never reaches
    # the lease. Same gate as launch_cancel/launch_start.
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "1")
    p, admin, org = _provisioner(monkeypatch)
    with pytest.raises(ProvisionDenied) as ei:
        p.launch_pause(admin, org, None)
    assert "may not manage launches" in str(ei.value)


def test_launch_pause_resume_accept_the_mfa_at_stepup_kwarg():
    import inspect

    from sigil.ui.provision import Provisioner
    for name in ("launch_pause", "launch_resume"):
        assert "mfa_at" in inspect.signature(getattr(Provisioner, name)).parameters, \
            f"{name} is missing the mfa_at step-up kwarg"
