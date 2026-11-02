"""Slice E3c — step-up MFA: SessionLedger.mfa_at/mfa_method + the provisioner freshness gate on the sensitive
customer ops (launch / target-verify / member grant+revoke), behind the default-OFF customer_stepup_required().

Load-bearing invariants:
  * the session carries mfa_at/mfa_method ONLY when set (byte-identical otherwise); stamp_mfa updates a LIVE
    session in place (fail-closed on a dead one);
  * _require_stepup is a NO-OP when enforcement is off (byte-identical to pre-E3c), and when ON requires a
    FRESH (within the window) mfa_at — absent / stale / non-positive refuses with ProvisionStepUpRequired;
  * a representative sensitive op (grant_member) enforces step-up end-to-end: off ⇒ proceeds; on ⇒ refused
    without a fresh factor, proceeds with one; the mfa_at is carried from the session (the kwarg), never the body;
  * every one of the 6 sensitive ops accepts the mfa_at kwarg (so none silently skips the gate).
"""
from __future__ import annotations

import inspect
import itertools
import tempfile

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import sessions as _sessions
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionStepUpRequired, Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64
NOW = 10000.0


# ---- SessionLedger: mfa_at / mfa_method + stamp_mfa ---------------------------------------------------
def test_session_mfa_is_byte_identical_when_absent_and_stampable_in_place():
    L = _sessions.SessionLedger(tempfile.mkdtemp())
    plain = L.create("u1", "customer", org_id="org_1")
    assert "mfa_at" not in L.resolve(plain) and "mfa_method" not in L.resolve(plain)   # byte-identical
    mfa = L.create("u2", "customer", org_id="org_1", mfa_at=1000.0, mfa_method="passkey")
    rec = L.resolve(mfa)
    assert rec["mfa_at"] == 1000.0 and rec["mfa_method"] == "passkey"
    assert L.stamp_mfa(plain, mfa_at=2000.0, mfa_method="totp") is True
    r2 = L.resolve(plain)
    assert r2["mfa_at"] == 2000.0 and r2["mfa_method"] == "totp" and r2["org_id"] == "org_1"  # org preserved
    assert L.stamp_mfa("no-such-sid", mfa_at=1.0, mfa_method="totp") is False    # fail-closed on a dead session


# ---- _require_stepup: the gate itself ----------------------------------------------------------------
def _bare():
    return Provisioner.__new__(Provisioner)   # only _require_stepup is exercised (pure; reads config)


def test_require_stepup_is_a_noop_when_disabled(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)
    p = _bare()
    for mfa_at in (None, 0.0, 1.0, NOW - 99999):      # even absent/stale passes when enforcement is off
        p._require_stepup(mfa_at, now=NOW)


def test_require_stepup_enforces_freshness_when_enabled(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p = _bare()
    p._require_stepup(NOW - 10, now=NOW)              # fresh (within 300s window) → passes
    p._require_stepup(NOW, now=NOW)                  # exactly now → passes
    for bad in (None, 0.0, -5.0, "nope", NOW - 301, NOW - 100000):
        with pytest.raises(ProvisionStepUpRequired):
            p._require_stepup(bad, now=NOW)


# ---- a representative sensitive op (grant_member) end-to-end -----------------------------------------
def _prov(monkeypatch, *, stepup=False):
    if stepup:
        monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    else:
        monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=orgs, wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    admin, target, org = "cust_admin000000000000001", "cust_target00000000000001", "org_su1"
    custs.create("admin@acme.com", issued_at=1.0, password="password-xyz", username=admin)
    custs.create("target@acme.com", issued_at=1.0, password="password-xyz", username=target)
    orgs.create_org(org, "Acme", owner=admin, issued_at=2.0)
    orgs.grant_membership(org, admin, "org_admin", issued_at=3.0)
    return p, admin, target, org


def test_grant_member_without_stepup_flag_proceeds(monkeypatch):
    p, admin, target, org = _prov(monkeypatch, stepup=False)
    out = p.grant_member(admin, org, target, "analyst")           # no mfa_at needed when enforcement is off
    assert out["role"] == "analyst" and out["org_id"] == org


def test_grant_member_with_stepup_flag_requires_a_fresh_factor(monkeypatch):
    p, admin, target, org = _prov(monkeypatch, stepup=True)
    with pytest.raises(ProvisionStepUpRequired):                  # no step-up stamp → refused
        p.grant_member(admin, org, target, "analyst", now=NOW)
    with pytest.raises(ProvisionStepUpRequired):                  # a STALE stamp → refused
        p.grant_member(admin, org, target, "analyst", mfa_at=NOW - 400, now=NOW)
    out = p.grant_member(admin, org, target, "analyst", mfa_at=NOW - 10, now=NOW)   # fresh → proceeds
    assert out["role"] == "analyst"


def test_stepup_is_checked_after_admit_not_before(monkeypatch):
    # a NON-member requester is refused by admit (ProvisionDenied), not by step-up — so step-up never leaks
    # "you'd need a factor" to someone who isn't even an admin. (grant_member admits first, inside the lock.)
    p, _admin, target, org = _prov(monkeypatch, stepup=True)
    with pytest.raises(ProvisionDenied) as ei:
        p.grant_member("cust_outsider0000000000001", org, target, "analyst", now=NOW)
    assert not isinstance(ei.value, ProvisionStepUpRequired)


# ---- every sensitive op threads the mfa_at kwarg (no silent skip) ------------------------------------
def test_all_sensitive_ops_accept_the_mfa_at_kwarg():
    for name in ("launch_reserve", "launch_cancel", "launch_start", "target_verify",
                 "grant_member", "revoke_member"):
        sig = inspect.signature(getattr(Provisioner, name))
        assert "mfa_at" in sig.parameters, f"{name} is missing the mfa_at step-up kwarg"
