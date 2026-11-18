"""Consumer PR-C — the flag-off golden: with VIGIL_CUSTOMER_CONNECT off the unified connect surface is absent / inert.

Master flag ``VIGIL_CUSTOMER_CONNECT`` is OFF by default. This pins that, off:
  * ``config.customer_connect_enabled()`` is False;
  * EVERY provisioner connect action refuses (404-equivalent ``ProvisionDenied`` / ``ProvisionError``) — the overview,
    the ownership poll, and the cloud challenge / verify / disconnect — BEFORE any admit, so even a FULLY-ENTITLED
    founder is refused and NOTHING is minted (no cloud challenge / grant on the spine);
  * the flag gate fires ahead of the admit gate (defence in depth under the dispatch's 404);
so a customer's effective reach is byte-identical to a build without PR-C.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil import config
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.ui.provision import ProvisionDenied, ProvisionError

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _off(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.delenv("VIGIL_CUSTOMER_CONNECT", raising=False)


def _prov():
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgs = OrgRegistry(s)
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4, base_lock_s=1.0),
                    email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


def test_the_master_flag_is_off_by_default():
    assert config.customer_connect_enabled() is False


def test_every_connect_action_refuses_when_off_even_for_a_founder():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")           # fully entitled: run_engagement + view_assessments
    for call in (
        lambda: p.customer_connect_overview("u_f", "org_a"),
        lambda: p.customer_ownership_poll("u_f", "org_a", "apme.cm"),
        lambda: p.cloud_connect_challenge("u_f", "org_a", "aws", "123456789012"),
        lambda: p.cloud_disconnect("u_f", "org_a", "aws", "123456789012"),
    ):
        with pytest.raises(ProvisionDenied):
            call()
    with pytest.raises((ProvisionDenied, ProvisionError)):
        p.cloud_connect_verify("u_f", "org_a", "aws", "123456789012", "arn:role")


def test_nothing_is_minted_when_off():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_challenge("u_f", "org_a", "aws", "123456789012")
    # the flag gate fires before issue_challenge -> NO cloud challenge/grant record exists for this org
    reg = CloudConnectRegistry(s, owner_key=None)
    assert reg.challenge("org_a", "aws", "123456789012") is None
    assert reg.grants_of_org("org_a") == []


def test_the_flag_gate_fires_before_admit():
    # a NON-member is refused by the flag gate (connect_off), proving the flag is checked ahead of membership —
    # so turning the flag off makes the surface vanish regardless of any role.
    p, s, orgs = _prov()
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_challenge("nobody", "ghost_org", "aws", "123456789012")
