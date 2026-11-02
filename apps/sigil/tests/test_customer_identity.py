"""Slice E3a — the customer-plane IdentityProvider seam + the shared finish_login tail.

Load-bearing invariants:
  * a provider returns IDENTITY only (CustomerIdentity carries no role/org); PasswordIdentityProvider wraps
    the constant-time verify_login and raises IdentityRefused on a bad credential;
  * finish_login resolves a verified identity to {username, orgs} from the OWNER-SIGNED registries (never a
    claim), and is fail-closed when no ACTIVE customer maps;
  * ISOLATION — a resolved customer username is a cust_ id that is NOT a governor.account (AccountsRegistry
    resolves it to None); finish_login yields only {username, orgs}, so a customer login can never carry an
    operator role.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.accounts import AccountsRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.customer_identity import (METHOD_GOOGLE_OIDC, METHOD_PASSWORD, CustomerIdentity,
                                        IdentityProvider, IdentityRefused, PasswordIdentityProvider)
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64


# ---- unit: CustomerIdentity + PasswordIdentityProvider (no Provisioner) ------------------------------
class _FakeAcct:
    def __init__(self, username, email):
        self.username, self.email = username, email


class _FakeCustomers:
    """Minimal verify_login stand-in: matches (good_email, good_pw) -> acct, else None."""
    def __init__(self, acct, good_email, good_pw):
        self._acct, self._e, self._pw = acct, good_email, good_pw

    def verify_login(self, email, password):
        return self._acct if (email == self._e and password == self._pw) else None


def test_customer_identity_rejects_unknown_method():
    with pytest.raises(ValueError):
        CustomerIdentity(method="totally-not-a-method", email="x@y.z")


def test_customer_identity_carries_no_role():
    idn = CustomerIdentity(method=METHOD_PASSWORD, email="a@b.c", email_verified=True)
    assert not hasattr(idn, "role") and not hasattr(idn, "global_role") and not hasattr(idn, "org_id")


def test_password_provider_verifies_and_refuses():
    prov = PasswordIdentityProvider(_FakeCustomers(_FakeAcct("cust_abc", "a@b.c"), "a@b.c", "pw"))
    assert prov.method == METHOD_PASSWORD
    idn = prov.verify(email="a@b.c", password="pw")
    assert idn.method == METHOD_PASSWORD and idn.email == "a@b.c" and idn.email_verified is True
    with pytest.raises(IdentityRefused):
        prov.verify(email="a@b.c", password="WRONG")
    with pytest.raises(IdentityRefused):
        prov.verify(email="unknown@b.c", password="pw")


def test_identity_provider_is_abstract():
    with pytest.raises(TypeError):
        IdentityProvider()              # abstractmethod verify -> cannot instantiate the ABC directly


# ---- finish_login + the isolation invariant (real Provisioner rig) -----------------------------------
def _prov():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    tokens = EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0)
    rl = LoginRateLimiter(tempfile.mkdtemp(), max_fails=3, window_s=10_000.0, base_lock_s=50.0)
    clock = itertools.count(1)
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet, email_tokens=tokens, rate_limiter=rl,
                    email_sender=NullEmailSender(), trial_credits=100, expose_dev_tokens=True,
                    now_fn=lambda: float(next(clock)))
    return p, s


def _signup(p, email, pw="customer-pw-1", org="Acme"):
    tok = p.request_signup(email, ip="1.1.1.1", now=100.0)["dev_token"]
    return p.confirm_signup(tok, password=pw, org_name=org, now=100.0)


def test_finish_login_resolves_username_and_orgs_for_a_password_identity():
    p, _s = _prov()
    out = _signup(p, "alice@acme.com")
    idn = CustomerIdentity(method=METHOD_PASSWORD, email="alice@acme.com", email_verified=True)
    assert p.finish_login(idn) == {"username": out["username"], "orgs": [out["org_id"]]}


def test_finish_login_is_fail_closed_for_an_unmapped_identity():
    p, _s = _prov()
    # a verified identity whose email maps to no active customer -> refused (never a guessed session)
    with pytest.raises(ProvisionDenied):
        p.finish_login(CustomerIdentity(method=METHOD_PASSWORD, email="ghost@nowhere.com", email_verified=True))
    # an OIDC identity is not resolvable until E2a/E2b -> fail-closed (no login on an un-wired method)
    _signup(p, "real@acme.com")
    with pytest.raises(ProvisionDenied):
        p.finish_login(CustomerIdentity(method=METHOD_GOOGLE_OIDC, email="real@acme.com", email_verified=True))


def test_finish_login_output_is_role_free_and_the_username_is_not_an_operator_account():
    # THE isolation invariant: a resolved customer is a cust_ identity, NEVER a governor.account; finish_login
    # yields only {username, orgs} (no role), so a customer login can never carry an operator role.
    p, s = _prov()
    out = _signup(p, "iso@acme.com")
    result = p.finish_login(CustomerIdentity(method=METHOD_PASSWORD, email="iso@acme.com", email_verified=True))
    assert set(result.keys()) == {"username", "orgs"}          # no role/global_role leaks into the login tail
    assert out["username"].startswith("cust_")
    assert AccountsRegistry(s).account(out["username"]) is None  # a customer is NOT an operator account (disjoint)
