"""Slice G0 — the provisioner's target_challenge / target_verify (the self-serve billing != testing bridge).

Load-bearing invariants:
  * the flow is gated on admit_customer(run_engagement) — the TESTING axis. A billing-only org_admin (and a
    viewer, and a non-member) is DENIED: paying / administering billing is not authorizing an assessment;
  * target_verify is FAIL-CLOSED when no fetcher is configured (ownership verification OFF by default);
  * a correct published token -> owner-signed proof recorded + owner-signed authority minted (on the seam);
  * a wrong published token -> refused, no authority;
  * requester + org are the server principal (the methods take them as args from the session, not the body).

Runs with the integration PYTHONPATH (the authority broker lives in vigil_integration). Uses a vault-backed
harness (one owner key throughout — faithful to production, unlike the injected-key signup harness).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


class _StubFetcher:
    """Returns a fixed body (what a resolver+GET of the customer's well-known would have seen)."""
    def __init__(self, body: str):
        self.body = body
        self.calls = 0

    def fetch(self, method, host, *, now=None):
        self.calls += 1
        return self.body


def _prov(fetcher=None):
    """A vault-backed Provisioner: all registries default to the ONE persisted owner key (ensure_owner_keypair),
    so the ownership proof, the membership grants, and the authority mint all sign/verify under it."""
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
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                  base_lock_s=1.0),
                    email_sender=NullEmailSender(), target_fetcher=fetcher,
                    now_fn=lambda: float(next(_iss)))
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


# --- the gate: run_engagement (testing axis), never billing -----------------------------------------

def test_challenge_requires_run_engagement_not_billing():
    from sigil.ui.provision import ProvisionDenied
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_admin", "org_admin")     # billing admin, NO run_engagement
    _seat(orgs, "org_b", "u_view", "viewer")
    with pytest.raises(ProvisionDenied):             # a billing org_admin may NOT register assessment targets
        p.target_challenge("u_admin", "org_a", "apme.cm")
    with pytest.raises(ProvisionDenied):
        p.target_challenge("u_view", "org_b", "apme.cm")
    with pytest.raises(ProvisionDenied):             # non-member of the org
        p.target_challenge("u_admin", "org_b", "apme.cm")


def test_operator_gets_a_challenge():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_op", "operator")         # operator carries run_engagement
    ch = p.target_challenge("u_op", "org_a", "apme.cm")
    assert ch["dns_name"] == "_vigil-challenge.apme.cm"
    assert ch["marker"].startswith("vigil-site-verification=")
    assert ch["well_known_url"].endswith("/.well-known/vigil-site-verification.txt")


# --- SS-4: the customer 'Domains' read is tenant-scoped + testing-axis gated ------------------------

def test_customer_assets_tenant_scoped_and_testing_gated():
    """The /api/customer/assets read: a member sees ONLY their own org's assets; another tenant sees none;
    a non-member is denied; and a BILLING-only org_admin (no view_assessments) cannot see the testing-domain
    asset surface (billing-authz != testing-authz)."""
    from sigil.ui.provision import ProvisionDenied
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_op", "operator")         # operator carries view_assessments
    _seat(orgs, "org_b", "u_b", "operator")
    _seat(orgs, "org_c", "u_bill", "org_admin")      # billing admin: NO view_assessments
    ch = p.target_challenge("u_op", "org_a", "apme.cm")
    p.target_fetcher = _StubFetcher(ch["well_known_body"])
    p.target_verify("u_op", "org_a", "apme.cm", "well-known", authorized=True)  # org_a owns apme.cm (proof recorded)

    out = p.customer_assets("u_op", "org_a")                      # org_a's own member
    assert [a["host"] for a in out["assets"]] == ["apme.cm"]
    assert "method" in out["assets"][0]                           # a proof is surfaced (status is time-relative)
    assert p.customer_assets("u_b", "org_b") == {"assets": []}    # a different tenant sees NOTHING of org_a
    with pytest.raises(ProvisionDenied):                          # a non-member of org_a is refused
        p.customer_assets("u_b", "org_a")
    with pytest.raises(ProvisionDenied):                          # billing org_admin cannot read testing assets
        p.customer_assets("u_bill", "org_c")


# --- verify: off-by-default, then the happy path + the refusals ------------------------------------

def test_verify_fail_closed_when_fetcher_disabled():
    from sigil.ui.provision import ProvisionError
    p, s, orgs = _prov(fetcher=None)                 # ownership verification OFF
    _seat(orgs, "org_a", "u_op", "operator")
    p.target_challenge("u_op", "org_a", "apme.cm")
    with pytest.raises(ProvisionError, match="not enabled"):      # the explicit fail-closed guard, pinned
        p.target_verify("u_op", "org_a", "apme.cm", "well-known")


def test_verify_records_proof_and_mints_authority():
    from sigil.ui.provision import Provisioner
    from vigil_core import verify_engagement_authority
    from vigil_integration.live.authorization_broker import read_authorization
    import os
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_op", "operator")
    ch = p.target_challenge("u_op", "org_a", "apme.cm")
    p.target_fetcher = _StubFetcher(ch["well_known_body"])        # the customer published the marker
    r = p.target_verify("u_op", "org_a", "apme.cm", "well-known", authorized=True)
    assert r["slug"].startswith("cust_") and r["scope"] == ["apme.cm"] and r["environment"] == "live"
    got = read_authorization(os.environ["VIGIL_BASE_DIR"], r["slug"])
    assert got is not None
    ok, reason = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert ok, reason
    assert got.signed_authority.document.issued_by == "customer:org_a"
    assert got.signed_authority.document.allow_destructive is False


def test_verify_wrong_token_refused_no_authority():
    from sigil.ui.provision import ProvisionDenied
    from vigil_integration.live.authorization_broker import read_authorization
    import os
    p, s, orgs = _prov(fetcher=_StubFetcher("vigil-site-verification=WRONG"))
    _seat(orgs, "org_a", "u_op", "operator")
    p.target_challenge("u_op", "org_a", "apme.cm")
    with pytest.raises(ProvisionDenied):
        p.target_verify("u_op", "org_a", "apme.cm", "well-known", authorized=True)  # affirmed, but token is WRONG
    # nothing authorized
    from sigil.ui.target_authorization import _customer_slug
    assert read_authorization(os.environ["VIGIL_BASE_DIR"], _customer_slug("org_a", "apme.cm")) is None


def test_verify_requires_run_engagement():
    """Even with a published token, a billing-only org_admin cannot verify+mint (billing != testing)."""
    from sigil.ui.provision import ProvisionDenied
    p, s, orgs = _prov(fetcher=_StubFetcher("vigil-site-verification=whatever"))
    _seat(orgs, "org_a", "u_admin", "org_admin")
    with pytest.raises(ProvisionDenied):
        p.target_verify("u_admin", "org_a", "apme.cm", "well-known", authorized=True)


def test_verify_requires_authorization_affirmation():
    """Option A: the inline 'I am authorized to test this asset' affirmation is REQUIRED + fail-closed. Without
    it NO authority is minted — AND the gate fires BEFORE the network fetch (no token is even read, so a user
    who has not affirmed authorization costs no outbound request)."""
    import os
    from sigil.ui.provision import ProvisionDenied
    from sigil.ui.target_authorization import _customer_slug
    from vigil_integration.live.authorization_broker import read_authorization
    fetcher = _StubFetcher("vigil-site-verification=whatever")
    p, s, orgs = _prov(fetcher=fetcher)
    _seat(orgs, "org_a", "u_op", "operator")
    p.target_challenge("u_op", "org_a", "apme.cm")
    with pytest.raises(ProvisionDenied, match="authorized to test this asset"):
        p.target_verify("u_op", "org_a", "apme.cm", "well-known")          # authorized omitted (defaults False)
    assert fetcher.calls == 0, "the affirmation gate must fire BEFORE the network fetch"
    assert read_authorization(os.environ["VIGIL_BASE_DIR"], _customer_slug("org_a", "apme.cm")) is None


def test_verify_records_authorization_attestation_on_the_owner_signed_spine():
    """The affirmation is recorded as the owner-signed, tamper-evident legal attestation: the verify mint's
    critical audit carries authorization_affirmed=True, bound to the requester + org + target."""
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_op", "operator")
    ch = p.target_challenge("u_op", "org_a", "apme.cm")
    p.target_fetcher = _StubFetcher(ch["well_known_body"])
    seen = []
    real_append = s.append

    def cap(**kw):
        pl = kw.get("payload")
        if isinstance(pl, dict) and pl.get("signal") == "provision.audit":
            seen.append(pl)
        return real_append(**kw)

    s.append = cap
    p.target_verify("u_op", "org_a", "apme.cm", "well-known", authorized=True)
    s.append = real_append
    attested = [pl for pl in seen if pl.get("action") == "target_verify" and pl.get("outcome") == "authorized"]
    assert attested, "the verify mint must write an owner-signed audit"
    assert attested[0].get("authorization_affirmed") is True, "the authorization affirmation must be recorded"
    assert attested[0].get("target") == "apme.cm" and attested[0].get("requester") == "u_op"
