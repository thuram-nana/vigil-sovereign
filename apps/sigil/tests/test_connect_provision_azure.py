"""Consumer PR-C — the provisioner's cloud leg, AZURE path (the Azure twin of test_connect_provision.py's cloud leg).

Load-bearing invariants pinned here:
  * the Azure challenge hands back the admin-consent placement (VIGIL's client id + the tenant, the external-id
    binding tag, the exact Graph read); a correct observation with the negative control DENIED records an owner-
    signed READ-ONLY grant; an unmatched binding, a wrong tenant, a control that is not denied, or a fetcher failure
    records nothing; the leg fails closed until the owner provisions VIGIL's Azure app, and refuses while off;
  * ``run_engagement`` is required (a billing-only admin is denied); the verify is rate-limited per org; the fetch is
    dispatched to the AZURE fetcher by the challenge's provider — the AWS fetcher is never touched;
  * CROSS-TENANT isolation: org B naming org A's tenant gets its own id and cannot read or disconnect A's grant.
"""
from __future__ import annotations

import itertools
import tempfile
import time

import pytest

from sigil.ui.provision import ProvisionDenied, ProvisionError, ProvisionRateLimited

_iss = itertools.count(1)
CLIENT_ID = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
OBJ = "33333333-3333-3333-3333-333333333333"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)


class _StubAzureFetcher:
    """Stands in for ``ui.cloud_fetch.AzureConsentConnectFetcher``: ``tenant_seen`` decides what the token's tid would
    be, ``external_id_matched`` whether the admin-set tag matched, ``control_denied`` what the negative control saw,
    ``error`` a failure to raise. Records each call. Derives ``control_tenant`` the way the real fetcher does so the
    verdict's control re-bind holds."""

    def __init__(self, *, tenant_seen=None, external_id_matched=True, control_denied=True, error=None):
        self.tenant_seen = tenant_seen
        self.external_id_matched = external_id_matched
        self.control_denied = control_denied
        self.error = error
        self.calls: list = []

    def assume(self, *, provider, account_id, role_ref, external_id, control_external_id, now=None):
        self.calls.append({"external_id": external_id, "control_external_id": control_external_id, "role": role_ref})
        if self.error is not None:
            raise self.error
        from sigil.governor.cloud_connect import azure_control_tenant
        return {"tenant": self.tenant_seen if self.tenant_seen is not None else account_id,
                "external_id_matched": self.external_id_matched, "external_id": external_id,
                "control_tenant": azure_control_tenant(control_external_id), "control_denied": self.control_denied}


def _limiter(max_fails, window):
    from sigil.ui.login_ratelimit import LoginRateLimiter
    return LoginRateLimiter(tempfile.mkdtemp(), max_fails=max_fails, window_s=window, base_lock_s=window,
                            max_lock_s=window)


def _prov(*, azure_fetcher=None, azure_client_id=CLIENT_ID, limiters=True, cloud_max=10):
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
                    email_sender=NullEmailSender(), azure_fetcher=azure_fetcher, azure_client_id=azure_client_id,
                    cloud_connect_limiter=_limiter(cloud_max, 600.0) if limiters else None, now_fn=time.time)
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


# ---- the Azure cloud leg --------------------------------------------------------------------------------------
def test_the_azure_challenge_hands_back_the_admin_consent_placement():
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    assert ch["provider"] == "azure" and ch["account_id"] == TENANT and ch["client_id"] == CLIENT_ID
    assert CLIENT_ID in ch["admin_consent_url"] and TENANT in ch["admin_consent_url"]
    assert ch["binding_tag"] == ch["external_id"] and CLIENT_ID in ch["graph_read"]
    assert isinstance(ch["steps"], list) and ch["steps"]
    assert "trust_policy" not in ch and "principal_arn" not in ch       # not the AWS shape


def test_azure_challenge_then_verify_records_a_read_only_grant_via_the_azure_fetcher():
    f = _StubAzureFetcher()
    p, s, orgs = _prov(azure_fetcher=f)
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    res = p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)
    assert res["provider"] == "azure" and res["account_id"] == TENANT and res["access"] == "read-only"
    assert len(f.calls) == 1 and f.calls[0]["role"] == OBJ and f.calls[0]["external_id"]      # the fetch happened once
    ov = p.customer_connect_overview("u_f", "org_a")
    assert [(c["provider"], c["account_id"], c["status"]) for c in ov["cloud"]] == [("azure", TENANT, "connected")]
    assert ov["available"]["cloud_connect"] is True


def test_azure_verify_refuses_an_unmatched_binding_and_records_nothing():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher(external_id_matched=False))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    with pytest.raises(ProvisionDenied, match="binding"):
        p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "azure", TENANT) is None


def test_azure_verify_refuses_a_control_not_denied_and_a_wrong_tenant():
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher(control_denied=False))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)
    p2, _s2, orgs2 = _prov(azure_fetcher=_StubAzureFetcher(tenant_seen="44444444-4444-4444-4444-444444444444"))
    _seat(orgs2, "org_a", "u_f", "operator")
    p2.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    with pytest.raises(ProvisionDenied):
        p2.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)


def test_azure_fetch_failure_fails_closed_without_echoing_internals():
    from sigil.ui.cloud_fetch import CloudFetchError
    err = CloudFetchError("VIGIL's app has not been admin-consented into this tenant", detail="AADSTS700016")
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher(error=err))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    with pytest.raises(ProvisionDenied, match="admin-consent"):
        p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)


def test_the_azure_leg_fails_closed_until_the_owner_provisions_it():
    for kw in ({"azure_fetcher": None}, {"azure_fetcher": _StubAzureFetcher(), "azure_client_id": ""},
               {"azure_fetcher": _StubAzureFetcher(), "limiters": False}):
        p, s, orgs = _prov(**kw)
        _seat(orgs, "org_a", "u_f", "operator")
        with pytest.raises(ProvisionError):
            p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
        with pytest.raises((ProvisionError, ProvisionDenied)):
            p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)


def test_azure_requires_run_engagement_not_billing_admin():
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher())
    _seat(orgs, "org_a", "u_admin", "org_admin")                 # billing admin: no run_engagement
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_challenge("u_admin", "org_a", "azure", TENANT)


def test_azure_verify_is_rate_limited_per_org():
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher(external_id_matched=False), cloud_max=1)
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "azure", TENANT)
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)
    with pytest.raises(ProvisionRateLimited):
        p.cloud_connect_verify("u_f", "org_a", "azure", TENANT, OBJ)


def test_cross_tenant_org_b_cannot_read_or_disconnect_org_a_azure_grant():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(azure_fetcher=_StubAzureFetcher())
    _seat(orgs, "org_a", "u_a", "operator")
    _seat(orgs, "org_b", "u_b", "operator")
    p.cloud_connect_challenge("u_a", "org_a", "azure", TENANT)
    p.cloud_connect_verify("u_a", "org_a", "azure", TENANT, OBJ)
    assert p.customer_connect_overview("u_b", "org_b")["cloud"] == []
    out = p.cloud_disconnect("u_b", "org_b", "azure", TENANT)
    assert out["disconnected"] is False
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "azure", TENANT) is not None
    resumed = p.cloud_connect_challenge("u_b", "org_b", "azure", TENANT)        # B naming A's tenant gets its own id
    assert resumed["external_id"] != CloudConnectRegistry(s, owner_key=None).challenge("org_a", "azure",
                                                                                       TENANT).external_id
