"""Consumer PR-C — the provisioner's unified connect actions, their admit gates, and the SELF-RED-PEN.

Vault-backed harness (one persisted owner key throughout, faithful to production). Runs with the integration
PYTHONPATH (the authority broker lives in vigil_integration).

Load-bearing invariants:
  * the READS (overview, poll) are gated on ``view_assessments``; the cloud WRITES (challenge, verify, disconnect)
    on ``run_engagement`` — a billing-only ``org_admin`` is DENIED both (registering/paying != testing authority);
  * ``cloud_connect_verify`` is FAIL-CLOSED when no cloud fetcher is configured;
  * a correct assume-role observation -> owner-signed READ-ONLY grant recorded; a WRONG-account observation ->
    refused, nothing recorded (SELF-RED-PEN: connect an asset you don't own);
  * CROSS-TENANT isolation (SELF-RED-PEN): org B cannot read or disconnect org A's grant;
  * CONNECT != OFFENSE (SELF-RED-PEN connect->offense escalation): recording a cloud grant mints NO
    EngagementAuthority, leaves the ``customer_prod_execution_enabled()`` owner gate untouched, and never unlocks a
    host launch; the poll is a pure read that mints nothing.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.ui.provision import ProvisionDenied, ProvisionError

_iss = itertools.count(1)
ACCT = "123456789012"
ROLE = "arn:aws:iam::123456789012:role/VigilReadOnly"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")             # the PR-C surface ON
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)   # the live-offense owner gate stays OFF


class _StubCloudFetcher:
    """Stands in for the live assume-role + caller-identity reader. ``account_seen`` decides what
    GetCallerIdentity would return (so a 'wrong account' attacker can be simulated)."""
    def __init__(self, *, account_seen=None):
        self.account_seen = account_seen
        self.calls = 0

    def assume(self, *, provider, account_id, role_ref, external_id, now=None):
        self.calls += 1
        return {"assumed_with_external_id": external_id,
                "account": self.account_seen if self.account_seen is not None else account_id}


def _prov(cloud_fetcher=None):
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
                    email_sender=NullEmailSender(), cloud_fetcher=cloud_fetcher,
                    now_fn=lambda: float(next(_iss)))
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


def _connect_cloud(p, user, org, *, account=ACCT):
    """Drive the full connect: challenge then verify (with a good fetcher already wired on p)."""
    p.cloud_connect_challenge(user, org, "aws", account)
    return p.cloud_connect_verify(user, org, "aws", account, ROLE)


# ---- admit gates ---------------------------------------------------------------------------------------------
def test_reads_need_view_assessments_writes_need_run_engagement():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_admin", "org_admin")     # billing admin: NO view_assessments, NO run_engagement
    for call in (
        lambda: p.customer_connect_overview("u_admin", "org_a"),
        lambda: p.customer_ownership_poll("u_admin", "org_a", "apme.cm"),
        lambda: p.cloud_connect_challenge("u_admin", "org_a", "aws", ACCT),
        lambda: p.cloud_disconnect("u_admin", "org_a", "aws", ACCT),
    ):
        with pytest.raises(ProvisionDenied):
            call()


def test_founder_can_read_the_overview_and_poll():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    ov = p.customer_connect_overview("u_f", "org_a")
    assert ov["org_id"] == "org_a" and ov["sites"] == [] and ov["repos"] == [] and ov["cloud"] == []
    poll = p.customer_ownership_poll("u_f", "org_a", "apme.cm")
    assert poll["status"] == "none" and poll["selected_method"] == "meta-tag"


def test_cloud_challenge_then_verify_records_a_read_only_grant():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    assert ch["provider"] == "aws" and ch["account_id"] == ACCT and ch["external_id"]
    res = p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert res["access"] == "read-only" and res["role_ref"] == ROLE
    ov = p.customer_connect_overview("u_f", "org_a")
    assert [(c["provider"], c["account_id"], c["status"]) for c in ov["cloud"]] == [("aws", ACCT, "connected")]


def test_cloud_verify_is_fail_closed_without_a_fetcher():
    p, s, orgs = _prov(cloud_fetcher=None)
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    with pytest.raises(ProvisionError, match="not enabled"):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)


# ---- SELF-RED-PEN: connect an asset you don't own ------------------------------------------------------------
def test_connect_an_account_you_do_not_own_is_refused_and_records_nothing():
    # the attacker claims ACCT but the assumed role lands in a DIFFERENT account (they can only make roles in theirs)
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher(account_seen="999999999999"))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "aws", ACCT)
    with pytest.raises(ProvisionDenied, match="not proven"):
        p.cloud_connect_verify("u_f", "org_a", "aws", ACCT, ROLE)
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "aws", ACCT) is None   # nothing recorded


# ---- SELF-RED-PEN: cross-tenant asset read -------------------------------------------------------------------
def test_cross_tenant_org_b_cannot_read_or_disconnect_org_a_grant():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_a", "operator")
    _seat(orgs, "org_b", "u_b", "operator")
    _connect_cloud(p, "u_a", "org_a")
    # org B's overview never shows org A's grant
    assert p.customer_connect_overview("u_b", "org_b")["cloud"] == []
    # org B disconnecting the SAME account is a no-op on its own (empty) tenant and leaves org A's grant intact
    out = p.cloud_disconnect("u_b", "org_b", "aws", ACCT)
    assert out["disconnected"] is False
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "aws", ACCT) is not None


# ---- SELF-RED-PEN: connect -> offense escalation -------------------------------------------------------------
def test_connecting_a_cloud_account_authorizes_no_offense():
    from vigil_core.posture import customer_prod_execution_enabled
    from sigil.ui.target_authorization import list_targets
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    assert customer_prod_execution_enabled() is False            # the live-offense owner gate starts OFF
    _connect_cloud(p, "u_f", "org_a")                            # a verified READ-ONLY grant now exists
    # 1) connecting minted NO engagement authority on the seam (a cloud grant is not a target authority)
    assert list_targets()["targets"] == []
    # 2) the K4 live-offense owner gate is UNCHANGED (connecting cannot flip it)
    assert customer_prod_execution_enabled() is False
    # 3) a cloud grant does not unlock a HOST launch — the host has no ownership proof, so the launch gate denies
    from sigil.ui.launch_gate import LaunchGate
    r = LaunchGate(s).reserve_launch(requester="u_f", org_id="org_a", host="apme.cm", units=10,
                                     now=float(next(_iss)))
    assert r["ok"] is False


def test_the_poll_is_a_pure_read_and_mints_nothing():
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    from sigil.ui.target_authorization import list_targets
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    p.customer_ownership_poll("u_f", "org_a", "apme.cm")
    p.customer_ownership_poll("u_f", "org_a", "apme.cm")
    # the read created neither an ownership proof/challenge nor an authority
    assert AssetOwnershipRegistry(s, owner_key=None).proof("org_a", "apme.cm") is None
    assert AssetOwnershipRegistry(s, owner_key=None).challenge("org_a", "apme.cm") is None
    assert list_targets()["targets"] == []


# ---- disconnect ----------------------------------------------------------------------------------------------
def test_disconnect_latches_and_is_idempotent():
    p, s, orgs = _prov(cloud_fetcher=_StubCloudFetcher())
    _seat(orgs, "org_a", "u_f", "operator")
    _connect_cloud(p, "u_f", "org_a")
    out = p.cloud_disconnect("u_f", "org_a", "aws", ACCT)
    assert out["disconnected"] is True
    assert p.customer_connect_overview("u_f", "org_a")["cloud"] == []
    again = p.cloud_disconnect("u_f", "org_a", "aws", ACCT)
    assert again["disconnected"] is False       # idempotent
