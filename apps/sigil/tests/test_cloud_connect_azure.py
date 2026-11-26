"""Consumer PR-C — the sovereign CloudConnectRegistry, AZURE leg (owner-signed READ-ONLY cloud-grant records).

Invariants pinned here (the Azure twin of test_cloud_connect.py's AWS pins):
  * the deterministic verdict (``cloud_grant_refusal`` / ``cloud_grant_proves``) is PURE, TOTAL and fail-closed: it
    holds ONLY when the token VIGIL got is for THIS tenant (``tid`` == account_id), the admin-set external-id binding
    matched AND is this challenge's id (replay refused), the control tenant is the one derived from this check, and
    the same-shape NEGATIVE CONTROL (a token in a fresh random tenant) was explicitly denied;
  * azure is now a VERIFIABLE provider: issue_challenge + verify_and_connect record a read-only grant on a passing
    verdict and refuse it otherwise (nothing recorded); the tenant id is a lowercase GUID, the role_ref a GUID;
  * the admin-consent placement trusts only VIGIL's client id and binds this challenge's external id;
  * the control-tenant derivation is a deterministic GUID of the control id (re-bound by the verdict).
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

from sigil.governor import cloud_connect as cc
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_c = itertools.count(1)
TENANT = "22222222-2222-2222-2222-222222222222"
OBJ = "33333333-3333-3333-3333-333333333333"        # VIGIL's enterprise-app Object ID in the customer tenant
CTL = "CONTROL-ID"


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return CloudConnectRegistry(store, owner_key=key, trusted_pubkey=pub)


def _obs(ext="EXT", tenant=TENANT, *, matched=True, control=None, denied=True) -> dict:
    """What the trusted Azure fetcher reports: the token's tid, whether the admin-set tag matched, the id it was
    checked against, the derived control tenant and whether the control was explicitly denied."""
    return {"tenant": tenant, "external_id_matched": matched, "external_id": ext,
            "control_tenant": cc.azure_control_tenant(control if control is not None else CTL),
            "control_denied": denied}


def _verify(r, ext="EXT1", *, tenant=TENANT, now=10.0, ttl=None, role=OBJ, **obs):
    kw = {} if ttl is None else {"ttl_seconds": ttl}
    return r.verify_and_connect("acme", "azure", tenant, role_ref=role, observed=_obs(ext, tenant, **obs),
                                control_external_id=CTL, now=now, **kw)


# ---- the pure verdict -----------------------------------------------------------------------------------------
def test_verdict_holds_for_matching_tenant_binding_and_denied_control():
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, _obs("EXT"), control_external_id=CTL) is True
    assert cc.cloud_grant_refusal("azure", "EXT", TENANT, _obs("EXT"), control_external_id=CTL) is None


def test_verdict_refuses_a_wrong_tenant():
    why = cc.cloud_grant_refusal("azure", "EXT", "44444444-4444-4444-4444-444444444444", _obs("EXT"),
                                 control_external_id=CTL)
    assert why is not None and "not proven" in why


def test_verdict_refuses_a_binding_that_did_not_match():
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, _obs("EXT", matched=False), control_external_id=CTL) is False
    for not_true in (None, 1, "true", [True]):
        assert cc.cloud_grant_proves("azure", "EXT", TENANT, {**_obs("EXT"), "external_id_matched": not_true},
                                     control_external_id=CTL) is False, not_true


def test_verdict_refuses_a_replayed_external_id():
    # the observation must belong to THIS challenge: a binding read back for a prior challenge's id is refused
    assert cc.cloud_grant_proves("azure", "NEW", TENANT, _obs("OLD"), control_external_id=CTL) is False


def test_verdict_refuses_a_control_not_denied_or_from_a_different_check():
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, _obs("EXT", denied=False), control_external_id=CTL) is False
    for not_true in (None, 1, "true", [True]):
        assert cc.cloud_grant_proves("azure", "EXT", TENANT, {**_obs("EXT"), "control_denied": not_true},
                                     control_external_id=CTL) is False, not_true
    # the control tenant must be the one derived from THIS check's control id (the observation belongs to this check)
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, _obs("EXT", control="SOMETHING-ELSE"),
                                 control_external_id=CTL) is False
    # a control id equal to the real id proves nothing
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, _obs("EXT", control="EXT"), control_external_id="EXT") is False
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, _obs("EXT"), control_external_id="") is False


def test_verdict_is_total_and_fail_closed_on_bad_shapes():
    good = _obs("EXT")
    assert cc.cloud_grant_proves("azure", "", TENANT, _obs(""), control_external_id=CTL) is False
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, "not-a-dict", control_external_id=CTL) is False
    for missing in ("tenant", "external_id_matched", "external_id", "control_tenant", "control_denied"):
        obs = dict(good)
        del obs[missing]
        assert cc.cloud_grant_proves("azure", "EXT", TENANT, obs, control_external_id=CTL) is False, missing
    assert cc.cloud_grant_proves("azure", "EXT", TENANT, {**good, "tenant": 1, "external_id": 2},
                                 control_external_id=CTL) is False
    for bad in (None, 1, [], object()):
        assert cc.cloud_grant_proves("azure", "EXT", TENANT, bad, control_external_id=CTL) is False


# ---- placement + control-tenant derivation --------------------------------------------------------------------
def test_azure_placement_is_deterministic_and_binds_the_client_id_and_external_id():
    p = cc.azure_placement("11111111-1111-1111-1111-111111111111", TENANT, "EXT-1")
    assert p["admin_consent_url"] == (f"https://login.microsoftonline.com/{TENANT}/adminconsent?"
                                      f"client_id=11111111-1111-1111-1111-111111111111")
    assert p["binding_tag"] == "EXT-1"
    assert p["graph_read"] == ("GET https://graph.microsoft.com/v1.0/servicePrincipals"
                               "(appId='11111111-1111-1111-1111-111111111111')?$select=appId,id,tags")
    assert isinstance(p["steps"], list) and p["steps"]
    assert cc.azure_placement("c", "t", "e") == cc.azure_placement("c", "t", "e")       # deterministic text


def test_azure_control_tenant_is_a_deterministic_guid_of_the_control_id():
    import re
    g = cc.azure_control_tenant("abc")
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", g)
    assert cc.azure_control_tenant("abc") == g and cc.azure_control_tenant("abd") != g


# ---- challenge + verify + record ------------------------------------------------------------------------------
def test_challenge_then_verify_records_a_read_only_grant_carrying_its_external_id():
    s = _store()
    r = _reg(s)
    ch = r.issue_challenge("acme", "azure", TENANT, issued_at=_t(), external_id="EXT1")
    assert ch.external_id == "EXT1" and ch.provider == "azure" and ch.account_id == TENANT
    g = _verify(r, now=100.0, ttl=1000.0)
    assert g.role_ref == OBJ and g.access == "read-only" and g.expires_at == 1100.0 and g.external_id == "EXT1"
    cur = r.grant("acme", "azure", TENANT)
    assert cur is not None and cur.role_ref == OBJ and cur.state == "active" and cur.external_id == "EXT1"
    assert "EXT1" not in repr(cur)
    assert r.has_current_grant("acme", "azure", TENANT, now=500.0) is True
    t = r.assume_target("acme", "azure", TENANT, now=500.0)
    assert t is not None and t.role_ref == OBJ and t.external_id == "EXT1" and "EXT1" not in repr(t)


def test_verify_refuses_a_failing_verdict_and_records_nothing():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "azure", TENANT, issued_at=_t(), external_id="EXT1")
    bad = _obs("EXT1", "44444444-4444-4444-4444-444444444444")
    with pytest.raises(ValueError, match="not proven"):
        r.verify_and_connect("acme", "azure", TENANT, role_ref=OBJ, observed=bad, control_external_id=CTL, now=1.0)
    assert r.grant("acme", "azure", TENANT) is None


def test_verify_refuses_an_unmatched_binding_and_a_control_not_denied():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "azure", TENANT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="binding was not found"):
        _verify(r, "EXT1", matched=False)
    with pytest.raises(ValueError, match="not specific to your tenant"):
        _verify(r, "EXT1", denied=False)
    assert r.grant("acme", "azure", TENANT) is None


def test_bad_azure_account_and_role_are_refused():
    s = _store()
    r = _reg(s)
    with pytest.raises(ValueError, match="lowercase GUID"):
        r.issue_challenge("acme", "azure", "not-a-guid", issued_at=_t())
    r.issue_challenge("acme", "azure", TENANT, issued_at=_t(), external_id="EXT1")
    with pytest.raises(ValueError, match="Object ID"):
        _verify(r, role="not-a-guid")
    assert r.grant("acme", "azure", TENANT) is None


def test_open_challenge_resumes_and_disconnect_retires_both():
    s = _store()
    r = _reg(s)
    ch, resumed = r.open_challenge("acme", "azure", TENANT, issued_at=_t())
    assert resumed is False and len(ch.external_id) >= 32
    again, resumed = r.open_challenge("acme", "azure", TENANT, issued_at=_t())
    assert resumed is True and again.external_id == ch.external_id
    _verify(r, ch.external_id, now=_t())
    r.disconnect("acme", "azure", TENANT)
    assert r.grant("acme", "azure", TENANT) is None and r.challenge("acme", "azure", TENANT) is None


# ---- overview / cross-tenant isolation ------------------------------------------------------------------------
def test_overview_marks_connected_and_hides_the_secret():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "azure", TENANT, issued_at=_t(), external_id="SECRET")
    _verify(r, "SECRET", now=100.0, ttl=1000.0)
    live = r.cloud_overview("acme", now=500.0)
    assert live == [{"provider": "azure", "account_id": TENANT, "role_ref": OBJ, "verified_at": 100.0,
                     "expires_at": 1100.0, "access": "read-only", "status": "connected"}]
    assert r.cloud_overview("acme", now=2000.0)[0]["status"] == "expired"
    assert "SECRET" not in json.dumps(live)
    assert r.cloud_overview("evil", now=500.0) == []


def test_overview_lists_a_started_azure_connection_as_pending():
    s = _store()
    r = _reg(s)
    r.issue_challenge("acme", "azure", TENANT, issued_at=_t(), external_id="SP")
    out = r.cloud_overview("acme", now=1.0)
    assert out == [{"provider": "azure", "account_id": TENANT, "access": "read-only", "status": "pending"}]
    assert "SP" not in json.dumps(out)
    _verify(r, "SP", now=100.0, ttl=1000.0)
    assert [c["status"] for c in r.cloud_overview("acme", now=500.0)] == ["connected"]
