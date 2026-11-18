"""PR-H Area 7 — the SCIM handler + SSO-login JIT composition (`ui.scim`), end-to-end on a real spine.

This is the END-TO-END + self-red-pen test: owner signs an org + SSO/SCIM config, then an IdP provisions /
logs in, and we assert the membership that lands is OWNER-SIGNED, CEILING-CAPPED and ORG-SCOPED. The three
self-red-pen attacks the task names are here: forge a SAML assertion, SCIM-provision a founder/owner, cross-org.
"""
from __future__ import annotations

import base64
import datetime
import itertools
import json
import tempfile

import pytest

from sigil.governor.orgs import OrgRegistry
from sigil.governor.sso_config import SsoConfigRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import scim as uiscim
from sigil.ui.scim import SsoLoginError

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)
NOW = 1_000_400_000.0


def _issue() -> float:
    return float(next(_iss))


def _cert_pem():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp")])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2035, 1, 1))
         .sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM).decode()


CERT = _cert_pem()


@pytest.fixture
def env():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgreg = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    cfgreg = SsoConfigRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgreg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    orgreg.create_org("beta", "Beta", owner="owner", issued_at=_issue())
    cfgreg.set_saml_config("acme", idp_entity_id="https://idp", idp_certs_pem=[CERT],
                           sp_entity_id="https://sp/acme", acs_url="https://app/acs/acme", default_role="viewer",
                           group_role_map={"admins": "org_admin", "sec": "analyst"}, role_cap="org_admin",
                           scim_enabled=True, scim_token="ACME" + "a" * 36, issued_at=_issue())
    cfgreg.set_saml_config("beta", idp_entity_id="https://idp", idp_certs_pem=[CERT],
                           sp_entity_id="https://sp/beta", acs_url="https://app/acs/beta", scim_enabled=True,
                           scim_token="BETA" + "b" * 36, issued_at=_issue())
    return orgreg, cfgreg


ACME_AUTH = "Bearer ACME" + "a" * 36


def _scim(env, method, path, body, auth=ACME_AUTH, org="acme"):
    orgreg, cfgreg = env
    return uiscim.handle_scim_request(method, path, body, auth, org_id=org, config_registry=cfgreg,
                                      org_registry=orgreg, now=NOW, issued_at=_issue())


# --- SCIM provisioning ------------------------------------------------------------------------------

def test_scim_create_mints_capped_owner_signed_membership(env):
    orgreg, _ = env
    st, body = _scim(env, "POST", "/scim/v2/Users",
                     {"userName": "alice", "externalId": "ext-alice", "groups": [{"value": "admins"}]})
    assert st == 201 and body["roles"] == [{"value": "org_admin"}]
    uname = body["id"]
    # owner-signed on the spine (re-read from a fresh registry)
    fresh = OrgRegistry(orgreg.store, owner_key=OWNER, trusted_pubkey=OP)
    assert fresh.membership_role(uname, "acme") == "org_admin"


def test_scim_create_defaults_to_viewer_for_unmapped_groups(env):
    st, body = _scim(env, "POST", "/scim/v2/Users",
                     {"userName": "bob", "externalId": "ext-bob", "groups": [{"value": "nobody"}]})
    assert st == 201 and body["roles"] == [{"value": "viewer"}]


def test_scim_bad_bearer_401(env):
    st, body = _scim(env, "POST", "/scim/v2/Users", {"userName": "x", "externalId": "e"}, auth="Bearer WRONG")
    assert st == 401


def test_scim_no_bearer_401(env):
    st, _ = _scim(env, "POST", "/scim/v2/Users", {"userName": "x", "externalId": "e"}, auth=None)
    assert st == 401


def test_scim_delete_revokes(env):
    orgreg, _ = env
    _, body = _scim(env, "POST", "/scim/v2/Users", {"userName": "al", "externalId": "e-al"})
    uname = body["id"]
    assert orgreg.membership_role(uname, "acme") == "viewer"
    st, _ = _scim(env, "DELETE", f"/scim/v2/Users/{uname}", None)
    assert st == 204 and orgreg.membership_role(uname, "acme") is None


def test_scim_patch_deactivate_revokes(env):
    orgreg, _ = env
    _, body = _scim(env, "POST", "/scim/v2/Users", {"userName": "al", "externalId": "e-al"})
    uname = body["id"]
    st, _ = _scim(env, "PATCH", f"/scim/v2/Users/{uname}",
                  {"Operations": [{"op": "replace", "value": {"active": False}}]})
    assert st == 200 and orgreg.membership_role(uname, "acme") is None


def test_scim_put_deactivate_revokes(env):
    orgreg, _ = env
    _, body = _scim(env, "POST", "/scim/v2/Users", {"userName": "al", "externalId": "e-al"})
    uname = body["id"]
    st, _ = _scim(env, "PUT", f"/scim/v2/Users/{uname}", {"userName": "al", "externalId": "e-al", "active": False})
    assert st == 200 and orgreg.membership_role(uname, "acme") is None


def test_scim_get_reconcile(env):
    _, body = _scim(env, "POST", "/scim/v2/Users",
                    {"userName": "al", "externalId": "e-al", "groups": [{"value": "sec"}]})
    uname = body["id"]
    st, got = _scim(env, "GET", f"/scim/v2/Users/{uname}", None)
    assert st == 200 and got["roles"] == [{"value": "analyst"}]
    st, lst = _scim(env, "GET", "/scim/v2/Users", None)
    assert st == 200 and lst["totalResults"] == 1
    st, nf = _scim(env, "GET", "/scim/v2/Users/sso_nonexistent", None)
    assert st == 404


def test_scim_unknown_endpoint_404(env):
    st, _ = _scim(env, "GET", "/scim/v2/Groups", None)
    assert st == 404


# --- SELF-RED-PEN #1: SCIM-provision a founder / owner ---------------------------------------------

def test_redpen_scim_cannot_provision_founder_or_owner(env):
    orgreg, _ = env
    # malicious groups literally named 'founder'/'owner' — not keys in the owner-signed map ⇒ they select
    # nothing; only 'admins' maps (to org_admin, the ceiling). The membership is capped org_admin, never higher.
    st, body = _scim(env, "POST", "/scim/v2/Users",
                     {"userName": "mallory", "externalId": "ext-m",
                      "groups": [{"value": "founder"}, {"value": "owner"}, {"value": "admins"}],
                      "roles": [{"value": "owner"}]})
    assert st == 201 and body["roles"] == [{"value": "org_admin"}]
    uname = body["id"]
    role = orgreg.membership_role(uname, "acme")
    assert role == "org_admin"
    assert role not in ("founder", "owner", "operator")
    # and a direct attempt to mint beyond the ceiling via the governor is refused
    from sigil.governor import scim as gscim
    _, cfgreg = env
    for bad in ("founder", "owner", "operator", "manage_code"):
        with pytest.raises(gscim.ScimError):
            gscim.provision_membership(orgreg, cfgreg.config("acme"), username="sso_x", role=bad,
                                       issued_at=_issue())


# --- SELF-RED-PEN #2: cross-org ---------------------------------------------------------------------

def test_redpen_cross_org_token_refused(env):
    # acme's SCIM token must NOT provision into beta (org-scoped auth).
    st, _ = _scim(env, "POST", "/scim/v2/Users", {"userName": "x", "externalId": "e"}, org="beta")
    assert st == 401


def test_redpen_cross_org_no_leak_into_other_tenant(env):
    orgreg, _ = env
    _, body = _scim(env, "POST", "/scim/v2/Users", {"userName": "al", "externalId": "e-al"})
    uname = body["id"]
    # the acme membership must not appear in beta
    assert orgreg.membership_role(uname, "acme") == "viewer"
    assert orgreg.membership_role(uname, "beta") is None


# --- SSO login (SAML) end-to-end + SELF-RED-PEN #3: forge a SAML assertion --------------------------

def _saml_response(aid="s1", aud="https://sp/acme", rcpt="https://app/acs/acme", issuer="https://idp",
                   nameid="saml-user", groups=("sec",)):
    grp = "".join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)
    a = (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}">'
         f'<saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID>{nameid}</saml:NameID>'
         f'<saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="{rcpt}" '
         f'NotOnOrAfter="2001-09-14T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject>'
         f'<saml:Conditions NotBefore="2001-09-13T00:00:00Z" NotOnOrAfter="2001-09-14T00:00:00Z">'
         f'<saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
         f'<saml:AttributeStatement><saml:Attribute Name="groups">{grp}</saml:Attribute></saml:AttributeStatement>'
         f'</saml:Assertion>')
    return (f'<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1" '
            f'Destination="https://app/acs/acme">{a}</samlp:Response>').encode()


def test_sso_login_saml_mints_capped_membership(env):
    orgreg, cfgreg = env
    res = uiscim.sso_login_saml(_saml_response(groups=("sec",)), org_id="acme", config_registry=cfgreg,
                                org_registry=orgreg, replay_ledger=saml_led(), now=NOW,
                                sig_verifier=lambda b, c: frozenset({"s1"}), issued_at=_issue())
    assert res.role == "analyst"
    assert orgreg.membership_role(res.username, "acme") == "analyst"


def test_redpen_forged_saml_assertion_refused(env):
    orgreg, cfgreg = env
    # a forged assertion: the sig_verifier attests NO valid signature → login refused, no membership minted.
    with pytest.raises(SsoLoginError):
        uiscim.sso_login_saml(_saml_response(), org_id="acme", config_registry=cfgreg, org_registry=orgreg,
                              replay_ledger=saml_led(), now=NOW, sig_verifier=lambda b, c: frozenset(),
                              issued_at=_issue())


def test_sso_login_saml_no_config_refused(env):
    orgreg, cfgreg = env
    with pytest.raises(SsoLoginError):
        uiscim.sso_login_saml(_saml_response(), org_id="gamma", config_registry=cfgreg, org_registry=orgreg,
                              replay_ledger=saml_led(), now=NOW, sig_verifier=lambda b, c: frozenset({"s1"}))


def saml_led():
    from sigil.ui.saml import SamlReplayLedger
    return SamlReplayLedger(tempfile.mktemp())


# --- SSO login (enterprise OIDC) end-to-end --------------------------------------------------------

def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _signed_jwt(priv, *, iss, aud, sub, nonce, groups, now=NOW, kid="k1"):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    hdr = _b64u(json.dumps({"alg": "RS256", "kid": kid}).encode())
    payload = _b64u(json.dumps({"iss": iss, "aud": aud, "sub": sub, "nonce": nonce, "exp": now + 300,
                                "iat": now - 10, "groups": groups}).encode())
    sig = priv.sign(f"{hdr}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{hdr}.{payload}.{_b64u(sig)}"


def _rsa_jwk_and_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pn = k.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "k1", "alg": "RS256",
           "n": _b64u(pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")),
           "e": _b64u(pn.e.to_bytes((pn.e.bit_length() + 7) // 8, "big"))}
    return k, jwk


def test_sso_login_oidc_mints_capped_membership(env):
    orgreg, cfgreg = env
    cfgreg.set_oidc_config("gamma", issuer="https://oidc", client_id="cid", jwks_uri="https://oidc/jwks",
                           authorize_endpoint="https://oidc/a", token_endpoint="https://oidc/t",
                           redirect_uri="https://app/cb", signing_algs=("RS256",), egress_hosts=("oidc",),
                           group_role_map={"eng": "analyst"}, issued_at=_issue())
    orgreg.create_org("gamma", "Gamma", owner="owner", issued_at=_issue())
    k, jwk = _rsa_jwk_and_key()
    jwt = _signed_jwt(k, iss="https://oidc", aud="cid", sub="user-123", nonce="N1", groups=["eng"])
    res = uiscim.sso_login_oidc(jwt, org_id="gamma", config_registry=cfgreg, org_registry=orgreg,
                                jwks_keys=[jwk], expected_nonce="N1", now=NOW, issued_at=_issue())
    assert res.role == "analyst" and orgreg.membership_role(res.username, "gamma") == "analyst"


def test_redpen_forged_oidc_token_refused(env):
    orgreg, cfgreg = env
    cfgreg.set_oidc_config("gamma", issuer="https://oidc", client_id="cid", jwks_uri="https://oidc/jwks",
                           authorize_endpoint="https://oidc/a", token_endpoint="https://oidc/t",
                           redirect_uri="https://app/cb", signing_algs=("RS256",), issued_at=_issue())
    orgreg.create_org("gamma", "Gamma", owner="owner", issued_at=_issue())
    k, jwk = _rsa_jwk_and_key()
    other, _ = _rsa_jwk_and_key()                           # a DIFFERENT key signs → signature invalid under jwk
    forged = _signed_jwt(other, iss="https://oidc", aud="cid", sub="evil", nonce="N1", groups=["eng"])
    with pytest.raises(SsoLoginError):
        uiscim.sso_login_oidc(forged, org_id="gamma", config_registry=cfgreg, org_registry=orgreg,
                              jwks_keys=[jwk], expected_nonce="N1", now=NOW, issued_at=_issue())


def test_redpen_oidc_wrong_nonce_refused(env):
    orgreg, cfgreg = env
    cfgreg.set_oidc_config("gamma", issuer="https://oidc", client_id="cid", jwks_uri="https://oidc/jwks",
                           authorize_endpoint="https://oidc/a", token_endpoint="https://oidc/t",
                           redirect_uri="https://app/cb", signing_algs=("RS256",), issued_at=_issue())
    orgreg.create_org("gamma", "Gamma", owner="owner", issued_at=_issue())
    k, jwk = _rsa_jwk_and_key()
    jwt = _signed_jwt(k, iss="https://oidc", aud="cid", sub="u", nonce="N1", groups=[])
    with pytest.raises(SsoLoginError):
        uiscim.sso_login_oidc(jwt, org_id="gamma", config_registry=cfgreg, org_registry=orgreg,
                              jwks_keys=[jwk], expected_nonce="DIFFERENT", now=NOW, issued_at=_issue())


# --- the config cap bounds the provisioned role end-to-end -----------------------------------------

def test_config_cap_bounds_provisioned_role(env):
    orgreg, cfgreg = env
    # A config CAPPED at analyst: bind-time already forbids mapping a group above the cap, so the strongest role
    # an IdP can ever be provisioned here is analyst — org_admin is unreachable for this org end-to-end.
    orgreg.create_org("capped", "Capped", owner="owner", issued_at=_issue())
    cfgreg.set_saml_config("capped", idp_entity_id="https://idp", idp_certs_pem=[CERT],
                           sp_entity_id="https://sp/capped", acs_url="https://app/acs/capped",
                           default_role="viewer", group_role_map={"staff": "analyst"}, role_cap="analyst",
                           scim_enabled=True, scim_token="CAP" + "c" * 37, issued_at=_issue())
    # the owner COULD NOT have mapped a group above the cap — prove it:
    import pytest as _pt
    from sigil.governor.sso_config import SsoConfigError
    with _pt.raises(SsoConfigError):
        cfgreg.set_saml_config("capped", idp_entity_id="https://idp", idp_certs_pem=[CERT],
                               sp_entity_id="https://sp/capped", acs_url="https://app/acs/capped",
                               group_role_map={"x": "org_admin"}, role_cap="analyst", issued_at=_issue())
    st, body = uiscim.handle_scim_request(
        "POST", "/scim/v2/Users", {"userName": "u", "externalId": "e", "groups": [{"value": "staff"}]},
        "Bearer CAP" + "c" * 37, org_id="capped", config_registry=cfgreg, org_registry=orgreg, now=NOW,
        issued_at=_issue())
    assert st == 201 and body["roles"] == [{"value": "analyst"}]     # the cap is the ceiling for this org
