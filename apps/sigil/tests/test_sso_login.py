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
    st, _ = _scim(env, "GET", "/scim/v2/Bogus", None)
    assert st == 404
    st, _ = _scim(env, "GET", "/scim/v2/Users/a/b", None)          # a deeper path is no resource either
    assert st == 404
    st, body = _scim(env, "GET", "/scim/v2/Groups", None)          # Groups is served (the HTTP-edge slice)
    assert st == 200 and body["totalResults"] == 0


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
    cfgreg.disable_scim("acme", issued_at=_issue())         # SCIM off ⇒ just-in-time provisioning at sign-in
    res = uiscim.sso_login_saml(_saml_response(groups=("sec",)), org_id="acme", config_registry=cfgreg,
                                org_registry=orgreg, replay_ledger=saml_led(), now=NOW,
                                sig_verifier=lambda b, c: frozenset({"s1"}), issued_at=_issue())
    assert res.role == "analyst" and res.seq is not None
    assert orgreg.membership_role(res.username, "acme") == "analyst"


def test_sso_login_saml_scim_managed_org_links_to_the_directory_and_never_jit_provisions(env):
    orgreg, cfgreg = env                                     # acme's config has SCIM ON ⇒ directory-managed
    with pytest.raises(SsoLoginError):                       # not pushed by SCIM ⇒ refused, nothing minted
        uiscim.sso_login_saml(_saml_response(aid="s0", nameid="saml-user"), org_id="acme", config_registry=cfgreg,
                              org_registry=orgreg, replay_ledger=saml_led(), now=NOW,
                              sig_verifier=lambda b, c: frozenset({"s0"}), issued_at=_issue())
    assert [m for m in orgreg.memberships("acme")] == []
    # the IdP pushes the person (userName == the NameID it asserts) ⇒ sign-in links to that SCIM member
    st, body = _scim(env, "POST", "/scim/v2/Users",
                     {"userName": "saml-user", "externalId": "okta-00u1", "groups": [{"value": "sec"}]})
    assert st == 201
    res = uiscim.sso_login_saml(_saml_response(aid="s2", nameid="SAML-USER"), org_id="acme", config_registry=cfgreg,
                                org_registry=orgreg, replay_ledger=saml_led(), now=NOW,
                                sig_verifier=lambda b, c: frozenset({"s2"}), issued_at=_issue())
    assert res.username == body["id"] and res.role == "analyst" and res.seq is None   # linked, nothing minted
    # deactivated in the directory ⇒ a still-valid assertion can never sign them back in
    _scim(env, "PATCH", f"/scim/v2/Users/{body['id']}", {"Operations": [{"op": "replace", "path": "active",
                                                                        "value": "False"}]})
    with pytest.raises(SsoLoginError):
        uiscim.sso_login_saml(_saml_response(aid="s3", nameid="saml-user"), org_id="acme", config_registry=cfgreg,
                              org_registry=orgreg, replay_ledger=saml_led(), now=NOW,
                              sig_verifier=lambda b, c: frozenset({"s3"}), issued_at=_issue())
    assert orgreg.membership_role(body["id"], "acme") is None


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


def _signed_jwt(priv, *, iss, aud, sub, nonce, groups, now=NOW, kid="k1", **claims):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    hdr = _b64u(json.dumps({"alg": "RS256", "kid": kid}).encode())
    payload = _b64u(json.dumps({"iss": iss, "aud": aud, "sub": sub, "nonce": nonce, "exp": now + 300,
                                "iat": now - 10, "groups": groups, **claims}).encode())
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


# --- SCIM-managed sign-in: the link is the DIRECTORY's, never a derived username; the role follows the config -----

_aid = itertools.count(1)


def _saml_in(env, nameid, *, audit=None, groups=()):
    """A verified SAML sign-in to acme (SCIM on in `env`) asserting `nameid` (and `groups`, which a directory-managed
    org ignores: only a just-in-time org selects by the assertion's groups)."""
    orgreg, cfgreg = env
    aid = f"sx{next(_aid)}"
    return uiscim.sso_login_saml(_saml_response(aid=aid, nameid=nameid, groups=groups), org_id="acme",
                                 config_registry=cfgreg, org_registry=orgreg, replay_ledger=saml_led(), now=NOW,
                                 sig_verifier=lambda b, c: frozenset({aid}), issued_at=_issue(), audit=audit)


GAMMA_AUTH = "Bearer GAMMA" + "g" * 36


@pytest.mark.parametrize("protocol,renamed", [("saml", "userName"), ("saml", "externalId"), ("oidc", "externalId")])
def test_scim_on_sign_in_refuses_a_subject_no_directory_user_carries(env, protocol, renamed):
    """A directory user's id is derived from the userName / externalId it was CREATED with. Once the IdP renames that
    attribute, the old value names a DIFFERENT person (the IdP cannot even provision them: their derived id is taken),
    so a sign-in asserting it is refused as not-in-the-directory — never resolved to the derived id, i.e. admitted as
    the renamed member with the renamed member's role."""
    orgreg, cfgreg = env
    org, auth = "acme", ACME_AUTH
    if protocol == "oidc":
        org, auth = "gamma", GAMMA_AUTH
        orgreg.create_org("gamma", "Gamma", owner="owner", issued_at=_issue())
        cfgreg.set_oidc_config("gamma", issuer="https://oidc", client_id="cid", jwks_uri="https://oidc/jwks",
                               authorize_endpoint="https://oidc/a", token_endpoint="https://oidc/t",
                               redirect_uri="https://app/cb", signing_algs=("RS256",), egress_hosts=("oidc",),
                               group_role_map={"admins": "org_admin"}, scim_enabled=True,
                               scim_token=GAMMA_AUTH[len("Bearer "):], issued_at=_issue())
    k, jwk = _rsa_jwk_and_key()

    def sign_in(subject: str):
        if protocol == "saml":
            return _saml_in(env, subject)
        jwt = _signed_jwt(k, iss="https://oidc", aud="cid", sub=subject, nonce="N1", groups=[])
        return uiscim.sso_login_oidc(jwt, org_id=org, config_registry=cfgreg, org_registry=orgreg,
                                     jwks_keys=[jwk], expected_nonce="N1", now=NOW, issued_at=_issue())

    old, new = (("alice@acme.test", "alice.smith@acme.test") if renamed == "userName"
                else ("okta-00ua", "okta-00ua-v2"))
    user = {"userName": "alice@acme.test", "groups": [{"value": "admins"}]}
    if renamed == "externalId":
        user["externalId"] = old
    st, alice = _scim(env, "POST", "/scim/v2/Users", user, auth=auth, org=org)
    assert st == 201 and alice["roles"] == [{"value": "org_admin"}]
    st, _ = _scim(env, "PATCH", f"/scim/v2/Users/{alice['id']}",
                  {"Operations": [{"op": "replace", "path": renamed, "value": new}]}, auth=auth, org=org)
    assert st == 200
    with pytest.raises(SsoLoginError, match="is not in it"):
        sign_in(old)
    assert orgreg.membership_role(alice["id"], org) == "org_admin"           # the renamed member is untouched
    res = sign_in(new)                                                       # control: the CURRENT value links
    assert res.username == alice["id"] and res.role == "org_admin" and res.seq is None


def test_scim_on_sign_in_links_by_letter_case_only_never_a_case_folding_look_alike(env):
    ids = {}
    for name in ("sam@acme.test", "kate@acme.test"):
        st, b = _scim(env, "POST", "/scim/v2/Users", {"userName": name, "groups": [{"value": "admins"}]})
        assert st == 201
        ids[name] = b["id"]
    # a DIFFERENT IdP account whose NameID only casefolds to a member's userName: LONG S folds to s, KELVIN SIGN to k
    for look_alike in ("\u017fam@acme.test", "\u212aate@acme.test"):
        with pytest.raises(SsoLoginError, match="is not in it"):
            _saml_in(env, look_alike)
    assert _saml_in(env, "SAM@ACME.TEST").username == ids["sam@acme.test"]       # letter case alone still links
    assert _saml_in(env, "Kate@Acme.Test").username == ids["kate@acme.test"]


def _resign_acme(env, **kw) -> None:
    """The owner re-signs acme's SAML config (SCIM stays on with the same bearer) with a new role policy."""
    _, cfgreg = env
    cfgreg.set_saml_config("acme", idp_entity_id="https://idp", idp_certs_pem=[CERT], sp_entity_id="https://sp/acme",
                           acs_url="https://app/acs/acme", default_role="viewer", scim_enabled=True,
                           scim_token=ACME_AUTH[len("Bearer "):], issued_at=_issue(), **kw)


def test_scim_on_sign_in_clamps_a_role_above_the_current_config_and_gives_back_only_what_it_took(env):
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _, carl = _scim(env, "POST", "/scim/v2/Users", {"userName": "carl@acme.test", "groups": [{"value": "sec"}]})
    assert orgreg.membership_role(bob["id"], "acme") == "org_admin"
    assert orgreg.membership_role(carl["id"], "acme") == "analyst"
    # (1) the owner TIGHTENS the cap: Admins now maps to analyst, nothing above it
    _resign_acme(env, group_role_map={"admins": "analyst", "sec": "analyst"}, role_cap="analyst")

    def boom(*_a):
        raise OSError("audit store unavailable")
    with pytest.raises(OSError):                                             # the clamp is audited FIRST: no row,
        _saml_in(env, "bob@acme.test", audit=boom)                           # no grant and no admission
    assert orgreg.membership_role(bob["id"], "acme") == "org_admin"
    audits: list = []
    res = _saml_in(env, "bob@acme.test", audit=lambda *a: audits.append(a))
    assert res.username == bob["id"] and res.role == "analyst" and res.seq is not None
    assert orgreg.membership_role(bob["id"], "acme") == "analyst"             # brought down by an owner-signed grant
    assert audits == [("sso_role_clamp", bob["id"], "role=analyst was=org_admin")]
    res = _saml_in(env, "carl@acme.test", audit=lambda *a: audits.append(a))  # control: already within the policy
    assert res.role == "analyst" and res.seq is None and len(audits) == 1
    # (2) the owner REMOVES the Admins mapping: Bob now resolves to the config's default role
    _resign_acme(env, group_role_map={"sec": "analyst"}, role_cap="analyst")
    res = _saml_in(env, "bob@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "viewer" and orgreg.membership_role(bob["id"], "acme") == "viewer"
    assert audits[1:] == [("sso_role_clamp", bob["id"], "role=viewer was=analyst")]
    # (3) the owner LOOSENS it again: the sign-in gives back what the clamps took (org_admin: the second clamp kept
    # the FIRST one's note, as the live grant was the first clamp's), and nothing more happens after that
    _resign_acme(env, group_role_map={"admins": "org_admin", "sec": "analyst"}, role_cap="org_admin")
    res = _saml_in(env, "bob@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "org_admin" and res.seq is not None and orgreg.membership_role(bob["id"], "acme") == "org_admin"
    assert audits[2:] == [("sso_role_restore", bob["id"], "role=org_admin was=viewer")]
    assert _directory(env).user(bob["id"]).clamp == ()                       # fully given back: the note is spent
    res = _saml_in(env, "bob@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "org_admin" and res.seq is None and len(audits) == 3
    # (4) Carl was never clamped: a looser config does not raise HIM at sign-in (that waits for the IdP's next write)
    _resign_acme(env, group_role_map={"admins": "org_admin", "sec": "org_admin"}, role_cap="org_admin")
    res = _saml_in(env, "carl@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "analyst" and res.seq is None and len(audits) == 3


def test_scim_on_sign_in_leaves_a_role_the_owner_set_outside_the_ceiling(env):
    orgreg, _ = env
    _, dana = _scim(env, "POST", "/scim/v2/Users", {"userName": "dana@acme.test", "groups": [{"value": "sec"}]})
    orgreg.grant_membership("acme", dana["id"], "founder", issued_at=_issue())  # the owner's own hand-set grant
    audits: list = []
    res = _saml_in(env, "dana@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "founder" and res.seq is None and audits == []        # never clamped to the config's analyst
    assert orgreg.membership_role(dana["id"], "acme") == "founder"


def test_scim_on_sign_in_refuses_when_the_config_resolves_no_role(env):
    import dataclasses
    orgreg, cfgreg = env
    _scim(env, "POST", "/scim/v2/Users", {"userName": "eve@acme.test", "groups": [{"value": "sec"}]})
    cfg = cfgreg.config("acme")
    # a hand-built config no ceiling role resolves under (a signed one cannot exist: bind time refuses it)
    broken = dataclasses.replace(cfg, default_role="founder", role_cap="founder")
    with pytest.raises(SsoLoginError, match="no provisionable role"):
        uiscim._login_principal(orgreg, broken, subject="eve@acme.test", groups=(), issued_at=_issue())
    assert uiscim._login_principal(orgreg, cfg, subject="eve@acme.test", groups=(), issued_at=_issue()).role == "analyst"


def test_a_refused_clamp_grant_is_a_clean_sign_in_refusal(env, monkeypatch):
    from sigil.governor import scim as gscim
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _resign_acme(env, group_role_map={"sec": "analyst"}, role_cap="analyst")

    def refuse(*_a, **_k):
        raise gscim.ScimError("the mint refused")
    monkeypatch.setattr(gscim, "provision_membership", refuse)
    with pytest.raises(SsoLoginError, match="the mint refused"):              # the edge's uniform refusal, never a 500
        _saml_in(env, "bob@acme.test")
    assert orgreg.membership_role(bob["id"], "acme") == "org_admin"


# --- SCIM-managed sign-in: each refusal on the link has its own isolating test ----------------------------------------

def _scim_dispatch(env, method, path, body, *, audit=None):
    orgreg, cfgreg = env
    return uiscim.scim_dispatch(method, path, body, ACME_AUTH, org_id="acme", config_registry=cfgreg,
                                org_registry=orgreg, now=NOW, issued_at=_issue(), audit=audit)


def _directory(env):
    from sigil.governor.scim_directory import ScimDirectoryRegistry
    orgreg, _ = env
    return ScimDirectoryRegistry(orgreg.store, owner_key=OWNER, trusted_pubkey=OP).directory("acme")


_DEACTIVATE = {"Operations": [{"op": "replace", "path": "active", "value": False}]}


@pytest.mark.parametrize("how", ["revoke-never-landed", "owner-regrant", "jit-regrant-while-scim-was-off"])
def test_scim_on_sign_in_refuses_a_deactivated_directory_user_even_with_a_live_membership(env, how):
    """A deactivation normally also revokes the membership, so `no active membership` refuses first. In each state
    below the directory says INACTIVE while a membership is still live, and the active check is the only barrier:
    the critical audit before the revoke failed (the IdP retries later); the owner re-granted the person by hand;
    or the owner turned SCIM off, a just-in-time sign-in re-granted the derived id, and SCIM came back on."""
    orgreg, cfgreg = env
    st, dave = _scim(env, "POST", "/scim/v2/Users", {"userName": "dave@acme.test", "groups": [{"value": "admins"}]})
    assert st == 201
    uid = dave["id"]
    assert _saml_in(env, "dave@acme.test").role == "org_admin"                     # control: active, admitted
    if how == "revoke-never-landed":
        def audit(action, target, outcome):
            if action == "scim_deactivate":
                raise OSError("audit store unavailable")
        with pytest.raises(OSError):
            _scim_dispatch(env, "PATCH", f"/scim/v2/Users/{uid}", _DEACTIVATE, audit=audit)
    else:
        assert _scim_dispatch(env, "PATCH", f"/scim/v2/Users/{uid}", _DEACTIVATE).status == 200
        assert orgreg.membership_role(uid, "acme") is None
        if how == "owner-regrant":
            orgreg.grant_membership("acme", uid, "founder", issued_at=_issue())
        else:
            cfgreg.disable_scim("acme", issued_at=_issue())
            assert _saml_in(env, "dave@acme.test", groups=("admins",)).username == uid
            _resign_acme(env, group_role_map={"admins": "org_admin", "sec": "analyst"}, role_cap="org_admin")
    assert _directory(env).user(uid).active is False and orgreg.membership_role(uid, "acme") is not None
    with pytest.raises(SsoLoginError, match="deactivated"):
        _saml_in(env, "dave@acme.test")


def test_scim_on_sign_in_refuses_an_active_directory_user_whose_membership_was_revoked(env):
    orgreg, _ = env
    st, fay = _scim(env, "POST", "/scim/v2/Users", {"userName": "fay@acme.test", "groups": [{"value": "sec"}]})
    assert st == 201 and _saml_in(env, "fay@acme.test").role == "analyst"          # control: admitted
    orgreg.revoke_membership("acme", fay["id"])                                    # the owner revokes her by hand
    assert _directory(env).user(fay["id"]).active is True                          # the IdP still lists her
    with pytest.raises(SsoLoginError, match="no active membership"):
        _saml_in(env, "fay@acme.test")


# --- the clamp: WHICH member it re-grants, and from WHAT it resolves -------------------------------------------------

def _second_admin(env) -> None:
    """A non-SSO administrator (the org's founder), so no clamp below is the org's last administrator's."""
    orgreg, _ = env
    orgreg.grant_membership("acme", "cust_founder", "founder", issued_at=_issue())


def test_the_clamp_lands_on_the_linked_directory_user_of_an_okta_shaped_member(env):
    """Okta / Entra always send an externalId, so the member's id derives from it — never from the userName the NameID
    carries. The clamp must re-grant THAT id and nothing else (no membership for the NameID-derived id)."""
    orgreg, _ = env
    _second_admin(env)
    st, rae = _scim(env, "POST", "/scim/v2/Users", {"userName": "rae@acme.test", "externalId": "00u-rae",
                                                   "groups": [{"value": "admins"}]})
    assert st == 201 and orgreg.membership_role(rae["id"], "acme") == "org_admin"
    before = {m.username: m.role for m in orgreg.memberships("acme")}
    _resign_acme(env, group_role_map={"admins": "analyst", "sec": "analyst"}, role_cap="analyst")
    res = _saml_in(env, "rae@acme.test")
    assert res.username == rae["id"] and res.role == "analyst"
    assert {m.username: m.role for m in orgreg.memberships("acme")} == {**before, rae["id"]: "analyst"}


def test_the_clamp_never_re_roles_the_member_a_derived_id_would_name(env):
    """After a rename the NameID-derived id belongs to a DIFFERENT member: Pat, created as pat@acme.test with no
    externalId (his id derives from that name), is renamed; Quinn (Okta-shaped) now carries pat@acme.test. The clamp
    at Quinn's sign-in lands on Quinn alone, and Pat's role is untouched."""
    orgreg, _ = env
    _second_admin(env)
    _, pat = _scim(env, "POST", "/scim/v2/Users", {"userName": "pat@acme.test"})
    assert orgreg.membership_role(pat["id"], "acme") == "viewer"
    st, _ = _scim(env, "PATCH", f"/scim/v2/Users/{pat['id']}",
                  {"Operations": [{"op": "replace", "path": "userName", "value": "pat.old@acme.test"}]})
    assert st == 200
    st, quinn = _scim(env, "POST", "/scim/v2/Users", {"userName": "pat@acme.test", "externalId": "00u-quinn",
                                                     "groups": [{"value": "admins"}]})
    assert st == 201 and quinn["id"] != pat["id"] and orgreg.membership_role(quinn["id"], "acme") == "org_admin"
    _resign_acme(env, group_role_map={"admins": "analyst", "sec": "analyst"}, role_cap="analyst")
    res = _saml_in(env, "pat@acme.test")
    assert res.username == quinn["id"] and orgreg.membership_role(quinn["id"], "acme") == "analyst"
    assert orgreg.membership_role(pat["id"], "acme") == "viewer"


def test_the_clamp_resolves_the_role_from_the_directory_never_from_the_assertion(env):
    """A directory-managed org ignores the assertion's groups: the clamp resolves what the DIRECTORY gives the user
    under the current config, even when the assertion names a group that maps higher."""
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    assert orgreg.membership_role(bob["id"], "acme") == "org_admin"
    _resign_acme(env, group_role_map={"sec": "analyst"}, role_cap="org_admin")       # the Admins mapping is gone
    res = _saml_in(env, "bob@acme.test", groups=("sec",))                            # the assertion claims sec
    assert res.role == "viewer" and orgreg.membership_role(bob["id"], "acme") == "viewer"


# --- identifiers padded with whitespace: refused at every entry, never trimmed into a member's ----------------------

_PADS = [" ", "　", " "]


def _gamma_oidc_scim(env):
    """gamma: enterprise OIDC with SCIM on (directory-managed)."""
    orgreg, cfgreg = env
    orgreg.create_org("gamma", "Gamma", owner="owner", issued_at=_issue())
    cfgreg.set_oidc_config("gamma", issuer="https://oidc", client_id="cid", jwks_uri="https://oidc/jwks",
                           authorize_endpoint="https://oidc/a", token_endpoint="https://oidc/t",
                           redirect_uri="https://app/cb", signing_algs=("RS256",), egress_hosts=("oidc",),
                           group_role_map={"admins": "org_admin"}, scim_enabled=True,
                           scim_token=GAMMA_AUTH[len("Bearer "):], issued_at=_issue())


@pytest.mark.parametrize("pad", _PADS, ids=lambda p: f"U+{ord(p):04X}")
def test_an_oidc_subject_or_object_id_padded_with_whitespace_never_signs_in_as_a_member(env, pad):
    """An id_token `sub` / `oid` that differs from a member's userName / externalId only by surrounding whitespace is
    a DIFFERENT IdP identifier that merely renders like it: the sign-in is refused, never trimmed into the member."""
    orgreg, cfgreg = env
    _gamma_oidc_scim(env)
    st, kate = _scim(env, "POST", "/scim/v2/Users", {"userName": "kate@acme.test", "externalId": "oid-kate",
                                                    "groups": [{"value": "admins"}]}, auth=GAMMA_AUTH, org="gamma")
    assert st == 201
    k, jwk = _rsa_jwk_and_key()

    def sign_in(sub, **claims):
        jwt = _signed_jwt(k, iss="https://oidc", aud="cid", sub=sub, nonce="N1", groups=[], **claims)
        return uiscim.sso_login_oidc(jwt, org_id="gamma", config_registry=cfgreg, org_registry=orgreg,
                                     jwks_keys=[jwk], expected_nonce="N1", now=NOW, issued_at=_issue())
    for padded in (pad + "kate@acme.test", "kate@acme.test" + pad):
        with pytest.raises(SsoLoginError, match="begins or ends with whitespace"):
            sign_in(padded)
    with pytest.raises(SsoLoginError, match="begins or ends with whitespace"):
        sign_in("someone-else", oid="oid-kate" + pad)
    assert sign_in("kate@acme.test").username == kate["id"]                           # controls: exact values link
    assert sign_in("someone-else", oid="oid-kate").username == kate["id"]


@pytest.mark.parametrize("pad", _PADS, ids=lambda p: f"U+{ord(p):04X}")
def test_a_just_in_time_subject_padded_with_whitespace_mints_nothing(env, pad):
    """Just-in-time, a padded subject would derive the SAME membership id as the unpadded one (the derivation trims):
    it is refused before that, and nothing is minted."""
    orgreg, cfgreg = env
    cfgreg.disable_scim("acme", issued_at=_issue())
    cfg = cfgreg.config("acme")
    for padded in (pad + "carol@acme.test", "carol@acme.test" + pad):
        with pytest.raises(SsoLoginError, match="begins or ends with whitespace"):
            uiscim._login_principal(orgreg, cfg, subject=padded, groups=("admins",), issued_at=_issue())
    assert orgreg.memberships("acme") == []
    res = uiscim._login_principal(orgreg, cfg, subject="carol@acme.test", groups=("admins",), issued_at=_issue())
    assert res.role == "org_admin" and res.seq is not None                            # control: minted


@pytest.mark.parametrize("attr", ["userName", "externalId"])
def test_scim_refuses_an_identifier_padded_with_whitespace_never_trims_it(env, attr):
    """A SCIM write whose userName / externalId begins or ends with whitespace is refused (400 invalidValue) — never
    trimmed into a member's identifier (which surfaced as a uniqueness collision, or re-keyed the member)."""
    orgreg, _ = env
    st, kate = _scim(env, "POST", "/scim/v2/Users", {"userName": "kate@acme.test", "externalId": "00u-kate"})
    assert st == 201
    padded = {"userName": "kate@acme.test ", "externalId": "00u-kate "}[attr]
    other = {"userName": "other@acme.test", "externalId": "00u-other"}
    for method, path, body in (
            ("POST", "/scim/v2/Users", {**other, attr: padded}),
            ("PUT", f"/scim/v2/Users/{kate['id']}", {"userName": "kate@acme.test", "externalId": "00u-kate",
                                                      attr: padded}),
            ("PATCH", f"/scim/v2/Users/{kate['id']}", {"Operations": [{"op": "replace", "path": attr,
                                                                       "value": padded}]}),
            ("PATCH", f"/scim/v2/Users/{kate['id']}", {"Operations": [{"op": "replace", "value": {attr: padded}}]})):
        st, body = _scim(env, method, path, body)
        assert st == 400 and body["scimType"] == "invalidValue" and "whitespace" in body["detail"], (method, body)
    st, b = _scim(env, "GET", f"/scim/v2/Users/{kate['id']}", None)
    assert (b["userName"], b["externalId"]) == ("kate@acme.test", "00u-kate")        # kate is unchanged
    st, b = _scim(env, "POST", "/scim/v2/Users", other)
    assert st == 201                                                                  # control: exact values land


# --- the clamp's give-back, and the org's last administrator ---------------------------------------------------------

def test_a_transient_config_mistake_heals_at_the_next_sign_in(env):
    """A re-sign that forgot the group map (e.g. a certificate rotation re-run without --group-role) lowers every SCIM
    member who signs in meanwhile; once the owner restores the map, each one's next sign-in gives the role back."""
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _resign_acme(env, group_role_map={}, role_cap="org_admin")                       # the mistake
    assert _saml_in(env, "bob@acme.test").role == "viewer"
    _resign_acme(env, group_role_map={"admins": "org_admin", "sec": "analyst"}, role_cap="org_admin")   # restored
    res = _saml_in(env, "bob@acme.test")
    assert res.role == "org_admin" and orgreg.membership_role(bob["id"], "acme") == "org_admin"


def test_the_give_back_never_undoes_a_change_made_after_the_clamp(env):
    """The give-back applies only while the clamp's own grant is still the live one: a role the owner sets by hand
    after the clamp stands (a sign-in never raises it), while an IdP write that leaves the membership as it was keeps
    the note."""
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _, eve = _scim(env, "POST", "/scim/v2/Users", {"userName": "eve@acme.test", "groups": [{"value": "admins"}]})
    _resign_acme(env, group_role_map={}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "viewer" and _saml_in(env, "eve@acme.test").role == "viewer"
    orgreg.grant_membership("acme", bob["id"], "analyst", issued_at=_issue())        # the owner's own later change
    st, _ = _scim(env, "PATCH", f"/scim/v2/Users/{eve['id']}",                      # an IdP write; membership as is
                  {"Operations": [{"op": "replace", "path": "displayName", "value": "Eve E."}]})
    assert st == 200 and orgreg.membership_role(eve["id"], "acme") == "viewer"
    _resign_acme(env, group_role_map={"admins": "org_admin"}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "analyst"                           # the owner's change stands
    assert _saml_in(env, "eve@acme.test").role == "org_admin"                         # given back


def test_the_give_back_is_never_more_than_the_clamp_took(env):
    """A member is given back at most the role the clamp took — partly while the config allows less, the rest once it
    allows it — never a role it did not hold (any further raise waits for the IdP's next write)."""
    _second_admin(env)
    _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _scim(env, "POST", "/scim/v2/Users", {"userName": "carl@acme.test", "groups": [{"value": "sec"}]})
    _resign_acme(env, group_role_map={}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "viewer" and _saml_in(env, "carl@acme.test").role == "viewer"
    _resign_acme(env, group_role_map={"admins": "analyst", "sec": "org_admin"}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "analyst"           # partly: the config allows only analyst now
    assert _saml_in(env, "carl@acme.test").role == "analyst"          # never more than the clamp took
    _resign_acme(env, group_role_map={"admins": "org_admin", "sec": "org_admin"}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "org_admin"         # the rest, once the config allows it
    assert _saml_in(env, "carl@acme.test").role == "analyst"


def test_a_refused_audit_before_the_give_back_grants_nothing(env):
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _resign_acme(env, group_role_map={}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "viewer"
    _resign_acme(env, group_role_map={"admins": "org_admin"}, role_cap="org_admin")

    def boom(action, *_a):
        if action == "sso_role_restore":
            raise OSError("audit store unavailable")
    with pytest.raises(OSError):                                       # audited FIRST: no row, no grant
        _saml_in(env, "bob@acme.test", audit=boom)
    assert orgreg.membership_role(bob["id"], "acme") == "viewer"
    assert _saml_in(env, "bob@acme.test").role == "org_admin"         # control: with the audit up it is given back


def test_a_note_naming_a_role_outside_the_ceiling_gives_nothing_back(env):
    orgreg, _ = env
    _second_admin(env)
    _, bob = _scim(env, "POST", "/scim/v2/Users", {"userName": "bob@acme.test", "groups": [{"value": "admins"}]})
    _resign_acme(env, group_role_map={}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "viewer"
    d = _directory(env)
    u = d.user(bob["id"])
    assert u.clamp[0] == "org_admin"
    d.put_user(u.id, user_name=u.user_name, active=True, selectors=u.selectors, clamp=("founder", u.clamp[1]),
               now=_issue())
    _resign_acme(env, group_role_map={"admins": "org_admin"}, role_cap="org_admin")
    assert _saml_in(env, "bob@acme.test").role == "viewer" and orgreg.membership_role(bob["id"], "acme") == "viewer"


def test_the_clamp_never_demotes_the_orgs_last_administrator(env):
    """`sigil org demote-founders` keeps each founder an administrator; an SSO-managed ex-founder whose config resolves
    lower is then NOT clamped below administrator while no other administrator exists — the clamp waits until one
    does (the owner's own membership verbs refuse to orphan an org likewise)."""
    from sigil.ui.provision import owner_demote_founders
    orgreg, _ = env
    _resign_acme(env, group_role_map={"sec": "analyst"}, role_cap="analyst")
    _, fay = _scim(env, "POST", "/scim/v2/Users", {"userName": "fay@acme.test", "groups": [{"value": "sec"}]})
    orgreg.grant_membership("acme", fay["id"], "founder", issued_at=_issue())
    assert _saml_in(env, "fay@acme.test").role == "founder"                           # outside the ceiling: as set
    owner_demote_founders(orgreg.store, reason="pre-rollback", issued_at=_issue(), orgs=orgreg)
    assert orgreg.membership_role(fay["id"], "acme") == "org_admin"
    audits: list = []
    res = _saml_in(env, "fay@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "org_admin" and res.seq is None and audits == []               # the last admin is kept
    _second_admin(env)                                                                # another administrator appears
    res = _saml_in(env, "fay@acme.test", audit=lambda *a: audits.append(a))
    assert res.role == "analyst" and audits == [("sso_role_clamp", fay["id"], "role=analyst was=org_admin")]
