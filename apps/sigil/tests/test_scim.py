"""PR-H Area 7 — capped owner-signed provisioning + the SCIM bearer secret (`governor.scim`).

Load-bearing invariants:
  * THE CEILING at MINT time (refusal #2): `provision_membership` refuses any role outside {viewer, analyst,
    org_admin}, and never passes a non-ceiling role to `OrgRegistry.grant_membership` (refusal #3);
  * the role is read FROM the owner-signed config (resolve_role), CLAMPED to role_cap and the ceiling — the IdP's
    groups only SELECT among the owner-authored map; they can never introduce a role the owner did not sign;
  * a SCIM bearer token is repr-hidden (never logged/f-stringed) and authenticated by constant-time fingerprint
    compare, org-scoped;
  * sso_username is deterministic + org/IdP-namespaced + charset-safe;
  * LOCKSTEP: the ceiling set equals sso_config's (two independent declarations, asserted equal).
"""
from __future__ import annotations

import itertools
import re
import sys
import tempfile

import pytest

from sigil.governor import scim as gscim
from sigil.governor.scim import BearerToken, ScimError
from sigil.governor.orgs import OrgRegistry, _USERNAME_RE
from sigil.governor.sso_config import SsoConfig
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _orgreg():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    reg = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    return reg


def _cfg(org="acme", *, role_cap="org_admin", default_role="viewer", group_role_map=None, scim_enabled=True,
         scim_token="T" * 40, idp="https://idp"):
    from sigil.governor.sso_config import token_fingerprint
    return SsoConfig(org_id=org, protocol="saml", issued_at=1.0, state="active", idp_entity_id=idp,
                     idp_certs_pem=("PEM",), sp_entity_id=f"https://sp/{org}", acs_url=f"https://app/acs/{org}",
                     default_role=default_role, group_role_map=group_role_map or {}, role_cap=role_cap,
                     scim_enabled=scim_enabled, scim_token_fp=token_fingerprint(scim_token) if scim_token else "")


# --- BearerToken: a repr-hidden secret ---------------------------------------------------------------

def test_bearer_token_never_discloses_the_secret():
    secret = "super-secret-token-value-123456"
    tok = BearerToken(secret)
    assert secret not in repr(tok)
    assert secret not in str(tok)
    assert secret not in f"{tok}"
    assert secret not in "{}".format(tok)
    assert secret not in f"{tok!r}"
    assert repr(tok) == "<BearerToken REDACTED>"


def test_bearer_token_fingerprint_and_constant_time_match():
    from sigil.governor.sso_config import token_fingerprint
    tok = BearerToken("abc")
    assert tok.fingerprint() == token_fingerprint("abc")
    assert tok.matches(token_fingerprint("abc"))
    assert not tok.matches(token_fingerprint("abd"))
    assert not tok.matches("")                               # blank stored fp fails closed
    assert not BearerToken("").matches(token_fingerprint("abc"))   # blank token fails closed


def test_bearer_from_authorization_header():
    assert gscim.bearer_from_authorization_header("Bearer xyz").fingerprint() == BearerToken("xyz").fingerprint()
    assert gscim.bearer_from_authorization_header("bearer xyz") is not None   # case-insensitive scheme
    assert gscim.bearer_from_authorization_header("Basic xyz") is None
    assert gscim.bearer_from_authorization_header("Bearer ") is None
    assert gscim.bearer_from_authorization_header("") is None
    assert gscim.bearer_from_authorization_header(None) is None


# --- authenticate_scim: org-scoped, fail-closed ------------------------------------------------------

def test_authenticate_scim_valid_and_wrong_token():
    cfg = _cfg(scim_token="RIGHT" + "r" * 35)
    assert gscim.authenticate_scim(cfg, BearerToken("RIGHT" + "r" * 35))
    assert not gscim.authenticate_scim(cfg, BearerToken("WRONG"))


def test_authenticate_scim_fail_closed_states():
    assert not gscim.authenticate_scim(None, BearerToken("x"))                   # no config
    assert not gscim.authenticate_scim(_cfg(scim_enabled=False), BearerToken("T" * 40))   # disabled
    assert not gscim.authenticate_scim(_cfg(scim_token=""), BearerToken("T" * 40))        # no fp
    assert not gscim.authenticate_scim(_cfg(), None)                             # no token


def test_authenticate_scim_is_org_scoped():
    # Two orgs, two different tokens: org A's token must NOT authenticate against org B's config.
    cfg_a = _cfg("acme", scim_token="ACME" + "a" * 36)
    cfg_b = _cfg("beta", scim_token="BETA" + "b" * 36)
    assert gscim.authenticate_scim(cfg_a, BearerToken("ACME" + "a" * 36))
    assert not gscim.authenticate_scim(cfg_b, BearerToken("ACME" + "a" * 36))


# --- resolve_role: the role comes from the config, clamped ------------------------------------------

def test_resolve_role_selects_from_map_highest_within_cap():
    cfg = _cfg(group_role_map={"a": "org_admin", "b": "analyst", "c": "viewer"}, role_cap="org_admin")
    assert gscim.resolve_role(cfg, ["b", "a", "c"]) == "org_admin"     # highest mapped wins
    assert gscim.resolve_role(cfg, ["b", "c"]) == "analyst"
    assert gscim.resolve_role(cfg, ["unmapped"]) == "viewer"           # falls back to default_role
    assert gscim.resolve_role(cfg, []) == "viewer"


def test_resolve_role_clamps_to_cap():
    # a group maps to org_admin but the cap is analyst → clamp DOWN to analyst (fail-safe).
    cfg = _cfg(group_role_map={"a": "analyst"}, default_role="viewer", role_cap="viewer")
    # default_role viewer, cap viewer: even if config somehow had a higher map it is clamped. Build one directly:
    cfg2 = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_certs_pem=("PEM",),
                     sp_entity_id="s", acs_url="https://a/b", default_role="viewer",
                     group_role_map={"a": "org_admin"}, role_cap="analyst", scim_enabled=True, scim_token_fp="x")
    assert gscim.resolve_role(cfg2, ["a"]) == "analyst"               # clamped from org_admin to the cap


def test_resolve_role_never_returns_a_non_ceiling_role():
    # Even a hand-built config whose default_role is somehow out of the ceiling returns None (defence in depth).
    bad = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_certs_pem=("PEM",),
                    sp_entity_id="s", acs_url="https://a/b", default_role="founder", group_role_map={},
                    role_cap="owner", scim_enabled=True, scim_token_fp="x")
    assert gscim.resolve_role(bad, []) is None


# --- sso_username: deterministic, namespaced, charset-safe ------------------------------------------

def test_sso_username_is_deterministic_namespaced_and_charset_safe():
    cfg = _cfg("acme", idp="https://idpA")
    u1 = gscim.sso_username(cfg, "user@x")
    assert u1 == gscim.sso_username(cfg, "user@x")                    # deterministic
    assert _USERNAME_RE.match(u1) and u1.startswith("sso_")           # charset-safe membership username
    # different org OR different idp OR different external id → different username
    assert gscim.sso_username(_cfg("beta", idp="https://idpA"), "user@x") != u1
    assert gscim.sso_username(_cfg("acme", idp="https://idpB"), "user@x") != u1
    assert gscim.sso_username(cfg, "other@x") != u1
    assert gscim.sso_username(cfg, "") is None                        # fail-closed on blank


# --- provision_membership: the ceiling gate (refusal #2 / #3) + capped mint ------------------------

@pytest.mark.parametrize("bad", ["founder", "owner", "operator", "manage_code", "", "admin"])
def test_provision_membership_refuses_non_ceiling_role(bad):
    org = _orgreg()
    with pytest.raises(ScimError):
        gscim.provision_membership(org, _cfg(), username="sso_x", role=bad, issued_at=_issue())
    # nothing was minted
    assert org.membership_role("sso_x", "acme") is None


@pytest.mark.parametrize("good", ["viewer", "analyst", "org_admin"])
def test_provision_membership_mints_capped_owner_signed(good):
    org = _orgreg()
    gscim.provision_membership(org, _cfg(), username="sso_alice", role=good, issued_at=_issue())
    # re-read from a FRESH registry to prove the grant is owner-signed on the spine (not just in-memory)
    fresh = OrgRegistry(org.store, owner_key=OWNER, trusted_pubkey=OP)
    assert fresh.membership_role("sso_alice", "acme") == good


def test_provision_into_absent_org_fails_closed_not_crash():
    # An SSO config can outlive its org (config for "ghost", org never created / revoked). grant_membership
    # raises ValueError; provision_membership must surface a clean ScimError (⇒ a 4xx), never let it crash.
    org = _orgreg()                                          # has "acme" only
    with pytest.raises(ScimError):
        gscim.provision_membership(org, _cfg(org="ghost"), username="sso_x", role="viewer", issued_at=_issue())


def test_deactivate_membership_revokes():
    org = _orgreg()
    gscim.provision_membership(org, _cfg(), username="sso_alice", role="analyst", issued_at=_issue())
    assert org.membership_role("sso_alice", "acme") == "analyst"
    gscim.deactivate_membership(org, _cfg(), username="sso_alice")
    assert org.membership_role("sso_alice", "acme") is None


# --- parse_scim_user --------------------------------------------------------------------------------

def test_parse_scim_user():
    u = gscim.parse_scim_user({"userName": "alice", "externalId": "e1", "active": True,
                               "groups": [{"value": "admins"}, {"display": "sec"}], "roles": ["ro"]})
    assert u.user_name == "alice" and u.external_id == "e1" and u.active is True
    assert set(u.groups) == {"admins", "sec", "ro"}
    assert gscim.parse_scim_user("not a dict") is None
    assert gscim.parse_scim_user({}) is None                         # no userName/externalId
    assert gscim.parse_scim_user({"userName": "x"}).active is True   # active defaults True
    assert gscim.parse_scim_user({"userName": "x", "active": False}).active is False


# --- LOCKSTEP + FATAL-2 -----------------------------------------------------------------------------

def test_ceiling_lockstep_with_sso_config():
    from sigil.governor.sso_config import SSO_PROVISIONABLE_ROLES
    assert gscim.SCIM_PROVISIONABLE_ROLES == SSO_PROVISIONABLE_ROLES


def test_fatal2_no_framework_import():
    import sigil.governor.scim  # noqa: F401
    assert "framework" not in sys.modules and "strix" not in sys.modules


# --- MUTATION PROBE: the mint-time ceiling gate is load-bearing -------------------------------------

def test_mutation_probe_mint_ceiling_is_load_bearing():
    with pytest.raises(ScimError):
        gscim._assert_ceiling("founder")
    assert gscim._assert_ceiling("org_admin") == "org_admin"
