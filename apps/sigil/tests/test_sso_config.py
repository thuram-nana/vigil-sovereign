"""PR-H Area 7 — owner-signed per-org SSO/SCIM config (`governor.sso_config`).

Load-bearing invariants (a false-green here would let SSO/SCIM breach the role ceiling or let a forged/replayed
config take effect):
  * THE ROLE CEILING at BIND time: a config can be signed ONLY for roles in {viewer, analyst, org_admin} — never
    operator/founder/owner or any money/offense role (refusal #1 of three);
  * owner-signed DANGEROUS direction (verify + strictly-increasing issued_at); a forged grant is inert;
  * SAFE-direction revoke (even unsigned, fixed issued_at 0.0); anti-replay high-water per org;
  * every security field is in the authenticated core (swap any → the signature breaks);
  * a SAML cert must be real X.509; OIDC signing-algs are asymmetric-only; endpoints are URLs;
  * a SCIM token is stored ONLY as its one-way fingerprint (never the token);
  * LOCKSTEP: the ceiling roles are real rbac roles carrying no forbidden permission; _TENANT_RE and the
    OIDC alg set stay in step with their sources of truth; FATAL-2 (no framework import).
"""
from __future__ import annotations

import datetime
import itertools
import pathlib
import re
import sys
import tempfile

import pytest

from sigil.governor import sso_config as sc
from sigil.governor.sso_config import SsoConfigError, SsoConfigRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, *, owner=OWNER):
    return SsoConfigRegistry(store, owner_key=owner, trusted_pubkey=OP)


def _cert_pem() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example")])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2035, 1, 1))
         .sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM).decode()


CERT = _cert_pem()


def _saml(reg, org="acme", **kw):
    base = dict(idp_entity_id="https://idp", idp_certs_pem=[CERT], sp_entity_id="https://sp/acme",
                acs_url="https://app/acs/acme", issued_at=_issue())
    base.update(kw)
    return reg.set_saml_config(org, **base)


# --- roundtrips -------------------------------------------------------------------------------------

def test_saml_config_roundtrips():
    s = _store()
    reg = _reg(s)
    _saml(reg, group_role_map={"admins": "org_admin", "sec": "analyst"}, default_role="viewer",
          role_cap="org_admin", scim_enabled=True, scim_token="T" * 40)
    c = reg.config("acme")
    assert c is not None and c.protocol == "saml" and c.state == "active"
    assert c.sp_entity_id == "https://sp/acme" and c.group_role_map == {"admins": "org_admin", "sec": "analyst"}
    assert c.idp_certs_pem == (CERT.strip(),)                # stored normalised (outer whitespace trimmed)
    assert reg.config("ghost") is None                       # fail-closed on unknown org


def test_oidc_config_roundtrips():
    s = _store()
    reg = _reg(s)
    reg.set_oidc_config("acme", issuer="https://idp", client_id="cid", jwks_uri="https://idp/jwks",
                        authorize_endpoint="https://idp/a", token_endpoint="https://idp/t",
                        redirect_uri="https://app/cb", signing_algs=("RS256", "ES256"),
                        egress_hosts=("idp",), issued_at=_issue())
    c = reg.config("acme")
    assert c.protocol == "oidc" and c.oidc_signing_algs == ("RS256", "ES256") and c.oidc_egress_hosts == ("idp",)


# --- THE ROLE CEILING at bind time (refusal #1) -----------------------------------------------------

@pytest.mark.parametrize("bad", ["founder", "owner", "operator", "manage_code", "admin", ""])
def test_ceiling_refuses_nonprovisionable_default_role(bad):
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, default_role=bad)


@pytest.mark.parametrize("bad", ["founder", "owner", "operator"])
def test_ceiling_refuses_nonprovisionable_group_role(bad):
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, group_role_map={"g": bad})


@pytest.mark.parametrize("bad", ["founder", "owner", "operator"])
def test_ceiling_refuses_nonprovisionable_role_cap(bad):
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, role_cap=bad)


def test_default_role_above_cap_refused():
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, default_role="org_admin", role_cap="viewer")


def test_group_role_above_cap_refused():
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, group_role_map={"g": "org_admin"}, role_cap="analyst")


# --- owner-signed DANGEROUS direction + forgery ----------------------------------------------------

def test_forged_config_is_inert():
    s = _store()
    _saml(_reg(s, owner=ATTACKER))                            # signed by the attacker, not the trusted owner
    assert _reg(s).config("acme") is None


def test_set_config_requires_owner_key():
    reg = _reg(_store())
    reg.owner_key = None                                     # a provisioner with no owner key must refuse
    with pytest.raises(SsoConfigError):
        _saml(reg)


# --- anti-replay + revoke (safe direction) ----------------------------------------------------------

def test_revoke_then_config_absent_safe_direction():
    s = _store()
    reg = _reg(s)
    _saml(reg)
    assert reg.config("acme") is not None
    reg.revoke_config("acme")
    assert reg.config("acme") is None


def test_captured_active_grant_cannot_resurrect_after_revoke():
    # Mint an active grant, capture its exact payload, revoke, then re-append the capture → refused by high-water.
    s = _store()
    reg = _reg(s)
    _saml(reg)
    captured = None
    for r in s.iter_records():
        p = r.payload
        if isinstance(p, dict) and p.get("signal") == sc.SSO_CONFIG_SIGNAL and p.get("state") == "active":
            captured = p
    assert captured is not None
    reg.revoke_config("acme")
    assert reg.config("acme") is None
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))   # replay the capture
    assert reg.config("acme") is None                        # issued_at <= high-water ⇒ ignored


def test_reactivate_needs_strictly_greater_issued_at():
    s = _store()
    reg = _reg(s)
    reg.set_saml_config("acme", idp_entity_id="https://idp", idp_certs_pem=[CERT], sp_entity_id="https://sp/acme",
                        acs_url="https://app/acs/acme", issued_at=100.0)
    reg.revoke_config("acme")
    reg.set_saml_config("acme", idp_entity_id="https://idp", idp_certs_pem=[CERT], sp_entity_id="https://sp/acme",
                        acs_url="https://app/acs/acme", issued_at=50.0)        # stale: <= high-water
    assert reg.config("acme") is None
    reg.set_saml_config("acme", idp_entity_id="https://idp", idp_certs_pem=[CERT], sp_entity_id="https://sp/acme",
                        acs_url="https://app/acs/acme", issued_at=200.0)       # fresh: > high-water
    assert reg.config("acme") is not None


# --- field validation -------------------------------------------------------------------------------

def test_malformed_cert_refused():
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, idp_certs_pem=["-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"])


def test_saml_requires_a_cert():
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        _saml(reg, idp_certs_pem=[])


@pytest.mark.parametrize("algs", [("none",), ("HS256",), ("RS256", "HS256"), ()])
def test_oidc_rejects_symmetric_or_empty_algs(algs):
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        reg.set_oidc_config("acme", issuer="i", client_id="c", jwks_uri="https://i/j",
                            authorize_endpoint="https://i/a", token_endpoint="https://i/t",
                            redirect_uri="https://a/c", signing_algs=algs, issued_at=_issue())


def test_oidc_rejects_non_https_jwks():
    reg = _reg(_store())
    with pytest.raises(SsoConfigError):
        reg.set_oidc_config("acme", issuer="i", client_id="c", jwks_uri="http://i/j",
                            authorize_endpoint="https://i/a", token_endpoint="https://i/t",
                            redirect_uri="https://a/c", issued_at=_issue())


# --- SCIM token stored only as a one-way fingerprint ------------------------------------------------

def test_scim_token_stored_as_fingerprint_only():
    s = _store()
    reg = _reg(s)
    secret = "SCIM-SECRET-" + "z" * 32
    _saml(reg, scim_enabled=True, scim_token=secret)
    c = reg.config("acme")
    assert c.scim_token_fp == sc.token_fingerprint(secret) and c.scim_token_fp != secret
    # the plaintext token NEVER appears anywhere in the spine record
    for r in s.iter_records():
        import json as _json
        assert secret not in _json.dumps(r.payload)


# --- lockstep / soundness ---------------------------------------------------------------------------

def test_ceiling_roles_are_real_rbac_roles_with_no_forbidden_permission():
    from vigil_core.rbac import PERMISSIONS
    for role in sc.SSO_PROVISIONABLE_ROLES:
        assert role in PERMISSIONS, f"{role} is not a real rbac role"
        perms = PERMISSIONS[role]
        leaked = perms & sc.SSO_FORBIDDEN_PERMISSIONS
        assert not leaked, f"provisionable role {role!r} carries forbidden permission(s) {leaked}"


def test_ceiling_excludes_the_dangerous_roles():
    # founder/operator/owner must NOT be provisionable (they carry run_engagement/offense/money authority).
    assert sc.SSO_PROVISIONABLE_ROLES.isdisjoint({"founder", "operator", "owner"})


def test_tenant_re_matches_engine_paths_literal():
    engine = pathlib.Path(__file__).resolve().parents[3] / "engine" / "crucible" / "framework" / "v2" / "common" / "paths.py"
    if not engine.is_file():
        pytest.skip("engine/crucible not present")
    src = engine.read_text(encoding="utf-8")
    # The engine defines `_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")`. Assert our replicated
    # pattern is exactly that literal (robust substring check — avoids importing framework, which would breach
    # FATAL-2 in a sovereign test).
    assert "_TENANT_RE = re.compile(" in src, "could not find _TENANT_RE in engine paths.py"
    assert f'r"{sc._TENANT_RE.pattern}"' in src, "sso_config._TENANT_RE drifted from the engine literal"


def test_oidc_alg_set_matches_ui_oidc():
    from sigil.ui.oidc import KNOWN_ASYMMETRIC_ALGS
    assert sc._KNOWN_OIDC_ALGS == KNOWN_ASYMMETRIC_ALGS


def test_fatal2_no_framework_import():
    import sigil.governor.sso_config  # noqa: F401
    assert "framework" not in sys.modules and "strix" not in sys.modules


# --- MUTATION PROBE: the bind-time ceiling gate is load-bearing -------------------------------------

def test_mutation_probe_ceiling_gate_is_load_bearing(monkeypatch):
    """If `check_provisionable_role` were weakened to accept any role, THIS test (and the ceiling tests) would
    turn green on a `founder` config — proving those tests actually exercise the guard. Here we assert the guard
    currently refuses `founder`, so breaking it makes a named test red."""
    with pytest.raises(SsoConfigError):
        sc.check_provisionable_role("founder")
    assert sc.check_provisionable_role("org_admin") == "org_admin"
