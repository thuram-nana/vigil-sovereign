"""PR-H edge — the unit contracts beneath the SSO / SCIM HTTP edge (the attacks end to end are in test_sso_edge.py).

  * `governor.sso_config`: the per-org ROTATABLE SCIM bearer (the old token dies at once; only a fingerprint is ever
    stored), disable-SCIM, the signed IdP sign-in URL (https only; inside the signature), the re-sign helper in
    lockstep with the authenticated core, and CROSS-ORG EXCLUSIVITY — no two orgs may share a SAML audience, an OIDC
    client or a SCIM bearer (refused at sign time; a legacy/hand-made collision is inert for BOTH orgs);
  * `ui.saml`: the SP-initiated AuthnRequest (escaped, raw-DEFLATE HTTP-Redirect, https-only) and the InResponseTo
    binding the ACS enforces;
  * `ui.sso_edge`: the single-use, kind-bound, expiring login-state ledger; the SCIM path parser; the public URLs;
  * `ui.sso_provision`: production enterprise-OIDC egress pinned to the owner-signed host allowlist; every leg
    fails closed without its ledger / limiter;
  * `ui.server`: the closed SSO/SCIM dispatch and its flag-gated body caps; `build_provisioner` wires the SSO
    ledgers ONLY while the flag is on;
  * `governor.scim.provision_membership` never appends an inert (stale) grant;
  * `sigil sso` (the owner CLI): the bearer is written once to a 0600 file and never printed; roles above the
    ceiling, an existing token file and a symlinked token path are refused.
"""
from __future__ import annotations

import base64
import datetime
import itertools
import json
import os
import re
import stat
import tempfile
import threading
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from types import SimpleNamespace

import pytest

from sigil.governor import sso_config as sc
from sigil.governor.orgs import OrgRegistry
from sigil.governor.sso_config import SsoConfig, SsoConfigError, SsoConfigRegistry, token_fingerprint
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import saml as uisaml
from sigil.ui import sso_edge, sso_provision

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return SsoConfigRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


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
    base = dict(idp_entity_id="https://idp", idp_certs_pem=[CERT], idp_sso_url="https://idp/sso",
                sp_entity_id=f"https://sp/{org}", acs_url="https://app/acs", issued_at=_issue())
    base.update(kw)
    return reg.set_saml_config(org, **base)


def _oidc(reg, org="acme", **kw):
    base = dict(issuer="https://idp", client_id=f"cid-{org}", jwks_uri="https://idp/jwks",
                authorize_endpoint="https://idp/a", token_endpoint="https://idp/t", redirect_uri="https://app/cb",
                egress_hosts=("idp",), issued_at=_issue())
    base.update(kw)
    return reg.set_oidc_config(org, **base)


# =====================================================================================================================
# governor.sso_config
# =====================================================================================================================
def test_rotate_scim_token_retires_the_old_token_and_stores_only_a_fingerprint():
    from sigil.governor.scim import BearerToken, authenticate_scim
    s = _store()
    reg = _reg(s)
    _saml(reg, scim_enabled=True, scim_token="OLD-" + "o" * 40, group_role_map={"Admins": "org_admin"})
    before = reg.config("acme")
    _seq, tok = reg.rotate_scim_token("acme", issued_at=_issue())
    after = reg.config("acme")
    assert len(tok) >= 43 and after.scim_enabled and after.scim_token_fp == token_fingerprint(tok)
    assert authenticate_scim(after, BearerToken(tok)) and not authenticate_scim(after, BearerToken("OLD-" + "o" * 40))
    # everything else is re-signed UNCHANGED
    for f in sc._CONFIG_CORE:
        if f not in ("signal", "state", "issued_at", "scim_token_fp", "scim_enabled"):
            assert getattr(after, f) == getattr(before, f), f
    raw = json.dumps([r.payload for r in s.iter_records()])
    assert tok not in raw and "OLD-" + "o" * 40 not in raw          # never the plaintext, old or new
    # a stale issued_at is bumped past the config's high-water (a rotation is never silently inert)
    _seq, tok2 = reg.rotate_scim_token("acme", issued_at=0.5)
    assert reg.config("acme").scim_token_fp == token_fingerprint(tok2)


def test_rotate_refuses_without_owner_key_or_active_config_or_with_a_weak_token():
    s = _store()
    reg = _reg(s)
    with pytest.raises(SsoConfigError):
        reg.rotate_scim_token("acme", issued_at=_issue())            # no config
    _saml(reg)
    for weak in ("short", "x" * 31, "has a space" + "x" * 30, "ctl\x01" + "x" * 30):
        with pytest.raises(SsoConfigError):
            reg.rotate_scim_token("acme", issued_at=_issue(), token=weak)
    keyless = SsoConfigRegistry(s, owner_key=None, trusted_pubkey=OP)
    keyless.owner_key = None
    with pytest.raises(SsoConfigError):
        keyless.rotate_scim_token("acme", issued_at=_issue())


def test_disable_scim_turns_the_bearer_off_and_keeps_sign_in():
    s = _store()
    reg = _reg(s)
    _saml(reg, scim_enabled=True, scim_token="T" * 40)
    reg.disable_scim("acme", issued_at=_issue())
    c = reg.config("acme")
    assert c is not None and c.protocol == "saml" and not c.scim_enabled and c.scim_token_fp == ""


def test_core_from_config_is_in_lockstep_with_the_authenticated_core():
    s = _store()
    reg = _reg(s)
    _saml(reg)
    core = sc._core_from_config(reg.config("acme"), issued_at=9.0)
    assert set(core) == set(sc._CONFIG_CORE)
    with pytest.raises(SsoConfigError):
        sc._core_from_config(reg.config("acme"), issued_at=9.0, not_a_core_field=1)


def test_the_idp_sign_in_url_is_signed_and_https_only():
    assert "idp_sso_url" in sc._CONFIG_CORE
    s = _store()
    reg = _reg(s)
    with pytest.raises(SsoConfigError):
        _saml(reg, idp_sso_url="http://idp/sso")                    # a browser is redirected there: https only
    _saml(reg)
    assert reg.config("acme").idp_sso_url == "https://idp/sso"
    # re-point the signed sign-in URL at a look-alike page: the signature breaks → the record is inert
    rec = [r for r in s.iter_records() if isinstance(r.payload, dict)
           and r.payload.get("signal") == sc.SSO_CONFIG_SIGNAL][-1].payload
    forged = dict(rec, idp_sso_url="https://idp.evil.example/sso", issued_at=float(rec["issued_at"]) + 100)
    s.append(kind="event", source="governor", actor="WARDEN", payload=forged)
    assert reg.config("acme").idp_sso_url == "https://idp/sso"


@pytest.mark.parametrize("clash", ["saml-audience", "oidc-client", "scim-token"])
def test_cross_org_exclusivity_is_refused_at_sign_time(clash):
    s = _store()
    reg = _reg(s)
    if clash == "saml-audience":
        _saml(reg, "acme")
        with pytest.raises(SsoConfigError, match="'acme'"):
            _saml(reg, "beta", sp_entity_id="https://sp/acme")
    elif clash == "oidc-client":
        _oidc(reg, "acme")
        with pytest.raises(SsoConfigError, match="'acme'"):
            _oidc(reg, "beta", client_id="cid-acme")
        _oidc(reg, "gamma", client_id="cid-acme", issuer="https://other-idp")   # another issuer's client: fine
    else:
        _saml(reg, "acme", scim_enabled=True, scim_token="SHARED-" + "s" * 40)
        with pytest.raises(SsoConfigError, match="SCIM bearer token") as e:
            _saml(reg, "beta", scim_enabled=True, scim_token="SHARED-" + "s" * 40)
        assert token_fingerprint("SHARED-" + "s" * 40) not in str(e.value)    # never echoes the fingerprint
        _saml(reg, "beta", scim_enabled=True, scim_token="BETA-" + "b" * 40)
        with pytest.raises(SsoConfigError):
            reg.rotate_scim_token("beta", issued_at=_issue(), token="SHARED-" + "s" * 40)
    assert reg.config("acme") is not None                                      # the first org is untouched
    if clash == "saml-audience":
        _saml(reg, "acme", default_role="analyst")                             # re-signing the SAME org is fine


@pytest.mark.parametrize("clash", ["saml-audience", "oidc-client", "scim-token"])
def test_a_legacy_cross_org_collision_is_inert_for_both_orgs(clash, monkeypatch):
    s = _store()
    reg = _reg(s)
    if clash == "saml-audience":
        _saml(reg, "acme")
    elif clash == "oidc-client":
        _oidc(reg, "acme")
    else:
        _saml(reg, "acme", scim_enabled=True, scim_token="SHARED-" + "s" * 40)
    monkeypatch.setattr(SsoConfigRegistry, "_refuse_cross_org_clash", lambda self, core: None)  # a hand-made record
    if clash == "saml-audience":
        _saml(reg, "beta", sp_entity_id="https://sp/acme")
    elif clash == "oidc-client":
        _oidc(reg, "beta", client_id="cid-acme")
    else:
        _saml(reg, "beta", scim_enabled=True, scim_token="SHARED-" + "s" * 40)
    monkeypatch.undo()
    assert reg.config("acme") is None and reg.config("beta") is None          # ambiguous ⇒ NO org, never the wrong one
    assert [c.org_id for c in reg.configs()] == []
    reg.revoke_config("beta")                                                  # the owner resolves it …
    assert reg.config("acme") is not None                                      # … and acme works again


# =====================================================================================================================
# ui.saml — the SP-initiated request side + the InResponseTo binding
# =====================================================================================================================
def test_new_request_id_is_an_ncname_with_160_random_bits():
    ids = {uisaml.new_request_id() for _ in range(50)}
    assert len(ids) == 50 and all(re.fullmatch(r"_[0-9a-f]{40}", i) for i in ids)


def test_authn_request_escapes_every_value_and_round_trips_the_redirect_binding():
    hostile = 'https://sp/x"><evil a="1'
    xml = uisaml.build_authn_request("_r1", sp_entity_id="urn:sp</saml:Issuer><x>&", acs_url=hostile,
                                     idp_sso_url="https://idp/sso", issue_instant=0.0)
    root = ET.fromstring(xml)                                         # still ONE well-formed element tree
    assert root.get("AssertionConsumerServiceURL") == hostile and root.get("IssueInstant") == "1970-01-01T00:00:00Z"
    assert root.findtext("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer") == "urn:sp</saml:Issuer><x>&"
    assert root.find("{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy") is not None
    assert len(list(root)) == 2                                        # nothing injected
    url = uisaml.authn_request_redirect_url("https://idp/sso?tenant=7", xml, "relay-1")
    parts = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parts.query)
    assert parts.path == "/sso" and q["tenant"] == ["7"] and q["RelayState"] == ["relay-1"]
    assert zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15) == xml   # raw DEFLATE (no zlib header)
    for bad in ("http://idp/sso", "javascript:alert(1)", "", "https:///nohost"):
        with pytest.raises(uisaml.SamlError):
            uisaml.authn_request_redirect_url(bad, xml, "relay-1")
    with pytest.raises(uisaml.SamlError):
        uisaml.authn_request_redirect_url("https://idp/sso", xml, "")
    for blank in ("request_id", "sp_entity_id", "acs_url", "idp_sso_url"):
        kw = dict(sp_entity_id="s", acs_url="https://a", idp_sso_url="https://i", issue_instant=0.0)
        rid = "_r"
        if blank == "request_id":
            rid = " "
        else:
            kw[blank] = ""
        with pytest.raises(uisaml.SamlError):
            uisaml.build_authn_request(rid, **kw)


def _cfg() -> SsoConfig:
    return SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_entity_id="https://idp",
                     idp_certs_pem=(CERT,), sp_entity_id="https://sp/acme", acs_url="https://app/acs")


def _resp(*, scd_irt="_req1", resp_irt: "str | None" = "_req1", aid="a1") -> bytes:
    irt_attr = f' InResponseTo="{resp_irt}"' if resp_irt is not None else ""
    scd = f' InResponseTo="{scd_irt}"' if scd_irt is not None else ""
    return (f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1" Destination="https://app/acs"{irt_attr}>'
            f'<saml:Assertion ID="{aid}"><saml:Issuer>https://idp</saml:Issuer>'
            f'<saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation>'
            f'<saml:SubjectConfirmationData Recipient="https://app/acs" NotOnOrAfter="2001-09-14T00:00:00Z"{scd}/>'
            f'</saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotOnOrAfter="2001-09-14T00:00:00Z"><saml:AudienceRestriction>'
            f'<saml:Audience>https://sp/acme</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            f'</saml:Assertion></samlp:Response>').encode()


@pytest.mark.parametrize("case,ok", [
    (dict(), True),
    (dict(resp_irt=None), True),                              # the (unsigned) Response attribute may be absent
    (dict(scd_irt=None), False),                              # unsolicited: the SIGNED binding is absent
    (dict(scd_irt="_other"), False),                          # answers ANOTHER login
    (dict(resp_irt="_other"), False),                         # the Response contradicts the signed binding
])
def test_the_acs_binds_the_signed_in_response_to(case, ok, tmp_path):
    led = uisaml.SamlReplayLedger(tmp_path / "replay")
    args = dict(config=_cfg(), now=1_000_400_000.0, replay_ledger=led,
                sig_verifier=lambda b, c: frozenset({"a1"}), expected_in_response_to="_req1")
    if ok:
        assert uisaml.verify_saml_response(_resp(**case), **args).name_id == "alice"
    else:
        with pytest.raises(uisaml.SamlError):
            uisaml.verify_saml_response(_resp(**case), **args)
        # a refused response never spends its id (in the org's own partition, where the verifier spends it)
        assert led.try_spend("a1", 1e12, now=1_000_400_000.0, scope=_cfg().org_id)


def test_an_empty_expected_request_id_fails_closed(tmp_path):
    with pytest.raises(uisaml.SamlError, match="fail-closed"):
        uisaml.verify_saml_response(_resp(), config=_cfg(), now=1_000_400_000.0,
                                    replay_ledger=uisaml.SamlReplayLedger(tmp_path / "r"),
                                    sig_verifier=lambda b, c: frozenset({"a1"}), expected_in_response_to="")


# =====================================================================================================================
# ui.sso_edge — the login-state ledger, the SCIM path parser, the public URLs
# =====================================================================================================================
def test_state_ledger_is_single_use_kind_bound_and_expiring(tmp_path):
    led = sso_edge.SsoStateLedger(tmp_path / "st")
    led.issue("k1", {"kind": "saml_login", "org_id": "o"}, ttl_s=60, now=100.0)
    assert led.consume("k1", kind="oidc_login", now=101.0) is None        # another kind: refused AND spent
    assert led.consume("k1", kind="saml_login", now=101.0) is None
    led.issue("k2", {"kind": "saml_login", "org_id": "o"}, ttl_s=60, now=100.0)
    assert led.consume("k2", kind="saml_login", now=101.0)["org_id"] == "o"
    assert led.consume("k2", kind="saml_login", now=101.0) is None         # single use
    led.issue("k3", {"kind": "saml_login"}, ttl_s=60, now=100.0)
    assert led.consume("k3", kind="saml_login", now=161.0) is None         # expired
    with pytest.raises(FileExistsError):                                   # a key is minted once
        led.issue("k4", {"kind": "x"}, ttl_s=60, now=100.0)
        led.issue("k4", {"kind": "x"}, ttl_s=60, now=100.0)
    for bad in ("", None):
        with pytest.raises(ValueError):
            led.issue(bad, {"kind": "x"}, ttl_s=60)
    with pytest.raises(ValueError):
        led.issue("k5", {"org_id": "no-kind"}, ttl_s=60)
    assert led.consume("", kind="x") is None and led.consume("z" * 600, kind="x") is None


def test_state_ledger_markers_are_hash_named_0600(tmp_path):
    led = sso_edge.SsoStateLedger(tmp_path / "st")
    led.issue("../../etc/passwd", {"kind": "x", "verifier": "v"}, ttl_s=60)
    (marker,) = list((tmp_path / "st").iterdir())
    assert re.fullmatch(r"[0-9a-f]{64}", marker.name)
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "st").stat().st_mode) == 0o700


def test_state_ledger_concurrent_consume_has_exactly_one_winner(tmp_path):
    led = sso_edge.SsoStateLedger(tmp_path / "st")
    for i in range(20):
        led.issue(f"k{i}", {"kind": "saml_finish"}, ttl_s=60)
    wins: list = []

    def grab(i):
        if led.consume(f"k{i % 20}", kind="saml_finish") is not None:
            wins.append(i % 20)
    threads = [threading.Thread(target=grab, args=(i,)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(wins) == list(range(20))                                  # each key spent exactly once


def test_state_ledger_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(sso_edge.SsoStateLedger, "_MAX_OUTSTANDING", 3)
    led = sso_edge.SsoStateLedger(tmp_path / "st")
    for i in range(3):
        led.issue(f"k{i}", {"kind": "x"}, ttl_s=60, now=100.0)
    with pytest.raises(RuntimeError):
        led.issue("k9", {"kind": "x"}, ttl_s=60, now=100.0)
    led.issue("k9", {"kind": "x"}, ttl_s=60, now=200.0)                     # the expired ones were swept


@pytest.mark.parametrize("path,want", [
    ("/scim/v2/org_abc/Users", ("org_abc", "/Users")),
    ("/scim/v2/org_abc/Users/sso_1", ("org_abc", "/Users/sso_1")),
    ("/scim/v2/org_abc", ("org_abc", "/")),
    ("/scim/v2/../Users", None), ("/scim/v2//Users", None), ("/scim/v2/-x/Users", None),
    ("/scim/v2/" + "a" * 65 + "/Users", None), ("/scim/v1/org_abc/Users", None), ("/api/scim/v2/o/Users", None),
])
def test_parse_scim_path(path, want):
    assert sso_edge.parse_scim_path(path) == want


def test_public_urls():
    u = sso_edge.public_urls("https://app.example.com/", "org_abc")
    assert u == {"login_url": "https://app.example.com/api/customer/sso/login?org=org_abc",
                 "saml_acs_url": "https://app.example.com/api/customer/sso/saml/acs",
                 "saml_sp_entity_id": "https://app.example.com/api/customer/sso/saml/org_abc",
                 "oidc_redirect_uri": "https://app.example.com/api/customer/sso/oidc/callback",
                 "scim_base_url": "https://app.example.com/scim/v2/org_abc"}
    assert sso_edge.public_urls("http://127.0.0.1:8734", "o")["saml_acs_url"].startswith("http://127.0.0.1:8734/")
    for base in ("http://app.example.com", "https://app.example.com/sub", "https://app.example.com?x=1", "ftp://a",
                 "app.example.com", ""):
        with pytest.raises(ValueError):
            sso_edge.public_urls(base, "o")
    with pytest.raises(ValueError):
        sso_edge.public_urls("https://app.example.com", "../o")


def test_public_urls_refuses_a_fragment_or_a_hostless_base():
    # every bad base above is refused by the scheme / path / query / plain-http clause; these two are refused ONLY
    # by the fragment and the host clause respectively
    for base in ("https://app.example.com#frag", "https://"):
        with pytest.raises(ValueError):
            sso_edge.public_urls(base, "o")


def test_the_sso_binding_cookie_is_secure_under_the_production_posture(monkeypatch):
    import vigil_core.posture as posture
    monkeypatch.setattr(posture, "is_production_posture", lambda *a, **k: True)
    prod = sso_edge.SsoEdgeMixin._sid_cookie_value(None, "sid-1")
    assert prod.endswith("; Secure") and "; HttpOnly;" in prod and "SameSite=Lax" in prod
    monkeypatch.setattr(posture, "is_production_posture", lambda *a, **k: False)
    assert "Secure" not in sso_edge.SsoEdgeMixin._sid_cookie_value(None, "sid-1")   # a loopback dev edge (http)


def test_tenant_re_lockstep():
    from sigil.governor import orgs
    assert sso_edge._TENANT_RE.pattern == orgs._TENANT_RE.pattern == sso_provision._TENANT_RE.pattern


# =====================================================================================================================
# ui.sso_provision — fail-closed legs
# =====================================================================================================================
class _P(SimpleNamespace):
    pass


def test_production_enterprise_oidc_egress_is_pinned_to_the_signed_allowlist():
    from sigil.ui.oidc import OidcError
    p = _P(sso_oidc_http_post=None, sso_oidc_jwks_fetcher=None)
    cfg = SimpleNamespace(oidc_egress_hosts=("login.acme-idp.example",))
    post, fetch = sso_provision._oidc_transport(p, cfg)
    for url in ("https://169.254.169.254/latest/meta-data", "http://login.acme-idp.example/token",
                "https://login.acme-idp.example.evil.com/token"):
        with pytest.raises(OidcError):
            post(url, {"code": "c"})                                   # refused BEFORE any connection
        with pytest.raises(OidcError):
            fetch(url)
    post0, _ = sso_provision._oidc_transport(p, SimpleNamespace(oidc_egress_hosts=()))
    with pytest.raises(OidcError):
        post0("https://login.acme-idp.example/token", {})              # an empty allowlist allows nothing


def test_saml_acs_without_a_replay_ledger_is_refused():
    from sigil.ui.provision import ProvisionError
    calls = []
    p = _P(saml_replay=None, _now=lambda: 1.0, _rate_guard=lambda *a, **k: calls.append(a))
    with pytest.raises(ProvisionError):
        sso_provision.sso_saml_acs(p, "org_abc", "PHg+", request_id="_r")


def test_scim_request_fails_closed_without_limiters_and_on_non_scim_methods():
    p = _P(scim_auth_limiter=None, scim_write_limiter=None, _now=lambda: 1.0)
    assert sso_provision.scim_request(p, "org_abc", method="GET", path="/Users")["status"] == 503
    for m in ("HEAD", "OPTIONS", "TRACE", "", "CONNECT"):
        r = sso_provision.scim_request(p, "org_abc", method=m, path="/Users")
        assert r["status"] == 405 and r["deactivated"] == []


def test_decode_saml_response_bounds():
    assert sso_provision._decode_saml_response(" PH\r\ng+ ") == b"<x>"           # folded base64 is accepted
    for bad in ("", "not base64!", "A" * (sso_provision.MAX_SAML_RESPONSE_B64 + 4)):
        with pytest.raises(ValueError):
            sso_provision._decode_saml_response(bad)


def test_decode_saml_response_is_strict_base64():
    # "not base64!" above also breaks base64 PADDING, so even a lenient decoder refuses it; "PHg+!" decodes to b"<x>"
    # once the stray byte is silently dropped — only the strict (validate=True) decode refuses it
    with pytest.raises(ValueError):
        sso_provision._decode_saml_response("PHg+!")


# =====================================================================================================================
# ui.server — the closed dispatch + the flag-gated body caps; build_provisioner wiring
# =====================================================================================================================
class _Rec:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": name}
        return call


def test_sso_dispatch_is_a_closed_exact_set():
    from sigil.ui.server import Handler
    p = _Rec()
    body = {"org_id": "org_abc", "saml_response": "PHg+", "request_id": "_r", "code": "c", "code_verifier": "v",
            "nonce": "n", "method": "PATCH", "path": "/Users/u", "query": "a=b", "body": {"Operations": []},
            "authorization": "Bearer t", "requester": "cust_evil", "ip": "ignored-the-hop-ip-wins"}
    Handler._sso_dispatch(p, "sso_login_start", body, "1.2.3.4")
    Handler._sso_dispatch(p, "sso_saml_acs", body, "1.2.3.4")
    Handler._sso_dispatch(p, "sso_oidc_finish", body, "1.2.3.4")
    Handler._sso_dispatch(p, "scim_request", body, "1.2.3.4")
    assert p.calls == [
        ("sso_login_start", ("org_abc",), {"ip": "1.2.3.4"}),
        ("sso_saml_acs", ("org_abc", "PHg+"), {"request_id": "_r", "ip": "1.2.3.4"}),
        ("sso_oidc_finish", ("org_abc",), {"code": "c", "code_verifier": "v", "nonce": "n", "ip": "1.2.3.4"}),
        ("scim_request", ("org_abc",), {"method": "PATCH", "path": "/Users/u", "query": "a=b",
                                        "body": {"Operations": []}, "authorization": "Bearer t", "ip": "1.2.3.4"})]
    for unknown in ("sso_", "scim_", "sso_login", "scim_request_x", "sso_saml_acs ", "scim_rotate_token"):
        assert Handler._sso_dispatch(p, unknown, body, "") is None
    blank = _Rec()
    Handler._sso_dispatch(blank, "sso_login_start", {"org_id": None}, "")
    assert blank.calls == [("sso_login_start", ("",), {"ip": ""})]            # null ⇒ "" (fail-closed), never "None"


def test_provision_body_caps_grow_only_while_the_flag_is_on(monkeypatch):
    from sigil.ui.server import Handler
    monkeypatch.delenv("VIGIL_CUSTOMER_SSO", raising=False)
    for action in ("sso_saml_acs", "scim_request", "login"):
        assert Handler._provision_body_cap(Handler, action) == Handler._MAX_BODY
    monkeypatch.setenv("VIGIL_CUSTOMER_SSO", "1")
    # any SAMLResponse the provisioner would accept (<= MAX_SAML_RESPONSE_B64 of base64) fits the hop with room for
    # the JSON envelope; the provisioner, not the cap, is what refuses a larger one
    assert Handler._provision_body_cap(Handler, "sso_saml_acs") >= sso_provision.MAX_SAML_RESPONSE_B64 + 64 * 1024
    assert Handler._provision_body_cap(Handler, "scim_request") > sso_edge.MAX_SCIM_BODY
    assert Handler._provision_body_cap(Handler, "login") == Handler._MAX_BODY


def test_build_provisioner_wires_the_sso_ledgers_only_with_the_flag(monkeypatch, tmp_path):
    from sigil import config
    from sigil.ui.provision import build_provisioner
    for attr in ("CUSTOMER_SAML_REPLAY_DIR", "SCIM_AUTH_RATELIMIT_DIR", "SCIM_WRITE_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    monkeypatch.delenv("VIGIL_CUSTOMER_SSO", raising=False)
    off = build_provisioner(_store())
    assert off.saml_replay is None and off.scim_auth_limiter is None and off.scim_write_limiter is None
    monkeypatch.setenv("VIGIL_CUSTOMER_SSO", "1")
    on = build_provisioner(_store())
    assert on.saml_replay is not None and on.scim_auth_limiter is not None and on.scim_write_limiter is not None
    assert on.scim_write_limiter.max_fails == config.SCIM_OPS_PER_MIN
    assert not any((tmp_path / a.lower()).exists() for a in ("CUSTOMER_SAML_REPLAY_DIR",))   # created lazily


def test_slow_hop_timeouts_cover_the_network_bound_sso_actions():
    from sigil.ui import custui
    assert custui._hop_timeout("sso_oidc_finish") >= 45.0 and custui._hop_timeout("scim_request") >= 45.0


# =====================================================================================================================
# governor.scim — the mint is never silently inert
# =====================================================================================================================
def test_provision_membership_bumps_a_stale_issued_at():
    from sigil.governor import scim as gscim
    s = _store()
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs.create_org("acme", "Acme", owner="o", issued_at=_issue())
    cfg = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_entity_id="https://idp")
    gscim.provision_membership(orgs, cfg, username="sso_" + "a" * 24, role="org_admin", issued_at=500.0)
    gscim.provision_membership(orgs, cfg, username="sso_" + "a" * 24, role="viewer", issued_at=1.0)   # a clock behind
    assert orgs.membership_role("sso_" + "a" * 24, "acme") == "viewer"                                 # still honored


# =====================================================================================================================
# `sigil sso` — the owner CLI
# =====================================================================================================================
@pytest.fixture
def cli_env(monkeypatch, tmp_path):
    """The CLI signs with the PERSISTED owner key (as in production): provision one, and scrub it (and any vault
    state) before and after, exactly like test_custui's shared-home hygiene."""
    import shutil

    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.platform import vault as _vault
    shutil.rmtree(config.KEYS_DIR, ignore_errors=True)
    shutil.rmtree(config.SIGIL_HOME / "vault", ignore_errors=True)
    _vault.reset_owner_vault_for_test()
    ensure_owner_keypair()
    path = str(tmp_path / "spine.jsonl")
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: SpineStore(path) if not a else SpineStore(*a, **k))
    monkeypatch.delenv("VIGIL_CUSTOMER_SSO", raising=False)
    OrgRegistry(SpineStore(path)).create_org("org_abc", "Acme", owner="cust_f", issued_at=_issue())
    yield cli, path, tmp_path
    shutil.rmtree(config.KEYS_DIR, ignore_errors=True)
    shutil.rmtree(config.SIGIL_HOME / "vault", ignore_errors=True)
    _vault.reset_owner_vault_for_test()


def test_cli_set_saml_writes_the_bearer_once_0600_and_never_prints_it(cli_env, capsys):
    cli, path, tmp = cli_env
    certf = tmp / "idp.pem"
    certf.write_text(CERT)
    out = tmp / "scim.token"
    cli.main(["sso", "set-saml", "org_abc", "--public-base", "https://app.example.com", "--idp-entity-id",
              "https://idp", "--idp-sso-url", "https://idp/sso", "--idp-cert", str(certf), "--group-role",
              "Admins=org_admin", "--scim", "--token-out", str(out)])
    printed = capsys.readouterr().out
    tok = out.read_text().strip()
    assert len(tok) >= 43 and tok not in printed and token_fingerprint(tok) not in printed
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "https://app.example.com/scim/v2/org_abc" in printed and "VIGIL_CUSTOMER_SSO is off" in printed
    c = SsoConfigRegistry(SpineStore(path)).config("org_abc")
    assert c.sp_entity_id == "https://app.example.com/api/customer/sso/saml/org_abc"
    assert c.acs_url == "https://app.example.com/api/customer/sso/saml/acs" and c.scim_token_fp == token_fingerprint(tok)
    assert tok not in open(path, encoding="utf-8").read()
    # rotate: a NEW file, the old token retired; an existing file is refused without --overwrite
    with pytest.raises(SystemExit) as e:
        cli.main(["sso", "rotate-scim-token", "org_abc", "--token-out", str(out)])
    assert e.value.code == 2 and out.read_text().strip() == tok
    cli.main(["sso", "rotate-scim-token", "org_abc", "--token-out", str(out), "--overwrite"])
    tok2 = out.read_text().strip()
    assert tok2 != tok and SsoConfigRegistry(SpineStore(path)).config("org_abc").scim_token_fp == token_fingerprint(tok2)
    assert tok2 not in capsys.readouterr().out
    cli.main(["sso", "status"])
    status = capsys.readouterr().out
    assert "org_abc: saml" in status and "SCIM on" in status and token_fingerprint(tok2) not in status
    cli.main(["sso", "disable-scim", "org_abc"])
    assert not SsoConfigRegistry(SpineStore(path)).config("org_abc").scim_enabled


def test_cli_refuses_ceiling_breaches_symlinks_and_unknown_orgs(cli_env, capsys):
    cli, path, tmp = cli_env
    certf = tmp / "idp.pem"
    certf.write_text(CERT)
    base = ["sso", "set-saml", "org_abc", "--public-base", "https://app.example.com", "--idp-entity-id", "https://idp",
            "--idp-sso-url", "https://idp/sso", "--idp-cert", str(certf)]
    for extra in (["--default-role", "founder"], ["--role-cap", "owner"], ["--group-role", "Admins=founder"],
                  ["--group-role", "nonsense"], ["--scim"]):
        with pytest.raises(SystemExit) as e:
            cli.main(base + extra)
        assert e.value.code == 2, extra
    victim = tmp / "victim"
    victim.write_text("keep")
    link = tmp / "link.token"
    os.symlink(victim, link)
    with pytest.raises(SystemExit):
        cli.main(base + ["--scim", "--token-out", str(link), "--overwrite"])
    assert victim.read_text() == "keep"
    with pytest.raises(SystemExit):
        cli.main(["sso", "set-saml", "org_" + "z" * 24] + base[3:])          # no such org
    assert SsoConfigRegistry(SpineStore(path)).config("org_abc") is None   # nothing was ever signed
    capsys.readouterr()


def test_cli_set_oidc_sp_info_and_revoke_deprovisions_sso_members(cli_env, capsys):
    cli, path, tmp = cli_env
    cli.main(["sso", "sp-info", "org_abc", "--public-base", "https://app.example.com"])
    assert "oidc_redirect_uri: https://app.example.com/api/customer/sso/oidc/callback" in capsys.readouterr().out
    cli.main(["sso", "set-oidc", "org_abc", "--public-base", "https://app.example.com", "--issuer", "https://idp",
              "--client-id", "cid", "--jwks-uri", "https://keys.idp/jwks", "--authorize-endpoint", "https://idp/a",
              "--token-endpoint", "https://token.idp/t"])
    c = SsoConfigRegistry(SpineStore(path)).config("org_abc")
    assert c.protocol == "oidc" and set(c.oidc_egress_hosts) == {"keys.idp", "token.idp"}   # derived, minimal
    assert c.oidc_redirect_uri == "https://app.example.com/api/customer/sso/oidc/callback"
    orgs = OrgRegistry(SpineStore(path))
    orgs.grant_membership("org_abc", "sso_" + "a" * 24, "analyst", issued_at=_issue())
    orgs.grant_membership("org_abc", "cust_f", "founder", issued_at=_issue())
    cli.main(["sso", "revoke", "org_abc", "--deprovision-members"])
    orgs = OrgRegistry(SpineStore(path))
    assert SsoConfigRegistry(SpineStore(path)).config("org_abc") is None
    assert orgs.membership_role("sso_" + "a" * 24, "org_abc") is None
    assert orgs.membership_role("cust_f", "org_abc") == "founder"            # only SSO-provisioned members
