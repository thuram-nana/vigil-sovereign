"""PR-H Area 7 — SAML 2.0 assertion verification (`ui.saml`).

Load-bearing invariants (a false-green here is a full auth bypass):
  * XML HARDENING: a DOCTYPE/DTD (⇒ XXE / billion-laughs / external-entity) is refused;
  * EXACTLY ONE assertion + NO duplicate ID (the structural XSW core);
  * SIGNATURE BINDING: a valid signature must cover the processed assertion OR the enveloping Response — a
    signature over any OTHER id (a wrapper) is refused; no valid signature ⇒ refused;
  * ISSUER / AUDIENCE / RECIPIENT / DESTINATION must match the org's config (org-scoping);
  * TIME WINDOWS (Conditions + SubjectConfirmationData NotOnOrAfter/NotBefore, skew) enforced; missing
    NotOnOrAfter refused;
  * REPLAY: an assertion ID is single-use;
  * the shipped signature backend FAILS CLOSED without a vetted XML-DSig library.

The crypto itself is treated as a verified dependency: tests inject a `sig_verifier` stub that attests WHICH
element ids are validly signed, so the structural/XSW/temporal/audience/replay logic is exercised without
depending on byte-correct exclusive-c14n (which the environment cannot provide; see the module honest boundary).
"""
from __future__ import annotations

import sys
import tempfile

import pytest

from sigil.governor.sso_config import SsoConfig
from sigil.ui import saml
from sigil.ui.saml import SamlError

# Assertion timestamps are year-2001 (epoch ~1e9); NOW sits inside the validity window.
NOW = 1_000_400_000.0
EXPIRED = 1_000_500_000.0
TOO_EARLY = 1_000_200_000.0

CFG = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active",
                idp_entity_id="https://idp.example", idp_certs_pem=("PEMCERT",),
                sp_entity_id="https://sp.vigil/acme", acs_url="https://app.vigil/acs/acme", clock_skew_seconds=60)


def _assertion(aid="a1", aud="https://sp.vigil/acme", rcpt="https://app.vigil/acs/acme",
               nooa="2001-09-14T00:00:00Z", nb="2001-09-13T00:00:00Z", issuer="https://idp.example",
               nameid="user@acme", groups=("admins",), with_subject=True, with_conditions=True,
               with_scd=True, with_nameid=True):
    grp = "".join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)
    subj = ""
    if with_subject:
        nid = f'<saml:NameID>{nameid}</saml:NameID>' if with_nameid else ''
        scd = (f'<saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="{rcpt}" '
               f'NotOnOrAfter="{nooa}"/></saml:SubjectConfirmation>') if with_scd else ''
        subj = f'<saml:Subject>{nid}{scd}</saml:Subject>'
    cond = ""
    if with_conditions:
        nbattr = f' NotBefore="{nb}"' if nb else ''
        cond = (f'<saml:Conditions{nbattr} NotOnOrAfter="{nooa}"><saml:AudienceRestriction>'
                f'<saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions>')
    return (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}">'
            f'<saml:Issuer>{issuer}</saml:Issuer>{subj}{cond}'
            f'<saml:AttributeStatement><saml:Attribute Name="groups">{grp}</saml:Attribute>'
            f'</saml:AttributeStatement></saml:Assertion>')


def _response(assertions=None, dest="https://app.vigil/acs/acme", rid="r1", **kw):
    body = assertions if assertions is not None else _assertion(**kw)
    destattr = f' Destination="{dest}"' if dest is not None else ''
    return (f'<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'ID="{rid}"{destattr}>{body}</samlp:Response>').encode()


def _led():
    return saml.SamlReplayLedger(tempfile.mktemp())


def _verify(xml, signed=("a1",), now=NOW, cfg=CFG, ledger=None):
    return saml.verify_saml_response(xml, config=cfg, now=now, replay_ledger=ledger or _led(),
                                     sig_verifier=lambda b, c: frozenset(signed))


# --- accept paths -----------------------------------------------------------------------------------

def test_valid_assertion_accepts():
    idn = _verify(_response())
    assert idn.name_id == "user@acme" and idn.assertion_id == "a1" and idn.groups == ("admins",)


def test_signature_over_response_root_binds():
    # a single assertion enveloped by a signed Response: binding holds (no wrapping gap).
    assert _verify(_response(), signed=("r1",)).name_id == "user@acme"


# --- the XSW structural core ------------------------------------------------------------------------

def test_forged_unsigned_assertion_refused():
    with pytest.raises(SamlError):
        _verify(_response(), signed=())


def test_xsw_signature_over_a_different_id_refused():
    # the signature validly covers 'attacker-wrapper', but the processed assertion is 'a1' → no binding.
    with pytest.raises(SamlError):
        _verify(_response(), signed=("attacker-wrapper",))


def test_multiple_assertions_refused():
    two = _assertion(aid="a1") + _assertion(aid="a2", nameid="evil@acme")
    with pytest.raises(SamlError):
        _verify(_response(assertions=two), signed=("a1",))


def test_duplicate_id_refused():
    dup = _assertion(aid="a1") + _assertion(aid="a1")
    with pytest.raises(SamlError):
        _verify(_response(assertions=dup), signed=("a1",))


def test_assertion_without_id_refused():
    a = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.example</saml:Issuer></saml:Assertion>'
    with pytest.raises(SamlError):
        _verify(_response(assertions=a), signed=("a1",))


# --- XML hardening ----------------------------------------------------------------------------------

def test_doctype_refused():
    xml = (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "x">]>'
           b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>')
    with pytest.raises(SamlError):
        _verify(xml)


def test_billion_laughs_refused():
    xml = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
           b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">&lol2;</samlp:Response>')
    with pytest.raises(SamlError):
        _verify(xml)


def test_external_entity_xxe_refused():
    xml = (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ext SYSTEM "file:///etc/passwd">]>'
           b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">&ext;</samlp:Response>')
    with pytest.raises(SamlError):
        _verify(xml)


def test_oversize_and_empty_refused():
    with pytest.raises(SamlError):
        saml._parse_hardened(b"x" * (saml._MAX_SAML_BYTES + 1))
    with pytest.raises(SamlError):
        saml._parse_hardened(b"")


def test_malformed_xml_refused():
    with pytest.raises(SamlError):
        _verify(b"<not-closed>")


# --- org-scoping: issuer / audience / recipient / destination --------------------------------------

def test_wrong_issuer_refused():
    with pytest.raises(SamlError):
        _verify(_response(issuer="https://evil-idp"))


def test_cross_org_audience_refused():
    # an assertion minted for another org's SP entity id must not verify for acme (org-scoping).
    with pytest.raises(SamlError):
        _verify(_response(aud="https://sp.vigil/other"))


def test_wrong_recipient_refused():
    with pytest.raises(SamlError):
        _verify(_response(rcpt="https://evil/acs"))


def test_wrong_destination_refused():
    with pytest.raises(SamlError):
        _verify(_response(dest="https://evil/acs"))


# --- time windows -----------------------------------------------------------------------------------

def test_expired_refused():
    with pytest.raises(SamlError):
        _verify(_response(), now=EXPIRED)


def test_not_yet_valid_refused():
    with pytest.raises(SamlError):
        _verify(_response(), now=TOO_EARLY)


def test_missing_not_on_or_after_refused():
    a = ('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">'
         '<saml:Issuer>https://idp.example</saml:Issuer>'
         '<saml:Subject><saml:NameID>u</saml:NameID><saml:SubjectConfirmation>'
         '<saml:SubjectConfirmationData Recipient="https://app.vigil/acs/acme"/></saml:SubjectConfirmation></saml:Subject>'
         '<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.vigil/acme</saml:Audience>'
         '</saml:AudienceRestriction></saml:Conditions></saml:Assertion>')
    with pytest.raises(SamlError):
        _verify(_response(assertions=a))


def test_clock_skew_tolerated():
    # just-expired within skew (60s): NOW == nooa + 30 should still pass.
    import datetime
    nooa_epoch = datetime.datetime(2001, 9, 14, tzinfo=datetime.timezone.utc).timestamp()
    assert _verify(_response(), now=nooa_epoch + 30).name_id == "user@acme"
    with pytest.raises(SamlError):                           # beyond skew → refused
        _verify(_response(), now=nooa_epoch + 120)


# --- replay -----------------------------------------------------------------------------------------

def test_replay_refused():
    led = _led()
    assert _verify(_response(), ledger=led).name_id == "user@acme"
    with pytest.raises(SamlError):
        _verify(_response(), ledger=led)                     # same assertion id, second time → replay


def test_distinct_assertion_ids_both_accepted():
    led = _led()
    assert _verify(_response(aid="a1"), signed=("a1",), ledger=led).name_id == "user@acme"
    assert _verify(_response(aid="a2"), signed=("a2",), ledger=led).name_id == "user@acme"


# --- missing structure ------------------------------------------------------------------------------

def test_missing_subject_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_subject=False))


def test_missing_nameid_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_nameid=False))


def test_missing_conditions_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_conditions=False))


def test_missing_scd_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_scd=False))


# --- the signature backend FAILS CLOSED without a vetted library -----------------------------------

def test_default_backend_fails_closed_without_signxml():
    # In this environment signxml is not installed, so the shipped backend returns NO verified ids ⇒ refused.
    with pytest.raises(SamlError):
        saml.verify_saml_response(_response(), config=CFG, now=NOW, replay_ledger=_led())


def test_protocol_mismatch_refused():
    oidc_cfg = SsoConfig(org_id="acme", protocol="oidc", issued_at=1.0, state="active")
    with pytest.raises(SamlError):
        _verify(_response(), cfg=oidc_cfg)


def test_config_without_cert_refused():
    nocert = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_certs_pem=(),
                       sp_entity_id="https://sp.vigil/acme", acs_url="https://app.vigil/acs/acme")
    with pytest.raises(SamlError):
        _verify(_response(), cfg=nocert)


# --- FATAL-2 ----------------------------------------------------------------------------------------

def test_fatal2_no_framework_import():
    import sigil.ui.saml  # noqa: F401
    assert "framework" not in sys.modules and "strix" not in sys.modules
