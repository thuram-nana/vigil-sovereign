"""
Workstream NW-1 — the offline SAML structural-forgery oracle (a captured SAML Response -> a
STRUCTURALLY-FORGEABLE FACT). The SSO SIBLING of ``test_jwt_forgery`` and the offline structural
complement to the LIVE response-differential SAML checks (``scanner.sso``).

A captured SAML Response is only a LEAD until a deterministic oracle proves it forgeable from the
decoded XML ALONE, offline, with ZERO forged traffic. The saml-forgery oracle promotes it to a FACT
ONLY on a coarse, c14n-free STRUCTURAL invariant a validly signed assertion cannot exhibit: (a) an
unsigned consumed assertion, (b) a ds:Reference/@URI that does not cover the consumed element, or
(c) the signature-wrapping shape (the dual of ``scanner.sso.wrap_assertion_xsw``). A properly signed
single assertion, a doc with no consumed NameID, malformed/empty XML, and a DOCTYPE/ENTITY doc (refused
by the XXE-safe parser) all correctly do NOT fire — near-zero false positives.
"""

from __future__ import annotations

from framework.v2.verify import (
    confirm_saml_forgery,
    saml_forgery_context,
    saml_forgery_oracle,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier
from framework.v2.scanner.sso import wrap_assertion_xsw

# ---------------------------------------------------------------------------
# SAML message builders (stdlib strings — the oracle parses through the XXE-safe safe_parse_xml)
# ---------------------------------------------------------------------------

_NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_D = "http://www.w3.org/2000/09/xmldsig#"


def _assertion(aid: str, nameid: str, *, sig_ref: str | None = None) -> str:
    """A saml:Assertion carrying ``nameid``; if ``sig_ref`` is given it embeds a ds:Signature whose
    single ds:Reference/@URI points at ``#{sig_ref}`` (a structural stand-in — no real crypto)."""
    sig = ""
    if sig_ref is not None:
        sig = (f'<ds:Signature><ds:SignedInfo><ds:Reference URI="#{sig_ref}"></ds:Reference>'
               f"</ds:SignedInfo><ds:SignatureValue>QUFB</ds:SignatureValue></ds:Signature>")
    return (f'<saml:Assertion ID="{aid}"><saml:Subject><saml:NameID>{nameid}</saml:NameID>'
            f"</saml:Subject>{sig}<saml:Conditions/></saml:Assertion>")


def _response(inner: str, *, rid: str = "_r1", sig_ref: str | None = None) -> str:
    """A samlp:Response wrapping ``inner``; if ``sig_ref`` is given the Response itself carries a
    ds:Signature referencing ``#{sig_ref}`` (a Response-level signature covering its descendants)."""
    sig = ""
    if sig_ref is not None:
        sig = (f'<ds:Signature><ds:SignedInfo><ds:Reference URI="#{sig_ref}"></ds:Reference>'
               f"</ds:SignedInfo></ds:Signature>")
    return (f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" xmlns:ds="{_NS_D}" '
            f'ID="{rid}" Version="2.0"><saml:Issuer>idp</saml:Issuer>{sig}{inner}</samlp:Response>')


# ---------------------------------------------------------------------------
# the oracle FIRES only on a re-runnable structural-forgery invariant
# ---------------------------------------------------------------------------


def test_fires_on_unsigned_assertion_carrying_a_nameid() -> None:
    xml = _response(_assertion("_a1", "alice@corp.test"))  # no ds:Signature anywhere
    sig = saml_forgery_oracle(xml)
    assert sig.fired and sig.kind is OracleKind.SAML_STRUCTURAL_FORGERY
    assert sig.confidence >= 0.7
    assert sig.observed["proof"] == "unsigned_assertion"
    assert sig.observed["signatures"] == 0


def test_fires_on_reference_uri_pointing_at_a_different_id() -> None:
    # a single assertion (ID=_a1) but the signature's ds:Reference/@URI covers #_WRONG — the signature
    # does not cover the consumed assertion, so its content is swappable.
    xml = _response(_assertion("_a1", "alice@corp.test", sig_ref="_WRONG"))
    sig = saml_forgery_oracle(xml)
    assert sig.fired
    assert sig.observed["proof"] == "reference_mismatch"
    assert "_a1" in sig.observed["consumed_chain_ids"]
    assert "_WRONG" in sig.observed["referenced_ids"]


def test_fires_on_xsw_wrapped_doc_from_scanner_sso() -> None:
    # the exact DUAL of the forger: a signed original assertion kept verbatim + an UNSIGNED forged copy
    # inserted ahead of it. wrap_assertion_xsw builds it; the oracle re-detects the wrapping shape.
    signed_original = _response(_assertion("_orig", "legit@corp.test", sig_ref="_orig"))
    wrapped = wrap_assertion_xsw(signed_original, "attacker@sso-test.invalid")
    sig = saml_forgery_oracle(wrapped)
    assert sig.fired
    assert sig.observed["proof"] == "signature_wrapping"
    assert sig.observed["assertions"] >= 2
    # the consumed (forged) assertion is the one the forger stamped, not the signed original.
    assert sig.observed["consumed_assertion_id"] == "_crucible_xsw_forged"


# ---------------------------------------------------------------------------
# the oracle does NOT fire (near-zero-FP)
# ---------------------------------------------------------------------------


def test_does_not_fire_on_properly_signed_single_assertion() -> None:
    # ds:Reference/@URI == the consumed assertion's own ID — the signature covers the consumed element.
    xml = _response(_assertion("_a1", "alice@corp.test", sig_ref="_a1"))
    assert not saml_forgery_oracle(xml).fired


def test_does_not_fire_on_response_level_signature_covering_the_assertion() -> None:
    # a Response-level signature (URI=#_r1) covers the consumed assertion via its ANCESTOR — properly
    # signed even though the assertion element itself carries no signature.
    xml = _response(_assertion("_a1", "alice@corp.test"), rid="_r1", sig_ref="_r1")
    assert not saml_forgery_oracle(xml).fired


def _assertion_raw_ref(aid: str, nameid: str, refs: str) -> str:
    """A signed saml:Assertion whose ds:SignedInfo carries the RAW ``refs`` markup (arbitrary
    ds:Reference forms) — for the spec-legal same-document reference variants the bare-#id helper
    can't express."""
    return (f'<saml:Assertion ID="{aid}"><saml:Subject><saml:NameID>{nameid}</saml:NameID>'
            f'</saml:Subject><ds:Signature><ds:SignedInfo>{refs}</ds:SignedInfo>'
            f'<ds:SignatureValue>QUFB</ds:SignatureValue></ds:Signature>'
            f'<saml:Conditions/></saml:Assertion>')


def test_does_not_fire_on_xpointer_id_reference() -> None:
    # regression [review HIGH]: `#xpointer(id('_a1'))` is a spec-legal same-document reference that
    # selects the SAME element as the bare `#_a1` shorthand — it COVERS the consumed assertion, so a
    # validly-signed assertion using it must NOT be flagged as forgeable.
    xml = _response(_assertion_raw_ref("_a1", "alice@corp.test",
                                       '<ds:Reference URI="#xpointer(id(&apos;_a1&apos;))"></ds:Reference>'))
    assert not saml_forgery_oracle(xml).fired


def test_does_not_fire_on_whole_document_xpointer() -> None:
    # regression: `#xpointer(/)` selects the whole document (equivalent to URI="") — whole-doc coverage.
    xml = _response(_assertion_raw_ref("_a1", "alice@corp.test",
                                       '<ds:Reference URI="#xpointer(/)"></ds:Reference>'))
    assert not saml_forgery_oracle(xml).fired


def test_does_not_fire_on_transform_selected_uriless_reference() -> None:
    # regression: a URI-less ds:Reference selects nodes via its Transforms (coverage not string-decidable),
    # plus a #_ki reference to a KeyInfo Object. The oracle must REFUSE to assert a mismatch rather than
    # read the transform-covered assertion as unsigned.
    refs = ('<ds:Reference><ds:Transforms><ds:Transform '
            'Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/></ds:Transforms></ds:Reference>'
            '<ds:Reference URI="#_ki"></ds:Reference>')
    xml = _response(_assertion_raw_ref("_a1", "alice@corp.test", refs))
    sig = saml_forgery_oracle(xml)
    assert not sig.fired
    assert sig.observed.get("unadjudicable_ref") is True


def test_does_not_fire_on_benign_saml_metadata_doc() -> None:
    md = ('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
          'entityID="urn:example:sp"><md:SPSSODescriptor '
          'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>')
    sig = saml_forgery_oracle(md)
    assert not sig.fired
    assert sig.observed.get("reason") == "no_nameid"  # no consumed SSO identity to adjudicate


def test_does_not_fire_on_nameid_outside_an_assertion() -> None:
    # a LogoutRequest-style NameID not inside a saml:Assertion is not an authentication assertion.
    xml = (f'<samlp:LogoutRequest xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" ID="_l1" Version="2.0">'
           f"<saml:NameID>alice@corp.test</saml:NameID></samlp:LogoutRequest>")
    sig = saml_forgery_oracle(xml)
    assert not sig.fired
    assert sig.observed.get("reason") == "nameid_outside_assertion"


def test_does_not_fire_on_malformed_or_empty_xml() -> None:
    for junk in ("", "   ", "<not><closed>", "not-xml-at-all", "{}", 123, None, [], {}):
        assert not saml_forgery_oracle(junk).fired


def test_does_not_fire_and_does_not_raise_on_doctype_or_entity_doc() -> None:
    # the XXE-safe safe_parse_xml REFUSES any DOCTYPE/ENTITY — the oracle must non-fire, never raise.
    xxe = ('<!DOCTYPE Response [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           + _response(_assertion("_a1", "&x;")))
    sig = saml_forgery_oracle(xxe)  # must not raise
    assert not sig.fired
    assert sig.observed.get("parse") == "refused"


# ---------------------------------------------------------------------------
# routing + the FROZEN-fallback invariant (gate safety)
# ---------------------------------------------------------------------------


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("saml_structural_forgery") == (OracleKind.SAML_STRUCTURAL_FORGERY,)
    assert v.oracles_for("saml_forgery") == (OracleKind.SAML_STRUCTURAL_FORGERY,)          # alias folds
    assert v.oracles_for("saml_unsigned_assertion") == (OracleKind.SAML_STRUCTURAL_FORGERY,)
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback
    assert OracleKind.SAML_STRUCTURAL_FORGERY not in _ALL_ORACLES
    assert OracleKind.SAML_STRUCTURAL_FORGERY not in v.oracles_for("some_unknown_class")


def test_all_oracles_frozen_fallback_stays_fifteen() -> None:
    # the gate-safety invariant: the frozen unknown-class fallback is EXACTLY the pre-AEGIS 15.
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.SAML_STRUCTURAL_FORGERY not in _ALL_ORACLES


def test_existing_live_saml_classes_are_not_repointed() -> None:
    # the LIVE response-differential SAML/OIDC classes must stay on ACHIEVED_STATE (additive-only).
    v = OracleVerifier()
    assert v.oracles_for("saml_signature_wrapping") == (OracleKind.ACHIEVED_STATE,)
    assert v.oracles_for("saml_assertion_tampering") == (OracleKind.ACHIEVED_STATE,)
    assert v.oracles_for("oidc_redirect_uri") == (OracleKind.ACHIEVED_STATE,)
    assert v.oracles_for("oidc_idtoken_forgery") == (OracleKind.ACHIEVED_STATE,)
    # and the JWT sibling class is likewise untouched
    assert v.oracles_for("jwt_forgeable") == (OracleKind.SSO_ASSERTION_FORGERY,)


# ---------------------------------------------------------------------------
# confirmation via the seam + the verifier
# ---------------------------------------------------------------------------


def test_confirm_via_seam_and_verifier() -> None:
    forged = _response(_assertion("_a1", "alice@corp.test"))  # unsigned -> forgeable
    assert confirm_saml_forgery(forged).confirmed
    assert OracleVerifier().confirm(saml_forgery_context(forged)).confirmed

    # a properly signed single assertion is NOT confirmed (stays an honest LEAD)
    proper = _response(_assertion("_a1", "alice@corp.test", sig_ref="_a1"))
    assert not confirm_saml_forgery(proper).confirmed


# ---------------------------------------------------------------------------
# offline re-verification (prove-don't-guess) + adapter retention
# ---------------------------------------------------------------------------


def test_confirmed_forgery_reverifies_offline_from_its_retained_context() -> None:
    wrapped = wrap_assertion_xsw(
        _response(_assertion("_orig", "legit@corp.test", sig_ref="_orig")),
        "attacker@sso-test.invalid",
    )
    oracle_context = saml_forgery_context(wrapped)
    # no target, no forged traffic — re-run the pure oracle over the retained XML
    r = reverify_context(oracle_context, bug_class="saml_structural_forgery")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.SAML_STRUCTURAL_FORGERY.value


def test_adapter_builder_emits_saml_xml() -> None:
    xml = _response(_assertion("_a1", "alice@corp.test"))
    emitted = FindingContext.from_saml_structure(xml).to_verifier_context()
    assert emitted["bug_class"] == "saml_structural_forgery"
    assert emitted["saml_xml"] == xml
