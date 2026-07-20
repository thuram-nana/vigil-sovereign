"""
verify.saml_forgery — the confirmation seam for the SAML structural-forgery oracle (Workstream NW-1).

The SAML half of prove-don't-guess and the SSO SIBLING of :mod:`verify.jwt_forgery`. A captured SAML
Response is only a LEAD — "this assertion looks unsigned", "the signature is over some other element" —
until a deterministic oracle proves it is STRUCTURALLY FORGEABLE from the captured XML ALONE. This
module is that seam: it routes a decoded SAML Response through the pure ``saml_forgery_oracle`` and
returns a re-verifiable verdict.

Two properties make this a re-verification, not a rubber-stamp of "it's a SAML message", exactly like
``verify.jwt_forgery`` / ``verify.k8s_posture`` / ``verify.policy_path``:

  * The judgement is a RE-RUNNABLE PROOF over the message's own XML: a coarse, c14n-free STRUCTURAL
    invariant a validly signed assertion cannot exhibit — an UNSIGNED consumed assertion, a
    ds:Reference/@URI that does not cover the consumed element, or the signature-wrapping shape (the
    dual of ``scanner.sso.wrap_assertion_xsw``). A properly signed single assertion whose Reference
    covers it — or a doc with no consumed NameID, or malformed/XXE-refused XML — is NOT confirmed
    (near-zero-FP); it stays an honest ``SsoLead``.
  * The XML is JSON-safe and the oracle is pure (it parses through the XXE-safe ``safe_parse_xml``), so
    a confirmed forgery RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no target
    and no forged traffic — re-run the structural analysis over the retained XML, get the same verdict.

There is NO active probe and NO gate here: the "capture" is a SAML Response the operator already holds
(a POST-binding ``SAMLResponse`` observed in their OWN SP integration). This is a pure re-derivation over
its decoded XML — ZERO bytes leave the box. Full XML-DSig C14N/transform processing is deliberately NOT
attempted (it needs lxml/signxml, out of scope); this is the OFFLINE STRUCTURAL COMPLEMENT to the LIVE
response-differential SAML checks in ``scanner.sso`` (SamlSignatureWrapping / SamlAssertionTampering).
"""

from __future__ import annotations

from typing import Sequence

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def saml_forgery_context(xml: str, candidate_certs: Sequence[str | bytes] = ()) -> dict:
    """The verifier context for a captured SAML Response's decoded XML — routes to the saml-forgery
    oracle. ``candidate_certs`` are the OPT-IN operator-supplied TRUSTED IdP PEM cert(s) the XML-DSig
    signature is cryptographically verified against when ``signxml`` is importable (absent -> structural)."""
    return FindingContext.from_saml_structure(xml, candidate_certs=candidate_certs).to_verifier_context()


def confirm_saml_forgery(
    xml: str,
    candidate_certs: Sequence[str | bytes] = (),
    *,
    verifier: OracleVerifier | None = None,
) -> VerificationResult:
    """Judge a captured SAML Response with the deterministic oracle: ``confirmed`` iff the decoded XML is
    provably STRUCTURALLY FORGEABLE from the message alone — an unsigned consumed assertion, a
    ds:Reference/@URI that does not cover the consumed element, or the signature-wrapping shape (the dual
    of ``scanner.sso.wrap_assertion_xsw``); OR (opt-in, when ``candidate_certs`` — the TRUSTED IdP cert(s)
    — are supplied AND ``signxml`` is importable) when the ds:Signature is DEFINITIVELY cryptographically
    INVALID against those trusted anchors (wrong signer / tampered digest). The signature's OWN embedded
    cert is NEVER trusted, and a signature signxml cannot verify is REFUSED not confirmed. The XML + PEM
    certs are JSON-safe, so the same verdict re-verifies offline from the finding's certificate via
    ``verify.reverify``. A properly signed single assertion, a doc with no consumed NameID, and malformed
    / XXE-refused XML are NOT confirmed (they stay honest LEADs). ZERO forged traffic to any target."""
    return (verifier or OracleVerifier()).confirm(saml_forgery_context(xml, candidate_certs))
