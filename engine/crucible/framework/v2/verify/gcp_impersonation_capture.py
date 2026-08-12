"""verify.gcp_impersonation_capture — the confirmation seam for the E3 GCP service-account IMPERSONATION
oracle (BUILD-PLAN §E3).

A DEFENSIVE VERIFICATION oracle, NOT an impersonation runner. A principal *able* to impersonate a service
account is a LEAD; it becomes an achieved-effect FACT only when a deterministic oracle re-derives, over the
RETAINED, secret-safe capture ALONE, that a short-lived token was minted AS the named target service-account
B (via iamcredentials getAccessToken / generateAccessToken / signJwt / an actAs / serviceAccountTokenCreator
flow) AND that a confirming tokeninfo/userinfo call ECHOED B's identity at a TRUSTED, allow-listed Google
endpoint, bound to the mint by a shared token fingerprint. This module routes a retained capture through the
pure ``gcp_sa_impersonation_oracle`` and returns a re-verifiable verdict.

Like ``verify.secret_capture`` this is a pure re-derivation, NOT a re-run of a live mint/introspect call
laundered as a fact: it NEVER reaches the network, NEVER mints a token, NEVER performs the impersonation — the
live mint + confirming call is the WARDEN-gated runner's job and is separately gated. The retained capture is
JSON-safe and SECRET-SAFE (``FindingContext.from_gcp_impersonation_capture`` redacts the minted token to a
``[REDACTED]`` presence marker; the oracle proves impersonation via the confirming echo + the fingerprint
binding, never the token's content), so a confirmed FACT re-verifies OFFLINE from its certificate
(``verify.reverify``) with no live token in the certificate.

E3 is the OPPOSITE shape to E1 (see the oracle): E1 gates on the credential SOURCE host (a credential
retrieved FROM the metadata endpoint); E3 makes no source claim and gates entirely on the CONFIRMING-side
identity echo of the target SA + the per-endpoint allow-list, so an attacker-controlled 'tokeninfo' endpoint
can never launder an arbitrary token into a FACT.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def gcp_impersonation_capture_context(capture: Mapping[str, Any]) -> dict:
    """The verifier context for a retained GCP SA-impersonation capture — routes to the E3 oracle."""
    return FindingContext.from_gcp_impersonation_capture(dict(capture or {})).to_verifier_context()


def confirm_gcp_impersonation_capture(
    capture: Mapping[str, Any], *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a retained GCP SA-impersonation capture with the deterministic oracle: ``confirmed`` iff the
    capture PROVES the achieved effect — an impersonation token minted AS a named target service-account B
    (an iamcredentials getAccessToken/generateAccessToken/signJwt verb, or an actAs /
    serviceAccountTokenCreator flow) that AUTHENTICATED via a confirming tokeninfo/userinfo call ECHOING B's
    identity, over a trusted, allow-listed Google endpoint, bound to the mint by a shared token fingerprint. A
    non-impersonation mint, a minted-but-unconfirmed token, a failed confirming call, an echo of a DIFFERENT
    SA, a fingerprint mismatch, an un-allow-listed confirming endpoint (a laundering attempt), or malformed
    evidence is NOT confirmed (stays an honest LEAD). No live mint/introspect call is made and no token is
    used: a pure re-derivation over already-captured, secret-safe evidence."""
    return (verifier or OracleVerifier()).confirm(gcp_impersonation_capture_context(capture))
