"""
verify.jwt_forgery — the confirmation seam for the SSO/JWT structural-forgery oracle (Workstream-B).

The SSO/JWT half of prove-don't-guess. A captured JWT is only a LEAD — "this looks like an HS256
token", "the header says alg=none" — until a deterministic oracle proves it is STRUCTURALLY FORGEABLE
from the token ALONE. This module is that seam: it routes a captured token (plus any candidate secrets
/ RSA public keys) through the pure ``jwt_forgery_oracle`` and returns a re-verifiable verdict.

Two properties make this a re-verification, not a rubber-stamp of "it's a JWT", exactly like
``verify.k8s_posture`` / ``verify.version`` / ``verify.policy_path``:

  * The judgement is a RE-RUNNABLE PROOF over the token's own bytes: ``alg=none``/``None`` (a valid
    token needs no secret), an HS* signature RECOMPUTABLE from a supplied/weak candidate key (the exact
    HMAC reproduces), or an RS256->HS256 confusion (the HS* signature verifies with a supplied RSA
    PUBLIC key as the HMAC secret). A normal RS256 token with an unknown key — or an HS* token whose
    secret is not recoverable — is NOT confirmed (near-zero-FP); it stays an honest LEAD.
  * The token + candidate keys are JSON-safe and the oracle is pure, so a confirmed forgery
    RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no target and no forged traffic
    — re-run the recomputation over the retained token, get the same verdict, byte-for-byte.

There is NO active probe and NO gate here: the "capture" is a token the operator already holds (a
cookie/Authorization header observed in their OWN session, or an artifact from their SSO/RP
integration). This is a pure re-derivation over it — ZERO bytes leave the box. SAML XSW/c14n forgery is
deliberately NOT attempted in this slice; this is JWT-only (see the roadmap note in the oracle module).
"""

from __future__ import annotations

from typing import Sequence

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def jwt_forgery_context(token: str, candidate_keys: Sequence[str | bytes] = ()) -> dict:
    """The verifier context for a captured JWT — routes to the jwt-forgery oracle."""
    return FindingContext.from_jwt_token(token, candidate_keys=candidate_keys).to_verifier_context()


def confirm_jwt_forgery(
    token: str,
    candidate_keys: Sequence[str | bytes] = (),
    *,
    verifier: OracleVerifier | None = None,
) -> VerificationResult:
    """Judge a captured JWT with the deterministic oracle: ``confirmed`` iff the token is provably
    STRUCTURALLY FORGEABLE from the token alone — ``alg=none``/``None``, an HS* signature recomputable
    from a supplied/weak candidate key, or an RS256->HS256 confusion. The token + candidate keys are
    JSON-safe, so the same verdict re-verifies offline from the finding's certificate via
    ``verify.reverify``. A normal RS256 token with an unknown key — or an HS* token whose secret is not
    recoverable — is NOT confirmed (it stays an honest LEAD). ZERO forged traffic to any target."""
    return (verifier or OracleVerifier()).confirm(jwt_forgery_context(token, candidate_keys))
