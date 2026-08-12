"""verify.secret_capture — the confirmation seam for the E5 exposed-secret VALIDITY oracle (BUILD-PLAN §E5).

A DEFENSIVE VERIFICATION oracle, NOT a validation runner. A regex match on a leaked credential is a LEAD; it
becomes an achieved-effect FACT only when a deterministic oracle re-derives, over the RETAINED, secret-safe
capture ALONE, that the exposed secret AUTHENTICATED as a real identity via a confirming call BOUND to it
over a trusted, per-TYPE-allow-listed transport. This module routes a retained capture through the pure
``exposed_secret_validity_oracle`` and returns a re-verifiable verdict.

Like ``verify.imds_capture`` this is a pure re-derivation, NOT a re-run of a live call laundered as a fact:
it NEVER reaches the network, NEVER uses a secret, NEVER performs the validation — the live confirming call
is the WARDEN-gated runner's job and is separately gated. The retained capture is JSON-safe and SECRET-SAFE
(``FindingContext.from_secret_capture`` redacts the secret value to a ``[REDACTED]`` presence marker; the
oracle proves VALIDITY via the confirming call, never the secret's content), so a confirmed FACT re-verifies
OFFLINE from its certificate (``verify.reverify``) with no live secret in the certificate.

SOURCE-SEMANTICS INVERSION (see the oracle): the exposure ``source`` is retained as evidence but is NOT a
firing gate; the anti-laundering gate is the per-TYPE confirming-endpoint allow-list, so an attacker-
controlled 'confirming' endpoint can never launder an arbitrary string into a FACT.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def secret_capture_context(capture: Mapping[str, Any]) -> dict:
    """The verifier context for a retained exposed-secret capture — routes to the E5 validity oracle."""
    return FindingContext.from_secret_capture(dict(capture or {})).to_verifier_context()


def confirm_secret_capture(
    capture: Mapping[str, Any], *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a retained exposed-secret capture with the deterministic oracle: ``confirmed`` iff the capture
    PROVES the achieved effect — a structurally-recognized secret (an AWS AccessKeyId shape, a GitHub PAT
    prefix) that AUTHENTICATED via a confirming call (sts:GetCallerIdentity / GitHub ``GET /user``) whose
    endpoint is on the per-TYPE allow-list, bound to the secret over a validated-TLS, no-proxy, no-redirect
    transport. A recognized-but-unconfirmed secret, a failed confirming call, an un-allow-listed confirming
    endpoint (a laundering attempt), a fingerprint mismatch, an action/type mismatch, or malformed evidence
    is NOT confirmed (stays an honest LEAD). No live validation call is made and no secret is used: a pure
    re-derivation over already-captured, secret-safe evidence."""
    return (verifier or OracleVerifier()).confirm(secret_capture_context(capture))
