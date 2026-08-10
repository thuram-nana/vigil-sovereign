"""
verify.imds_capture — the confirmation seam for the E1 IMDS/metadata credential-capture oracle
(BUILD-PLAN §E1).

The flagship exploitation-chain half of prove-don't-guess, and a DEFENSIVE VERIFICATION oracle — NOT an
attack runner. An SSRF/foothold reaching the instance metadata endpoint is a LEAD; it becomes an
achieved-effect FACT only when a deterministic oracle re-derives, over the RETAINED capture ALONE, BOTH
that role/SA credentials were retrieved from the metadata endpoint AND that a confirming call
(sts:GetCallerIdentity / a GCP tokeninfo) proved them usable. This module is that seam: it routes a
retained capture through the pure ``imds_credential_capture_oracle`` and returns a re-verifiable verdict.

Two properties make this a re-verification rather than a rubber-stamp of the runner's say-so, exactly like
``verify.cloud_posture`` / ``verify.k8s_posture``:

  * The capture judged is the RETAINED evidence the WARDEN-A2-gated runner produced (the credential's
    structural fields + its metadata-endpoint source + the confirming call's identity echo), NOT a re-run
    of a live IMDS/STS call laundered into a fact. This module NEVER reaches the network, NEVER mints a
    token, NEVER performs the attack — the live action is the runner's job and is separately gated. The
    oracle re-derives the achieved effect from the observed evidence and fires only when it literally
    proves a credential was captured from IMDS AND authenticated (a retrieved-but-unconfirmed credential,
    a 401/timeout, or a failed confirming call does not confirm).
  * The retained capture is JSON-safe and SECRET-SAFE — ``FindingContext.from_imds_capture`` redacts the
    credential's secret material (SecretAccessKey / Token / access_token) to a presence marker (the oracle
    never validates a secret's content, only its presence) — and the oracle is pure, so a confirmed FACT
    RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no target, no network, and no live
    secret in the certificate — re-run the structural + authentication proof over the retained capture,
    get the same verdict.

Like ``verify.cloud_posture`` there is NO active probe and NO gate here: the "capture" is the offline,
WARDEN-gated evidence the runner already produced; this is a pure re-derivation over it.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def imds_capture_context(capture: Mapping[str, Any]) -> dict:
    """The verifier context for a retained IMDS/metadata credential-capture — routes to the E1 oracle."""
    return FindingContext.from_imds_capture(dict(capture or {})).to_verifier_context()


def confirm_imds_capture(
    capture: Mapping[str, Any], *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a retained IMDS/metadata credential-capture with the deterministic oracle: ``confirmed`` iff
    the capture PROVES the achieved effect — a structurally-valid credential retrieved FROM the metadata
    endpoint (AWS AccessKeyId+SecretAccessKey+Token from ``169.254.169.254/iam/security-credentials``, or a
    GCP Bearer ``access_token`` from ``computeMetadata/v1/.../service-accounts/.../token``) AND a confirming
    call (sts:GetCallerIdentity / tokeninfo) that authenticated with it. The retained capture is JSON-safe
    and secret-safe, so the same verdict re-verifies offline from the finding's certificate via
    ``verify.reverify``. A retrieved-but-unconfirmed credential, a 401/timeout, a failed confirming call, a
    credential NOT from the metadata endpoint, or malformed evidence is NOT confirmed (it stays an honest
    LEAD). NO live IMDS/STS call is ever made and no attack is ever performed: this is a pure re-derivation
    over already-captured evidence."""
    return (verifier or OracleVerifier()).confirm(imds_capture_context(capture))
