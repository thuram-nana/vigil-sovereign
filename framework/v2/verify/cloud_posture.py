"""
verify.cloud_posture — the confirmation seam for the cloud/CSPM-posture oracle (Wave-F1).

The cloud-runtime achieved-state half of prove-don't-guess, and the SIBLING of ``verify.k8s_posture``.
A CSPM tool (ScoutSuite / Prowler / a provider export) reports "resource R is public / unencrypted /
grants ``*``". That is a THIRD-PARTY LEAD (``sensors.cloud.cloud_posture_leads`` mints it as
``GROUNDING_INTEL``) — a `fact` only when a deterministic oracle proves a CONCRETE insecure ACHIEVED
STATE over the RETAINED control. This module is that seam: it routes a retained cloud control through
the pure ``cloud_posture_oracle`` and returns a re-verifiable verdict.

Two properties make this a re-verification rather than a rubber-stamp of the scanner's say-so, exactly
like ``verify.k8s_posture`` / ``verify.policy_path``:

  * The control judged is the sensor's RETAINED evidence (the resource's achieved-state flags —
    ``encrypted`` / ``public`` / ``sensitive`` / the named principals), NOT a re-run of a live cloud
    call laundered into a fact. The lead says "public / unencrypted"; the oracle re-derives the weakness
    from the observed achieved state and fires only when it literally carries an insecure fact (a
    compliant control does not confirm).
  * The retained control is JSON-safe and the oracle is pure, so a confirmed cloud-posture FACT
    RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no cloud and no trust in the
    scanner — re-run the membership/parse-proof over the retained control, get the same verdict.

Complementary to (never a replacement for) ``sensors.cloud.confirm_cloud_posture_facts``: that seam
promotes the ``public_exposure`` / ``excessive_privilege`` leads by re-deriving a grant PATH over the
whole policy GRAPH with the EXISTING POLICY_PATH oracle; THIS seam promotes the achieved-STATE facts a
reachability path cannot prove — principally the ``misconfiguration`` (encryption-at-rest-disabled) lead
that is ``oracle_provable=False`` there. Like ``verify.policy_path`` there is NO active probe and NO gate
here: the "capture" is the offline, kill-switch-gated cloud ingest the sensor already ran; this is a pure
re-derivation over it.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def cloud_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained cloud-posture control — routes to the cloud-posture oracle."""
    return FindingContext.from_cloud_control(dict(control or {})).to_verifier_context()


def confirm_cloud_posture(control: Mapping[str, Any], *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a retained cloud-posture control with the deterministic oracle: ``confirmed`` iff the
    control's RETAINED achieved state provably carries an insecure fact (encryption-at-rest disabled on a
    sensitive datastore, an explicit public-exposure flag, or a wildcard/anonymous principal named in the
    retained policy). The retained ``control`` is JSON-safe, so the same verdict re-verifies offline from
    the finding's certificate via ``verify.reverify``. A compliant control — encryption on, not public,
    no wildcard principal — or one with only absent/unknown flags is NOT confirmed (it stays an honest
    LEAD). NO live cloud call is ever made: this is a pure re-derivation over already-ingested evidence."""
    return (verifier or OracleVerifier()).confirm(cloud_posture_context(control))
