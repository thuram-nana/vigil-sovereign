"""verify.mobile_posture — the confirmation seam for the mobile-posture oracle.

A MobSF static-analysis report yields mobile-posture LEADS (``sensors.mobile``). The adversarial soundness
map ruled nearly every mobile signal a LEAD — an Android precedence/gating chain (network_security_config
vs the manifest cleartext attr, min vs target vs device SDK, explicit vs default component export) that a
MobSF descriptor routinely omits, so a naive promotion would false-fire. The ONE offline-re-derivable FACT
this slice proves is an embedded PRIVATE-KEY PEM block: ``mobile_posture_oracle`` RE-DERIVES it by actually
LOADING the key material (``cryptography``), firing ONLY on an UNENCRYPTED, structurally-valid private key.

No benchmark/scan/engage finding carries ``mobile_control``, so the gate stays byte-identical. Never
raises: an unrecognised control is a non-confirmation, not a crash. This is the SEAM only — the ingest
lives in ``sensors.mobile`` (``parse_mobsf`` retains the ``pem``); a direct ``confirm_mobile_control`` is
provided for callers holding a control dict.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def mobile_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained MobSF control — routes to the mobile-posture oracle."""
    return FindingContext.from_mobile_control(dict(control or {})).to_verifier_context()


def confirm_mobile_posture(control: Mapping[str, Any], *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained MobSF control: ``confirmed`` iff the oracle RE-DERIVES a concrete weakness over
    it (this slice: an embedded PEM private key that loads as an unencrypted key). Offline; never raises."""
    return (verifier or OracleVerifier()).confirm(mobile_posture_context(control))


def confirm_mobile_controls(controls: Any, *, verifier: OracleVerifier | None = None) -> list[dict[str, Any]]:
    """Return the retained controls the oracle CONFIRMED as FACTs (each with its rule/evidence).
    Convenience over ``confirm_mobile_posture``; deterministic; tolerant of a non-list."""
    if not isinstance(controls, (list, tuple)):
        return []
    v = verifier or OracleVerifier()
    out: list[dict[str, Any]] = []
    for c in controls:
        if isinstance(c, Mapping) and confirm_mobile_posture(c, verifier=v).confirmed:
            out.append(dict(c))
    return out
