"""verify.oracle_version — a content-derived version identity for each oracle kind.

The Proof-Carrying Findings (PCF) standard requires a certificate to name the EXACT oracle *id@version*,
so a verifier re-runs the SAME decision procedure that produced the verdict and can detect that the oracle
body changed since the certificate was issued. CRUCIBLE oracles carry a *kind* (``OracleKind``) but have no
version. This module derives one: ``oracle_version(kind)`` is a sha256 over the canonical SOURCE of the pure
function(s) that ``verifier._run`` dispatches ``kind`` to — so ANY change to an oracle's body changes its
version, and a certificate minted under the old body is detectably *stale* at re-verification.

The version is captured at MINT time and signed into the certificate (see ``evidence/certify.py``); a
verifier compares that stamped version against the CURRENT ``oracle_version(kind)``. If they differ, the
retained proof still re-fires but under a different procedure than the one the issuer signed — a fact PCF
requires be surfaced (and which the PCF verifier treats fail-closed).

Pure + deterministic: the hash is a stable function of the oracle source, identical across runs and across
machines holding the same source. Uses the SOURCE (not bytecode) so it is portable across Python versions —
the reference implementation ships with source. If the source is unavailable (a frozen/zipped deployment),
the version is the empty string and a PCF verifier reports it cannot confirm the version rather than guessing.
"""

from __future__ import annotations

import hashlib
import inspect
from functools import lru_cache
from typing import Any, Callable

from . import oracles
from .models import OracleKind

# The pure oracle function(s) each kind dispatches to in ``verifier._run``. A kind whose dispatch selects
# more than one function by context keys (TLS_WEAKNESS → protocol/cipher OR cert-signature; ACHIEVED_STATE
# → predicate OR expected/observed) lists ALL of them, so editing EITHER body changes the kind's version.
# A test pins ``set(_ORACLE_FNS) == set(OracleKind)`` so a newly-added kind must register here.
_ORACLE_FNS: dict[OracleKind, tuple[Callable[..., Any], ...]] = {
    OracleKind.DIFFERENTIAL_RESPONSE: (oracles.differential_response_oracle,),
    OracleKind.TIMING: (oracles.timing_oracle,),
    OracleKind.BOOLEAN_INFERENCE: (oracles.boolean_inference_oracle,),
    OracleKind.ACHIEVED_STATE: (oracles.predicate_oracle, oracles.achieved_state_oracle),
    OracleKind.SIDE_EFFECT: (oracles.side_effect_oracle,),
    OracleKind.REFLECTION_CONTEXT: (oracles.reflection_context_oracle,),
    OracleKind.EVALUATION: (oracles.evaluation_oracle,),
    OracleKind.ERROR_SIGNATURE: (oracles.error_signature_oracle,),
    OracleKind.DOM_EXECUTION: (oracles.dom_execution_oracle,),
    OracleKind.SANITIZER_SIGNAL: (oracles.sanitizer_signal_oracle,),
    OracleKind.OOB_CALLBACK: (oracles.oob_callback_oracle,),
    OracleKind.SERVICE_REACHABILITY: (oracles.service_reachability_oracle,),
    OracleKind.ACTIVE_EXPOSURE: (oracles.anonymous_reachable_oracle,),
    OracleKind.TLS_WEAKNESS: (oracles.tls_weakness_oracle, oracles.weak_crypto_artifact_oracle),
    OracleKind.VERSION_RANGE: (oracles.version_range_oracle,),
    OracleKind.POLICY_PATH: (oracles.policy_path_oracle,),
    OracleKind.SYSTEM_PROMPT_DISCLOSURE: (oracles.system_prompt_disclosure_oracle,),
    OracleKind.PROMPT_INJECTION: (oracles.prompt_injection_oracle,),
    OracleKind.AUTOMATED_ACCESS: (oracles.honeypot_hit_oracle,),
    OracleKind.CREDENTIAL_STUFFING: (oracles.credential_stuffing_oracle,),
    OracleKind.SQL_INJECTION_BREAKOUT: (oracles.sql_injection_breakout_oracle,),
    OracleKind.COMMAND_INJECTION_BREAKOUT: (oracles.command_injection_breakout_oracle,),
    OracleKind.NOSQL_INJECTION_BREAKOUT: (oracles.nosql_injection_breakout_oracle,),
    OracleKind.K8S_POSTURE: (oracles.k8s_posture_oracle,),
    OracleKind.CLOUD_POSTURE: (oracles.cloud_posture_oracle,),
    OracleKind.MESH_POSTURE: (oracles.mesh_posture_oracle,),
    OracleKind.CICD_POSTURE: (oracles.cicd_posture_oracle,),
    OracleKind.MOBILE_POSTURE: (oracles.mobile_posture_oracle,),
    OracleKind.EMAIL_AUTH_POSTURE: (oracles.email_auth_posture_oracle,),
    OracleKind.IDENTITY_POSTURE: (oracles.identity_posture_oracle,),
    OracleKind.SSO_ASSERTION_FORGERY: (oracles.jwt_forgery_oracle,),
    OracleKind.SAML_STRUCTURAL_FORGERY: (oracles.saml_forgery_oracle,),
}


def _coerce_kind(kind: Any) -> OracleKind | None:
    """Accept an ``OracleKind`` or its string value (a certificate stores ``confirmed_by`` as a str)."""
    if isinstance(kind, OracleKind):
        return kind
    try:
        return OracleKind(str(kind))
    except ValueError:
        return None


@lru_cache(maxsize=None)
def oracle_version(kind: Any) -> str:
    """The version identity for ``kind`` — ``"sha256:<hex>"`` over the canonical source of its oracle
    function(s), or ``""`` when the kind is unknown or its source is unavailable (a frozen deployment).
    Pure + deterministic. Accepts an ``OracleKind`` or its string value."""
    ok = _coerce_kind(kind)
    if ok is None:
        return ""
    fns = _ORACLE_FNS.get(ok)
    if not fns:
        return ""
    parts: list[str] = []
    for fn in fns:
        try:
            parts.append(inspect.getsource(fn))
        except (OSError, TypeError):
            return ""   # source unavailable → cannot derive a version (verifier reports, never guesses)
    blob = "\x00".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()
