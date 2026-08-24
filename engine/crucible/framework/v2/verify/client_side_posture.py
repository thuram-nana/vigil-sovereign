"""verify.client_side_posture — the confirmation seam + minimal offline ingest for the three
always-applicable constitution *client-side* posture-weakness oracles (W16-STD-5).

Constitution §V names four always-applicable client-side classes — XSS, **CSRF**, **clickjacking**,
**postMessage**. XSS already has an oracle (``reflection_context`` / ``dom_execution``); this module is
the confirmation seam for the other three, each of which proves a **MISSING or WEAK client-side
DEFENSE** (a posture weakness) from a RETAINED artifact ALONE — a captured response's headers, a
control-vs-treatment response pair, or a message handler's source — offline, ZERO traffic. Exactly like
``verify.email_auth`` / ``verify.cicd_posture``, it maps an operator-/scanner-supplied observation into
the canonical control shape the oracle judges, then routes it through the deterministic oracle.

**Deliberately out of scope (REFUSE, never assert): the achieved-state exploit.** A single-response
"the page WAS framed" / "the forged request went through" signal cannot be made near-zero-FP
(legitimate framing, intentional embedding, SameSite-protected endpoints), so VIGIL does NOT build an
achieved-state clickjacking/CSRF oracle — it proves the WEAKNESS (the absent/weak defense) instead. See
``docs/DELIBERATE-REFUSALS.md`` refusal 8. The three oracles emit FACTs about the DEFENSE POSTURE, never
a proven exploit.

No benchmark/scan/engage finding carries ``clickjacking_control`` / ``csrf_control`` /
``postmessage_control``, so the gate stays byte-identical. Never raises: a malformed observation is a
non-ingestion (the oracle refuses), not a crash.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


# ---------------------------------------------------------------------------
# Clickjacking — missing framing defense (X-Frame-Options / CSP frame-ancestors)
# ---------------------------------------------------------------------------


def clickjacking_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained response's headers — routes to the clickjacking posture oracle.
    Total: a non-mapping yields an empty control (which the oracle refuses), never an exception."""
    src = control if isinstance(control, Mapping) else {}
    return FindingContext.from_clickjacking_control(dict(src)).to_verifier_context()


def confirm_clickjacking_posture(control: Mapping[str, Any], *,
                                 verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained response: ``confirmed`` iff the oracle re-derives that NEITHER a framing
    X-Frame-Options (DENY/SAMEORIGIN) NOR a CSP frame-ancestors directive is present. Offline; never raises."""
    return (verifier or OracleVerifier()).confirm(clickjacking_context(control))


def ingest_response_headers(url: str, headers: Mapping[str, Any]) -> dict[str, Any]:
    """Map ONE captured response's headers into the control the clickjacking oracle judges. Pass the
    headers EXACTLY as observed (the complete captured header set — the oracle proves BOTH defenses absent,
    so a partial header set would be unsound). Absence of a framing header in a captured response IS its
    observation (unlike a DNS lookup); no separate ``observed`` flag is needed."""
    return {"rule": "framing_unprotected", "url": str(url or ""), "headers": dict(headers or {})}


# ---------------------------------------------------------------------------
# CSRF — anti-CSRF (synchronizer) token not enforced (control-differential)
# ---------------------------------------------------------------------------


def csrf_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained control-vs-treatment status pair — routes to the CSRF oracle."""
    src = control if isinstance(control, Mapping) else {}
    return FindingContext.from_csrf_control(dict(src)).to_verifier_context()


def confirm_csrf_posture(control: Mapping[str, Any], *,
                         verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained CSRF control-differential: ``confirmed`` iff a state-changing request was accepted
    (2xx) with a valid anti-CSRF token AND accepted (2xx) with the token removed/forged — proving the token
    is NOT enforced. Proves the missing token defense, never a cross-site exploit. Offline; never raises."""
    return (verifier or OracleVerifier()).confirm(csrf_context(control))


def ingest_csrf_differential(method: str, endpoint: str, *,
                             token_present_status: int, token_absent_status: int) -> dict[str, Any]:
    """Map ONE state-changing endpoint's CSRF control-differential into the control the oracle judges.
    ``token_present_status`` is the status when a VALID token is sent; ``token_absent_status`` is the status
    when the SAME request is replayed with the token REMOVED or FORGED. The oracle fires only when both are
    2xx (both accepted) on a state-changing method."""
    return {"rule": "token_not_enforced", "method": str(method or ""), "endpoint": str(endpoint or ""),
            "token_present_status": token_present_status, "token_absent_status": token_absent_status}


# ---------------------------------------------------------------------------
# postMessage — wildcard target-origin / missing origin check (static)
# ---------------------------------------------------------------------------


def postmessage_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained postMessage handler source — routes to the postMessage oracle."""
    src = control if isinstance(control, Mapping) else {}
    return FindingContext.from_postmessage_control(dict(src)).to_verifier_context()


def confirm_postmessage_posture(control: Mapping[str, Any], *,
                                verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained postMessage handler: ``confirmed`` iff the oracle re-derives a wildcard '*'
    targetOrigin send, or a handler that consumes event.data with NO origin check. A sound static check over
    the retained source. Offline; never raises."""
    return (verifier or OracleVerifier()).confirm(postmessage_context(control))


def ingest_postmessage_handler(handler_source: str, *, rule: str = "",
                               target_origin: str = "") -> dict[str, Any]:
    """Map ONE captured message handler (its source, and optionally a captured targetOrigin literal) into
    the control the postMessage oracle judges. ``rule`` is optional — the oracle infers ``wildcard_target``
    when a target origin/source is present, else ``no_origin_check`` — pass it to force one lens."""
    out: dict[str, Any] = {"handler_source": str(handler_source or "")}
    if rule:
        out["rule"] = str(rule)
    if target_origin:
        out["target_origin"] = str(target_origin)
    return out
