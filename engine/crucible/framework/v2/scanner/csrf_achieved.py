"""
scanner.csrf_achieved — CSRF ACHIEVED, confirmed by an OBSERVABLE cross-site state
change reached with ONLY the ambient session cookie (Wave-3.3, gated-workflow).

Cross-site request forgery (CWE-352) is an authorization bug: a state-changing request
a victim's browser issues cross-site is honored because it rides the victim's ambient
session cookie, and the app neither validates a synchronizer token nor an Origin, nor
scopes the cookie with SameSite. The posture oracle (``verify.oracles.csrf_posture_oracle``)
finds a *lead / posture-FACT*: a state-changing request accepted 2xx with a valid token
AND accepted 2xx with the token stripped proves the token is unenforced — but it says
NOTHING about whether a cross-site attack actually succeeds (a SameSite=Lax cookie, or an
Origin check, is a separate defense the posture oracle explicitly does not adjudicate).
That gap is exactly why the naive "no CSRF token ⇒ CSRF" claim was refused.

This module proves the achieved exploit end to end, judging the ACHIEVED post-state, never
the token's mere absence:

  1. mint a UNIQUE per-probe ``marker`` (a fresh high-entropy token) that the write carries,
     so a state change is attributable to THIS probe and cannot pre-exist in the readback;
  2. issue the state-changing request CROSS-ORIGIN (from a context whose scheme+host+port
     genuinely differ from the target's) carrying ONLY the ambient session cookies VIGIL's
     OWN authenticated session already holds — no attacker-supplied anti-CSRF token, custom
     header, or extra credential — through the gated write path (the 0.3 owner-signed
     per-action approval authorizes the write to HAPPEN; the oracle still adjudicates the
     FACT);
  3. read back the AUTHORITATIVE post-state (an independent, non-destructive GET of the
     resource state — NEVER the attacker's echo of its own request) both after a NO-COOKIE
     control (issued FIRST) and after the ambient-cookie treatment;
  4. fire the ``csrf_achieved`` oracle (``verify.oracles.csrf_achieved_oracle``,
     ``OracleKind.ACHIEVED_STATE``, conf 0.9) ONLY when the marker appears in the
     with-ambient-cookie readback AND is ABSENT from the no-cookie control readback — the
     write was authorized SOLELY by the ambient cookie riding cross-site.

This DISSOLVES the SameSite objection: a Lax/Strict cookie is not sent on a cross-site
request, so the treatment produces no state change, the marker never appears, and the oracle
correctly does NOT fire. An enforced anti-CSRF token likewise rejects the token-less
cross-site write. An endpoint that accepts the write with NO cookie at all (merely
unauthenticated, not CSRF) leaves the marker in the control readback and does not fire.

The confirmation is a ``verify.FindingContext`` (``from_csrf_achieved``, bug_class
``csrf_achieved``), so a confirmed CSRF carries the same re-verifiable certificate every
other CRUCIBLE finding does — the retained ``oracle_context`` re-fires the pure oracle
offline and a tampered readback no longer confirms.

Soundness is total (a fire means the ambient cookie riding cross-site is what reached the
post-state, attributed via the no-cookie control); the class is gated-workflow — it needs a
VIGIL-OWNED authenticated session and an operator-declared observable post-state (a bizlogic
readback spec), and the write goes through the 0.3 approval. Absent those, or when the
post-state is unobservable, the claim stays a LEAD/INCONCLUSIVE — never a false negative,
never a CLEAN, and never the naive token-absence false-positive.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Optional

from ..verify.adapter import FindingContext

# The state-changing request goes through the gated write path; the authoritative post-state
# read is a non-destructive GET. The runner (integration/vigil_integration/live) supplies both
# callables — the WRITE one wraps the 0.3 owner-signed per-action approval, the READ one the
# WARDEN-gated GET. This module stays transport-agnostic (I/O via injected callables) so it is
# pure to unit-test and cannot itself send un-gated traffic.
SubmitFn = Callable[..., None]      # submit(*, with_ambient_cookies: bool, marker: str) -> None
ReadStateFn = Callable[[], object]  # read_state() -> the authoritative post-state (str/bytes/obj)

_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class CsrfAchievedResult:
    """One CSRF-achieved re-drive attempt against a state-changing endpoint."""
    method: str
    endpoint: str
    marker: str
    with_cookie_state: str
    no_cookie_state: str
    cross_origin: bool
    ambient_only: bool
    channel_established: bool
    achieved: bool
    context: FindingContext


def _mint_marker() -> str:
    # A VIGIL-chosen unique per-probe token; the oracle floors the length at 8, this gives 32 hex.
    return "VIGIL-CSRF-" + secrets.token_hex(16)


def confirm_csrf_achieved(
    *,
    submit: SubmitFn,
    read_state: ReadStateFn,
    method: str,
    endpoint: str,
    marker: Optional[str] = None,
    cross_origin: bool = True,
    ambient_only: bool = True,
) -> CsrfAchievedResult:
    """Drive the cross-site state-changing request (control WITHOUT the ambient cookies FIRST, then
    treatment WITH them) and read the authoritative post-state after each, returning a
    :class:`CsrfAchievedResult`.

    ``result.achieved`` (and the ``csrf_achieved`` oracle over ``result.context``) is True only when the
    unique ``marker`` reached the post-state WITH the ambient cookie but is ABSENT from the no-cookie
    control — an achieved cross-site state change, never the naive token-absence signal. The control is
    issued FIRST so a marker already present there attributes the change to something other than the
    cookie (a merely-unauthenticated endpoint) and correctly suppresses the fire.

    ``submit`` MUST route the WITH-ambient-cookie write through the gated per-action approval; the READ is
    a non-destructive GET. A transport failure on either leg yields an empty readback (⇒ no channel ⇒
    non-firing result / LEAD), never a guess. ``method`` must be state-changing; a safe method returns a
    non-firing result (the oracle also REFUSES it)."""
    marker = marker or _mint_marker()
    method_u = (method or "").strip().upper()

    def _read() -> str:
        try:
            return _coerce(read_state())
        except Exception:       # noqa: BLE001 — a failed readback is no-channel, never a guess
            return ""

    channel = True
    # CONTROL FIRST: identical cross-site request WITHOUT the ambient cookies.
    try:
        submit(with_ambient_cookies=False, marker=marker)
    except Exception:           # noqa: BLE001
        channel = False
    no_cookie_state = _read()

    # TREATMENT: the SAME cross-site request carrying ONLY the ambient session cookies (gated write).
    try:
        submit(with_ambient_cookies=True, marker=marker)
    except Exception:           # noqa: BLE001
        channel = False
    with_cookie_state = _read()

    ctx = FindingContext.from_csrf_achieved(
        method=method_u,
        endpoint=endpoint,
        marker=marker,
        with_cookie_state=with_cookie_state,
        no_cookie_state=no_cookie_state,
        cross_origin=cross_origin,
        ambient_only=ambient_only,
    )
    achieved = (
        method_u in _STATE_CHANGING
        and cross_origin is True
        and ambient_only is True
        and marker in with_cookie_state
        and marker not in no_cookie_state
    )
    return CsrfAchievedResult(
        method=method_u,
        endpoint=endpoint,
        marker=marker,
        with_cookie_state=with_cookie_state,
        no_cookie_state=no_cookie_state,
        cross_origin=bool(cross_origin),
        ambient_only=bool(ambient_only),
        channel_established=channel,
        achieved=bool(achieved),
        context=ctx,
    )


def _coerce(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def csrf_achieved_finding(result: CsrfAchievedResult, *, check_id: str = "") -> dict:
    """Build the finding dict (carrying the retained ``oracle_context``) for a CSRF-achieved result, ready
    for the STD-WIRING admission choke (``verdict.admit("csrf_achieved.achieved_state", ...)`` →
    ``oracle_adapter.certify_admitted(provenance="live_redrive")``).

    The ``oracle_context`` is the pure, re-verifiable bundle the ``csrf_achieved`` oracle re-fires over
    offline; ``framework.v2 verify`` re-runs it and ``reverify.matches_claim`` rejects any tamper (a
    mutated readback no longer carries the unique marker in the with-cookie state / absent in the
    control)."""
    return {
        "check_id": check_id or f"csrf_achieved:{result.method}:{result.endpoint}",
        "bug_class": "csrf_achieved",
        "title": "CSRF achieved (cross-site state change reached with only the ambient session cookie)",
        "severity": "High",
        "surface": f"{result.method} {result.endpoint}",
        "summary": (
            "a state-changing request issued cross-origin carrying only the ambient session cookie "
            "reached an authoritative post-state change (a unique per-probe marker) that the no-cookie "
            "control did not — the write was authorized solely by the cookie riding cross-site"
        ),
        "oracle_context": result.context.to_verifier_context(),
    }
