"""
scanner.mfa — the MFA-bypass achieved-state re-drive (Wave-4.5, gated-workflow, opt-in). CWE-287/CWE-308.

A "second-factor bypass" is an ACHIEVED-STATE claim: a session that completed ONLY factor-1
(username+password / a magic link / an SSO first hop) nevertheless reaches a resource the app is supposed to
release ONLY after factor-2. Wave-3 proved an achieved authenticated state CANNOT be proven from response
CONTENT, and — worse here — an INTENTIONALLY factor-1 page (a public dashboard, a "verify your device"
landing page) is byte-for-byte indistinguishable, from the outside, from a page that leaked past MFA. No
automatic content check can tell a deliberate factor-1 surface from a bypassed one.

So this VIGIL-owned re-drive (the RUNNER crafts every probe through the injected, scope/charter/kill-switch-
gated ``send`` — never the tool, never the LLM) captures the RAW bytes and hands them, together with the
operator's THREE-PART attestation, to the deterministic :func:`~framework.v2.verify.oracles.mfa_bypass_oracle`
via :meth:`FindingContext.from_mfa_bypass`. The oracle — never this code — decides, under TWO independent
locks (see the oracle's module docstring):

  LOCK 1 — a FAIL-CLOSED operator attestation, re-derived at every verification: (a) the account is
           MFA-ENROLLED, (b) VIGIL's session presented ONLY factor-1, (c) the read resource/datum is genuinely
           gated BEHIND factor-2 (the lock that closes the killer FP of an intentionally factor-1 page).
  LOCK 2 — the PRIVATE-READ REDUCTION (the same Wave-3.1 / session-fixation differential): the operator's
           genuine victim-PRIVATE datum D is PRESENT in the factor-1-only session's read of the post-MFA
           resource AND in a fully post-MFA-authenticated OWNER's authoritative read yet PROVABLY ABSENT from a
           SUBSTANTIVE SAME-SHAPE 2xx read by an OTHER not-post-MFA identity AND from a no-session baseline.

WITHOUT the attestation the oracle emits NO fire for ANY input (a rigorous LEAD); a benign app that correctly
enforces factor-2 (D absent from the factor-1-only read, present for the owner) is a channel-confirmed CLEAN,
never a FACT. Nothing in the default scan/engage roster supplies the attestation or the private D + references,
so this check is opt-in and mints nothing at runtime — the default benchmark sends zero MFA-bypass requests
and ``make gate`` stays byte-identical.
"""

from __future__ import annotations

from ..verify.adapter import FindingContext
from .checks import Send
from .insertion import HttpRequest


def _mfa_view(resp: object) -> dict:
    """The retained ``{status, body}`` of a protected-page response the oracle re-runs its differential over.
    A non-dict (no channel on that leg) becomes ``{status: None, body: ""}`` — a non-substantive view the
    oracle treats as undecidable (fails closed to a LEAD), never as a differential reference."""
    if isinstance(resp, dict):
        return {"status": resp.get("status"), "body": str(resp.get("body", ""))}
    return {"status": None, "body": str(resp) if resp is not None else ""}


def confirm_mfa_bypass(
    send: Send,
    *,
    protected_url: str,
    factor1_send: Send,
    private_discriminator: str | None = None,
    owner_send: Send | None = None,
    other_identity_send: Send | None = None,
    mfa_enrolled_account: bool = False,
    factor1_only_presented: bool = False,
    post_mfa_resource_certified: bool = False,
    logged_out_markers: tuple[str, ...] = (),
    logged_out_statuses: tuple[int, ...] = (401, 403),
) -> FindingContext | None:
    """Gated-workflow MFA-bypass probe (CWE-287/CWE-308).

    The RUNNER crafts every probe — a GET of ``protected_url`` through each injected, gated send — and captures
    the RAW responses:

      * ``factor1_send``          — an operator-supplied ``send`` whose session completed ONLY factor-1 (no
        OTP/WebAuthn/push): its read is the BYPASS-under-test (D present ⇒ the factor-1-only session reached
        the post-MFA content);
      * ``owner_send``            — a fully post-MFA-authenticated OWNER/victim ``send`` (the POSITIVE reference:
        the operator's ``private_discriminator`` D must be PRESENT — proving D is REAL post-MFA-gated content);
      * ``other_identity_send``   — an OTHER not-post-MFA identity ``send`` (the DECISIVE SAME-SHAPE negative
        reference: a substantive same-shape 2xx from which D must be ABSENT — the only reference a benign
        credential-presence-varying app cannot fool, since cosmetic chrome shown for any credential appears
        here too);
      * a no-session gating baseline: ``protected_url`` fetched through the bare ``send`` with NO session.

    The three attestation booleans are the operator's HARD certification (each must be genuinely ``True``); the
    scanner makes NO authentication decision and NO attestation decision — it hands the RAW bytes + the
    attestation to :func:`~framework.v2.verify.oracles.mfa_bypass_oracle`, which fires ONLY under the complete
    attestation AND when the PRIVATE-READ differential proves the factor-1-only session reached the victim's
    post-MFA private view. Returns ``None`` only when no channel was established for the factor-1-only read (a
    non-dict response); every other outcome is adjudicated by the oracle. All traffic rides the injected sends
    (the scope/charter/kill-switch-gated executor); nothing here weakens the boundary."""
    protected_get = HttpRequest(method="GET", url=protected_url, headers=[], body=None)

    # 0. NO-SESSION GATING BASELINE: fetch the protected URL with NO session. D absent from a valid
    #    (substantive-2xx or genuine-denial) read proves the datum is authorization-gated, not public.
    logged_out_resp = send(protected_get)

    # 0b. POSITIVE reference (post-MFA owner) + DECISIVE SAME-SHAPE negative reference (other not-post-MFA
    #     identity). D PRESENT in the owner's read proves D is real post-MFA-gated content; D ABSENT from the
    #     other-identity's SUBSTANTIVE SAME-SHAPE read proves it is gated to the victim identity (not chrome
    #     shown for any credential). None when not supplied (⇒ the oracle fails closed to a LEAD — the achieved
    #     bypass is unprovable without them).
    owner_resp = owner_send(protected_get) if owner_send is not None else None
    other_resp = other_identity_send(protected_get) if other_identity_send is not None else None

    # 1. THE BYPASS-UNDER-TEST: read the protected URL through the factor-1-ONLY session and CAPTURE THE RAW
    #    RESPONSE. The oracle re-derives — from these raw bytes vs the owner/other-identity/no-session
    #    references — whether the factor-1-only session reached the victim's post-MFA private view.
    factor1_resp = factor1_send(protected_get)
    if not isinstance(factor1_resp, dict):
        return None   # no channel established for the factor-1-only read — INCONCLUSIVE, never a CLEAN

    return FindingContext.from_mfa_bypass(
        mfa_enrolled_account=mfa_enrolled_account,
        factor1_only_presented=factor1_only_presented,
        post_mfa_resource_certified=post_mfa_resource_certified,
        private_discriminator=private_discriminator,
        factor1_view=_mfa_view(factor1_resp),
        owner_view=_mfa_view(owner_resp) if owner_resp is not None else None,
        pre_mfa_ref=_mfa_view(other_resp) if other_resp is not None else None,
        logged_out_ref=_mfa_view(logged_out_resp),
        logged_out_markers=logged_out_markers,
        logged_out_statuses=logged_out_statuses,
    )
