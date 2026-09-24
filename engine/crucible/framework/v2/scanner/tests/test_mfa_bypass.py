"""
MFA-bypass confirmation (Wave 4.5, gated-workflow) — end-to-end over the in-process benchmark app, without a
browser: VIGIL reads a post-MFA-gated resource through a session that completed ONLY factor-1, captures the
factor-1-only read PLUS a POSITIVE reference (a fully post-MFA-authenticated owner's read), a DECISIVE
SAME-SHAPE negative reference (an OTHER not-post-MFA identity's read) and a no-session baseline; the
deterministic ``mfa_bypass_oracle`` adjudicates under TWO locks — a FAIL-CLOSED operator attestation and the
PRIVATE-READ REDUCTION over the RAW retained bytes.

Principle (Wave-3 lesson + the killer FP): an achieved post-MFA state CANNOT be proven from response content,
AND an intentionally factor-1 page is byte-for-byte indistinguishable from a bypassed one from the outside. So
the oracle requires BOTH the three-part operator attestation (the account is MFA-enrolled, VIGIL presented only
factor-1, the resource is genuinely post-MFA-gated) AND a genuine victim-PRIVATE datum D PRESENT in the
factor-1-only read AND in a post-MFA owner's read yet PROVABLY ABSENT from a SUBSTANTIVE SAME-SHAPE read by an
OTHER not-post-MFA identity and a valid no-session baseline.

Proves:
  * a FACT on the PLANTED vulnerable console (``/mfa/bypass/account`` releases the per-user private datum to
    ANY factor-1 session), under the operator attestation;
  * SILENCE on the BENIGN TWIN (``/mfa/enforced/account`` releases the private datum only post-factor-2) —
    even WITH the attestation (the factor-1-only read lacks D);
  * the killer FP is CLOSED: WITHOUT the attestation the vulnerable console mints NOTHING (a LEAD) — live AND
    under offline re-verification;
  * the oracle NEVER trusts a pre-computed bool nor a bare marker;
  * the default GET-only crawl never touches the login POST route (the fixture is deep-only), so ``make gate``
    is unaffected.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from framework.v2.eval.benchmark_app import _MFA_SUCCESS_MARKER, _mfa_private, serve
from framework.v2.scanner.insertion import HttpRequest
from framework.v2.scanner.mfa import confirm_mfa_bypass
from framework.v2.scanner.session import CookieJar
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

_D = _mfa_private("admin")   # the victim (admin) PRIVATE, post-MFA-gated datum the differential requires


def _send(req: HttpRequest) -> dict:
    """A direct (test-only) send that faithfully carries the Cookie header and captures Set-Cookie — stands in
    for the gated CRUCIBLE executor for this deterministic in-process test."""
    body = req.body.encode("utf-8") if req.body is not None else None
    r = urllib.request.Request(req.url, data=body, method=req.method)
    for k, v in req.headers:
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:   # noqa: S310 (loopback benchmark app)
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
            headers = [(k, v) for k, v in resp.getheaders()]
    except urllib.error.HTTPError as e:                       # pragma: no cover - benchmark never 4xx/5xx here
        raw = e.read().decode("utf-8", "replace")
        status = e.code
        headers = list(e.headers.items())
    return {"status": status, "headers": headers, "body": raw}


def _authed_send(base: str, user: str, *, factor2: bool):
    """A ``send`` authenticated as ``user``. ``factor2=True`` completes the second factor (a full post-MFA
    session); ``factor2=False`` stops after factor-1 (a factor-1-only session). Log in via ``/mfa/login``,
    capture the MFASESSION cookie, and carry it on every request."""
    body = f"user={user}&password=x" + ("&factor2=yes" if factor2 else "")
    resp = _send(HttpRequest(method="POST", url=f"{base}/mfa/login",
                             headers=[("Content-Type", "application/x-www-form-urlencoded")], body=body))
    jar = CookieJar()
    jar.update_from_headers([(str(k), str(v)) for k, v in resp["headers"]])
    sid = jar.get("MFASESSION")

    def send(req: HttpRequest) -> dict:
        headers = [(k, v) for k, v in req.headers if k.lower() != "cookie"] + [("Cookie", f"MFASESSION={sid}")]
        return _send(req.model_copy(update={"headers": headers}))

    return send


def _confirm_offline(ctx: FindingContext) -> bool:
    """Re-verify from the SERIALIZED retained record — the durable-certificate path."""
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    return OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def _drive(base: str, protected_path: str, *, attested: bool):
    factor1 = _authed_send(base, "admin", factor2=False)        # the bypass-under-test: factor-1 ONLY, as admin
    owner = _authed_send(base, "admin", factor2=True)           # the fully post-MFA owner (POSITIVE reference)
    other = _authed_send(base, "attacker", factor2=False)       # an OTHER not-post-MFA identity (SAME-SHAPE neg)
    return confirm_mfa_bypass(
        _send,
        protected_url=f"{base}{protected_path}",
        factor1_send=factor1,
        private_discriminator=_D,
        owner_send=owner,
        other_identity_send=other,
        mfa_enrolled_account=attested,
        factor1_only_presented=attested,
        post_mfa_resource_certified=attested,
        logged_out_markers=("You are logged out",),
    )


def test_planted_mfa_bypass_confirms_a_fact() -> None:
    with serve() as base:
        ctx = _drive(base, "/mfa/bypass/account", attested=True)
    assert ctx is not None and ctx.bug_class == "mfa_bypass"
    rec = ctx.mfa_bypass
    assert rec is not None
    assert rec["operator_attestation"] == {
        "mfa_enrolled_account": True, "factor1_only_presented": True, "post_mfa_resource_certified": True}
    # the PRIVATE-READ differential raw material: D present in the factor-1-only read AND the owner's, absent
    # from the OTHER identity's same-shape read AND the no-session baseline; chrome IS present for the other.
    assert _D in rec["factor1_view"]["body"]
    assert _D in rec["owner_view"]["body"]
    assert _D not in rec["pre_mfa_ref"]["body"]
    assert _MFA_SUCCESS_MARKER in rec["pre_mfa_ref"]["body"]
    assert _D not in rec["logged_out_ref"]["body"]
    outcome = OracleVerifier().confirm(ctx.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.MFA_BYPASS and s.fired for s in outcome.signals)
    # round-trip: the retained context re-fires (a re-verifiable certificate) from the SAME raw bytes.
    assert _confirm_offline(ctx)


def test_benign_twin_that_enforces_factor2_never_fires() -> None:
    with serve() as base:
        ctx = _drive(base, "/mfa/enforced/account", attested=True)
    assert ctx is not None
    rec = ctx.mfa_bypass
    # the factor-1-only read carries the chrome but NOT the private datum (present only for the post-MFA owner).
    assert _MFA_SUCCESS_MARKER in rec["factor1_view"]["body"]
    assert _D not in rec["factor1_view"]["body"]
    assert _D in rec["owner_view"]["body"]
    outcome = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not outcome.confirmed          # the app enforces factor-2 — no bypass, even WITH the attestation
    assert not _confirm_offline(ctx)
    # and it is a channel-confirmed CLEAN, not a bare LEAD.
    sig = next(s for s in outcome.signals if s.kind is OracleKind.MFA_BYPASS)
    assert sig.conclusive and not sig.fired


def test_without_the_attestation_the_vulnerable_console_mints_nothing() -> None:
    # The KILLER FP: an intentionally factor-1 page is indistinguishable from a bypass. Absent the operator
    # attestation the oracle refuses to mint for the SAME vulnerable capture that fired above — a LEAD, and NOT
    # a channel-confirmed clean (we cannot know the resource is post-MFA-gated).
    with serve() as base:
        ctx = _drive(base, "/mfa/bypass/account", attested=False)
    assert ctx is not None
    assert _D in ctx.mfa_bypass["factor1_view"]["body"]     # the raw bytes are the SAME firing capture
    outcome = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not outcome.confirmed
    assert not _confirm_offline(ctx)
    sig = next(s for s in outcome.signals if s.kind is OracleKind.MFA_BYPASS)
    assert not sig.fired and not sig.conclusive             # LEAD, never a false CLEAN
