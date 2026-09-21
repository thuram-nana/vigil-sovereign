"""The OWNER-SIGNED ENGAGEMENT WINDOW as the OOB receipt-bearing anti-replay boundary (the slide-defeat fix).

The prior VF-2b replay gate centered the TTL window on the PRODUCER-controlled mint anchor ``oob_issued_at``.
A fully-dishonest producer could SLIDE that anchor onto a stale receipt's signed ``received_at`` (which the
collector signs but the producer re-presents), re-centering the window and re-confirming a year-1970 or
prior-engagement receipt through the REAL serialized reverify path. Authority-bound duration/skew stopped the
window WIDENING but not this SLIDING.

The fix anchors anti-replay on a NON-FORGEABLE, offline-available bound: the receipt's target-observed,
collector-SIGNED ``received_at`` must fall inside the OWNER-SIGNED ENGAGEMENT WINDOW
``[not_before - skew, not_after + skew]`` taken from the SAME signed ``EngagementAuthority`` that supplies the
pin + TTL (via ``verifier_from_authority``) — never the producer ctx. These tests drive the real serialized
reverify path (``reverify_finding`` / ``verifier_from_authority``) and prove:

  (a) a stale receipt (received_at = 1970, or before not_before) WITH issued_at SLID onto it ⇒ REFUSED, HTTP + DNS;
  (b) a receipt with received_at INSIDE [not_before, not_after] ⇒ confirmed (with the pin);
  (c) a PRIOR-ENGAGEMENT receipt (a DIFFERENT authority's window) ⇒ refused;
  (d) the honest INTRA-engagement residual ⇒ BOUNDED to the signed window (a real in-window receipt confirms;
      one just past the window edge does not) — documents the irreducible residual, not a false pass.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vigil_core import generate_keypair
from vigil_core.authority import EngagementAuthority, TargetEnvironment

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.oob import OOBHit, sign_oob_receipt
from framework.v2.verify.reverify import reverify_finding, verifier_from_authority

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
_TTL = 300.0
_SKEW = 5.0


def _authority(*, http_pin: str = "", dns_pin: str = "", ttl: float = _TTL, skew: float = _SKEW,
               not_before: datetime | None = None, not_after: datetime | None = None) -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug="eng", environment=TargetEnvironment.TWIN, scope=["*.example.com"],
        not_before=not_before or (_NOW - timedelta(hours=1)),
        not_after=not_after or (_NOW + timedelta(hours=1)),
        oob_collector_pubkey=http_pin, oob_dns_collector_pubkey=dns_pin,
        oob_ttl_seconds=ttl, oob_skew_seconds=skew)


def _signed_hit(kp, *, method: str, token: str, received_at: float) -> OOBHit:
    path = (f"{token}.oob.op.example" if method == "DNS" else "/" + token)
    hit = OOBHit(token=token, method=method, path=path, query="", client_ip="10.0.0.9",
                 received_at=received_at)
    hit.collector_sig = sign_oob_receipt(kp.private_key_b64, hit)
    return hit


def _finding(kp, *, method: str, received_at: float, issued_at: float | None) -> dict:
    token = "t" * 32
    hit = _signed_hit(kp, method=method, token=token, received_at=received_at)
    ctx = FindingContext.from_oob([hit], bug_class="ssrf", expected_token=token, issued_at=issued_at)
    return {"bug_class": "ssrf", "check_id": f"{method.lower()}-oob",
            "oracle_context": ctx.model_dump(mode="json"),
            "confirmed_by": "oob_callback", "confidence": 0.95}


def _verifier(kp, *, method: str, **auth_kw):
    pin = {"dns_pin": kp.public_key_b64} if method == "DNS" else {"http_pin": kp.public_key_b64}
    return verifier_from_authority(_authority(**pin, **auth_kw))


# ---------------------------------------------------------------- (a) slid stale receipt ⇒ refused (HTTP+DNS)
def test_a_year1970_slid_receipt_is_refused_http_and_dns() -> None:
    kp = generate_keypair()
    for method in ("GET", "DNS"):
        # A year-1970 receipt with the mint anchor SLID onto it: the advisory TTL window centers on 1970 and
        # (pre-fix) would confirm. The signed engagement window (2026) refuses it — received_at is outside it.
        f = _finding(kp, method=method, received_at=0.0, issued_at=0.0)
        r = reverify_finding(f, verifier=_verifier(kp, method=method))
        assert not r.reproduced, f"{method}: a slid year-1970 receipt must be refused (outside signed window)"


def test_a_before_not_before_slid_receipt_is_refused() -> None:
    kp = generate_keypair()
    before = (_NOW - timedelta(hours=2)).timestamp()   # before not_before (_NOW - 1h)
    f = _finding(kp, method="DNS", received_at=before, issued_at=before)  # issued_at slid onto the stale hit
    r = reverify_finding(f, verifier=_verifier(kp, method="DNS"))
    assert not r.reproduced, "a receipt before the signed not_before must be refused even with issued_at slid"


# ---------------------------------------------------------------- (b) in-window receipt ⇒ confirmed
def test_b_in_window_receipt_confirms_http_and_dns() -> None:
    kp = generate_keypair()
    ra = _NOW.timestamp()   # squarely inside [_NOW - 1h, _NOW + 1h]
    for method in ("GET", "DNS"):
        f = _finding(kp, method=method, received_at=ra, issued_at=_NOW.timestamp())
        r = reverify_finding(f, verifier=_verifier(kp, method=method))
        assert r.reproduced and r.confirmed_by == "oob_callback", f"{method}: in-window receipt must confirm"


# ---------------------------------------------------------------- (c) prior-engagement receipt ⇒ refused
def test_c_prior_engagement_receipt_is_refused() -> None:
    kp = generate_keypair()
    # A GENUINE receipt observed during a PRIOR engagement (10h ago), re-presented against THIS authority's
    # window (_NOW ± 1h). issued_at is slid onto it. The prior received_at is outside this window ⇒ refused.
    prior = (_NOW - timedelta(hours=10)).timestamp()
    f = _finding(kp, method="DNS", received_at=prior, issued_at=prior)
    r = reverify_finding(f, verifier=_verifier(kp, method="DNS"))
    assert not r.reproduced, "a prior-engagement receipt must not re-confirm under this engagement's window"
    # Its OWN (prior) authority window WOULD admit it — proving it is a real receipt, refused only because it
    # is outside THIS engagement's signed window (cross-engagement replay is what the window closes).
    prior_auth_v = _verifier(kp, method="DNS",
                             not_before=_NOW - timedelta(hours=11), not_after=_NOW - timedelta(hours=9))
    assert reverify_finding(f, verifier=prior_auth_v).reproduced


# ---------------------------------------------------------------- (d) honest residual ⇒ bounded to the window
def test_d_intra_engagement_residual_is_bounded_to_signed_window() -> None:
    """The irreducible residual: a REAL receipt observed DURING the authorized window, re-presented (issued_at
    slid) later WITHIN the SAME window, still confirms — the mint time is not committed into the token, so an
    intra-window slide cannot be distinguished. This is BOUNDED to the owner-signed engagement window: the
    same slide one step past the window edge is refused. This documents the honest residual, not a false pass."""
    kp = generate_keypair()
    skew = _SKEW
    # Inside the window (issued_at slid onto received_at) ⇒ confirms — the honest, bounded residual.
    inside = (_NOW + timedelta(minutes=30)).timestamp()
    f_in = _finding(kp, method="DNS", received_at=inside, issued_at=inside)
    assert reverify_finding(f_in, verifier=_verifier(kp, method="DNS")).reproduced, \
        "an intra-window receipt confirms — the bounded residual"
    # Just past not_after + skew ⇒ refused: the residual cannot escape the signed window.
    outside = (_NOW + timedelta(hours=1)).timestamp() + skew + 60.0
    f_out = _finding(kp, method="DNS", received_at=outside, issued_at=outside)
    assert not reverify_finding(f_out, verifier=_verifier(kp, method="DNS")).reproduced, \
        "the slide cannot escape the signed engagement window (residual is bounded)"


# ------------------------------------------------- (e) half-threaded signed window ⇒ fail-closed (defensive)
def test_e_half_threaded_signed_window_is_refused() -> None:
    """Unreachable via verifier_from_authority / _engage_oob_authority (not_before/not_after are mandatory and
    always threaded together), but a hand-constructed direct oracle call that threads only ONE edge must NOT
    fall back to the producer-slidable advisory bound on the missing edge. A partial signed window is refused
    fail-closed (INCOMPLETE_SIGNED_WINDOW) — it is neither a clean self-check (neither edge) nor a sound signed
    window (both edges)."""
    from framework.v2.verify.oracles import oob_callback_oracle

    kp = generate_keypair()
    token = "t" * 32
    ra = _NOW.timestamp()
    hit = _signed_hit(kp, method="DNS", token=token, received_at=ra)
    nb = (_NOW - timedelta(hours=1)).timestamp()
    na = (_NOW + timedelta(hours=1)).timestamp()

    # Sanity: BOTH edges present, in-window ⇒ fires (the sound signed-window path).
    both = oob_callback_oracle([hit], expected_token=token, dns_collector_pubkey=kp.public_key_b64,
                               issued_at=ra, authority_not_before=nb, authority_not_after=na)
    assert both.fired and both.observed.get("signed_window") is True

    # Only ONE edge present ⇒ fail-closed, regardless of which edge, even with received_at in range.
    for kw in ({"authority_not_before": nb}, {"authority_not_after": na}):
        r = oob_callback_oracle([hit], expected_token=token, dns_collector_pubkey=kp.public_key_b64,
                                issued_at=ra, **kw)
        assert not r.fired, f"half-threaded window {list(kw)} must be refused"
        assert r.observed.get("oob_verdict") == "INCOMPLETE_SIGNED_WINDOW"

    # NEITHER edge (a genuine direct/self-check call) ⇒ advisory-TTL only, still fires (unchanged behaviour).
    neither = oob_callback_oracle([hit], expected_token=token, dns_collector_pubkey=kp.public_key_b64,
                                  issued_at=ra)
    assert neither.fired and neither.observed.get("signed_window") is False
