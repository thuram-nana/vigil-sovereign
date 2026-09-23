"""
Wave-3.3 CSRF-achieved oracle — the deterministic re-derivation over BROWSER-OBSERVED evidence proving
an ACHIEVED cross-site state change (kind ACHIEVED_STATE, reused; NO new OracleKind). It DERIVES
cross_origin and ambient_only from the retained evidence (never a bare bool) and fires ONLY when a
SameSite-honoring browser ACTUALLY attached the ambient session cookie to a genuinely cross-site write,
carried no anti-CSRF token, reached a VIGIL-chosen unique marker in the with-cookie post-state, and did
NOT reach it in the no-cookie control.

The adversarial non-fire cases below are the ones that got the naive / urllib version refused: a
SameSite-protected cookie the browser did NOT attach (observed SameSite* block), a same-origin /
same-site observation, an anti-CSRF token riding the write, a merely-unauthenticated endpoint, and — the
core fail-closed guard — a bare-bool / evidence-less context that can NEVER mint.
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import csrf_achieved_oracle

_MARKER = "VIGIL-CSRF-0123456789abcdef"


def _ctrl(**over: object) -> dict:
    """A control carrying the SAME shape a real browser drive retains: observed origins, observed
    associated cookies (with SameSite blocked_reasons), the observed Cookie header + request fields,
    and the two authoritative readbacks. The FIRE case is genuinely cross-site, the ambient cookie was
    attached with NO SameSite block, no token rode along, and the marker landed only with the cookie."""
    base = {
        "rule": "cross_site_state_change",
        "method": "post",
        "endpoint": "/csrf/transfer",
        "target_origin": "http://127.0.0.1:8001",
        "initiator_origin": "http://localhost:9002",          # a genuinely different SITE
        "ambient_cookie_name": "csrf_session",
        "associated_cookies": [{"name": "csrf_session", "blocked_reasons": []}],  # attached, no block
        "observed_cookie_header": "csrf_session=owner-authenticated-session",
        "observed_request_fields": ["marker"],
        "observed_request_header_names": ["content-type", "origin", "referer"],
        "marker": _MARKER,
        "with_cookie_state": f"<ul><li>{_MARKER}</li></ul>",   # the ambient-cookie write landed
        "no_cookie_state": "<ul></ul>",                         # the no-cookie control did not
    }
    base.update(over)
    return base


def test_fires_on_browser_observed_achieved_cross_site_state_change() -> None:
    sig = csrf_achieved_oracle(_ctrl())
    assert sig.fired is True
    assert sig.kind is OracleKind.ACHIEVED_STATE      # reused frozen kind — no new OracleKind
    assert sig.conclusive is True
    assert sig.confidence >= 0.9


def test_silent_when_samesite_cookie_was_blocked_cross_site() -> None:
    # SameSite=Strict/Lax: the browser did NOT attach the ambient cookie cross-site — the observation
    # carries a SameSite* blocked reason. This is the SameSite dissolution: a correct NON-fire even if a
    # readback were (impossibly) present.
    sig = csrf_achieved_oracle(_ctrl(
        associated_cookies=[{"name": "csrf_session", "blocked_reasons": ["SameSiteStrict"]}],
        with_cookie_state="<ul></ul>"))
    assert sig.fired is False


def test_silent_when_the_ambient_cookie_was_not_observed_attached_at_all() -> None:
    # No associated-cookie evidence for the ambient cookie (a urllib re-drive that hand-set the Cookie
    # header has no CDP observation) => the browser-attachment fact is UNPROVEN => REFUSE, even though
    # the readbacks (which urllib could still produce) look "achieved".
    sig = csrf_achieved_oracle(_ctrl(associated_cookies=[], observed_cookie_header=""))
    assert sig.fired is False


def test_silent_when_cookie_header_does_not_corroborate_attachment() -> None:
    # The associated-cookie says "attached" but the observed Cookie header does not carry it — the
    # attachment is not corroborated, so REFUSE (belt-and-suspenders against a forged associated list).
    sig = csrf_achieved_oracle(_ctrl(observed_cookie_header="other=1"))
    assert sig.fired is False


def test_refuses_when_not_cross_site_same_origin() -> None:
    # A same-origin observation (initiator == target) — the topology the naive urllib producer falsely
    # attested — can never fire now: cross_origin is DERIVED from the observed origins.
    assert csrf_achieved_oracle(_ctrl(initiator_origin="http://127.0.0.1:8001")).fired is False


def test_refuses_when_only_the_port_differs_same_site() -> None:
    # Different port, SAME host => SAME site (ports are not part of the SameSite site) => not cross-site.
    assert csrf_achieved_oracle(_ctrl(initiator_origin="http://127.0.0.1:9999")).fired is False


def test_refuses_when_an_anti_csrf_token_rode_the_write() -> None:
    # ambient_only is DERIVED from the observed request: a csrf token field defeats ambient-cookie-only.
    assert csrf_achieved_oracle(_ctrl(observed_request_fields=["marker", "csrf_token"])).fired is False
    # ... or a custom guard header.
    assert csrf_achieved_oracle(_ctrl(
        observed_request_header_names=["content-type", "x-csrf-token"])).fired is False


def test_silent_when_marker_absent_from_with_cookie_state() -> None:
    # No cross-site state change reached (a SameSite cookie not sent, or an enforced token rejected it).
    assert csrf_achieved_oracle(_ctrl(with_cookie_state="<ul></ul>")).fired is False


def test_refuses_when_write_succeeds_without_the_cookie() -> None:
    # A merely-unauthenticated endpoint: the marker also appears in the no-cookie control, so the state
    # change is NOT attributable to the ambient cookie (not CSRF).
    assert csrf_achieved_oracle(_ctrl(no_cookie_state=f"<ul><li>{_MARKER}</li></ul>")).fired is False


def test_refuses_safe_method() -> None:
    assert csrf_achieved_oracle(_ctrl(method="get")).fired is False


def test_refuses_short_or_missing_marker() -> None:
    assert csrf_achieved_oracle(_ctrl(marker="short", with_cookie_state="short")).fired is False
    assert csrf_achieved_oracle(_ctrl(marker="")).fired is False


def test_refuses_unrecognised_rule_and_non_mapping() -> None:
    assert csrf_achieved_oracle(_ctrl(rule="something_else")).fired is False
    assert csrf_achieved_oracle(None).fired is False
    assert csrf_achieved_oracle("nope").fired is False


def test_fail_closed_on_a_bare_bool_evidence_less_context() -> None:
    # The RED-PENNED shape: a context that merely ATTESTS cross_origin/ambient_only with no browser
    # observation. It must NEVER mint — the derivation has no evidence to stand on.
    legacy = {
        "rule": "cross_site_state_change", "method": "post", "endpoint": "/csrf/transfer",
        "cross_origin": True, "ambient_only": True, "marker": _MARKER,
        "with_cookie_state": f"<ul><li>{_MARKER}</li></ul>", "no_cookie_state": "<ul></ul>",
    }
    sig = csrf_achieved_oracle(legacy)
    assert sig.fired is False
    assert sig.conclusive is False


def test_non_fire_is_not_conclusive_clean() -> None:
    # A non-fire is UNINFORMATIVE (no channel / SameSite / enforced token) — never a channel-confirmed
    # CLEAN, so this positive-only branch never asserts absence.
    sig = csrf_achieved_oracle(_ctrl(with_cookie_state="<ul></ul>"))
    assert sig.fired is False
    assert sig.conclusive is False
