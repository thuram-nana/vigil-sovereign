"""
Wave-3.3 CSRF-achieved oracle — the deterministic control-differential proving an ACHIEVED
cross-site state change (kind ACHIEVED_STATE, reused; NO new OracleKind). It fires ONLY when a
VIGIL-chosen unique marker reached the authoritative post-state WITH the ambient session cookie
riding cross-site but is ABSENT from a no-cookie control — never on the naive token-absence signal.

The adversarial non-fire cases below are the ones that got the naive CSRF claim refused: a
SameSite-protected cookie (not sent cross-site ⇒ no state change), an enforced anti-CSRF token
(token-less write rejected ⇒ no state change), and a merely-unauthenticated endpoint (the write
succeeds even WITHOUT the cookie ⇒ not attributable to the cookie).
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import csrf_achieved_oracle

_MARKER = "VIGIL-CSRF-0123456789abcdef"


def _ctrl(**over: object) -> dict:
    base = {
        "rule": "cross_site_state_change",
        "method": "post",
        "endpoint": "/csrf/transfer",
        "cross_origin": True,
        "ambient_only": True,
        "marker": _MARKER,
        "with_cookie_state": f"<ul><li>{_MARKER}</li></ul>",   # the cookie write landed
        "no_cookie_state": "<ul></ul>",                         # the control did not
    }
    base.update(over)
    return base


def test_fires_on_achieved_cross_site_state_change() -> None:
    sig = csrf_achieved_oracle(_ctrl())
    assert sig.fired is True
    assert sig.kind is OracleKind.ACHIEVED_STATE      # reused frozen kind — no new OracleKind
    assert sig.conclusive is True
    assert sig.confidence >= 0.9


def test_silent_when_samesite_cookie_not_sent_cross_site() -> None:
    # SameSite=Lax/Strict: the ambient cookie is NOT sent cross-site, so the with-cookie request
    # produces no state change and the marker never appears — the objection that refused the naive
    # version is dissolved by a correct NON-fire.
    sig = csrf_achieved_oracle(_ctrl(with_cookie_state="<ul></ul>"))
    assert sig.fired is False


def test_silent_when_anti_csrf_token_enforced() -> None:
    # The token-less cross-site write is rejected, so the marker reaches neither state.
    sig = csrf_achieved_oracle(_ctrl(with_cookie_state="<ul></ul>", no_cookie_state="<ul></ul>"))
    assert sig.fired is False


def test_refuses_when_write_succeeds_without_the_cookie() -> None:
    # A merely-unauthenticated endpoint: the marker also appears in the no-cookie control, so the
    # state change is NOT attributable to the ambient cookie (not CSRF).
    sig = csrf_achieved_oracle(_ctrl(no_cookie_state=f"<ul><li>{_MARKER}</li></ul>"))
    assert sig.fired is False


def test_refuses_safe_method() -> None:
    assert csrf_achieved_oracle(_ctrl(method="get")).fired is False


def test_refuses_when_not_cross_origin() -> None:
    assert csrf_achieved_oracle(_ctrl(cross_origin=False)).fired is False
    assert csrf_achieved_oracle(_ctrl(cross_origin=None)).fired is False


def test_refuses_when_not_ambient_only() -> None:
    # More than the ambient cookie was attached (an explicit token/header/credential) — not the
    # ambient-cookie-alone topology the class proves.
    assert csrf_achieved_oracle(_ctrl(ambient_only=False)).fired is False


def test_refuses_short_or_missing_marker() -> None:
    assert csrf_achieved_oracle(_ctrl(marker="short", with_cookie_state="short")).fired is False
    assert csrf_achieved_oracle(_ctrl(marker="")).fired is False


def test_refuses_unrecognised_rule_and_non_mapping() -> None:
    assert csrf_achieved_oracle(_ctrl(rule="something_else")).fired is False
    assert csrf_achieved_oracle(None).fired is False
    assert csrf_achieved_oracle("nope").fired is False


def test_non_fire_is_not_conclusive_clean() -> None:
    # A non-fire is UNINFORMATIVE (no channel / SameSite / enforced token) — never a channel-confirmed
    # CLEAN, so this positive-only branch never asserts absence.
    sig = csrf_achieved_oracle(_ctrl(with_cookie_state="<ul></ul>"))
    assert sig.fired is False
    assert sig.conclusive is False
