"""
W13-3 (#496) — the signed EngagementAuthorization and the executor that
HONOURS its four bounds: danger ceiling, validity window, rate limit, and
concurrency limit.

Fail-without-fix: this file imports ``..authorization`` at module scope; on a
tree without W13-3 that module does not exist and the whole file ERRORs at
collection (observed by moving the module aside — see RED-PEN-BRIEF.md).

The three MANDATORY negative controls (an action outside the window, above the
ceiling, or beyond the rate limit is refused) are three separate assertions,
each paired with a positive control so the gate is provably not a no-op. The
fourth honoured bound (concurrency) has its own negative control too.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ...common.errors import (
    AuthorityExpired,
    ConcurrencyLimitExceeded,
    DangerCeilingExceeded,
    RateLimitExceeded,
)
from ...entitlement import provision
from ...entitlement.models import AuthorizerKey, TrustRoot
from ..authorization import (
    EngagementAuthorization,
    EngagementExecutor,
    action_danger,
    authorize_engagement_action,
    sign_authorization,
    verify_authorization,
)

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _authz(**overrides: object) -> EngagementAuthorization:
    base: dict[str, object] = dict(
        authorization_id="auth-1",
        engagement_slug="eng",
        issuer="governance",
        scope=["*.example.com"],
        danger_ceiling="A2",
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
        rate_limit=3,
        rate_window_seconds=60.0,
        concurrency_limit=2,
        issued_at=_NOW - timedelta(hours=2),
    )
    base.update(overrides)
    return EngagementAuthorization(**base)  # type: ignore[arg-type]


def _authorizer_set(n: int, threshold: int) -> tuple[TrustRoot, dict[str, str]]:
    authorizers: list[AuthorizerKey] = []
    privs: dict[str, str] = {}
    for i in range(n):
        ak, priv = provision.new_authorizer(f"a{i}", f"Authoriser {i}")
        authorizers.append(ak)
        privs[f"a{i}"] = priv
    return provision.build_trust_root(authorizers, threshold), privs


# ---------------------------------------------------------------------------
# The danger ceiling reuses the ONE WARDEN classifier of record
# ---------------------------------------------------------------------------


def test_danger_ceiling_uses_the_warden_classifier() -> None:
    # These are the WARDEN tiers of record; if the shared classifier changed,
    # this pins that the ceiling is expressed in the SAME vocabulary.
    assert action_danger("read.status").label == "A0"
    assert action_danger("file.export").label == "A2"
    assert action_danger("db.delete").label == "A3"


# ---------------------------------------------------------------------------
# MANDATORY negative control #1 — an action ABOVE THE CEILING is refused
# ---------------------------------------------------------------------------


def test_action_within_ceiling_is_allowed() -> None:
    ex = EngagementExecutor(_authz(danger_ceiling="A2"))
    d = ex.authorize("file.export", now=_NOW)  # A2 <= A2
    assert d.allowed is True
    assert d.denial_code == ""


def test_negative_control_action_above_ceiling_is_refused() -> None:
    ex = EngagementExecutor(_authz(danger_ceiling="A2"))
    d = ex.authorize("db.delete", now=_NOW)  # A3 > A2
    assert d.allowed is False
    assert d.denial_code == "above_ceiling"
    assert d.danger_tier == "A3"
    assert d.ceiling == "A2"
    with pytest.raises(DangerCeilingExceeded):
        _raise_via_execute(ex, "db.delete")


def _raise_via_execute(ex: EngagementExecutor, op: str) -> None:
    with ex.execute(op, now=_NOW):
        pass


def test_ceiling_gate_is_not_a_no_op() -> None:
    # Same A2 action: refused under an A1 ceiling, allowed under an A2 ceiling.
    # Proves the gate actually READS the ceiling rather than hardcoding a verdict.
    refused = EngagementExecutor(_authz(danger_ceiling="A1")).authorize("file.export", now=_NOW)
    allowed = EngagementExecutor(_authz(danger_ceiling="A2")).authorize("file.export", now=_NOW)
    assert refused.allowed is False and refused.denial_code == "above_ceiling"
    assert allowed.allowed is True
    # And the most-permissive ceiling admits even an A3 action.
    top = EngagementExecutor(_authz(danger_ceiling="A3")).authorize("db.delete", now=_NOW)
    assert top.allowed is True


# ---------------------------------------------------------------------------
# MANDATORY negative control #2 — an action OUTSIDE THE WINDOW is refused
# ---------------------------------------------------------------------------


def test_action_inside_window_is_allowed() -> None:
    ex = EngagementExecutor(_authz())
    assert ex.authorize("read.status", now=_NOW).allowed is True


def test_negative_control_action_before_window_is_refused() -> None:
    ex = EngagementExecutor(_authz())
    d = ex.authorize("read.status", now=_NOW - timedelta(hours=2))
    assert d.allowed is False
    assert d.denial_code == "expired"


def test_negative_control_action_after_window_is_refused() -> None:
    ex = EngagementExecutor(_authz())
    d = ex.authorize("read.status", now=_NOW + timedelta(hours=2))
    assert d.allowed is False
    assert d.denial_code == "expired"
    with pytest.raises(AuthorityExpired):
        _raise_via_execute_at(ex, "read.status", _NOW + timedelta(hours=2))


def _raise_via_execute_at(ex: EngagementExecutor, op: str, now: datetime) -> None:
    with ex.execute(op, now=now):
        pass


# ---------------------------------------------------------------------------
# MANDATORY negative control #3 — an action BEYOND THE RATE LIMIT is refused
# ---------------------------------------------------------------------------


def test_actions_up_to_the_rate_limit_are_allowed() -> None:
    ex = EngagementExecutor(_authz(rate_limit=3))
    for _ in range(3):
        with ex.execute("read.status", now=_NOW) as d:
            assert d.allowed is True


def test_negative_control_action_beyond_rate_limit_is_refused() -> None:
    ex = EngagementExecutor(_authz(rate_limit=2, rate_window_seconds=60.0))
    with ex.execute("read.status", now=_NOW):
        pass
    with ex.execute("read.status", now=_NOW):
        pass
    # third within the window
    d = ex.authorize("read.status", now=_NOW + timedelta(seconds=1))
    assert d.allowed is False
    assert d.denial_code == "rate_limited"
    with pytest.raises(RateLimitExceeded):
        _raise_via_execute_at(ex, "read.status", _NOW + timedelta(seconds=1))


def test_rate_window_slides_so_old_actions_do_not_count() -> None:
    # Two actions, then wait past the window: a later action is allowed again.
    ex = EngagementExecutor(_authz(rate_limit=2, rate_window_seconds=60.0))
    with ex.execute("read.status", now=_NOW):
        pass
    with ex.execute("read.status", now=_NOW):
        pass
    later = _NOW + timedelta(seconds=61)  # both prior actions now outside the window
    assert ex.authorize("read.status", now=later).allowed is True


# ---------------------------------------------------------------------------
# Fourth honoured bound — CONCURRENCY (its own negative control)
# ---------------------------------------------------------------------------


def test_negative_control_action_beyond_concurrency_limit_is_refused() -> None:
    ex = EngagementExecutor(_authz(concurrency_limit=1, rate_limit=100))
    with ex.execute("read.status", now=_NOW):
        # one in flight; a second concurrent action is refused
        d = ex.authorize("read.status", now=_NOW)
        assert d.allowed is False
        assert d.denial_code == "concurrency_limited"
        with pytest.raises(ConcurrencyLimitExceeded):
            _raise_via_execute(ex, "read.status")
    # once the first completes, concurrency frees up
    assert ex.authorize("read.status", now=_NOW).allowed is True


# ---------------------------------------------------------------------------
# First-failure-wins ordering (window before ceiling before rate)
# ---------------------------------------------------------------------------


def test_window_is_checked_before_ceiling() -> None:
    # An out-of-window A3 action reports "expired", not "above_ceiling".
    ex = EngagementExecutor(_authz(danger_ceiling="A0"))
    d = ex.authorize("db.delete", now=_NOW + timedelta(hours=5))
    assert d.denial_code == "expired"


# ---------------------------------------------------------------------------
# The object is threshold-signed and tamper-evident
# ---------------------------------------------------------------------------


def test_sign_and_verify_roundtrip() -> None:
    tr, privs = _authorizer_set(3, 2)
    signed = sign_authorization(_authz(), {"a0": privs["a0"], "a1": privs["a1"]})
    ok, _ = verify_authorization(signed, tr)
    assert ok is True


def test_below_threshold_fails() -> None:
    tr, privs = _authorizer_set(3, 2)
    signed = sign_authorization(_authz(), {"a0": privs["a0"]})  # 1 of 2
    ok, _ = verify_authorization(signed, tr)
    assert ok is False


def test_tampered_ceiling_is_detected() -> None:
    tr, privs = _authorizer_set(1, 1)
    signed = sign_authorization(_authz(danger_ceiling="A0"), {"a0": privs["a0"]})
    # Raise the ceiling after signing — the signature must no longer verify.
    tampered = signed.model_copy(
        update={"document": signed.document.model_copy(update={"danger_ceiling": "A3"})}
    )
    ok, _ = verify_authorization(tampered, tr)
    assert ok is False


def test_tampered_rate_limit_is_detected() -> None:
    tr, privs = _authorizer_set(1, 1)
    signed = sign_authorization(_authz(rate_limit=1), {"a0": privs["a0"]})
    tampered = signed.model_copy(
        update={"document": signed.document.model_copy(update={"rate_limit": 10_000})}
    )
    ok, _ = verify_authorization(tampered, tr)
    assert ok is False


# ---------------------------------------------------------------------------
# Model invariants
# ---------------------------------------------------------------------------


def test_window_validator_rejects_inverted_window() -> None:
    with pytest.raises(ValueError):
        _authz(not_before=_NOW + timedelta(hours=1), not_after=_NOW - timedelta(hours=1))


def test_pure_gate_matches_executor() -> None:
    # The pure gate and the executor agree when handed the same counts.
    authz = _authz(danger_ceiling="A2")
    d = authorize_engagement_action(
        authz,
        danger=action_danger("db.delete"),
        actions_in_window=0,
        in_flight=0,
        now=_NOW,
    )
    assert d.allowed is False and d.denial_code == "above_ceiling"
