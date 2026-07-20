"""Tests for the authority gate — scope, window, destructive, budget,
and the kill-switch's absolute precedence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ...common.errors import (
    AuthorityExpired,
    BudgetExhausted,
    DestructiveActionRefused,
    EngagementHalted,
    OutOfScope,
)
from ..gate import authorize_action, require_authorization
from ..killswitch import KillSwitch
from ..models import (
    ActionRequest,
    AuthorityState,
    EngagementAuthority,
    TargetEnvironment,
)

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _authority(**kw: object) -> EngagementAuthority:
    base = dict(
        engagement_slug="eng",
        environment=TargetEnvironment.TWIN,
        scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
    )
    base.update(kw)
    return EngagementAuthority(**base)  # type: ignore[arg-type]


def _req(target: str = "https://app.example.com/x", destructive: bool = False) -> ActionRequest:
    return ActionRequest(target=target, destructive=destructive)


def test_allowed_in_scope_in_window() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW)
    assert d.allowed is True
    assert d.state is AuthorityState.ACTIVE


def test_killswitch_halts_everything_first(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "halt")
    ks.trip("stop")
    # Out-of-scope AND halted: the halt wins (checked first), not out_of_scope.
    d = authorize_action(
        _authority(), _req(target="https://evil.invalid/x"), killswitch=ks, now=_NOW
    )
    assert d.allowed is False
    assert d.state is AuthorityState.HALTED
    assert d.denial_code == "halted"


def test_expired_before_and_after() -> None:
    early = authorize_action(_authority(), _req(), now=_NOW - timedelta(hours=2))
    late = authorize_action(_authority(), _req(), now=_NOW + timedelta(hours=2))
    assert early.state is AuthorityState.EXPIRED and early.denial_code == "expired"
    assert late.state is AuthorityState.EXPIRED


def test_out_of_scope_denied() -> None:
    d = authorize_action(_authority(), _req(target="https://other.invalid/"), now=_NOW)
    assert d.allowed is False
    assert d.denial_code == "out_of_scope"


def test_destructive_refused_without_permission() -> None:
    d = authorize_action(_authority(), _req(destructive=True), now=_NOW)
    assert d.denial_code == "destructive"


def test_destructive_allowed_on_twin() -> None:
    d = authorize_action(_authority(allow_destructive=True), _req(destructive=True), now=_NOW)
    assert d.allowed is True


def test_destructive_on_live_needs_double_ack() -> None:
    live = _authority(environment=TargetEnvironment.LIVE, allow_destructive=True)
    denied = authorize_action(live, _req(destructive=True), now=_NOW)
    assert denied.denial_code == "live_destructive"

    acked = _authority(
        environment=TargetEnvironment.LIVE,
        allow_destructive=True,
        live_destructive_acknowledged=True,
    )
    allowed = authorize_action(acked, _req(destructive=True), now=_NOW)
    assert allowed.allowed is True


def test_budget_exhausted() -> None:
    d = authorize_action(_authority(max_actions=5), _req(), actions_taken=5, now=_NOW)
    assert d.denial_code == "budget"


def test_require_authorization_raises_typed_errors(tmp_path: Path) -> None:
    with pytest.raises(OutOfScope):
        require_authorization(_authority(), _req(target="https://no.invalid/"), now=_NOW)
    with pytest.raises(AuthorityExpired):
        require_authorization(_authority(), _req(), now=_NOW + timedelta(hours=2))
    with pytest.raises(DestructiveActionRefused):
        require_authorization(_authority(), _req(destructive=True), now=_NOW)
    with pytest.raises(BudgetExhausted):
        require_authorization(_authority(max_actions=1), _req(), actions_taken=1, now=_NOW)

    ks = KillSwitch("eng", path=tmp_path / "halt")
    ks.trip("stop")
    with pytest.raises(EngagementHalted):
        require_authorization(_authority(), _req(), killswitch=ks, now=_NOW)


def test_require_authorization_returns_decision_when_allowed() -> None:
    d = require_authorization(_authority(), _req(), now=_NOW)
    assert d.allowed is True
