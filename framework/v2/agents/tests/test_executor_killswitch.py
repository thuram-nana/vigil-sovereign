"""The kill-switch / authority gate halts the live executor per-action.

These tests prove the off-switch is real at the point of action: a
tripped kill-switch refuses the next execute() call before any scope
check or network I/O, and an out-of-scope authority refuses too.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...authority import EngagementAuthority, KillSwitch, TargetEnvironment
from ..http_executor import HttpExecutor
from ..models import HypothesisPayload, PlanPayload

_NOW = datetime.now(timezone.utc)


def _hyp() -> HypothesisPayload:
    return HypothesisPayload(
        handle="H1", surface="https://app.example.com/orders/{id}", bug_class="IDOR",
        given="g", if_action="a", then_observation="t", because_model="b",
        refute_on="r", cheap_test="c",
    )


def _plan() -> PlanPayload:
    return PlanPayload(plan_id="P-001", targets_hypothesis="H1", next_action="probe")


def _authority(**kw: object) -> EngagementAuthority:
    base = dict(
        engagement_slug="eng", environment=TargetEnvironment.TWIN,
        scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1), not_after=_NOW + timedelta(hours=1),
    )
    base.update(kw)
    return EngagementAuthority(**base)  # type: ignore[arg-type]


def test_tripped_killswitch_halts_next_action(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "halt")
    ks.trip("operator stop")
    ex = HttpExecutor(
        engagement_slug="<proto-killswitch>",  # sentinel: skips engagement bind
        base_url="https://app.example.com",
        dry_run=True,
        killswitch=ks,
    )
    outcome = ex.execute(_hyp(), _plan())
    assert outcome.success is False
    assert "halted by kill-switch" in outcome.note
    # No network attempt was counted — the halt preceded everything.
    assert outcome.status_code == 0


def test_untripped_killswitch_lets_gate_pass_through(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "halt")  # not tripped
    ex = HttpExecutor(
        engagement_slug="<proto-killswitch>",
        base_url="https://app.example.com",
        dry_run=True,
        killswitch=ks,
    )
    outcome = ex.execute(_hyp(), _plan())
    # The authority gate passed (not halted); the next gate (scope/charter)
    # then refuses because the sentinel slug has no charter — proving the
    # kill-switch did NOT short-circuit when untripped.
    assert "halted by kill-switch" not in outcome.note


def test_killswitch_auto_wired_when_not_supplied() -> None:
    # The off-switch is always present: even with no killswitch passed,
    # the executor wires one bound to the engagement, so an operator can
    # always halt a running engagement.
    ex = HttpExecutor(
        engagement_slug="<proto-killswitch>",
        base_url="https://app.example.com",
        dry_run=True,
    )
    assert ex.killswitch is not None
    assert isinstance(ex.killswitch, KillSwitch)


def test_out_of_scope_authority_refuses(tmp_path: Path) -> None:
    ex = HttpExecutor(
        engagement_slug="<proto-killswitch>",
        base_url="https://app.example.com",
        dry_run=True,
        authority=_authority(scope=["only.other-domain.test"]),
    )
    outcome = ex.execute(_hyp(), _plan())
    assert outcome.success is False
    assert "authority refused (out_of_scope)" in outcome.note


def test_in_scope_authority_passes_gate(tmp_path: Path) -> None:
    ex = HttpExecutor(
        engagement_slug="<proto-killswitch>",
        base_url="https://app.example.com",
        dry_run=True,
        authority=_authority(),  # scope *.example.com matches the target
    )
    outcome = ex.execute(_hyp(), _plan())
    # Authority allowed; refusal (if any) comes from the later scope/charter
    # gate, not the authority gate.
    assert "authority refused" not in outcome.note
