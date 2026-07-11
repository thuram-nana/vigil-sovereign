"""
Doctrine-boundary + fail-closed tests for the Tier-3 validation layer
(``agents.tier3_validation``).

This is the critical safety proof for the doctrine-MAXIMUM slice of CRUCIBLE's
offensive surface. The layer re-proves an *already oracle-CONFIRMED* finding by
re-firing its retained oracle proof — and only behind a full stack of
fail-closed gates. These tests assert, against REAL logic and REAL oracle
firing (no fixture-theatre, AUTONOMY-CHARTER.md § 4.5), that:

  * every gate fails CLOSED — the path refuses without the latch, without an
    oracle-CONFIRMED finding, off charter scope, against a non-localhost
    target, when the operator declines, and RAISES (recorded) when the
    entitlement is denied;
  * the gates enforce their evaluation ORDER (kill-switch first, latch before
    the epistemic gate) so a more-fundamental refusal always wins;
  * the veracity firewall holds — a retained proof that no longer re-fires is
    DEMOTED to a refusal, never asserted as impact;
  * nothing on the hard-exclusion list is reachable — the ONLY entitlement the
    code can ever require is EXPLOIT_EXECUTION (asserted structurally over the
    module AST), the minimal PoC sends ZERO network traffic (pure offline
    re-execution), and the layer emits no offensive Action/Result/Plan events;
  * every attempt — pass or refuse — lands an auditable decision + refusal /
    observation on the append-only spine.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path
from typing import Any

import pytest

from framework.v2.agents import tier3_validation as t3
from framework.v2.agents.blackboard import Blackboard
from framework.v2.agents.tier3_validation import (
    FORBIDDEN_CAPABILITIES,
    GATE_ORDER,
    TIER3_REQUIRED_CAPABILITY,
    Tier3Latch,
    Tier3ValidationLayer,
    resolves_to_loopback,
)
from framework.v2.common.errors import EntitlementMissing, EntitlementViolation, OutOfScope
from framework.v2.entitlement import Capability
from framework.v2.entitlement import policy as ent_policy
from framework.v2.verify.adapter import FindingContext

SLUG = "tier3-test"
LOCAL_TARGET = "http://127.0.0.1:8899/vuln"

# A real, unique canary that lands in an EXECUTABLE HTML position — the
# reflection-context oracle fires deterministically over it (confidence 0.95).
_MARKER = "OBSIDIANtier3canary9f2c"
_EXECUTABLE_SINK = f'<div>results</div>"\'><x{_MARKER}>'


# ---------------------------------------------------------------------------
# Fixtures / builders — every finding carries a context a real oracle judges.
# ---------------------------------------------------------------------------


@pytest.fixture()
def bb(tmp_path: Path) -> Blackboard:
    return Blackboard(db_path=tmp_path / "spine.db")


def _confirmed_finding(slug: str = "xss-reflected-001") -> dict[str, Any]:
    """An oracle-CONFIRMED finding whose retained context RE-FIRES: the marker
    reached an executable DOM position, so the reflection-context oracle
    confirms it on re-execution."""
    ctx = FindingContext.from_side_effect(_MARKER, _EXECUTABLE_SINK, bug_class="xss")
    return {
        "finding_slug": slug,
        "bug_class": "xss",
        "title": "reflected xss",
        "severity": "high",
        "critique_status": "confirmed",
        "verified_by_oracle": True,
        "oracle_context": ctx.model_dump(),
    }


def _stale_finding(slug: str = "xss-stale-002") -> dict[str, Any]:
    """Passes the CONFIRMED-metadata gate (status/flag/context all present) but
    the retained proof NO LONGER re-fires — the marker is absent from the sink.
    The veracity firewall must demote this, not assert impact."""
    ctx = FindingContext.from_side_effect("STALEcanary1234", "an unrelated body", bug_class="xss")
    return {
        "finding_slug": slug,
        "bug_class": "xss",
        "critique_status": "confirmed",
        "verified_by_oracle": True,
        "oracle_context": ctx.model_dump(),
    }


def _grant(_q: str, _t: float) -> bool:
    return True


def _deny(_q: str, _t: float) -> bool:
    return False


def _in_scope(_slug: str, _target: str) -> None:
    return None


def _out_of_scope(_slug: str, target: str) -> None:
    raise OutOfScope(f"{target} not in charter scope")


def _layer(
    bb: Blackboard,
    tmp_path: Path,
    *,
    engaged: bool = True,
    approval: Any = _grant,
    scope: Any = _in_scope,
    ks_path: str = "ks-absent.json",
) -> Tier3ValidationLayer:
    """A layer wired for a test. Defaults are the *permissive* wiring (latch
    engaged, approval granted, in-scope, kill-switch absent) so each test can
    flip exactly one gate to prove it fails closed in isolation."""
    return Tier3ValidationLayer(
        bb=bb,
        engagement_slug=SLUG,
        killswitch=t3.KillSwitch(SLUG, path=tmp_path / ks_path),
        latch=Tier3Latch(engaged=engaged),
        approval_hook=approval,
        scope_check=scope,
    )


def _spine_kinds(bb: Blackboard, kind: str) -> list[dict[str, Any]]:
    return [r.payload for r in bb.read(engagement=SLUG, kinds=[kind])]


# ---------------------------------------------------------------------------
# A. Happy path — every gate passes, the retained proof re-fires.
# ---------------------------------------------------------------------------


def test_all_gates_pass_validates_and_proves_impact(bb: Blackboard, tmp_path: Path) -> None:
    layer = _layer(bb, tmp_path)
    result = layer.validate(_confirmed_finding(), target_url=LOCAL_TARGET)

    assert result.validated is True
    assert result.refused_gate == ""
    assert result.oracle_kind is not None and "REFLECTION" in result.oracle_kind.upper()
    assert result.proof_marker == _MARKER
    assert result.confidence is not None
    assert result.confidence >= 0.7  # >= verifier high-confidence threshold

    # audit: a decision was posted, a proof-of-impact observation landed, no refusal.
    assert len(_spine_kinds(bb, "decision")) == 1
    obs = _spine_kinds(bb, "observation")
    assert len(obs) == 1
    assert obs[0]["source"] == "tier3-validation"
    assert _MARKER in obs[0]["raw_excerpt"]
    assert _spine_kinds(bb, "refusal") == []


# ---------------------------------------------------------------------------
# B. Fail-closed gates — flip exactly one, prove it refuses & records.
# ---------------------------------------------------------------------------


def test_killswitch_tripped_refuses_and_takes_no_action(bb: Blackboard, tmp_path: Path) -> None:
    layer = _layer(bb, tmp_path, ks_path="ks-tripped.json")
    assert layer.killswitch is not None
    layer.killswitch.trip("operator halt for test")

    result = layer.validate(_confirmed_finding(), target_url=LOCAL_TARGET)

    assert result.validated is False
    assert result.refused_gate == "kill-switch"
    refusals = _spine_kinds(bb, "refusal")
    assert len(refusals) == 1 and refusals[0]["gate"] == "kill-switch"
    assert refusals[0]["fatal"] is True
    # NO offensive action / proof was produced.
    assert _spine_kinds(bb, "observation") == []


def test_latch_disengaged_refuses_by_default(bb: Blackboard, tmp_path: Path, monkeypatch) -> None:
    # env unset + no explicit override => DISENGAGED (the default-off inertness).
    monkeypatch.delenv(t3.TIER3_LATCH_ENV, raising=False)
    layer = Tier3ValidationLayer(
        bb=bb, engagement_slug=SLUG,
        killswitch=t3.KillSwitch(SLUG, path=tmp_path / "ks.json"),
        latch=Tier3Latch(),  # reads env -> disengaged
        approval_hook=_grant, scope_check=_in_scope,
    )
    result = layer.validate(_confirmed_finding(), target_url=LOCAL_TARGET)

    assert result.validated is False
    assert result.refused_gate == "tier3-latch"
    # a disengaged latch is recorded as a SOVEREIGNTY refusal.
    assert _spine_kinds(bb, "refusal")[0]["gate"] == "sovereignty"
    assert _spine_kinds(bb, "observation") == []


def test_env_can_arm_the_latch(monkeypatch) -> None:
    monkeypatch.setenv(t3.TIER3_LATCH_ENV, "1")
    assert Tier3Latch().is_engaged() is True
    monkeypatch.setenv(t3.TIER3_LATCH_ENV, "0")
    assert Tier3Latch().is_engaged() is False
    monkeypatch.delenv(t3.TIER3_LATCH_ENV, raising=False)
    assert Tier3Latch().is_engaged() is False


@pytest.mark.parametrize(
    "mutate",
    [
        {"critique_status": "pending"},              # not confirmed by critique
        {"verified_by_oracle": False},               # no oracle carried it
        {"oracle_context": None},                    # nothing retained to re-fire
        {"oracle_context": {}},                      # empty retained context
    ],
)
def test_unconfirmed_finding_refuses(bb: Blackboard, tmp_path: Path, mutate: dict) -> None:
    finding = _confirmed_finding()
    finding.update(mutate)
    result = _layer(bb, tmp_path).validate(finding, target_url=LOCAL_TARGET)

    assert result.validated is False
    assert result.refused_gate == "finding-confirmed"
    assert _spine_kinds(bb, "refusal")[0]["gate"] == "epistemic"
    assert _spine_kinds(bb, "observation") == []


def test_off_scope_target_refuses(bb: Blackboard, tmp_path: Path) -> None:
    layer = _layer(bb, tmp_path, scope=_out_of_scope)
    result = layer.validate(_confirmed_finding(), target_url=LOCAL_TARGET)

    assert result.validated is False
    assert result.refused_gate == "charter-scope"
    assert _spine_kinds(bb, "refusal")[0]["gate"] == "scope"


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com/vuln",   # public name
        "http://8.8.8.8/vuln",       # public IP literal
        "http://169.254.169.254/",   # cloud metadata — must NOT be reachable
        "http://[::ffff:8.8.8.8]/",  # v4-mapped public v6
        "http:///nohost",            # empty host
    ],
)
def test_non_localhost_target_refuses(bb: Blackboard, tmp_path: Path, target: str) -> None:
    result = _layer(bb, tmp_path).validate(_confirmed_finding(), target_url=target)

    assert result.validated is False
    assert result.refused_gate == "localhost"
    assert _spine_kinds(bb, "refusal")[0]["gate"] == "scope"
    assert _spine_kinds(bb, "observation") == []


def test_operator_declines_refuses(bb: Blackboard, tmp_path: Path) -> None:
    result = _layer(bb, tmp_path, approval=_deny).validate(
        _confirmed_finding(), target_url=LOCAL_TARGET,
    )
    assert result.validated is False
    assert result.refused_gate == "operator-approval"
    assert _spine_kinds(bb, "refusal")[0]["gate"] == "ethics"
    assert _spine_kinds(bb, "observation") == []


def test_operator_timeout_denies(bb: Blackboard, tmp_path: Path) -> None:
    # The approval contract is default-deny on timeout / non-interactive: a hook
    # that "times out" returns False, and the layer refuses.
    def _timed_out(_q: str, _t: float) -> bool:
        return False

    result = _layer(bb, tmp_path, approval=_timed_out).validate(
        _confirmed_finding(), target_url=LOCAL_TARGET,
    )
    assert result.validated is False
    assert result.refused_gate == "operator-approval"


def test_entitlement_denied_raises_and_records(bb: Blackboard, tmp_path: Path) -> None:
    # Force an enforced deployment with no valid grant -> require_capability
    # raises. The layer must record the refusal on the spine, THEN re-raise
    # (this gate is the one hard-stop that is never swallowed).
    ent_policy.set_policy(
        ent_policy.EntitlementPolicy(
            ent_policy._denied_state(EntitlementMissing, "test: no entitlement provisioned")
        )
    )
    try:
        with pytest.raises(EntitlementViolation):
            _layer(bb, tmp_path).validate(_confirmed_finding(), target_url=LOCAL_TARGET)
    finally:
        ent_policy.reset_policy()

    refusals = _spine_kinds(bb, "refusal")
    assert len(refusals) == 1 and refusals[0]["gate"] == "entitlement"
    assert refusals[0]["fatal"] is True
    # the raise happened BEFORE approval / PoC — no proof, no double refusal.
    assert _spine_kinds(bb, "observation") == []


# ---------------------------------------------------------------------------
# C. Veracity firewall — a proof that no longer re-fires is DEMOTED.
# ---------------------------------------------------------------------------


def test_stale_proof_does_not_refire_is_demoted(bb: Blackboard, tmp_path: Path) -> None:
    result = _layer(bb, tmp_path).validate(_stale_finding(), target_url=LOCAL_TARGET)

    assert result.validated is False
    assert result.refused_gate == "finding-confirmed"
    reason = _spine_kinds(bb, "refusal")[0]["reason"]
    assert "did NOT re-fire" in reason
    # the firewall can only demote — it never fabricated a proof-of-impact.
    assert _spine_kinds(bb, "observation") == []


def test_malformed_retained_context_refuses(bb: Blackboard, tmp_path: Path) -> None:
    finding = _confirmed_finding()
    finding["oracle_context"] = {"not_a_real_field": 123}  # truthy but unparseable
    result = _layer(bb, tmp_path).validate(finding, target_url=LOCAL_TARGET)

    assert result.validated is False
    assert result.refused_gate == "finding-confirmed"
    assert "did not parse" in _spine_kinds(bb, "refusal")[0]["reason"]


# ---------------------------------------------------------------------------
# D. Gate ORDER — a more-fundamental refusal always wins.
# ---------------------------------------------------------------------------


def test_killswitch_precedes_every_other_gate(bb: Blackboard, tmp_path: Path) -> None:
    # kill-switch tripped AND latch off AND unconfirmed AND off-scope AND deny.
    layer = _layer(bb, tmp_path, engaged=False, approval=_deny, scope=_out_of_scope,
                   ks_path="ks.json")
    assert layer.killswitch is not None
    layer.killswitch.trip("halt")
    finding = _confirmed_finding()
    finding["critique_status"] = "pending"

    result = layer.validate(finding, target_url="http://example.com/")
    assert result.refused_gate == "kill-switch"  # first in GATE_ORDER wins


def test_latch_precedes_finding_confirmed(bb: Blackboard, tmp_path: Path) -> None:
    layer = _layer(bb, tmp_path, engaged=False)
    finding = _confirmed_finding()
    finding["critique_status"] = "pending"  # would also fail G3

    result = layer.validate(finding, target_url=LOCAL_TARGET)
    assert result.refused_gate == "tier3-latch"  # G2 fires before G3


def test_finding_confirmed_precedes_scope(bb: Blackboard, tmp_path: Path) -> None:
    layer = _layer(bb, tmp_path, scope=_out_of_scope)
    finding = _confirmed_finding()
    finding["critique_status"] = "pending"

    result = layer.validate(finding, target_url="http://example.com/")
    assert result.refused_gate == "finding-confirmed"  # G3 before G4/G5


# ---------------------------------------------------------------------------
# E. Doctrine boundary — NOTHING on the hard-exclusion list is reachable.
# ---------------------------------------------------------------------------


def test_only_exploit_execution_capability_is_declared() -> None:
    assert TIER3_REQUIRED_CAPABILITY is Capability.EXPLOIT_EXECUTION
    assert TIER3_REQUIRED_CAPABILITY not in FORBIDDEN_CAPABILITIES
    # the hard-exclusion set is exactly the forbidden trio.
    assert FORBIDDEN_CAPABILITIES == frozenset({
        Capability.DEFENDER_EVASION,
        Capability.FULL_CHAIN_EXPLOITATION,
        Capability.SELF_IMPROVEMENT_MERGE,
    })


def test_source_can_only_ever_require_exploit_execution() -> None:
    """Structural proof over the module AST: every capability-gate call in the
    module (`require_capability` / `assert_capability` / `is_capability_available`)
    is passed ONLY `Capability.EXPLOIT_EXECUTION`. A forbidden capability can
    therefore never be requested from this code path."""
    src = Path(t3.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    gate_calls = {"require_capability", "assert_capability", "is_capability_available"}
    seen = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if name not in gate_calls:
            continue
        seen += 1
        assert node.args, f"{name}() called with no capability argument"
        arg = node.args[0]
        # must be exactly Capability.EXPLOIT_EXECUTION or the TIER3_REQUIRED_CAPABILITY alias
        if isinstance(arg, ast.Attribute):
            assert arg.attr == "EXPLOIT_EXECUTION", (
                f"{name}() requests forbidden capability {arg.attr}"
            )
        elif isinstance(arg, ast.Name):
            assert arg.id == "TIER3_REQUIRED_CAPABILITY"
        else:  # pragma: no cover - anything else is a red flag
            raise AssertionError(f"unexpected capability argument: {ast.dump(arg)}")
    assert seen >= 1, "expected at least one capability-gated call in the module"


def test_no_forbidden_capability_member_is_ever_gated() -> None:
    """No forbidden Capability member appears as an argument to a gate call —
    they exist in the module only inside the FORBIDDEN_CAPABILITIES *denylist*,
    never in a require/assert."""
    src = Path(t3.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden_names = {c.name for c in FORBIDDEN_CAPABILITIES}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in {"require_capability", "assert_capability", "is_capability_available"}:
                for arg in node.args:
                    if isinstance(arg, ast.Attribute):
                        assert arg.attr not in forbidden_names


def test_minimal_poc_sends_no_network_traffic(bb: Blackboard, tmp_path: Path, monkeypatch) -> None:
    """The 'PoC' is pure OFFLINE re-execution of the retained proof — it opens
    no socket, reaches no host. Poison every network primitive; the happy path
    (a loopback IP *literal*, so even the localhost gate does no DNS) must still
    validate."""
    def _boom(*_a: Any, **_k: Any):
        raise AssertionError("Tier-3 PoC attempted network I/O")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)

    result = _layer(bb, tmp_path).validate(_confirmed_finding(), target_url=LOCAL_TARGET)
    assert result.validated is True  # re-proven with zero network traffic


def test_layer_emits_no_offensive_action_events(bb: Blackboard, tmp_path: Path) -> None:
    """Unlike ExploitAgent (which posts plan/action/result for live attempts),
    the Tier-3 layer performs NO new offensive execution: across a success and a
    refusal, the only event kinds it emits are decision / observation / refusal.
    No action, result, or plan (which would represent new attack traffic) is
    ever posted."""
    _layer(bb, tmp_path).validate(_confirmed_finding("ok"), target_url=LOCAL_TARGET)
    _layer(bb, tmp_path, approval=_deny).validate(
        _confirmed_finding("refused"), target_url=LOCAL_TARGET,
    )
    rows = bb.read(engagement=SLUG, include_superseded=True)
    kinds = {r.kind for r in rows}
    assert kinds <= {"decision", "observation", "refusal"}
    assert not (kinds & {"action", "result", "plan", "hypothesis"})


def test_default_approval_hook_reuses_stdin_prompt() -> None:
    """The per-action approval is the ONE canonical stdin y/N prompt from the
    http_executor (deny on timeout / non-tty) — not a second, weaker
    implementation."""
    from framework.v2.agents.http_executor import stdin_prompt_with_timeout
    assert t3._default_approval_hook() is stdin_prompt_with_timeout


# ---------------------------------------------------------------------------
# F. Localhost resolver — fail-closed unit coverage (closes DNS rebinding).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.5", "::1", "[::1]"])
def test_loopback_literals_pass(host: str) -> None:
    # IP literals resolve without touching the DNS resolver — deterministic.
    ok, _ = resolves_to_loopback(host)
    assert ok is True


def test_split_horizon_dns_rebinding_fails_closed(monkeypatch) -> None:
    # A name that resolves to BOTH loopback and a public IP must fail closed.
    def _mixed(host, *_a, **_k):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _mixed)
    ok, reason = resolves_to_loopback("rebind.evil.test")
    assert ok is False
    assert "non-loopback" in reason


def test_unresolvable_host_fails_closed(monkeypatch) -> None:
    def _fail(host, *_a, **_k):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)
    ok, reason = resolves_to_loopback("does-not-exist.test")
    assert ok is False
    assert "unresolvable" in reason


def test_name_resolving_only_to_loopback_passes(monkeypatch) -> None:
    def _loop(host, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _loop)
    ok, _ = resolves_to_loopback("my-local-app.test")
    assert ok is True


# ---------------------------------------------------------------------------
# G. Audit-trail integrity — every attempt is on the spine.
# ---------------------------------------------------------------------------


def test_every_attempt_posts_a_decision_first(bb: Blackboard, tmp_path: Path) -> None:
    # Even a refused attempt records the decision (the audit anchor) and links
    # the refusal to it via parent_id.
    layer = _layer(bb, tmp_path, engaged=False)
    result = layer.validate(_confirmed_finding(), target_url=LOCAL_TARGET)

    decisions = bb.read(engagement=SLUG, kinds=["decision"])
    refusals = bb.read(engagement=SLUG, kinds=["refusal"])
    assert len(decisions) == 1
    assert len(refusals) == 1
    assert refusals[0].parent_id == decisions[0].id
    assert result.decision_event_id == decisions[0].id


def test_gate_order_constant_matches_documented_stack() -> None:
    assert GATE_ORDER == (
        "kill-switch", "tier3-latch", "finding-confirmed",
        "charter-scope", "localhost", "entitlement", "operator-approval",
    )
