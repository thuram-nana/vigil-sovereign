"""A4c — the production MemberRunner (fireteam/member_runner.py) + run_fireteam end-to-end.

Proves the fan-out is never more capable than the parent: an in-cap non-destructive edge runs through the
SAME governed executor (approved=False — a member can't self-approve); an over-cap/destructive edge is
QUEUED (an escalation) and NEVER executed; a denied edge pivots; the loop is bounded by credit AND a hard
step ceiling; a think/executor error ends the member cleanly (never the wave); and end-to-end only an
oracle-confirmed claim mints a FACT (collect re-fires the oracle), a malformed/over-cap plan spawns nothing.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from vigil_integration.agent.state import ActionType, LLMDecision, OutputAnalysis, Phase, ToolCall
from vigil_integration.fireteam.member import FireteamMember
from vigil_integration.fireteam.member_runner import build_member_runner
from vigil_integration.fireteam.models import FireteamMemberSpec, MemberStatus
from vigil_integration.fireteam.orchestrator import MemberRunContext, run_fireteam


def _member(*, tier="A1", phase=Phase.INFORMATIONAL, credit=5, tools=("nmap",)):
    return FireteamMember(
        spec=FireteamMemberSpec(member_id="m1", role="recon", capped_tier=tier, tools=list(tools),
                                credit=credit),
        wave_id="w1", phase=phase)


def _ctx(gate, *, seq=0, phase=Phase.INFORMATIONAL):
    return MemberRunContext(seq=seq, phase=phase, gate=gate, oracle=None, spine=None)


def _use(tool="nmap", *, exploit=None):
    return LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name=tool, tool_args={"target": "t"}),
                       output_analysis=OutputAnalysis(exploit_succeeded=exploit,
                                                      findings=[{"title": "x", "bug_class": "info"}]))


def _allow_gate(t, tg, d):
    return SimpleNamespace(allowed=True, outcome="allow", reason="ok")


def _deny_gate(t, tg, d):
    return SimpleNamespace(allowed=False, outcome="deny", reason="no")


def _think(*decisions):
    it = iter(decisions)
    return lambda state: next(it, LLMDecision(action=ActionType.COMPLETE, summary="done"))


def _tool_recorder():
    calls = []

    def rt(tool, phase, seq, *, approved=False):
        calls.append((tool.tool_name, approved))
        return SimpleNamespace(ran=True, stdout="RAW " + tool.tool_name + " output", reason="")
    return rt, calls


def test_in_cap_edge_runs_through_the_governed_executor_and_yields_a_claim():
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    res = runner(_member(tier="A1", phase=Phase.INFORMATIONAL), _ctx(_allow_gate))
    assert res.status == MemberStatus.SUCCESS
    assert len(res.claims) == 1 and res.claims[0].source == "nmap"
    assert res.claims[0].raw_output == "RAW nmap output"
    assert calls == [("nmap", False)]                          # executed exactly once, NEVER self-approved


def test_over_cap_edge_is_queued_and_never_executed():
    # nmap @ EXPLOITATION needs A2 > the member's A1 cap → queued escalation, NOT run (even with allow gate)
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    res = runner(_member(tier="A1", phase=Phase.EXPLOITATION),
                 _ctx(_allow_gate, phase=Phase.EXPLOITATION))
    assert res.status == MemberStatus.NEEDS_CONFIRMATION
    assert len(res.escalations) == 1 and not res.claims
    assert calls == []                                         # a queued edge NEVER reaches the executor


def test_destructive_edge_is_queued_not_run():
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=_think(_use("sqlmap")), run_tool=rt)
    res = runner(_member(tier="A2", phase=Phase.EXPLOITATION, tools=("sqlmap",)),
                 _ctx(_allow_gate, phase=Phase.EXPLOITATION))
    assert res.status == MemberStatus.NEEDS_CONFIRMATION and not calls   # destructive → queued, never run


def test_denied_edge_pivots_and_the_loop_is_bounded():
    # gate denies forever + think never completes → must still terminate (hard step ceiling), no claims
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=lambda s: _use("nmap"), run_tool=rt)   # infinite USE_TOOL
    res = runner(_member(tier="A1", credit=3), _ctx(_deny_gate))
    assert not res.claims and not calls                        # denied → never executed
    assert res.iterations_used <= 3 * 2 + 3                     # bounded by the step ceiling


def test_credit_bounds_executions():
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=lambda s: _use("nmap"), run_tool=rt)   # infinite USE_TOOL
    res = runner(_member(tier="A1", credit=1), _ctx(_allow_gate))
    assert len(calls) == 1                                     # credit=1 → at most one execution
    assert res.credit_used == 1


def test_think_error_ends_the_member_cleanly():
    def _boom(state):
        raise RuntimeError("think backend down")
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=_boom, run_tool=rt)
    res = runner(_member(), _ctx(_allow_gate))
    assert res.status == MemberStatus.ERROR and not calls      # isolated, no raise


def test_executor_error_ends_the_member_cleanly():
    def _boom_rt(tool, phase, seq, *, approved=False):
        raise RuntimeError("executor down")
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=_boom_rt)
    res = runner(_member(tier="A1"), _ctx(_allow_gate))
    assert res.status == MemberStatus.ERROR                    # isolated, no raise


def test_run_fireteam_end_to_end_only_oracle_confirms_a_fact():
    rt, _ = _tool_recorder()
    runner = build_member_runner(think=_think(_use("nmap", exploit=True)), run_tool=rt)
    plan = {"wave_id": "wave1",
            "members": [{"member_id": "a", "role": "recon", "capped_tier": "A1",
                         "tools": ["nmap"], "credit": 2}]}
    # oracle CONFIRMS → the claim becomes a signed FACT via collect
    out = asyncio.run(run_fireteam(plan, runner, phase=Phase.INFORMATIONAL, gate=_allow_gate,
                                   oracle=lambda raw, an: "spine:" + "f" * 60))
    assert not out.refused and out.facts                       # the confirmed exploit is a FACT
    assert out.facts[0].status == "fact" and out.facts[0].evidence_ref
    # oracle SILENT → the same claim stays a LEAD (no fact)
    rt2, _ = _tool_recorder()
    runner2 = build_member_runner(think=_think(_use("nmap", exploit=True)), run_tool=rt2)
    out2 = asyncio.run(run_fireteam(plan, runner2, phase=Phase.INFORMATIONAL, gate=_allow_gate,
                                    oracle=lambda raw, an: None))
    assert not out2.refused and not out2.facts and out2.leads


def test_run_fireteam_refuses_a_malformed_or_overcap_plan_spawning_nothing():
    rt, calls = _tool_recorder()
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    # capped_tier A3 is refused at the spec type → the whole plan is refused, NOTHING spawned
    bad = {"wave_id": "w", "members": [{"member_id": "a", "capped_tier": "A3", "tools": ["nmap"]}]}
    out = asyncio.run(run_fireteam(bad, runner, gate=_allow_gate))
    assert out.refused and not out.facts and not out.member_results and not calls
    # over-count (6 > FIRETEAM_MAX_MEMBERS=5) also refused
    over = {"wave_id": "w", "members": [{"member_id": f"m{i}", "capped_tier": "A1"} for i in range(6)]}
    assert asyncio.run(run_fireteam(over, runner, gate=_allow_gate)).refused
