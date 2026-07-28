"""A5 — S5 agent-to-agent coordination wired into the fireteam wave (orchestrator + member_runner).

Doctrine under test:
  * a claim-producing member BROADCASTS one coordination hint AFTER the wave; the NEXT wave reads it at
    wave-START as ADVISORY context (folded into the member objective) — a read-only snapshot, so intra-wave
    concurrency never races a read against a write;
  * a coordination message is NEVER evidence — hints alone (no oracle-confirmed claim) mint NO fact/lead;
  * posts are DETERMINISTIC (member/plan order); the poster equals the sender (anti-spoof, mirrored here).

Uses a minimal fake blackboard so this runs in the two-env-boundary CI job (no framework on the path); the
REAL blackboard's schema + anti-spoof are covered by framework's own test_agent_message.py.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from vigil_integration.agent.state import ActionType, LLMDecision, OutputAnalysis, Phase, ToolCall
from vigil_integration.fireteam.member import FireteamMember
from vigil_integration.fireteam.member_runner import _member_state, build_member_runner
from vigil_integration.fireteam.models import FireteamMemberSpec, MemberResult, MemberStatus
from vigil_integration.fireteam.orchestrator import _COORD_RECIPIENT, run_fireteam


class _FakeBB:
    """A stand-in for framework's Blackboard: append-only agent_message log, recipient-filtered inbox, and
    the SAME anti-spoof the real blackboard enforces (poster == payload.sender)."""

    def __init__(self):
        self.msgs: list[dict] = []

    def inbox(self, *, engagement, recipient, since_id=0, limit=1000):
        return [SimpleNamespace(payload=m) for m in self.msgs if m.get("recipient") == recipient]

    def post(self, *, engagement, kind, agent_name, payload):
        assert kind == "agent_message"
        assert str(payload.get("sender")) == str(agent_name), "anti-spoof: poster must equal sender"
        self.msgs.append(dict(payload))
        return len(self.msgs)


def _allow_gate(t, tg, d):
    return SimpleNamespace(allowed=True, outcome="allow", reason="ok")


def _use(tool="nmap", *, exploit=None):
    return LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name=tool, tool_args={"target": "t"}),
                       output_analysis=OutputAnalysis(exploit_succeeded=exploit,
                                                      findings=[{"title": "x", "bug_class": "info"}]))


def _think(*decisions):
    it = iter(decisions)
    return lambda state: next(it, LLMDecision(action=ActionType.COMPLETE, summary="done"))


def _tool_recorder():
    def rt(tool, phase, seq, *, approved=False):
        return SimpleNamespace(ran=True, stdout="RAW " + tool.tool_name, reason="")
    return rt


def _plan(wave_id, member_ids):
    return {"wave_id": wave_id,
            "members": [{"member_id": m, "role": "recon", "capped_tier": "A1", "tools": ["nmap"], "credit": 2}
                        for m in member_ids]}


def test_wave_broadcasts_a_hint_and_the_next_wave_reads_it():
    bb = _FakeBB()
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=_tool_recorder())
    # wave 1: member 'a' produces a claim → after the wave it broadcasts exactly one coordination hint.
    asyncio.run(run_fireteam(_plan("eng-w0", ["a"]), runner, phase=Phase.INFORMATIONAL, gate=_allow_gate,
                             blackboard=bb, engagement="eng"))
    msgs = bb.inbox(engagement="eng", recipient=_COORD_RECIPIENT)
    assert len(msgs) == 1 and msgs[0].payload["sender"] == "a"
    assert "produced 1 lead" in msgs[0].payload["body"]

    # wave 2: a capturing runner sees the prior wave's hint in its wave-START snapshot (ctx.hints).
    captured = {}

    def cap_runner(member, ctx):
        captured["hints"] = tuple(ctx.hints)
        return MemberResult(member_id=member.member_id, status=MemberStatus.COMPLETE)

    asyncio.run(run_fireteam(_plan("eng-w1", ["b"]), cap_runner, phase=Phase.INFORMATIONAL, gate=_allow_gate,
                             blackboard=bb, engagement="eng"))
    assert captured["hints"] and "produced 1 lead" in captured["hints"][0]


def test_hint_folds_into_the_member_objective_as_advisory():
    m = FireteamMember(spec=FireteamMemberSpec(member_id="m1", role="recon", capped_tier="A1",
                                               tools=["nmap"], credit=2),
                       wave_id="w", phase=Phase.INFORMATIONAL)
    st = _member_state(m, "assess", hints=("a found an admin panel",))
    assert "ADVISORY" in st.objective and "admin panel" in st.objective
    # no hints → the objective is unchanged (no dangling coordination text)
    assert "ADVISORY" not in _member_state(m, "assess").objective


def test_hints_alone_mint_no_fact_or_lead():
    # a coordination message injected as if from a prior wave + a member that produces NO claim → NOTHING.
    bb = _FakeBB()
    bb.post(engagement="eng", kind="agent_message", agent_name="a",
            payload={"sender": "a", "recipient": _COORD_RECIPIENT, "topic": "x", "body": "SQLi on /login"})

    def idle_runner(member, ctx):
        return MemberResult(member_id=member.member_id, status=MemberStatus.COMPLETE)

    out = asyncio.run(run_fireteam(_plan("eng-w1", ["b"]), idle_runner, phase=Phase.INFORMATIONAL,
                                   gate=_allow_gate, oracle=lambda raw, an: "spine:x",
                                   blackboard=bb, engagement="eng"))
    assert out.facts == [] and out.leads == []              # a hint is NEVER evidence


def test_coordination_posts_are_deterministic_member_order():
    bb = _FakeBB()
    # every member proposes nmap (bounded by its credit) → each produces a claim → each broadcasts one hint.
    runner = build_member_runner(think=lambda state: _use("nmap"), run_tool=_tool_recorder())
    asyncio.run(run_fireteam(_plan("eng-w0", ["a", "b", "c"]), runner, phase=Phase.INFORMATIONAL,
                             gate=_allow_gate, blackboard=bb, engagement="eng"))
    senders = [m.payload["sender"] for m in bb.inbox(engagement="eng", recipient=_COORD_RECIPIENT)]
    assert senders == ["a", "b", "c"]                       # posted in plan order — deterministic


def test_a_hint_never_reaches_claim_raw_output_or_a_fact():
    # THE invariant, locked at the fireteam layer: run the PRODUCTION runner with a hint present + an
    # always-fire oracle, and prove the hint text reaches NO claim.raw_output (the only thing the oracle
    # sees) and NO fact — so a future member_runner refactor that leaked a hint into evidence fails CI.
    secret = "HINT-SENTINEL-never-evidence"
    bb = _FakeBB()
    bb.post(engagement="eng", kind="agent_message", agent_name="a",
            payload={"sender": "a", "recipient": _COORD_RECIPIENT, "topic": "x", "body": secret})
    runner = build_member_runner(think=_think(_use("nmap", exploit=True)), run_tool=_tool_recorder())
    out = asyncio.run(run_fireteam(_plan("eng-w1", ["b"]), runner, phase=Phase.INFORMATIONAL,
                                   gate=_allow_gate, oracle=lambda raw, an: "spine:x",
                                   blackboard=bb, engagement="eng"))
    assert out.facts                                            # the real nmap claim IS confirmed…
    for mr in out.member_results:
        for c in mr.claims:
            assert secret not in c.raw_output                  # …but the hint never entered the evidence
    for f in out.facts:
        assert secret not in (f.title or "")


def test_no_blackboard_is_a_clean_no_op():
    # without a blackboard the wave behaves exactly as before (no coordination, no error).
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=_tool_recorder())
    out = asyncio.run(run_fireteam(_plan("eng-w0", ["a"]), runner, phase=Phase.INFORMATIONAL,
                                   gate=_allow_gate))
    assert not out.refused and out.member_results
