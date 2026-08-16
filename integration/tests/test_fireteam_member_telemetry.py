"""E1 — per-member step telemetry. A fireteam member submits its OODA steps (think / claim / escalation) to
the injected single-writer spine queue, ATTRIBUTED by member_id/role/wave_id, so the operator watches each
agent work on its task in the parent engagement's live feed. Pins:

  * a member emits an attributed ``think`` step and, on a successful edge, a ``claim`` step;
  * a claim is labelled a LEAD (oracle-pending) — never a fact (collect() re-fires the oracle for facts);
  * an over-cap edge emits an ``escalation`` step (queued for signed approval, never run);
  * the queue REDACTS every record (no secret reaches the feed);
  * telemetry is best-effort — with NO spine wired the member runs identically (no error).
"""

from __future__ import annotations

from types import SimpleNamespace

from vigil_integration.agent.state import ActionType, LLMDecision, OutputAnalysis, Phase, ToolCall
from vigil_integration.fireteam.member import FireteamMember
from vigil_integration.fireteam.member_runner import build_member_runner
from vigil_integration.fireteam.models import FireteamMemberSpec, MemberStatus
from vigil_integration.fireteam.orchestrator import MemberRunContext
from vigil_integration.fireteam.spine_queue import SingleWriterSpineQueue


def _member(*, tier="A1", phase=Phase.INFORMATIONAL, credit=5):
    return FireteamMember(
        spec=FireteamMemberSpec(member_id="auth1", role="auth-specialist", capped_tier=tier,
                                tools=["nmap"], credit=credit),
        wave_id="w7", phase=phase)


def _allow_gate(t, tg, d):
    return SimpleNamespace(allowed=True, outcome="allow", reason="ok")


def _use(tool="nmap", *, reasoning="probing the login flow"):
    # the model's reasoning rides `.reasoning` (LLMDecision has NO `.rationale` — pydantic would silently
    # drop that kwarg, which is exactly what made an earlier redaction test vacuous). Set the real field.
    return LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name=tool, tool_args={"target": "t"}),
                       reasoning=reasoning,
                       output_analysis=OutputAnalysis(findings=[{"title": "x", "bug_class": "info"}]))


def _think(*decisions):
    it = iter(decisions)
    return lambda state: next(it, LLMDecision(action=ActionType.COMPLETE, summary="done"))


def _recording_queue():
    written: list = []
    q = SingleWriterSpineQueue(writer=lambda rec: (written.append(rec), "ref")[1])
    return q, written


def test_member_emits_attributed_think_and_claim_steps():
    q, written = _recording_queue()
    rt = lambda tool, phase, seq, *, approved=False: SimpleNamespace(ran=True, stdout="RAW out", reason="")
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    ctx = MemberRunContext(seq=0, phase=Phase.INFORMATIONAL, gate=_allow_gate, oracle=None, spine=q)
    res = runner(_member(), ctx)
    q.flush()                                            # drain buffered records through the writer
    assert res.status == MemberStatus.SUCCESS
    steps = {r.get("step"): r for r in written}
    assert "think" in steps and "claim" in steps, [r.get("step") for r in written]
    for r in written:                                    # every step is attributed to THIS member
        assert r["member_id"] == "auth1" and r["role"] == "auth-specialist" and r["wave_id"] == "w7"
    # a member claim is a LEAD until the oracle re-fires — the summary says so, it is never a fact
    assert "oracle-pending" in steps["claim"]["summary"] or "lead" in steps["claim"]["summary"].lower()


def test_over_cap_edge_emits_an_escalation_step():
    q, written = _recording_queue()
    rt = lambda tool, phase, seq, *, approved=False: SimpleNamespace(ran=True, stdout="x", reason="")
    # nmap @ EXPLOITATION needs A2 > the member's A1 cap → queued escalation, never run
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    ctx = MemberRunContext(seq=0, phase=Phase.EXPLOITATION, gate=_allow_gate, oracle=None, spine=q)
    res = runner(_member(tier="A1", phase=Phase.EXPLOITATION), ctx)
    q.flush()
    assert res.status == MemberStatus.NEEDS_CONFIRMATION
    steps = [r.get("step") for r in written]
    assert "escalation" in steps
    esc = next(r for r in written if r["step"] == "escalation")
    assert "approval" in esc["summary"].lower()


def test_reasoning_flows_to_the_feed_but_a_structured_secret_is_redacted():
    """BLOCK-2: the member's REASONING must actually reach the feed — that IS how the operator sees the agent
    work (it rides `decision.reasoning`; an earlier version read a non-existent `.rationale`, so nothing
    flowed). BLOCK-1: and a credential-shaped token inside that reasoning must be scrubbed by the queue
    BEFORE the feed. The control is real: the non-secret words survive (proving reasoning flows) while the
    secret VALUE does not (proving the F3 scrubber fired — this second assertion FAILS if _redact_record is
    neutered, unlike the prior vacuous test where the secret never entered the summary at all)."""
    q, written = _recording_queue()
    rt = lambda tool, phase, seq, *, approved=False: SimpleNamespace(ran=True, stdout="x", reason="")
    runner = build_member_runner(
        think=_think(_use("nmap", reasoning="probing the login flow with api_key=SBX-SECRET-VALUE-123")),
        run_tool=rt)
    ctx = MemberRunContext(seq=0, phase=Phase.INFORMATIONAL, gate=_allow_gate, oracle=None, spine=q)
    runner(_member(), ctx)
    q.flush()
    think = next(r for r in written if r["step"] == "think")
    assert "probing the login flow" in think["summary"], "member reasoning did not reach the feed (BLOCK-2)"
    assert "SBX-SECRET-VALUE-123" not in think["summary"], "a structured secret reached the feed unredacted (BLOCK-1)"
    # the scrubber masks the structured form (belt-and-braces on the exact scrubbed shape)
    assert "api_key=SBX-SECRET-VALUE-123" not in think["summary"]


def test_no_spine_wired_is_safe():
    rt = lambda tool, phase, seq, *, approved=False: SimpleNamespace(ran=True, stdout="x", reason="")
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    ctx = MemberRunContext(seq=0, phase=Phase.INFORMATIONAL, gate=_allow_gate, oracle=None, spine=None)
    res = runner(_member(), ctx)                          # no spine — telemetry is a no-op, member unaffected
    assert res.status == MemberStatus.SUCCESS and len(res.claims) == 1
