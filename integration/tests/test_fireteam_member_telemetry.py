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


def _use(tool="nmap", *, rationale="probing the login flow"):
    return LLMDecision(action=ActionType.USE_TOOL, tool=ToolCall(tool_name=tool, tool_args={"target": "t"}),
                       rationale=rationale,
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


def test_secret_in_a_step_summary_is_redacted_before_the_feed():
    q, written = _recording_queue()
    rt = lambda tool, phase, seq, *, approved=False: SimpleNamespace(ran=True, stdout="x", reason="")
    # a rationale carrying a credential-shaped token must be scrubbed by the queue before it can reach the feed
    runner = build_member_runner(think=_think(_use("nmap", rationale="using api_key=SBX-super-secret-value")),
                                 run_tool=rt)
    ctx = MemberRunContext(seq=0, phase=Phase.INFORMATIONAL, gate=_allow_gate, oracle=None, spine=q)
    runner(_member(), ctx)
    q.flush()
    blob = " ".join(str(r.get("summary", "")) for r in written)
    assert "super-secret-value" not in blob, "a secret in a member step summary reached the feed unredacted"


def test_no_spine_wired_is_safe():
    rt = lambda tool, phase, seq, *, approved=False: SimpleNamespace(ran=True, stdout="x", reason="")
    runner = build_member_runner(think=_think(_use("nmap")), run_tool=rt)
    ctx = MemberRunContext(seq=0, phase=Phase.INFORMATIONAL, gate=_allow_gate, oracle=None, spine=None)
    res = runner(_member(), ctx)                          # no spine — telemetry is a no-op, member unaffected
    assert res.status == MemberStatus.SUCCESS and len(res.claims) == 1
