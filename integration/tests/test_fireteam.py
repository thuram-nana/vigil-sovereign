"""
F6 — the governed fireteam: capped per-member tiers, forbidden-action stripping, signed-approval-only
escalation, single-writer spine serialization, and oracle-only fact promotion at fan-in.

The load-bearing test is ``test_ADVERSARIAL_sovereign_invariant_member_cannot_break_out`` — it attacks
exactly the sovereign invariant the red-pen targets.
"""

from __future__ import annotations

import asyncio

from vigil_integration.agent import (
    ActionType,
    Finding,
    LLMDecision,
    OutputAnalysis,
    Phase,
    ToolCall,
)
from vigil_integration.fireteam import (
    ConfirmationOutcome,
    ConfirmationRegistry,
    EscalationRequest,
    FireteamMember,
    FireteamMemberSpec,
    MemberBudget,
    MemberFindingClaim,
    MemberResult,
    MemberStatus,
    SingleWriterSpineQueue,
    authorize_member_edge,
    collect,
    parse_fireteam_plan,
    run_fireteam,
    run_member_step,
)
from vigil_integration.fireteam.member import _strip_forbidden_actions


# --- injected-callable stubs (gate / oracle / approver / writer) --------------------------------

class _V:
    """A gate verdict shape: ``.allowed`` / ``.outcome`` / ``.reason`` (the injected-gate contract)."""

    def __init__(self, allowed: bool, outcome: str, reason: str = "") -> None:
        self.allowed = allowed
        self.outcome = outcome
        self.reason = reason


def allow_gate(tool, target, destructive):
    return _V(True, "allow", "gate allows")


def deny_gate(tool, target, destructive):
    return _V(False, "deny", "gate denies")


def queue_gate(tool, target, destructive):
    return _V(False, "queue", "gate queues")


def raising_gate(tool, target, destructive):
    raise RuntimeError("gate exploded")


class _Appr:
    def __init__(self, approved, reason: str = "") -> None:
        self.approved = approved
        self.reason = reason


def approver_ok(signed, esc):
    return _Appr(True, "operator signed")


def approver_no(signed, esc):
    return _Appr(False, "operator declined")


def approver_boom(signed, esc):
    raise RuntimeError("signature verification failed")


def oracle_confirm(raw, analysis):
    return "spine:confirmed-hash"


def _member(tier="A1", phase=Phase.INFORMATIONAL, credit=5, deadline=1000, tools=("nmap",)):
    spec = FireteamMemberSpec(member_id="m1", capped_tier=tier, tools=list(tools), credit=credit)
    return FireteamMember(spec=spec, wave_id="w1", phase=phase,
                          budget=MemberBudget(credit_remaining=credit, deadline_seq=deadline))


def _use(tool_name, **args):
    return LLMDecision(action=ActionType.USE_TOOL,
                       tool=ToolCall(tool_name=tool_name, tool_args=args or {"target": "t"}))


# --- plan / spec validation (fail-closed) -------------------------------------------------------

def test_valid_plan_parses():
    p = parse_fireteam_plan({"wave_id": "w", "members": [{"member_id": "a", "tools": ["nmap"]}]})
    assert p is not None and p.wave_id == "w" and len(p.members) == 1


def test_plan_refuses_a3_member_cap():
    assert parse_fireteam_plan({"wave_id": "w", "members": [{"member_id": "a", "capped_tier": "A3"}]}) is None
    assert parse_fireteam_plan({"wave_id": "w", "members": [{"member_id": "a", "capped_tier": "A9"}]}) is None


def test_plan_refuses_oversize_and_empty():
    members = [{"member_id": f"m{i}"} for i in range(6)]
    assert parse_fireteam_plan({"wave_id": "w", "members": members}) is None
    assert parse_fireteam_plan({"wave_id": "w", "members": []}) is None


def test_plan_refuses_duplicate_ids_and_mutex_singleton():
    dup = {"wave_id": "w", "members": [{"member_id": "a"}, {"member_id": "a"}]}
    assert parse_fireteam_plan(dup) is None
    # two members both claim the singleton metasploit → mutex refusal
    mutex = {"wave_id": "w", "members": [{"member_id": "a", "tools": ["metasploit"]},
                                         {"member_id": "b", "tools": ["metasploit"]}]}
    assert parse_fireteam_plan(mutex) is None


def test_plan_refuses_garbage_never_raises():
    for junk in (None, 42, "nope", {"wave_id": "!!bad!!", "members": [{"member_id": "a"}]},
                 {"members": [{"member_id": "a"}]}, {"wave_id": "w"}):
        assert parse_fireteam_plan(junk) is None


def test_member_credit_bounds():
    assert parse_fireteam_plan({"wave_id": "w", "members": [{"member_id": "a", "credit": 0}]}) is None
    assert parse_fireteam_plan({"wave_id": "w", "members": [{"member_id": "a", "credit": 9999}]}) is None


# --- forbidden-action stripping -----------------------------------------------------------------

def test_strip_forbidden_actions_rewrites_to_complete():
    for act in (ActionType.DEPLOY_FIRETEAM, ActionType.TRANSITION_PHASE,
                ActionType.ASK_USER, ActionType.SWITCH_SKILL):
        safe, reason = _strip_forbidden_actions(LLMDecision(action=act))
        assert safe.action == ActionType.COMPLETE and reason


def test_strip_egress_control_tool():
    for name in ("open_egress", "egress_gate", "netns_egress", "weird_egress_helper"):
        safe, reason = _strip_forbidden_actions(_use(name))
        assert safe.action == ActionType.COMPLETE and reason
    # a plan naming an egress tool is stripped too
    plan = LLMDecision(action=ActionType.PLAN_TOOLS,
                       plan=[ToolCall(tool_name="nmap"), ToolCall(tool_name="open_egress")])
    safe, _ = _strip_forbidden_actions(plan)
    assert safe.action == ActionType.COMPLETE


def test_strip_leaves_normal_actions_untouched():
    safe, reason = _strip_forbidden_actions(_use("nmap"))
    assert safe.action == ActionType.USE_TOOL and reason == ""


def test_strip_total_on_malformed():
    safe, reason = _strip_forbidden_actions("not a decision")
    assert safe.action == ActionType.COMPLETE and reason


# --- member edge authorization (tier cap + gate) ------------------------------------------------

def test_within_cap_nondestructive_reaches_gate():
    m = _member(tier="A1", phase=Phase.INFORMATIONAL)   # nmap @ informational needs A1 ≤ cap
    assert authorize_member_edge(m, _use("nmap"), gate=allow_gate).outcome == "allow"
    assert authorize_member_edge(m, _use("nmap"), gate=deny_gate).outcome == "deny"
    assert authorize_member_edge(m, _use("nmap"), gate=queue_gate).outcome == "queue"


def test_no_gate_and_gate_error_are_deny():
    m = _member(tier="A1", phase=Phase.INFORMATIONAL)
    assert authorize_member_edge(m, _use("nmap"), gate=None).outcome == "deny"
    assert authorize_member_edge(m, _use("nmap"), gate=raising_gate).outcome == "deny"


def test_over_cap_tool_escalates_not_runs():
    # capped A1 but the EXPLOITATION phase needs A2 → escalate, DO NOT run, even with a permissive gate
    m = _member(tier="A1", phase=Phase.EXPLOITATION)
    v = authorize_member_edge(m, _use("nmap"), gate=allow_gate, seq=7)
    assert v.outcome == "queue" and v.escalation is not None
    assert v.escalation.requested_tier == "A2" and v.escalation.seq == 7
    assert v.escalation.binding_key() == ("w1", "m1", 7)


def test_destructive_tool_escalates_even_within_phase_tier():
    m = _member(tier="A2", phase=Phase.EXPLOITATION, tools=("sqlmap",))   # cap A2, phase A2
    v = authorize_member_edge(m, _use("sqlmap"), gate=allow_gate, seq=3)
    assert v.outcome == "queue" and v.escalation.requested_tier == "A3"


def test_member_cannot_dodge_by_claiming_nondestructive():
    m = _member(tier="A2", phase=Phase.EXPLOITATION, tools=("mimikatz",))
    d = LLMDecision(action=ActionType.USE_TOOL,
                    tool=ToolCall(tool_name="mimikatz", tool_args={"target": "t"}, destructive=False))
    v = authorize_member_edge(m, d, gate=allow_gate, seq=4)
    assert v.outcome == "queue"   # destructiveness re-derived from the tool NAME, not the member's flag


def test_run_member_step_budget_and_deadline():
    m = _member(tier="A1", phase=Phase.INFORMATIONAL, credit=1, deadline=5)
    o = run_member_step(m, _use("nmap"), gate=allow_gate, seq=1)
    assert o.status == MemberStatus.SUCCESS and m.budget.credit_remaining == 0
    o2 = run_member_step(m, _use("nmap"), gate=allow_gate, seq=2)
    assert o2.status == MemberStatus.COMPLETE   # credit exhausted
    m2 = _member(tier="A1", phase=Phase.INFORMATIONAL, credit=5, deadline=3)
    o3 = run_member_step(m2, _use("nmap"), gate=allow_gate, seq=4)   # 4 > deadline 3
    assert o3.status == MemberStatus.TIMEOUT


# --- confirmation registry (signed-approval-only, fail-closed) ----------------------------------

def _reg_with_esc(seq=1):
    reg = ConfirmationRegistry()
    esc = EscalationRequest(wave_id="w", member_id="m", tool_name="sqlmap", requested_tier="A3", seq=seq)
    key = reg.register(esc)
    return reg, key


def test_register_returns_deterministic_key():
    reg, key = _reg_with_esc(seq=5)
    assert key == ("w", "m", 5) and reg.pending_keys() == [("w", "m", 5)]


def test_no_approver_rejects():
    reg, key = _reg_with_esc()
    r = reg.resolve(key, "sig", approver=None)
    assert r.outcome == ConfirmationOutcome.REJECTED and not r.approved


def test_none_approval_rejects():
    reg, key = _reg_with_esc()
    assert reg.resolve(key, None, approver=approver_ok).outcome == ConfirmationOutcome.REJECTED


def test_approver_error_rejects():
    reg, key = _reg_with_esc()
    assert reg.resolve(key, "sig", approver=approver_boom).outcome == ConfirmationOutcome.REJECTED


def test_non_true_verdict_rejects():
    reg, key = _reg_with_esc()
    assert reg.resolve(key, "sig", approver=approver_no).outcome == ConfirmationOutcome.REJECTED
    # a truthy-but-not-True approved must NOT pass (is-True check)
    reg2, key2 = _reg_with_esc()
    assert reg2.resolve(key2, "sig", approver=lambda s, e: _Appr(1)).outcome == ConfirmationOutcome.REJECTED


def test_valid_signed_approval_approves():
    reg, key = _reg_with_esc()
    r = reg.resolve(key, "sig", approver=approver_ok)
    assert r.outcome == ConfirmationOutcome.APPROVED and r.approved is True


def test_resolution_is_final_append_only():
    reg, key = _reg_with_esc()
    assert reg.reject(key, "operator declined").outcome == ConfirmationOutcome.REJECTED
    # a later signed approval can NOT flip a recorded rejection (append-only, replay-safe)
    r = reg.resolve(key, "sig", approver=approver_ok)
    assert r.outcome == ConfirmationOutcome.REJECTED and not r.approved


def test_unknown_key_rejects():
    reg = ConfirmationRegistry()
    assert reg.resolve(("x", "y", 9), "sig", approver=approver_ok).outcome == ConfirmationOutcome.REJECTED


def test_expire_auto_rejects_past_deadline():
    reg, key = _reg_with_esc(seq=1)   # deadline = 1 + 600 = 601
    assert reg.expire(key, seq=100) is None            # not yet past
    r = reg.expire(key, seq=602)
    assert r is not None and r.outcome == ConfirmationOutcome.EXPIRED and not r.approved


def test_resolve_past_deadline_expires_not_approves():
    reg, key = _reg_with_esc(seq=1)
    r = reg.resolve(key, "sig", approver=approver_ok, seq=602)   # a late signature can't win
    assert r.outcome == ConfirmationOutcome.EXPIRED and not r.approved


def test_sweep_and_drop_wave():
    reg = ConfirmationRegistry()
    reg.register(EscalationRequest(wave_id="w", member_id="a", tool_name="sqlmap", seq=1))
    reg.register(EscalationRequest(wave_id="w", member_id="b", tool_name="hydra", seq=2))
    swept = reg.sweep(9999)
    assert len(swept) == 2 and all(s.outcome == ConfirmationOutcome.EXPIRED for s in swept)
    reg2 = ConfirmationRegistry()
    reg2.register(EscalationRequest(wave_id="w", member_id="c", tool_name="sqlmap", seq=3))
    dropped = reg2.drop_wave("w")
    assert dropped == [("w", "c", 3)]
    assert reg2.resolution(("w", "c", 3)).outcome == ConfirmationOutcome.REJECTED


def test_registry_emits_events_to_spine_redacted():
    writes = []
    q = SingleWriterSpineQueue(lambda rec: (writes.append(rec), "r1")[1])
    reg = ConfirmationRegistry(spine=q)
    reg.register(EscalationRequest(wave_id="w", member_id="m", tool_name="sqlmap", seq=1))
    reg.resolve(("w", "m", 1), "sig", approver=approver_ok)
    q.flush()
    events = [w["kind"] for w in writes]
    assert "confirmation.register" in events and "confirmation.approved" in events


# --- single-writer spine queue ------------------------------------------------------------------

def test_flush_orders_deterministically():
    writes = []
    q = SingleWriterSpineQueue(lambda rec: (writes.append((rec["seq"], rec["member_id"], rec["kind"])),
                                            f"r{len(writes)}")[1])
    q.submit(member_id="b", seq=2, kind="x", record={})
    q.submit(member_id="a", seq=2, kind="x", record={})
    q.submit(member_id="a", seq=1, kind="x", record={})
    refs = q.flush()
    assert writes == [(1, "a", "x"), (2, "a", "x"), (2, "b", "x")]
    assert len(refs) == 3


def test_spine_write_redacts_secrets():
    seen = []
    q = SingleWriterSpineQueue(lambda rec: (seen.append(rec), "r1")[1])
    q.submit(member_id="m", seq=1, kind="tool", record={"secret_token": "LEAKVALUE", "url": "http://t"})
    q.flush()
    assert "LEAKVALUE" not in str(seen[0]) and seen[0]["url"] == "http://t"


def test_writer_error_is_isolated():
    def bad(rec):
        if rec["member_id"] == "b":
            raise RuntimeError("boom")
        return f"r-{rec['member_id']}"
    q = SingleWriterSpineQueue(bad)
    for mid, s in (("a", 1), ("b", 2), ("c", 3)):
        q.submit(member_id=mid, seq=s, kind="x", record={})
    assert q.flush() == ["r-a", "r-c"]   # the failing write is skipped; the chain is intact


def test_no_writer_writes_nothing():
    q = SingleWriterSpineQueue(None)
    q.submit(member_id="a", seq=1, kind="x", record={})
    assert q.flush() == []


def test_async_single_writer_serializes_concurrent_writes():
    log = []

    async def async_writer(rec):
        log.append(("enter", rec["member_id"]))
        await asyncio.sleep(0)   # an UNGUARDED writer would let another member interleave here
        log.append(("exit", rec["member_id"]))
        return f"r-{rec['member_id']}-{rec['seq']}"

    q = SingleWriterSpineQueue(async_writer)

    async def worker(mid):
        for k in range(3):
            await q.write(member_id=mid, seq=k, kind="w", record={"k": k})

    async def run():
        await asyncio.gather(worker("a"), worker("b"), worker("c"))

    asyncio.run(run())
    # every enter is immediately followed by its OWN exit ⇒ no two writes overlapped
    assert len(log) == 18
    for i in range(0, len(log), 2):
        assert log[i][0] == "enter" and log[i + 1] == ("exit", log[i][1])
    assert len(q.refs) == 9


# --- collect (fan-in): leads only, oracle mints facts -------------------------------------------

def test_collect_member_findings_are_leads():
    mr = MemberResult(member_id="m", leads=[Finding(ref="f1", title="sqli", severity="high")])
    out = collect([mr], oracle=None)
    assert out.facts == [] and len(out.leads) == 1
    assert out.leads[0].status == "lead" and out.leads[0].source == "fireteam:m"


def test_collect_downgrades_member_forged_fact():
    forged = Finding(ref="rce", status="fact", evidence_ref="spine:forged")   # constructible, but a lie
    out = collect([MemberResult(member_id="m", leads=[forged])], oracle=None)
    assert out.facts == []
    assert out.leads[0].status == "lead" and out.leads[0].evidence_ref == ""


def test_collect_promotes_only_oracle_confirmed():
    claim = MemberFindingClaim(raw_output="pwned", analysis=OutputAnalysis(exploit_succeeded=True))
    mr = MemberResult(member_id="m", claims=[claim])
    # no oracle wired → nothing is promoted (fail-closed)
    out = collect([mr], oracle=None)
    assert out.facts == [] and any("UNCONFIRMED" in lead.title for lead in out.leads)
    # oracle confirms → a signed FACT
    out2 = collect([mr], oracle=oracle_confirm)
    assert len(out2.facts) == 1 and out2.facts[0].status == "fact"
    assert out2.facts[0].evidence_ref == "spine:confirmed-hash"


def test_collect_total_on_garbage():
    out = collect(["not a result", 42, None, MemberResult(member_id="ok")], oracle=None)
    assert out.facts == [] and out.leads == []


# --- orchestrator -------------------------------------------------------------------------------

def test_run_fireteam_refuses_malformed_plan():
    out = asyncio.run(run_fireteam({"wave_id": "w", "members": [{"member_id": "a", "capped_tier": "A3"}]},
                                   lambda m, c: MemberResult(member_id="a")))
    assert out.refused and out.member_results == []


def test_run_fireteam_runs_members_and_rolls_up():
    def runner(member, ctx):
        if ctx.spine is not None:
            ctx.spine.submit(member_id=member.member_id, seq=ctx.seq, kind="step", record={"ok": 1})
        return MemberResult(member_id=member.member_id, leads=[Finding(ref=f"f-{member.member_id}")])

    q = SingleWriterSpineQueue(lambda rec: f"ref-{rec['member_id']}-{rec['seq']}")
    plan = {"wave_id": "wv", "members": [{"member_id": "a", "tools": ["nmap"]},
                                         {"member_id": "b", "tools": ["dirb"]}]}
    out = asyncio.run(run_fireteam(plan, runner, spine=q))
    assert not out.refused and len(out.member_results) == 2
    assert len(out.leads) == 2 and out.facts == [] and len(out.spine_refs) == 2


def test_run_fireteam_isolates_member_crash():
    def runner(member, ctx):
        if member.member_id == "b":
            raise RuntimeError("member boom")
        return MemberResult(member_id=member.member_id)

    out = asyncio.run(run_fireteam({"wave_id": "wv", "members": [{"member_id": "a"}, {"member_id": "b"}]},
                                   runner))
    statuses = {r.member_id: r.status for r in out.member_results}
    assert statuses["a"] != MemberStatus.ERROR and statuses["b"] == MemberStatus.ERROR


def test_run_fireteam_registers_escalations_pending():
    reg = ConfirmationRegistry()

    def runner(member, ctx):
        esc = EscalationRequest(wave_id="wv", member_id=member.member_id, tool_name="sqlmap",
                                requested_tier="A3", seq=ctx.seq)
        return MemberResult(member_id=member.member_id, escalations=[esc],
                            status=MemberStatus.NEEDS_CONFIRMATION)

    out = asyncio.run(run_fireteam({"wave_id": "wv", "members": [{"member_id": "a"}]}, runner, registry=reg))
    assert len(out.escalations) == 1 and len(reg.pending_keys()) == 1
    assert reg.resolution(reg.pending_keys()[0]) is None   # still pending — no signed approval yet


def test_run_fireteam_is_deterministic():
    def runner(member, ctx):
        ctx.spine.submit(member_id=member.member_id, seq=ctx.seq, kind="s", record={})
        return MemberResult(member_id=member.member_id)

    plan = {"wave_id": "wv", "members": [{"member_id": "a"}, {"member_id": "b"}, {"member_id": "c"}]}

    def go():
        order = []
        q = SingleWriterSpineQueue(lambda rec: (order.append((rec["seq"], rec["member_id"])),
                                                f"r{len(order)}")[1])
        out = asyncio.run(run_fireteam(plan, runner, spine=q, seq_start=0))
        return out.spine_refs, order

    assert go() == go()


# --- THE adversarial sovereign-invariant test ---------------------------------------------------

def test_ADVERSARIAL_sovereign_invariant_member_cannot_break_out():
    """RED-PEN target. Even with a fully permissive gate and no oracle, this package alone must stop a
    rogue member from: (1) escalating its own tier, (2) self-authorizing a dangerous tool, (3)
    deploy_fireteam / transition_phase / crossing egress, (4) forging a fact — and it must serialize
    parallel spine writes and refuse a malformed plan."""

    # (1) tier self-escalation: A1-capped member in an A2 phase → QUEUE, never run, despite allow_gate.
    m = FireteamMember(spec=FireteamMemberSpec(member_id="rogue", capped_tier="A1", tools=["nmap"], credit=9),
                       wave_id="w", phase=Phase.EXPLOITATION,
                       budget=MemberBudget(credit_remaining=9, deadline_seq=9999))
    over = authorize_member_edge(m, _use("nmap"), gate=allow_gate, seq=1)
    assert over.outcome == "queue" and over.allowed is False and over.escalation is not None

    # (2) dangerous-tool self-authorization, even lying that it is non-destructive → still QUEUE.
    dang = authorize_member_edge(
        m, LLMDecision(action=ActionType.USE_TOOL,
                       tool=ToolCall(tool_name="mimikatz", tool_args={"target": "t"}, destructive=False)),
        gate=allow_gate, seq=2)
    assert dang.outcome == "queue" and dang.allowed is False

    # (2b) the escalation resolves ONLY via a signed operator approval; auto/none all fail closed.
    reg = ConfirmationRegistry()
    key_no_sig = reg.register(dang.escalation)
    assert reg.resolve(key_no_sig, None, approver=approver_ok).outcome == ConfirmationOutcome.REJECTED
    key_signed = reg.register(EscalationRequest(wave_id="w", member_id="rogue", tool_name="mimikatz",
                                                requested_tier="A3", seq=99))
    assert reg.resolve(key_signed, "operator-signature", approver=approver_ok).approved is True

    # (3) forbidden actions are structurally stripped; a member deploy never reaches the gate.
    for act in (ActionType.DEPLOY_FIRETEAM, ActionType.TRANSITION_PHASE):
        safe, reason = _strip_forbidden_actions(LLMDecision(action=act, target_phase=Phase.POST_EXPLOITATION))
        assert safe.action == ActionType.COMPLETE and reason
    egress, _ = _strip_forbidden_actions(_use("open_egress"))
    assert egress.action == ActionType.COMPLETE
    deploy_v = authorize_member_edge(
        m, LLMDecision(action=ActionType.DEPLOY_FIRETEAM, fireteam=[{"member_id": "x"}]),
        gate=allow_gate, seq=5)
    assert deploy_v.outcome == "allow" and deploy_v.tier == "A0"   # neutralized to inert; touches nothing

    # (4) a member-forged fact is downgraded to a lead; with no oracle nothing becomes true.
    forged = Finding(ref="rce", status="fact", evidence_ref="spine:forged")
    out = collect([MemberResult(member_id="rogue", leads=[forged],
                                claims=[MemberFindingClaim(raw_output="x",
                                                           analysis=OutputAnalysis(exploit_succeeded=True))])],
                  oracle=None)
    assert out.facts == []
    assert all(f.status == "lead" and f.evidence_ref == "" for f in out.leads)

    # (5) parallel members serialize spine writes — no interleave, secrets redacted.
    log = []
    seen = []

    async def async_writer(rec):
        log.append(("enter", rec["member_id"]))
        await asyncio.sleep(0)
        seen.append(rec)
        log.append(("exit", rec["member_id"]))
        return f"r-{rec['member_id']}-{rec['seq']}"

    q = SingleWriterSpineQueue(async_writer)

    async def worker(mid):
        for k in range(4):
            await q.write(member_id=mid, seq=k, kind="w", record={"secret_token": "LEAKVALUE", "k": k})

    async def run_all():
        await asyncio.gather(worker("a"), worker("b"), worker("c"))

    asyncio.run(run_all())
    for i in range(0, len(log), 2):
        assert log[i][0] == "enter" and log[i + 1] == ("exit", log[i][1])
    assert len(q.refs) == 12
    assert all("LEAKVALUE" not in str(rec) for rec in seen)   # no credential reached the spine

    # (6) a malformed / A3-capped plan is refused — nothing spawns.
    refused = asyncio.run(run_fireteam(
        {"wave_id": "w", "members": [{"member_id": "a", "capped_tier": "A3"}]},
        lambda mm, cc: MemberResult(member_id="a")))
    assert refused.refused and refused.member_results == []
