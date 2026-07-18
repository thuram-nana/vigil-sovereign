"""SIGIL Phase 6 — Hardening: the governor (kill switch / budgets / promotion), self-audit (C18),
the signed approval queue, the read-only dashboard, and the SCHOLAR SSRF gate.
Run: ~/.sigil/venv/bin/python tests/test_hardening.py

The acceptance bar is "zero unauthorized A2/A3 in the audit log": these tests prove the gate is
airtight — A2 never auto-runs without an explicit promotion, ENVOY never promotes, A3 needs a signed
confirmation, a kill halts the mesh, and every decision is reconstructable from the log."""
import tempfile
from pathlib import Path

from sigil.agents.base import Agent, Proposal, Tier
from sigil.governor import BudgetCaps, Governor, KillSwitch, PromotionPolicy
from sigil.spine.store import SpineStore


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class _Emitter(Agent):
    name = "TESTER"
    ceiling = Tier.A2

    def run(self, tier, scope=None):
        return self._dispatch([Proposal("event", {"subject": "x"}, tier, scope=scope)])


# ---- kill switch ---------------------------------------------------------------------------------
def test_killswitch_halts_mesh_but_keeps_observe_alive():
    s = _store()
    KillSwitch(s).engage(reason="drill")
    t = _Emitter(s)
    assert t.run(Tier.A0).applied, "A0 observe stays alive under the kill switch"
    r1 = t.run(Tier.A1)
    assert not r1.applied and not r1.queued, "A1 agent action is halted"
    assert any("DENIED" in n for n in r1.notes)
    assert any(x.kind == "refusal" and x.payload.get("decision") == "denied" for x in s.iter_records())
    KillSwitch(s).release()
    assert t.run(Tier.A1).applied, "release restores the mesh"


# ---- budgets -------------------------------------------------------------------------------------
def test_budget_denies_beyond_daily_cap_fail_closed():
    s = _store()
    t = _Emitter(s)
    t.governor = Governor(s, caps=BudgetCaps(daily_actions=2))
    assert t.run(Tier.A1).applied
    assert t.run(Tier.A1).applied
    r3 = t.run(Tier.A1)
    assert not r3.applied and any("cap" in n for n in r3.notes), "the 3rd action hits the cap → denied"


def test_budget_uncapped_by_default():
    s = _store()
    t = _Emitter(s)   # default governor = no caps
    for _ in range(6):
        assert t.run(Tier.A1).applied, "with no configured cap the mesh is unthrottled (backward compatible)"


# ---- promotion policy ----------------------------------------------------------------------------
def test_a2_queues_unless_promoted_for_scope():
    s = _store()
    t = _Emitter(s)
    assert t.run(Tier.A2, scope="calendar").queued, "unpromoted A2 queues for approval"
    PromotionPolicy(s).grant("TESTER", "calendar")
    r = t.run(Tier.A2, scope="calendar")
    assert r.applied and not r.queued, "a per-scope promotion auto-approves that scope's A2"
    assert t.run(Tier.A2, scope="email").queued, "an unpromoted scope still queues"


def test_a3_never_auto_even_when_promoted():
    s = _store()
    t = _Emitter(s)
    PromotionPolicy(s).grant("TESTER", "*")            # promote everything…
    assert t.run(Tier.A3, scope="anything").queued, "…A3 still queues — no promotion path for A3"


def test_envoy_has_no_promotion_path():
    s = _store()
    assert PromotionPolicy(s).grant("ENVOY", "*") is None, "promoting ENVOY is refused, not granted"
    refusal = [r for r in s.iter_records() if r.kind == "refusal" and r.payload.get("agent") == "ENVOY"]
    assert refusal, "the refusal is logged"
    # even a FORGED 'granted' event cannot promote ENVOY — the exclusion is structural
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={"signal": "governor.promotion", "state": "granted", "agent": "ENVOY", "scope": "*"})
    assert PromotionPolicy(s).is_promoted("ENVOY", "*") is False


# ---- self-audit (C18) ----------------------------------------------------------------------------
def test_self_audit_reconstructs_actions_with_why():
    from sigil.audit import render_audit, self_audit
    s = _store()
    t = _Emitter(s)
    t.run(Tier.A1)
    t.run(Tier.A2, scope="x")
    rows = self_audit(s, agent="TESTER")
    assert len(rows) == 2 and {r["decision"] for r in rows} == {"auto", "queued"}
    assert all(r["seq"] is not None and r["why"] for r in rows), "each action is cited + reasoned"
    assert "TESTER" in render_audit(rows, agent="TESTER")


# ---- signed approval queue -----------------------------------------------------------------------
def test_approval_signed_and_supersedes_the_queue():
    from sigil.agents.approvals import ApprovalQueue, pending, verify_approval
    from sigil.reuse import generate_keypair
    s = _store()
    _Emitter(s).run(Tier.A2, scope="x")
    pend = pending(s)
    assert len(pend) == 1
    kp = generate_keypair()
    seq = ApprovalQueue(s, owner_key=kp).approve(pend[0].seq, approver="owner")
    assert not pending(s), "an approved item leaves the queue"
    assert verify_approval(s.get(seq), kp.public_key_b64) is True, "the approval carries a valid owner signature"


def test_a3_approval_requires_signed_confirmation():
    from sigil.agents.approvals import ApprovalError, ApprovalQueue, pending
    s = _store()
    _Emitter(s).run(Tier.A3, scope="x")   # A3 queues (above ceiling / no promotion)
    q = ApprovalQueue(s, owner_key=None)   # no owner key
    try:
        q.approve(pending(s)[0].seq)
        assert False, "A3 must not be approvable without a signed confirmation"
    except ApprovalError:
        pass


def test_forged_approval_does_not_verify_against_owner():
    from sigil.agents.approvals import ApprovalQueue, pending, verify_approval
    from sigil.reuse import generate_keypair
    s = _store()
    _Emitter(s).run(Tier.A2, scope="x")
    attacker, owner = generate_keypair(), generate_keypair()
    seq = ApprovalQueue(s, owner_key=attacker).approve(pending(s)[0].seq)   # signed by the wrong key
    assert verify_approval(s.get(seq), owner.public_key_b64) is False, "a non-owner signature fails against the owner key"


# ---- dashboard (read-only) -----------------------------------------------------------------------
def test_dashboard_is_read_only_and_reflects_state():
    from sigil.dashboard import render_dashboard, snapshot
    s = _store()
    t = _Emitter(s)
    t.run(Tier.A1)
    t.run(Tier.A2, scope="x")
    KillSwitch(s).engage()
    before = s.count()
    snap = snapshot(s)
    assert s.count() == before, "the dashboard writes NOTHING to the spine"
    assert snap["kill_switch"] == "ENGAGED" and len(snap["pending_approvals"]) == 1
    txt = render_dashboard(snap)
    assert "Kill switch" in txt and "Pending approvals" in txt


# ---- SCHOLAR SSRF gate ---------------------------------------------------------------------------
def test_scholar_ssrf_gate_blocks_internal_targets():
    from sigil.agents.sources import is_public_host, read_source
    assert is_public_host("127.0.0.1") is False
    assert is_public_host("169.254.169.254") is False   # cloud metadata endpoint
    assert is_public_host("10.0.0.1") is False and is_public_host("192.168.1.1") is False
    assert is_public_host("localhost") is False
    assert is_public_host("8.8.8.8") is True
    assert read_source("http://127.0.0.1:9/secret") == "", "a loopback URL is refused before any request"
    p = tempfile.mktemp(suffix=".txt")
    Path(p).write_text("hello world")
    assert "hello" in read_source(p), "a local file still reads"


# ---- doctrine + integrity ------------------------------------------------------------------------
def test_governance_imports_are_offense_free():
    import sigil.audit  # noqa: F401
    import sigil.dashboard  # noqa: F401
    import sigil.governor  # noqa: F401
    from sigil.agents import approvals  # noqa: F401


def test_spine_integrity_after_governance_writes():
    from sigil.agents.approvals import ApprovalQueue, pending
    from sigil.reuse import generate_keypair
    s = _store()
    t = _Emitter(s)
    KillSwitch(s).engage(); t.run(Tier.A1); KillSwitch(s).release(); t.run(Tier.A1)
    PromotionPolicy(s).grant("TESTER", "x")
    t.run(Tier.A2, scope="y")
    ApprovalQueue(s, owner_key=generate_keypair()).approve(pending(s)[0].seq)
    ok, msg = s.verify()
    assert ok, f"the hash chain must verify after all governance writes: {msg}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-6 (Hardening) guarantees hold")
