"""SIGIL Phase 6 — Hardening (post red-pen): AUTHENTICATED governance — a forged promotion grants
nothing, a forged/unsigned kill-release cannot revive the mesh, a forged/replayed approval cannot
drop a queued item, and every A2/A3 approval needs the trusted OWNER key. Plus self-audit (incl.
denials), the read-only dashboard, and the SSRF gate with IP pinning.
Run: ~/.sigil/venv/bin/python tests/test_hardening.py

The acceptance bar is "zero unauthorized A2/A3 in the audit log": these prove the gate is airtight and
governance events are owner-signed, so an A2-auto log line PROVES a real owner promotion."""
import tempfile
from pathlib import Path

from sigil.agents.base import Agent, Proposal, Tier
from sigil.governor import BudgetCaps, Governor, KillSwitch, PromotionPolicy
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()                 # the established owner identity for these tests
OWNER_PUB = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _gov(store, *, caps=None):
    return Governor(store, caps=caps, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


class _Emitter(Agent):
    name = "TESTER"
    ceiling = Tier.A2

    def __init__(self, store, *, caps=None):
        super().__init__(store, governor=_gov(store, caps=caps))

    def run(self, tier, kind="event"):
        return self._dispatch([Proposal(kind, {"subject": "x"}, tier)])


# ---- kill switch: any engage halts; only a SIGNED release restores -------------------------------
def test_killswitch_halts_and_only_signed_release_restores():
    s = _store()
    KillSwitch(s, owner_key=OWNER).engage(reason="drill")
    t = _Emitter(s)
    assert t.run(Tier.A0).applied, "A0 observe stays alive under the kill switch"
    assert not t.run(Tier.A1).applied, "A1 agent action is halted"
    # a FORGED (unsigned) release must NOT revive the mesh
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={"signal": "governor.killswitch", "state": "released"})
    assert not t.run(Tier.A1).applied, "an unsigned release cannot un-halt the mesh (fail-closed)"
    KillSwitch(s, owner_key=OWNER).release()
    assert t.run(Tier.A1).applied, "an OWNER-SIGNED release restores the mesh"


# ---- budgets -------------------------------------------------------------------------------------
def test_budget_denies_beyond_daily_cap_fail_closed():
    s = _store()
    t = _Emitter(s, caps=BudgetCaps(daily_actions=2))
    assert t.run(Tier.A1).applied and t.run(Tier.A1).applied
    r3 = t.run(Tier.A1)
    assert not r3.applied and any("cap" in n for n in r3.notes), "the 3rd action hits the cap → denied"


def test_budget_uncapped_by_default():
    s = _store()
    t = _Emitter(s)
    for _ in range(6):
        assert t.run(Tier.A1).applied, "no configured cap ⇒ unthrottled (backward compatible)"


# ---- promotion: signed grant auto-approves its KIND; forged grants do nothing ---------------------
def test_a2_queues_unless_promoted_for_kind():
    s = _store()
    t = _Emitter(s)
    assert t.run(Tier.A2, kind="draft").queued, "unpromoted A2 queues"
    PromotionPolicy(s, owner_key=OWNER).grant("TESTER", "draft")     # owner-signed grant
    assert t.run(Tier.A2, kind="draft").applied, "a signed promotion auto-approves that kind's A2"
    assert t.run(Tier.A2, kind="event").queued, "a different kind still queues (scope bound to kind)"


def test_a3_never_auto_even_when_promoted():
    s = _store()
    t = _Emitter(s)
    PromotionPolicy(s, owner_key=OWNER).grant("TESTER", "wire")
    assert t.run(Tier.A3, kind="wire").queued, "A3 has no promotion path — always queues"


def test_forged_promotion_grants_nothing():
    s = _store()
    t = _Emitter(s)
    # unsigned forged grant (what a prompt-injected agent with store access could write)
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={"signal": "governor.promotion", "state": "granted", "agent": "TESTER", "scope": "draft"})
    assert t.run(Tier.A2, kind="draft").queued, "an unsigned/forged grant auto-approves nothing"
    # grant signed by a NON-owner key also grants nothing
    attacker = generate_keypair()
    s.append(kind="event", source="governor", actor="WARDEN",
             payload=signed_payload({"signal": "governor.promotion", "state": "granted",
                                     "agent": "TESTER", "scope": "draft"}, attacker))
    assert t.run(Tier.A2, kind="draft").queued, "a non-owner-signed grant auto-approves nothing"


def test_envoy_has_no_promotion_path():
    s = _store()
    assert PromotionPolicy(s, owner_key=OWNER).grant("ENVOY", "*") is None, "promoting ENVOY is refused"
    # even a genuinely OWNER-SIGNED grant cannot promote ENVOY — the exclusion is structural
    s.append(kind="event", source="governor", actor="WARDEN",
             payload=signed_payload({"signal": "governor.promotion", "state": "granted",
                                     "agent": "ENVOY", "scope": "*"}, OWNER))
    assert PromotionPolicy(s, trusted_pubkey=OWNER_PUB).is_promoted("ENVOY", "*") is False


# ---- self-audit (C18) incl. denials --------------------------------------------------------------
def test_self_audit_reconstructs_including_denials():
    from sigil.audit import render_audit, self_audit
    s = _store()
    t = _Emitter(s)
    KillSwitch(s, owner_key=OWNER).engage()
    t.run(Tier.A3, kind="wire")                       # DENIED under the kill switch
    KillSwitch(s, owner_key=OWNER).release()
    t.run(Tier.A1, kind="event")                      # auto
    rows = self_audit(s, agent="TESTER")
    decs = {r["decision"] for r in rows}
    assert "denied" in decs and "auto" in decs, "the audit must show BLOCKED attempts, not just successes"
    assert any(r["decision"] == "denied" and r["tier"] == "A3" for r in rows), "the blocked A3 is on record"
    assert "TESTER" in render_audit(rows, agent="TESTER")


# ---- signed approval queue: verify on the enforcement path ---------------------------------------
def test_approval_signed_and_supersedes_the_queue():
    from sigil.agents.approvals import ApprovalQueue, pending, verify_approval
    s = _store()
    _Emitter(s).run(Tier.A2, kind="draft")
    pend = pending(s, OWNER_PUB)
    assert len(pend) == 1
    seq = ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OWNER_PUB).approve(pend[0].seq)
    assert not pending(s, OWNER_PUB), "a verified approval removes the item"
    assert verify_approval(s.get(seq), OWNER_PUB) is True


def test_forged_approval_leaves_item_pending():
    from sigil.agents.approvals import pending
    s = _store()
    _Emitter(s).run(Tier.A3, kind="wire")
    tgt = pending(s, OWNER_PUB)[0].seq
    # a completely forged, unsigned approval superseding the queued A3
    s.append(kind="event", source="governor", actor="OWNER", supersedes_id=tgt,
             payload={"signal": "governor.approval", "approval": "approved", "target_seq": tgt,
                      "approver": "owner", "sig": None, "pubkey": None})
    assert len(pending(s, OWNER_PUB)) == 1, "an UNVERIFIED approval must NOT drop the item from the queue"


def test_replayed_approval_does_not_resolve_another_item():
    from sigil.agents.approvals import ApprovalQueue, pending
    s = _store()
    _Emitter(s).run(Tier.A2, kind="draft")            # harmless
    _Emitter(s).run(Tier.A3, kind="wire")             # dangerous
    pend = pending(s, OWNER_PUB)
    harmless, dangerous = pend[0].seq, pend[1].seq
    approved = ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OWNER_PUB).approve(harmless)
    genuine = s.get(approved).payload
    # attacker copies the genuine signed approval onto a record that "supersedes" the dangerous seq
    s.append(kind="event", source="governor", actor="OWNER", supersedes_id=dangerous, payload=dict(genuine))
    still = [r.seq for r in pending(s, OWNER_PUB)]
    assert dangerous in still, "a replayed approval (signed for another seq) must not resolve the dangerous item"
    assert harmless not in still, "the genuine approval resolved its own item"


def test_a3_approval_requires_the_trusted_owner_key():
    from sigil.agents.approvals import ApprovalError, ApprovalQueue, pending
    s = _store()
    _Emitter(s).run(Tier.A3, kind="wire")
    tgt = pending(s, OWNER_PUB)[0].seq
    attacker = generate_keypair()
    q = ApprovalQueue(s, owner_key=attacker, trusted_pubkey_b64=OWNER_PUB)   # wrong signing key
    try:
        q.approve(tgt)
        assert False, "an attacker key must not approve against the owner's trusted key"
    except ApprovalError:
        pass


# ---- dashboard (read-only) -----------------------------------------------------------------------
def test_dashboard_is_read_only_and_counts_only_real_actions():
    from sigil.dashboard import render_dashboard, snapshot
    s = _store()
    t = _Emitter(s)
    t.run(Tier.A1)
    KillSwitch(s, owner_key=OWNER).engage()
    t.run(Tier.A2, kind="draft")     # DENIED (kill engaged) → must NOT inflate budget usage
    before = s.count()
    snap = snapshot(s)
    assert s.count() == before, "the dashboard writes NOTHING to the spine"
    assert snap["kill_switch"] == "ENGAGED"
    assert snap["budget_today"].get("TESTER", {}).get("actions") == 1, "denied attempts don't count as actions"
    assert "Kill switch" in render_dashboard(snap)


# ---- SSRF gate: IPv6/mapped/notation + IP pinning ------------------------------------------------
def test_ssrf_gate_blocks_internal_including_ipv6():
    from sigil.agents.sources import is_public_host, read_source
    for internal in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "localhost",
                     "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0"):
        assert is_public_host(internal) is False, f"{internal} must be refused"
    assert is_public_host("8.8.8.8") is True
    assert read_source("http://127.0.0.1:9/secret") == "", "a loopback URL is refused before any request"
    p = tempfile.mktemp(suffix=".txt")
    Path(p).write_text("hello world")
    assert "hello" in read_source(p), "a local file still reads"


def test_ssrf_pins_the_vetted_ip_not_a_reresolve():
    import sigil.agents.sources as src
    calls = []
    orig_cc = src.socket.create_connection
    orig_vet = src._vetted_ip
    src._vetted_ip = lambda host: "203.0.113.9"      # gate sees a public IP

    def spy(addr, *a, **k):
        calls.append(addr)
        raise OSError("blocked in test")             # don't actually connect out

    src.socket.create_connection = spy
    try:
        assert src.read_source("http://rebind.example/x") == ""
    finally:
        src.socket.create_connection = orig_cc
        src._vetted_ip = orig_vet
    assert calls and calls[0][0] == "203.0.113.9", "the socket is pinned to the vetted IP, not re-resolved"


# ---- doctrine + integrity ------------------------------------------------------------------------
def test_governance_imports_are_offense_free():
    import sigil.audit  # noqa: F401
    import sigil.dashboard  # noqa: F401
    import sigil.governor  # noqa: F401
    from sigil.agents import approvals  # noqa: F401


def test_spine_integrity_after_governance_writes():
    from sigil.agents.approvals import ApprovalQueue, pending
    s = _store()
    t = _Emitter(s)
    KillSwitch(s, owner_key=OWNER).engage(); t.run(Tier.A1)
    KillSwitch(s, owner_key=OWNER).release(); t.run(Tier.A1)
    PromotionPolicy(s, owner_key=OWNER).grant("TESTER", "draft")
    t.run(Tier.A2, kind="event")
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OWNER_PUB).approve(pending(s, OWNER_PUB)[0].seq)
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
