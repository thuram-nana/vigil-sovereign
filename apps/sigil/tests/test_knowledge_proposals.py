"""K2b — the sovereign propose→queue→accept loop (`sigil.knowledge` + the `queue_learn` action).

Doctrine under test:
  * ENQUEUING grants nothing — a learn-proposal is a plain awaiting-approval item; the owner-signed
    `ApprovalQueue.approve` (unchanged) is the sole trust op, and accepting authorises LEARNING, not a fact;
  * IDEMPOTENT — a vuln already awaiting approval is never re-queued;
  * FAIL-CLOSED — `queue_learn` is refused when the kill-switch is engaged OR autolearn is disabled;
  * the dashboard surfaces pending learn-proposals as a structured subset of the approval queue.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_knowledge_proposals.py -q
"""

import tempfile

import pytest

from sigil.dashboard import snapshot
from sigil.governor import CapabilityGate, KillSwitch
from sigil.knowledge import enqueue_learn_proposal, pending_learn_proposals
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import actions

OWNER = generate_keypair()

_PROP = {"vuln_id": "CVE-2024-0001", "rank": 1, "exploit_known": True,
         "severity": "CRITICAL", "rationale": "known-exploited"}


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


@pytest.fixture
def owner(monkeypatch):
    # point every identity reader at the test key (ApprovalQueue/pending re-import these inside __init__),
    # so the owner-signed approve verifies without a persisted keyring/vault.
    import sigil.governor.identity as idmod
    monkeypatch.setattr(idmod, "ensure_owner_keypair", lambda: OWNER)
    monkeypatch.setattr(idmod, "owner_keypair", lambda: OWNER)
    monkeypatch.setattr(idmod, "owner_pubkey", lambda: OWNER.public_key_b64)
    return OWNER


# ---- enqueue: idempotent, grants nothing -----------------------------------

def test_enqueue_is_idempotent_by_vuln_id():
    s = _store()
    seq1 = enqueue_learn_proposal(s, _PROP)
    seq2 = enqueue_learn_proposal(s, dict(_PROP, rank=9))   # same vuln_id → no new record
    assert seq1 == seq2
    pend = pending_learn_proposals(s)
    assert [p["vuln_id"] for p in pend] == ["CVE-2024-0001"] and len(pend) == 1


def test_enqueue_requires_a_vuln_id():
    with pytest.raises(ValueError, match="vuln_id"):
        enqueue_learn_proposal(_store(), {"rank": 1})


def test_enqueue_bounds_operator_typed_vuln_id():
    # K4 manual-add feeds an operator-typed vuln_id into the spine — bound its length (like rationale[:500]).
    s = _store()
    enqueue_learn_proposal(s, {"vuln_id": "CVE-" + "9" * 500})
    assert len(pending_learn_proposals(s)[0]["vuln_id"]) <= 120


def test_enqueue_queue_depth_is_bounded(monkeypatch):
    import sigil.knowledge.proposals as kp
    monkeypatch.setattr(kp, "_MAX_PENDING", 3)
    s = _store()
    for i in range(3):
        kp.enqueue_learn_proposal(s, {"vuln_id": f"CVE-{i}"})
    with pytest.raises(ValueError, match="full"):
        kp.enqueue_learn_proposal(s, {"vuln_id": "CVE-OVERFLOW"})     # a distinct-vuln flood is refused
    # an already-pending vuln stays idempotent — the cap never blocks a re-queue of an existing item.
    assert kp.enqueue_learn_proposal(s, {"vuln_id": "CVE-0"}) is not None


def test_forged_or_replayed_approval_cannot_resolve_a_learn_proposal(owner):
    # ACCEPT is the unchanged owner-signed ApprovalQueue; prove here (not just in its own suite) that NO
    # unsigned / non-owner / replayed approval resolves a learn-proposal — only a genuine owner signature.
    from sigil.agents.approvals import _approval_message
    from sigil.reuse import sign

    s = _store()
    seq = actions.do_action("queue_learn", _PROP, store=s)["recorded_seq"]

    # (1) unsigned approval of the learn-proposal
    s.append(kind="event", source="governor", actor="ATTACKER",
             payload={"signal": "governor.approval", "approval": "approved", "target_seq": seq,
                      "approver": "attacker", "tier": "A0", "decision": "auto"})
    assert [p["vuln_id"] for p in pending_learn_proposals(s)] == ["CVE-2024-0001"]   # still pending

    # (2) approval signed by a NON-owner key
    att = generate_keypair()
    msg = _approval_message(seq, "approved", "attacker")
    s.append(kind="event", source="governor", actor="ATTACKER",
             payload={"signal": "governor.approval", "approval": "approved", "target_seq": seq,
                      "approver": "attacker", "pubkey": att.public_key_b64,
                      "sig": sign(att.private_key_b64, msg), "tier": "A0", "decision": "auto"})
    assert [p["vuln_id"] for p in pending_learn_proposals(s)] == ["CVE-2024-0001"]   # still pending

    # (3) the genuine owner approve is the ONLY thing that resolves it
    actions.do_action("approve", {"seq": seq, "reason": "accept"}, store=s)
    assert pending_learn_proposals(s) == []


# ---- the queue_learn action: fail-closed gating ----------------------------

def test_queue_learn_happy_path_and_accept_resolves(owner):
    s = _store()
    r = actions.do_action("queue_learn", _PROP, store=s)
    assert r["ok"] and r["vuln_id"] == "CVE-2024-0001"
    seq = r["recorded_seq"]
    assert [p["vuln_id"] for p in pending_learn_proposals(s)] == ["CVE-2024-0001"]
    # ACCEPT via the existing owner-signed approve resolves it (no new authority path).
    actions.do_action("approve", {"seq": seq, "reason": "accept"}, store=s)
    assert pending_learn_proposals(s) == []


def test_queue_learn_refused_when_killswitch_engaged(owner):
    s = _store()
    KillSwitch(s, owner_key=OWNER).engage(reason="stop")
    with pytest.raises(ValueError, match="kill-switch"):
        actions.do_action("queue_learn", _PROP, store=s)
    assert pending_learn_proposals(s) == []                 # nothing enqueued


def test_queue_learn_refused_when_autolearn_disabled(owner):
    s = _store()
    CapabilityGate(s, owner_key=OWNER).disable("autolearn", reason="off")
    with pytest.raises(ValueError, match="autolearn"):
        actions.do_action("queue_learn", _PROP, store=s)
    assert pending_learn_proposals(s) == []


# ---- dashboard read plane --------------------------------------------------

def test_dashboard_surfaces_pending_learn_proposals(owner):
    s = _store()
    actions.do_action("queue_learn", _PROP, store=s)
    snap = snapshot(s)
    assert "learn_proposals" in snap
    lp = snap["learn_proposals"]
    assert len(lp) == 1 and lp[0]["vuln_id"] == "CVE-2024-0001" and lp[0]["exploit_known"] is True
    # a learn-proposal is ALSO an ordinary pending approval (owner can accept it from Safety too).
    assert any(a["seq"] == lp[0]["seq"] for a in snap["pending_approvals"])
