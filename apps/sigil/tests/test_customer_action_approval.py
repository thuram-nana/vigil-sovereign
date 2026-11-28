"""The per-action APPROVAL GATE — VIGIL's Allow/Block human-in-the-loop checkpoint before a risky engagement
action (the richer-and-safer sibling of Strix's approval judge). Deterministic, NO-LLM, FATAL-2-clean.

What a false green would hide (each is a test below):
  * risky action PAUSES — a running engagement that proposes a risky action stops at ``awaiting_approval`` and
    emits an approval request instead of running;
  * DEFAULT-BLOCK on timeout — a pending ask that is never answered yields no grant, so the action never runs;
  * the Allow is BOUNDED, SINGLE-USE, OWNER-SIGNED and resumes EXACTLY that action — a grant authorizes one
    action once, binds to its exact scope + params, and a replay is inert;
  * Block REFUSES — a blocked action stays blocked (no grant written);
  * the advisory LLM judge can only RAISE risk, never lower it;
  * a FORGED / REPLAYED approval is INERT — a tampered grant does not authorize; a tampered evidence trail does
    not verify; a rolled-back trail is refused (LWW high-water);
  * flag-OFF is BYTE-IDENTICAL — with VIGIL_CUSTOMER_ACTION_APPROVAL off there is no pause and the routes 404;
  * STEP-UP is enforced for an Allow of a HIGH-risk action;
  * TENANT ISOLATION — an org sees/answers only its OWN approvals, bound to its engagement + org.
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_ACTION_APPROVAL", "1")       # the gate ON (strict opt-in)


# ============================== the DETERMINISTIC risk classifier (pure) =====================================
def test_classifier_deterministic_base_policy():
    from sigil.ui import action_risk as ar
    # the genuinely risky launch is HIGH + step-up; a live steer is ELEVATED + approval but not step-up.
    r = ar.classify_action("reserve_start")
    assert r.level_name == "high" and r.requires_approval and r.requires_stepup
    assert "spend_crossing" in r.categories and "changes_target" in r.categories
    i = ar.classify_action("instruct")
    assert i.level_name == "elevated" and i.requires_approval and not i.requires_stepup
    # reads + the DE-RISKING controls are never gated.
    for safe in ("none", "assets", "activity", "challenge", "pause", "cancel"):
        assert ar.classify_action(safe).requires_approval is False, safe


def test_classifier_unknown_action_is_risky_fail_closed():
    from sigil.ui import action_risk as ar
    r = ar.classify_action("exfiltrate_everything")           # not in the policy table
    assert r.level_name == "high" and r.requires_approval is True


def test_classifier_facts_only_raise():
    from sigil.ui import action_risk as ar
    base = ar.classify_action("verify")                        # LOW, not gated by default
    assert base.requires_approval is False
    raised = ar.classify_action("verify", facts={"out_of_window": True, "cross_tenant_adjacent": True})
    assert raised.level_name == "high" and raised.requires_approval
    assert "out_of_window" in raised.categories and "out_of_scope" in raised.categories


def test_advisory_judge_can_only_raise():
    from sigil.ui import action_risk as ar
    base = ar.classify_action("instruct")                      # ELEVATED
    # a judge that says HIGH raises it...
    up = ar.apply_advisory_judge(base, {"level": "high", "reason": "touches prod auth"})
    assert up.level_name == "high"
    # ...but a judge that says LOW can NEVER lower the deterministic floor.
    down = ar.apply_advisory_judge(base, {"level": "low"})
    assert down.level_name == "elevated"
    # a malformed judge is treated as "risky" — raised to HIGH, never accepted as a lower reading.
    bad = ar.apply_advisory_judge(base, "not-a-verdict")
    assert bad.level_name == "high"
    # disabled / absent judge ⇒ unchanged (byte-identical to deterministic-only).
    assert ar.apply_advisory_judge(base, {"level": "high"}, enabled=False).level_name == "elevated"
    assert ar.apply_advisory_judge(base, None).level_name == "elevated"


# ============================== the PURE flow gate ===========================================================
def test_pure_gate_pauses_only_a_risky_unapproved_action():
    from sigil.ui import engagement_flow as ef
    plan = {"action": "reserve_start", "state": ef.RESERVING, "blocked": None, "need": None}
    # risky + no approval ⇒ PAUSE at awaiting_approval.
    paused = ef.gate(plan, requires_approval=True, approval_present=False)
    assert paused["state"] == ef.AWAITING_APPROVAL and paused["action"] == "none" and paused["need"] == "approval"
    # risky + a live Allow ⇒ the base plan unchanged (proceed).
    assert ef.gate(plan, requires_approval=True, approval_present=True) == plan
    # not risky ⇒ unchanged.
    assert ef.gate(plan, requires_approval=False, approval_present=False) == plan
    # a plan that already took no action / was blocked is never turned INTO a run.
    noop = {"action": "none", "state": ef.AWAITING_CONFIRM, "blocked": "confirm first", "need": "confirm"}
    assert ef.gate(noop, requires_approval=True, approval_present=False) == noop
    assert ef.AWAITING_APPROVAL in ef.STATES


# ============================== the GATE STORE (owner-signed, single-use, tamper-evident) ====================
def _owner_pub():
    from sigil.governor.identity import ensure_owner_keypair
    return ensure_owner_keypair().public_key_b64


def _org():
    # SIGIL_HOME (hence the per-org approval dir) is resolved at config import, so it is shared across tests in
    # one process; a FRESH org id per test is the clean isolation (the per-org path is the tenant boundary).
    return f"org_{next(_iss)}"


def _risk(action="reserve_start"):
    from sigil.ui import action_risk as ar
    return ar.classify_action(action)


def test_risky_action_pauses_then_allow_resumes_exactly_that_action_once():
    from sigil.ui import action_approval as aa
    org, host = _org(), "api.example.com"
    params = {"host": host, "depth": "standard"}
    # (1) first propose ⇒ no grant ⇒ pending (BLOCK) with a risk-bearing card.
    o1 = aa.gate_step(org, host, "reserve_start", risk=_risk(), params=params, requested_by="alice", now=100.0)
    assert o1.allow is False and o1.approval["risk"]["level_name"] == "high"
    aid = o1.approval["approval_id"]
    # (2) owner ALLOWS ⇒ an owner-signed grant is minted.
    res = aa.answer(org, "alice", aid, allow=True, now=101.0)
    assert res.ok and res.decision == "allowed"
    # (3) the SAME action now passes (the single-use grant is spent).
    assert aa.gate_step(org, host, "reserve_start", risk=_risk(), params=params, requested_by="alice",
                        now=102.0).allow is True
    # (4) SINGLE-USE: a replay of the same action is inert ⇒ re-asks (block).
    assert aa.gate_step(org, host, "reserve_start", risk=_risk(), params=params, requested_by="alice",
                        now=103.0).allow is False


def test_allow_is_bounded_to_exactly_that_action_and_params():
    from sigil.ui import action_approval as aa
    org, host = _org(), "h.example.com"
    o = aa.gate_step(org, host, "instruct", risk=_risk("instruct"), params={"host": host, "text": "focus on auth"},
                     requested_by="a", now=1.0)
    aa.answer(org, "a", o.approval["approval_id"], allow=True, now=2.0)
    # a grant for instruct 'focus on auth' does NOT authorize a DIFFERENT instruction (binding) ...
    assert aa.gate_step(org, host, "instruct", risk=_risk("instruct"), params={"host": host, "text": "wipe prod"},
                        requested_by="a", now=3.0).allow is False
    # ... nor a different action kind on the same host.
    assert aa.gate_step(org, host, "resume", risk=_risk("resume"), params={"host": host},
                        requested_by="a", now=4.0).allow is False
    # the exact action+params still resumes once.
    assert aa.gate_step(org, host, "instruct", risk=_risk("instruct"), params={"host": host, "text": "focus on auth"},
                        requested_by="a", now=5.0).allow is True


def test_block_refuses_and_writes_no_grant():
    from sigil.ui import action_approval as aa
    org, host = _org(), "b.example.com"
    o = aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=1.0)
    assert aa.answer(org, "a", o.approval["approval_id"], allow=False, now=2.0).decision == "blocked"
    # the action stays blocked (default-block: a Block mints no grant).
    assert aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host},
                        requested_by="a", now=3.0).allow is False


def test_default_block_on_timeout():
    from sigil.ui import action_approval as aa
    org, host = _org(), "t.example.com"
    aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=10.0)
    # never answered: after the window elapses the sweep records a timed_out (default-block) and clears it.
    swept = aa.sweep_timeouts(org, now=10.0 + aa.REQUEST_TTL_SECONDS + 1.0)
    assert swept == 1
    assert aa.list_pending(org, now=10.0 + aa.REQUEST_TTL_SECONDS + 2.0) == []
    assert "timed_out" in [d["decision"] for d in aa.read_evidence(org)]
    # with the ask timed out there is no grant ⇒ the action is still blocked.
    assert aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host},
                        requested_by="a", now=10.0 + aa.REQUEST_TTL_SECONDS + 3.0).allow is False


def test_forged_grant_is_inert():
    from sigil.ui import action_approval as aa
    org, host = _org(), "f.example.com"
    o = aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=1.0)
    aid = o.approval["approval_id"]
    aa.answer(org, "a", aid, allow=True, now=2.0)
    # TAMPER the stored owner signature ⇒ the grant no longer verifies ⇒ inert (re-asks).
    gp = aa._granted_path(org, aid)
    doc = json.loads(gp.read_text(encoding="utf-8"))
    doc["signature_b64"] = "A" * len(doc["signature_b64"])
    gp.write_text(json.dumps(doc), encoding="utf-8")
    assert aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host},
                        requested_by="a", now=3.0).allow is False


def test_evidence_is_owner_signed_tamper_evident_and_rollback_guarded():
    from sigil.ui import action_approval as aa
    org, host = _org(), "e.example.com"
    o = aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=1.0)
    aa.answer(org, "a", o.approval["approval_id"], allow=True, now=2.0)
    aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=3.0)
    ok, why = aa.verify_evidence(org, trusted_pubkey=_owner_pub())
    assert ok, why
    # TAMPER a record's content ⇒ the chain + signature no longer verify.
    recs = aa._read_evidence(org)
    recs[0]["decision"] = "allowed"            # was "requested"
    aa._evidence_path(org).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), encoding="utf-8")
    assert aa.verify_evidence(org)[0] is False
    # restore, then TRUNCATE (rollback) ⇒ the LWW high-water floor refuses.
    recs[0]["decision"] = "requested"
    full = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
    aa._evidence_path(org).write_text(full, encoding="utf-8")
    assert aa.verify_evidence(org)[0] is True
    aa._evidence_path(org).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs[:-1]),
                                      encoding="utf-8")
    ok, why = aa.verify_evidence(org)
    assert ok is False and "ROLLBACK" in why


def test_evidence_resigned_under_attacker_key_is_detected_and_append_refuses():
    """The RED-PEN forgery the owner-pin closes: a same-host writer REWRITES the approval audit history and
    RE-SIGNS a self-consistent hash chain under their OWN keypair (own pub embedded), keeping entry_count /
    last_seq == the genuine floor — so the LWW high-water alone (which only guards monotonic length/seq) would
    let the equal-length re-sign pass. The DEFAULT ``verify_evidence`` (no ``trusted_pubkey``) must now PIN the
    owner key and return NOT-ok, and ``_append_evidence`` must REFUSE to extend / bless such a chain."""
    from sigil.ui import action_approval as aa
    from sigil.reuse import generate_keypair
    from vigil_core import sign
    org, host = _org(), "forge.example.com"
    # (1) a GENUINE owner-signed trail (requested -> allowed -> consumed) that verifies under the DEFAULT pin.
    o = aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=1.0)
    aa.answer(org, "a", o.approval["approval_id"], allow=True, now=2.0)
    aa.gate_step(org, host, "reserve_start", risk=_risk(), params={"host": host}, requested_by="a", now=3.0)
    assert aa.verify_evidence(org)[0] is True              # DEFAULT (owner-pinned) path accepts the genuine trail
    genuine = aa._read_evidence(org)
    assert len(genuine) >= 2
    # (2) FORGE: re-sign a chain with IDENTICAL content (so the hashes — hence entry_count/last_seq, hence the
    # floor — are byte-for-byte preserved) under a FRESH ATTACKER keypair, embedding the attacker's OWN pub.
    atk = generate_keypair()
    assert atk.public_key_b64 != _owner_pub()
    forged, prev = [], aa._GENESIS_PREV
    for r in genuine:
        content = aa._evidence_content(r)
        eh = aa._entry_hash(prev, content)                 # hashes are key-independent ⇒ == the genuine entry_hash
        sig = sign(atk.private_key_b64, aa._evidence_sig_bytes(prev, eh, content))
        forged.append({**content, "prev": prev, "entry_hash": eh, "sig": sig, "pub": atk.public_key_b64})
        prev = eh
    aa._evidence_path(org).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in forged),
                                      encoding="utf-8")
    # the forgery is internally self-consistent AND keeps the high-water floor (same hashes, length and seqs) ...
    assert [r["entry_hash"] for r in forged] == [r["entry_hash"] for r in genuine]
    # ... yet the DEFAULT verify (owner-pinned) now REJECTS it — it is not signed by the owner key.
    ok, why = aa.verify_evidence(org)
    assert ok is False and "owner" in why.lower()
    # an explicit pin to the genuine owner key rejects the attacker-signed trail too.
    assert aa.verify_evidence(org, trusted_pubkey=_owner_pub())[0] is False
    # and _append_evidence REFUSES to extend / bless the forged (non-owner-signed) chain.
    with pytest.raises(aa.ApprovalStoreError):
        aa._append_evidence(org, {"decision": aa.DECISION_REQUESTED, "approval_id": "appr_" + "0" * 32,
                                  "slug": "s", "host": host, "action": "reserve_start",
                                  "action_digest": "d"}, now=4.0)


def test_tenant_isolation_store_level():
    from sigil.ui import action_approval as aa
    oa, ob = _org(), _org()
    o = aa.gate_step(oa, "x.example.com", "reserve_start", risk=_risk(), params={"host": "x.example.com"},
                     requested_by="a", now=1.0)
    aid = o.approval["approval_id"]
    # org B cannot see org A's pending ...
    assert aa.list_pending(ob, now=2.0) == []
    # ... nor answer org A's approval id (no such pending under org B ⇒ not allowed).
    assert aa.answer(ob, "intruder", aid, allow=True, now=2.0).decision != "allowed"
    # org A's own grant is therefore still ungranted.
    assert aa.gate_step(oa, "x.example.com", "reserve_start", risk=_risk(), params={"host": "x.example.com"},
                        requested_by="a", now=3.0).allow is False


# ============================== the PROVISIONER end-to-end ===================================================
def _store():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    import os
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _prove(store, org, host):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=1e9, ttl_seconds=1e12)


def _prov(store):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    orgs = OrgRegistry(store)
    if orgs.org("org_a") is None:
        orgs.create_org("org_a", "org_a", owner="alice", issued_at=float(next(_iss)))
    orgs.grant_membership("org_a", "alice", "operator", issued_at=float(next(_iss)))
    return Provisioner(store, customers=CustomerRegistry(store), orgs=orgs, wallet=WalletRegistry(store),
                       email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                       rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                     base_lock_s=1.0),
                       email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))


def test_provisioner_launch_pauses_for_approval_when_on():
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    # a confirmed launch would reserve credits; the gate intercepts the risky reserve_start BEFORE any reserve.
    out = p.customer_flow_step("alice", "org_a", intent="launch", host="api.example.com", confirm=True, now=1.0)
    assert out["state"] == "awaiting_approval" and out["need"] == "approval"
    assert out["approval"]["risk"]["level_name"] == "high"
    assert "reserved" not in out and "started" not in out       # nothing ran — it paused first


def test_provisioner_flag_off_is_byte_identical_no_pause(monkeypatch):
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    monkeypatch.setenv("VIGIL_CUSTOMER_ACTION_APPROVAL", "0")    # force OFF (monkeypatch auto-reverts)
    # confirm=False still stops at awaiting_confirm (unchanged) — NEVER awaiting_approval, no approval key.
    out = p.customer_flow_step("alice", "org_a", intent="launch", host="api.example.com", confirm=False, now=1.0)
    assert out["state"] == "awaiting_confirm" and "approval" not in out
    # and the read/answer routes are refused when off (defence in depth under the dispatch 404).
    from sigil.ui.provision import ProvisionDenied
    with pytest.raises(ProvisionDenied):
        p.customer_approvals("alice", "org_a")


def test_provisioner_read_answer_and_resume():
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    out = p.customer_flow_step("alice", "org_a", intent="launch", host="api.example.com", confirm=True, now=1.0)
    aid = out["approval"]["approval_id"]
    # the read route surfaces the SAME pending card (tenant-scoped to the session org).
    pend = p.customer_approvals("alice", "org_a", now=2.0)["pending"]
    assert any(c["approval_id"] == aid for c in pend)
    # Allow it (step-up OFF ⇒ no second factor needed).
    assert p.customer_approval_answer("alice", "org_a", approval_id=aid, allow=True, now=3.0)["decision"] == "allowed"
    # resume: the gate now passes that exact action (the grant is consumed) — the audit shows it, whatever the
    # downstream reserve then does (no funding here, so it may raise — the GATE itself has passed).
    from sigil.ui import action_approval as aa
    from sigil.ui.provision import ProvisionError
    try:
        r = p.customer_flow_step("alice", "org_a", intent="launch", host="api.example.com", confirm=True, now=4.0)
        assert r.get("state") != "awaiting_approval"
    except ProvisionError:
        pass                                                     # downstream reserve failed (no funding) — fine
    assert "consumed" in [d["decision"] for d in aa.read_evidence("org_a")]


def test_provisioner_stepup_enforced_for_high_risk_allow(monkeypatch):
    from sigil.ui.provision import ProvisionStepUpRequired
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")     # step-up enforcement ON
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    out = p.customer_flow_step("alice", "org_a", intent="launch", host="api.example.com", confirm=True, now=1.0)
    aid = out["approval"]["approval_id"]
    # Allowing a HIGH-risk action with NO fresh second factor is refused (fail-closed).
    with pytest.raises(ProvisionStepUpRequired):
        p.customer_approval_answer("alice", "org_a", approval_id=aid, allow=True, mfa_at=0.0, now=2.0)
    # a FRESH step-up stamp lets the Allow through.
    assert p.customer_approval_answer("alice", "org_a", approval_id=aid, allow=True, mfa_at=2.0,
                                      now=2.0)["decision"] == "allowed"


def test_provisioner_tenant_isolation_read_and_answer():
    from sigil.ui.provision import ProvisionDenied
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    p.customer_flow_step("alice", "org_a", intent="launch", host="api.example.com", confirm=True, now=1.0)
    # a requester not admitted for org_a cannot read or answer its approvals (tenant isolation at admit).
    with pytest.raises(ProvisionDenied):
        p.customer_approvals("mallory", "org_a")
    with pytest.raises(ProvisionDenied):
        p.customer_approval_answer("mallory", "org_a", approval_id="appr_" + "0" * 32, allow=True)
