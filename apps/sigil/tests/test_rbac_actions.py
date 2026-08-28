"""Claim 6 — the RBAC admission gate at the action funnel (ui/actions.do_action) and the approval-tier
gate (agents/approvals.ApprovalQueue).

The load-bearing invariants (§7 negative controls):
  * a viewer/analyst cannot approve (and NO governor.approval record is appended — the gate fires before
    signing);
  * an operator can approve ≤A2 but NOT an A3 (owner-only);
  * owner-only ops (release, promote, secrets, offense authority, user management) refuse an operator (403)
    and succeed for the owner;
  * the SAFE directions (kill/engage) are allowed for any authenticated role;
  * disabling the protected-domain safety floor (VIGIL_ALLOW_PROTECTED_DOMAINS) is OWNER-ONLY, while a
    normal set_config is operator-allowed;
  * the OWNER KEY remains the sole signer — an operator-approved ≤A2 action is signed by the owner pubkey
    with the operator recorded as `approver` (admission, not key custody).
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.agents.approvals import ApprovalQueue
from sigil.agents.base import Agent, Proposal, Tier
from sigil.governor import Governor
from sigil.governor.accounts import Principal
from sigil.governor.identity import ensure_owner_keypair, owner_pubkey
from sigil.spine.store import SpineStore
from sigil.ui import actions

VIEWER = Principal("vera", "viewer")
ANALYST = Principal("anna", "analyst")
OPERATOR = Principal("otto", "operator")
OWNER = Principal("owner", "owner")


@pytest.fixture(autouse=True)
def _owner_identity():
    # do_action signs with the PERSISTED owner key; the targeted test run sets SIGIL_HOME to a temp dir.
    ensure_owner_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class _Emitter(Agent):
    name = "TESTER"
    ceiling = Tier.A3

    def __init__(self, store, owner):
        super().__init__(store, governor=Governor(store, owner_key=owner,
                                                   trusted_pubkey=owner.public_key_b64))

    def run(self, tier, kind="draft"):
        return self._dispatch([Proposal(kind, {"subject": "please approve me"}, tier)])


def _queue(store, tier):
    """Queue one proposal at `tier` and return its seq (via the real pending() view)."""
    from sigil.agents.approvals import pending
    owner = ensure_owner_keypair()
    _Emitter(store, owner).run(tier)
    pend = pending(store, owner.public_key_b64)
    assert pend, "a proposal should have queued"
    return pend[-1].seq


# --- approvals: viewer/analyst refused, no record written ------------------------

def test_viewer_cannot_approve_and_writes_no_record():
    s = _store()
    seq = _queue(s, Tier.A2)
    before = s.count()
    # a viewer approve raises PermissionDenied and appends nothing (the gate fires before signing)
    from sigil.governor.accounts import PermissionDenied
    with pytest.raises(PermissionDenied):
        actions.do_action("approve", {"seq": seq}, store=s, principal=VIEWER)
    assert s.count() == before, "a refused approval must append NO governor.approval record"


def test_analyst_cannot_approve():
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    seq = _queue(s, Tier.A2)
    with pytest.raises(PermissionDenied):
        actions.do_action("approve", {"seq": seq}, store=s, principal=ANALYST)


# --- approvals: operator can A2, not A3; owner can both --------------------------

def test_operator_can_approve_a2_and_the_owner_key_signs_it():
    s = _store()
    seq = _queue(s, Tier.A2)
    out = actions.do_action("approve", {"seq": seq}, store=s, principal=OPERATOR)
    assert out["ok"] and out["requested_by"] == "otto"
    appr = [r for r in s.iter_records() if r.payload.get("signal") == "governor.approval"
            and r.payload.get("approval") == "approved"]
    assert appr, "the approval was recorded"
    p = appr[-1].payload
    # ADMISSION, not custody: the signature is the OWNER's; the operator is only the recorded requester.
    assert p["pubkey"] == owner_pubkey()
    assert p["approver"] == "otto"


def test_operator_cannot_approve_a3_owner_can():
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    seq = _queue(s, Tier.A3)
    with pytest.raises(PermissionDenied):
        actions.do_action("approve", {"seq": seq}, store=s, principal=OPERATOR)
    # the owner resolves the same A3
    out = actions.do_action("approve", {"seq": seq}, store=s, principal=OWNER)
    assert out["ok"]


def test_approvalqueue_principal_gate_direct():
    # the tier gate lives in ApprovalQueue._decide too (defence in depth for a direct caller)
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    seq = _queue(s, Tier.A2)
    owner = ensure_owner_keypair()
    with pytest.raises(PermissionDenied):
        ApprovalQueue(s, owner_key=owner, principal=VIEWER).approve(seq)


# --- owner-only ops refuse an operator, succeed for the owner --------------------

OWNER_ONLY = [
    ("release", {}),
    ("promote", {"agent": "SENTINEL", "scope": "*"}),
    ("revoke", {"agent": "SENTINEL", "scope": "*"}),
    ("set_secret", {"name": "ANTHROPIC_API_KEY", "value": "sk-test-xxxxxxxxxxxx"}),
    ("offense_bind_authority", {}),
    ("create_account", {"username": "newbie", "role": "viewer"}),
    ("assign_role", {"username": "newbie", "role": "operator"}),
    ("revoke_account", {"username": "newbie"}),
    ("revoke_all_teammates", {}),
    ("rotate_bootstrap_token", {}),
    ("revoke_bootstrap_token", {}),
    ("revoke_sessions", {}),
    ("enroll_webauthn", {"credential_id": "c", "cose_alg": -7, "public_key_spki_b64": "x"}),
    ("revoke_webauthn", {}),
    # W17-3 enrolment actions are user-management -> owner-only, same as create/assign/revoke. The RBAC gate
    # fires at the funnel BEFORE the registry is touched, so an unknown-account username is irrelevant here.
    ("enroll_pubkey", {"username": "newbie", "user_pubkey": "x"}),
    ("enroll_totp", {"username": "newbie"}),
    ("set_password", {"username": "newbie", "password": "irrelevant-because-denied-first"}),
]


@pytest.mark.parametrize("action,params", OWNER_ONLY)
def test_owner_only_actions_refuse_an_operator(action, params):
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    with pytest.raises(PermissionDenied):
        actions.do_action(action, params, store=s, principal=OPERATOR)


@pytest.mark.parametrize("action,params", OWNER_ONLY)
def test_owner_only_actions_refuse_a_viewer(action, params):
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    with pytest.raises(PermissionDenied):
        actions.do_action(action, params, store=s, principal=VIEWER)


def test_owner_can_manage_users_end_to_end():
    s = _store()
    out = actions.do_action("create_account", {"username": "teammate", "role": "operator"},
                            store=s, principal=OWNER)
    assert out["ok"] and out["bearer_token"] and out["role"] == "operator"
    # the minted bearer authenticates as the operator it was created for
    from sigil.governor.accounts import AccountsRegistry
    assert AccountsRegistry(s).resolve(out["bearer_token"]) == Principal("teammate", "operator")
    # assign + revoke also succeed for the owner
    assert actions.do_action("assign_role", {"username": "teammate", "role": "analyst"},
                             store=s, principal=OWNER)["ok"]
    assert actions.do_action("revoke_account", {"username": "teammate"}, store=s, principal=OWNER)["ok"]
    assert AccountsRegistry(s).resolve(out["bearer_token"]) is None


def test_owner_create_with_ttl_returns_expiry_and_it_enforces():
    import time as _time

    from sigil.governor.accounts import AccountsRegistry
    s = _store()
    out = actions.do_action("create_account", {"username": "temp", "role": "operator", "ttl_seconds": 3600},
                            store=s, principal=OWNER)
    assert out["ok"] and out["bearer_token"]
    assert out["expires_at"] is not None and out["expires_at"] > _time.time()
    reg = AccountsRegistry(s)
    # valid now, denied once past the returned absolute deadline
    assert reg.resolve(out["bearer_token"]) == Principal("temp", "operator")
    assert reg.resolve(out["bearer_token"], now=out["expires_at"] + 1) is None


def test_owner_create_without_ttl_never_expires():
    s = _store()
    out = actions.do_action("create_account", {"username": "perm", "role": "viewer"},
                            store=s, principal=OWNER)
    assert out["expires_at"] is None                                     # omitted ttl ⇒ never expires


def test_owner_bulk_revoke_clears_every_teammate():
    from sigil.governor.accounts import AccountsRegistry
    s = _store()
    for u in ("t1", "t2", "t3"):
        actions.do_action("create_account", {"username": u, "role": "viewer"}, store=s, principal=OWNER)
    out = actions.do_action("revoke_all_teammates", {}, store=s, principal=OWNER)
    assert out["ok"] and out["count"] == 3 and sorted(out["revoked"]) == ["t1", "t2", "t3"]
    assert AccountsRegistry(s).accounts() == []


def test_owner_can_rotate_and_revoke_the_session_token(monkeypatch, tmp_path):
    # isolate the bootstrap-token file to tmp_path (do_action calls the module with no explicit path)
    from sigil.ui import bootstrap_token as bt
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)   # dev posture
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    tok_file = tmp_path / ".vigil-live" / "cockpit-bootstrap-token"
    s = _store()
    out = actions.do_action("rotate_bootstrap_token", {}, store=s, principal=OWNER)
    assert out["ok"] and out["new_url_path"].startswith("/?token=") and tok_file.exists()
    out2 = actions.do_action("revoke_bootstrap_token", {}, store=s, principal=OWNER)
    assert out2["ok"] and not tok_file.exists()


def test_session_actions_are_noop_in_production(monkeypatch, tmp_path):
    # In production the persistent bootstrap token is inert (owner logs in via passkey), so rotate/revoke
    # refuse honestly and touch no file — the dev token must never masquerade as the production boundary.
    from sigil.ui import bootstrap_token as bt
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    s = _store()
    out = actions.do_action("rotate_bootstrap_token", {}, store=s, principal=OWNER)
    assert out["ok"] is False and out.get("production_noop") is True
    assert not (tmp_path / ".vigil-live" / "cockpit-bootstrap-token").exists()


def test_owner_release_and_promote_succeed():
    s = _store()
    assert actions.do_action("release", {}, store=s, principal=OWNER)["ok"]
    assert actions.do_action("promote", {"agent": "SENTINEL", "scope": "*"},
                             store=s, principal=OWNER)["ok"]


# --- safe directions are allowed for any authenticated role ----------------------

def test_kill_is_allowed_for_a_viewer_safe_direction():
    # halting is the SAFE direction — mapped to `read`, so any authenticated principal may engage it.
    s = _store()
    out = actions.do_action("kill", {}, store=s, principal=VIEWER)
    assert out["ok"]


def test_analyst_can_queue_learn_but_not_start_learn():
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    # queue_learn = analyst+ ; a real run may be refused by other gates, but NOT by RBAC for the analyst
    try:
        actions.do_action("queue_learn", {"vuln_id": "X"}, store=s, principal=ANALYST)
    except PermissionDenied:
        pytest.fail("queue_proposal is an analyst permission — RBAC must not refuse it")
    except Exception:
        pass  # a non-RBAC refusal (kill-switch / autolearn latch) is fine for this test
    with pytest.raises(PermissionDenied):
        actions.do_action("start_learn", {"url": "http://x"}, store=s, principal=ANALYST)


# --- the VIGIL_ALLOW_PROTECTED_DOMAINS owner-only special case (Claim 5 reconciliation) ---

def test_operator_cannot_disable_the_protected_domain_guard():
    from sigil.governor.accounts import PermissionDenied
    s = _store()
    with pytest.raises(PermissionDenied):
        actions.do_action("set_config", {"env": "VIGIL_ALLOW_PROTECTED_DOMAINS", "value": "1"},
                          store=s, principal=OPERATOR)


def test_operator_can_set_a_normal_config(monkeypatch, tmp_path):
    from sigil.ui import settings as smod
    monkeypatch.setattr(smod, "SIGIL_HOME", tmp_path)
    monkeypatch.delenv("CRUCIBLE_LLM_MAX_WORKERS", raising=False)
    s = _store()
    out = actions.do_action("set_config", {"env": "CRUCIBLE_LLM_MAX_WORKERS", "value": "8"},
                            store=s, principal=OPERATOR)
    assert out["ok"] and out["value"] == "8"     # config_nonsecret is an operator permission


def test_owner_can_disable_the_protected_domain_guard(monkeypatch, tmp_path):
    from sigil.ui import settings as smod
    monkeypatch.setattr(smod, "SIGIL_HOME", tmp_path)
    monkeypatch.delenv("VIGIL_ALLOW_PROTECTED_DOMAINS", raising=False)
    s = _store()
    out = actions.do_action("set_config", {"env": "VIGIL_ALLOW_PROTECTED_DOMAINS", "value": "1"},
                            store=s, principal=OWNER, )
    assert out["ok"] and out["value"] == "1"     # owner carries toggle_protected_guard


# --- internal/CLI callers (principal=None) still act as the owner (back-compat) ---

def test_principal_none_acts_as_owner():
    s = _store()
    # the existing ~100 call sites pass no principal → they act as OWNER_PRINCIPAL, byte-identical
    assert actions.do_action("kill", {}, store=s)["ok"]
    assert actions.do_action("create_account", {"username": "cliuser", "role": "viewer"},
                             store=s)["ok"]
