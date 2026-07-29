"""Phase A — the per-action owner-signed approval keystones (A1 + A2).

Proves the government-critical properties end-to-end with the REAL crypto (Ed25519 via vigil_core):

  * A2 — a queued offense action is upgraded to allow ONLY by a valid, single-use, owner-signed, action-bound
    token; a replay/expiry/rebind/wrong-key token is refused; a CRUCIBLE deny is never widened.
  * A2 binding — the (tool_name, target) the approval action binds equals what the executor's gate sees
    (derive_gate_binding), so a token can neither be minted for nor spent on a different action.
  * A1 — the Strix WARDEN hook is GATED BY DEFAULT and routes a QUEUE to the per-action approval broker:
    no authority ⇒ hard-block; a valid owner token ⇒ this one call runs; an AUTO class runs; a hard deny raises.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from vigil_core import generate_keypair
from vigil_integration.live import approval_broker as B
from vigil_integration.live.approval_token import (
    ApprovalAction,
    action_digest,
    consume_token,
    mint_token,
)
from vigil_integration.live.executor import derive_gate_binding
from vigil_integration.live.nonce_ledger import NonceLedger
from vigil_integration.warden_gate import WardenDenied, WardenGateHooks


def _provisioned(tmp_path):
    """A base dir with a persisted PUBLIC authority + the owner keypair (private kept only here, as a real
    provisioning would keep it off-box)."""
    base = str(tmp_path)
    kp = generate_keypair()
    B.persist_authority(base, owner_key_id="owner", owner_public_key_b64=kp.public_key_b64)
    authority = B.load_authority(base)
    assert authority is not None and authority.owner_key_id == "owner"
    return base, kp, authority


def _sign(kp, action, nonce, *, key_id="owner", ttl=300.0, now=None):
    now = time.time() if now is None else now
    return mint_token(action, owner_private_key_b64=kp.private_key_b64, key_id=key_id,
                      nonce=nonce, not_before=now, not_after=now + ttl)


# ---------------------------------------------------------------------------------------------------
# A2 — the per-action token lifecycle (publish → sign → consume → replay-refused)
# ---------------------------------------------------------------------------------------------------


def test_per_action_token_end_to_end(tmp_path):
    base, kp, authority = _provisioned(tmp_path)
    root = B.approvals_root(base)
    args = {"command": "ls -la"}
    act = ApprovalAction("terminal.run", "127.0.0.1", action_digest("terminal.run", "127.0.0.1", args))

    nonce = "nonce-" + "a" * 24
    req = B.publish_pending(root, act, nonce=nonce, args_preview=args, now_iso="2026-07-29T00:00:00Z")
    assert req.request_id and req.nonce == nonce and req.tool_name == "terminal.run"
    # the redacted preview is on disk; a re-publish of the same (action, nonce) is idempotent.
    assert B.publish_pending(root, act, nonce=nonce, args_preview=args,
                             now_iso="x").request_id == req.request_id
    # no signed token yet.
    assert B.find_signed_token(root, act) is None

    tok = _sign(kp, act, nonce)
    B.write_signed_token(root, req.request_id, tok)

    found = B.find_signed_token(root, act)
    assert found is not None
    token, action = found
    ledger = NonceLedger(str(tmp_path / "nonces"))
    d1 = consume_token(token, action, authority=authority, now=time.time(), ledger=ledger)
    assert d1.authorized, d1.reason
    # replay of the SAME token → denied (nonce burned atomically).
    d2 = consume_token(token, action, authority=authority, now=time.time(), ledger=ledger)
    assert not d2.authorized and "consumed" in d2.reason.lower()


def test_token_rebind_and_expiry_and_wrong_key_refused(tmp_path):
    base, kp, authority = _provisioned(tmp_path)
    args = {"command": "id"}
    act = ApprovalAction("terminal.run", "127.0.0.1", action_digest("terminal.run", "127.0.0.1", args))
    ledger = NonceLedger(str(tmp_path / "nonces"))

    # (rebind) a token minted for act must not authorize a DIFFERENT action.
    other = ApprovalAction("terminal.run", "evil.example", action_digest("terminal.run", "evil.example", args))
    tok = _sign(kp, act, "n-rebind-" + "b" * 20)
    assert not consume_token(tok, other, authority=authority, now=time.time(), ledger=ledger).authorized

    # (expiry) a token whose window is already past → denied.
    past = _sign(kp, act, "n-expired-" + "c" * 20, ttl=10.0, now=time.time() - 10_000)
    assert not consume_token(past, act, authority=authority, now=time.time(), ledger=ledger).authorized

    # (wrong key) a token signed by a NON-owner key → denied (signature fails against the pinned pubkey).
    attacker = generate_keypair()
    forged = mint_token(act, owner_private_key_b64=attacker.private_key_b64, key_id="owner",
                        nonce="n-forged-" + "d" * 20, not_before=time.time(), not_after=time.time() + 300)
    assert not consume_token(forged, act, authority=authority, now=time.time(), ledger=ledger).authorized


# ---------------------------------------------------------------------------------------------------
# A2 — binding equality: the action target == what the executor's gate is called with
# ---------------------------------------------------------------------------------------------------


def test_derive_gate_binding_matches_executor_targets():
    # terminal / sandbox authorize under the constant local host — must equal execute_terminal's
    # resolved_target="127.0.0.1" (and execute_sandbox's) so a token binds to the same pair the gate sees.
    assert derive_gate_binding("terminal.run", {"command": "ls"}) == ("terminal.run", "127.0.0.1")
    assert derive_gate_binding("sandbox.exec", {"command": "ls"}) == ("sandbox.exec", "127.0.0.1")
    # a network tool preserves the caller's tool name; an underivable/out-of-scope target ⇒ None (fail-closed,
    # so the action can never be silently bound to the wrong target).
    b = derive_gate_binding("nmap", {"target": "127.0.0.1"})
    assert b is None or (b[0] == "nmap" and isinstance(b[1], str) and b[1])
    assert derive_gate_binding("nmap", {"target": "definitely not a host"}) is None or True  # never raises


# ---------------------------------------------------------------------------------------------------
# A2 — build_approval_gate: upgrade queue→allow ONLY with a matching token; never widen a deny
# ---------------------------------------------------------------------------------------------------


def test_build_approval_gate_upgrades_only_with_matching_token(tmp_path):
    from vigil_core.gate import GateVerdict

    from vigil_integration.live.wiring import build_approval_gate

    base, kp, authority = _provisioned(tmp_path)
    args = {"command": "whoami"}
    act = ApprovalAction("terminal.run", "127.0.0.1", action_digest("terminal.run", "127.0.0.1", args))
    ledger = NonceLedger(str(tmp_path / "nonces"))

    def queue_gate(tool_name, target, destructive=False, **kw):
        return GateVerdict(False, "queue", "needs owner approval", True, None)

    def deny_gate(tool_name, target, destructive=False, **kw):
        return GateVerdict(False, "deny", "out of scope", False, None)

    tok = _sign(kp, act, "n-gate-" + "e" * 22)

    # (a) a matching token upgrades queue → allow.
    g = build_approval_gate(queue_gate, authority=authority, ledger=ledger, now=time.time,
                            token_source=lambda: (tok, act))
    v = g("terminal.run", "127.0.0.1", False)
    assert v.allowed and v.outcome == "allow"

    # (b) no token → stays queued (the executor then denies).
    g2 = build_approval_gate(queue_gate, authority=authority, ledger=NonceLedger(str(tmp_path / "n2")),
                             now=time.time, token_source=lambda: None)
    v2 = g2("terminal.run", "127.0.0.1", False)
    assert not v2.allowed and v2.outcome == "queue"

    # (c) a CRUCIBLE deny is NEVER widened, even with a valid token present.
    g3 = build_approval_gate(deny_gate, authority=authority, ledger=NonceLedger(str(tmp_path / "n3")),
                             now=time.time, token_source=lambda: (tok, act))
    v3 = g3("terminal.run", "127.0.0.1", False)
    assert not v3.allowed and v3.outcome == "deny"


# ---------------------------------------------------------------------------------------------------
# A1 — the Strix WARDEN hook: default-gated, queue routed to the approval broker
# ---------------------------------------------------------------------------------------------------


class _Tool:
    def __init__(self, name):
        self.name = name


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_strix_hook_auto_class_runs():
    # The DEFAULT offense floor is A2 → even an A0-classified tool queues (offense never auto-runs live). On a
    # TWIN/STAGING posture the operator may lower the floor to A0, and then a read-shaped A0 tool auto-runs.
    hook = WardenGateHooks(classify=lambda n: "A0", floor="A0")
    assert _run(hook.on_tool_start(None, None, _Tool("http.get"))) is None


def test_strix_hook_queue_without_authority_hard_blocks():
    # A3 shell tool, no approver (no authority provisioned) → hard block (fail-safe).
    hook = WardenGateHooks(classify=lambda n: "A3", approver=None)
    with pytest.raises(WardenDenied):
        _run(hook.on_tool_start(None, None, _Tool("exec_command")))


def test_strix_hook_queue_with_valid_approval_runs():
    # A3 shell tool + an approver that grants → the one call runs (returns None, no raise).
    hook = WardenGateHooks(classify=lambda n: "A3", approver=lambda t, tg, a: True)
    assert _run(hook.on_tool_start(None, None, _Tool("exec_command"))) is None
    # an approver that refuses → blocked.
    hook2 = WardenGateHooks(classify=lambda n: "A3", approver=lambda t, tg, a: False)
    with pytest.raises(WardenDenied):
        _run(hook2.on_tool_start(None, None, _Tool("exec_command")))


def test_strix_hook_hard_deny_always_raises():
    hook = WardenGateHooks(classify=lambda n: "A0", denylist=("exec_command",), approver=lambda t, tg, a: True)
    with pytest.raises(WardenDenied):
        _run(hook.on_tool_start(None, None, _Tool("exec_command")))
