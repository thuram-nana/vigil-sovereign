"""The owner-signed action broker (Phase 7, WS-C C-v) — the single funnel for every gated action the
UI (and later the mobile bridge) can trigger. The browser never holds key material: it sends an
authenticated REQUEST ("approve seq N"), and the SERVER signs with the persisted owner key exactly
as `cli.cmd_warden`/`cmd_approve` do. No new authority path — this only calls the existing
owner-signed cores (`ApprovalQueue`, `KillSwitch`, `PromotionPolicy`)."""
from __future__ import annotations

from typing import Optional

from ..spine.store import SpineStore

# the closed set of gated actions the plane will route (fail-closed: anything else is refused)
_CAP_ACTIONS = frozenset({"disable_gesture", "enable_gesture", "disable_voice", "enable_voice",
                          "disable_both", "enable_both"})
ACTIONS = frozenset({"approve", "deny", "kill", "release", "promote", "revoke"}) | _CAP_ACTIONS


def do_action(action: str, params: dict, *, store: Optional[SpineStore] = None) -> dict:
    """Perform one owner-signed action. Returns {seq, action, ...} or raises ValueError/ApprovalError.
    The owner key is the persisted identity (auto-created once) — never supplied by the caller."""
    if action not in ACTIONS:
        raise ValueError(f"unknown action: {action!r}")
    store = store or SpineStore()
    from ..agents.approvals import ApprovalQueue
    from ..governor import KillSwitch, PromotionPolicy
    from ..governor.identity import ensure_owner_keypair
    owner = ensure_owner_keypair()
    reason = str(params.get("reason", ""))[:200]

    if action in ("approve", "deny"):
        seq = int(params["seq"])
        q = ApprovalQueue(store, owner_key=owner)
        out = q.approve(seq, reason=reason) if action == "approve" else q.deny(seq, reason=reason)
        return {"ok": True, "action": action, "target_seq": seq, "recorded_seq": out}
    if action in ("kill", "release"):
        ks = KillSwitch(store, owner_key=owner)
        out = ks.engage(reason=reason) if action == "kill" else ks.release(reason=reason)
        return {"ok": True, "action": action, "recorded_seq": out}
    if action in ("promote", "revoke"):
        pp = PromotionPolicy(store, owner_key=owner)
        agent, scope = str(params["agent"]), str(params.get("scope", "*"))
        out = pp.grant(agent, scope) if action == "promote" else pp.revoke(agent, scope)
        return {"ok": out is not None, "action": action, "agent": agent, "scope": scope, "recorded_seq": out}
    if action in _CAP_ACTIONS:
        from ..governor import CAPABILITIES, CapabilityGate
        cg = CapabilityGate(store, owner_key=owner)
        verb, _, which = action.partition("_")          # ("disable","","gesture") / ("enable","","both")
        caps = sorted(CAPABILITIES) if which == "both" else [which]
        seqs = {c: (cg.disable(c, reason=reason) if verb == "disable" else cg.enable(c, reason=reason))
                for c in caps}
        return {"ok": True, "action": action, "capabilities": caps, "recorded_seqs": seqs}
    raise ValueError(f"unhandled action: {action!r}")   # unreachable (ACTIONS-gated)
