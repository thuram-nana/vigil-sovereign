"""Sign OFFENSE per-action approvals from the sovereign cockpit — the "route via sovereign plane" bridge.

The offense console is KEYLESS by design: it holds only the public approval-authority and polls
``<base>/approvals/signed/`` for a token an owner signed. Until now the only signer was the CLI
(``vigil approve sign``) reading ``VIGIL_APPROVAL_OWNER_KEY``; no screen could sign, so a queued Strix /
engage action could only be released from a terminal.

Operator choices this implements (see the approvals decision set):
  * KEY MODEL = unify on the sovereign key. The offense approval authority is pinned to the SAME owner
    keypair the cockpit already holds and signs governance with (``governor.identity``). ``bind_authority``
    persists that public key as the offense authority; ``sign_pending`` mints tokens with its private half.
  * SIGNING POSTURE = sign in-process on click. ``sign_pending`` uses the already-unsealed owner key
    directly, so one Approve click releases the action.

BOUNDARY (FATAL-2): this is sovereign-side and imports ONLY the import-clean, vigil_core+stdlib approval
primitives (``vigil_integration.live.approval_token`` / ``approval_broker`` — proven framework-free by
``integration/tests/test_two_env_boundary.py``); it touches no ``framework``/``strix`` module. The PRIVATE
key never leaves this process — only a signed token (public-safe) crosses the shared filesystem seam. The
offense broker still independently verifies the signature, the key-id pin, the action-binding, and burns
the single-use nonce (``approval_token.verify_token`` / ``nonce_ledger``), so a forged or replayed token
is refused regardless of what is dropped in ``signed/``.
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

# ttl for a signed offense token: the offense broker consumes it near-instantly once it appears (0.25s
# poll), so a short life is ample; capped by the token dead-man's bound (approval_token max_token_lifetime).
_TOKEN_TTL_SECONDS = 300.0


def _base_dir() -> str:
    """The shared engagement base dir both planes agree on (``vigil up`` sets VIGIL_BASE_DIR for both);
    matches the offense console's own resolution in ``console/api.approvals``."""
    return os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"


def _owner_keypair():
    from ..governor.identity import ensure_owner_keypair
    return ensure_owner_keypair()


def authority_status() -> dict:
    """Whether the offense approval authority is bound to THIS owner key (so cockpit signing will be
    accepted). Read-only; never raises. Used by the UI to show a one-time Bind action when needed."""
    from vigil_integration.live.approval_broker import load_authority
    kp = _owner_keypair()
    auth = load_authority(_base_dir())
    bound = bool(auth and auth.owner_public_key_b64 == kp.public_key_b64 and auth.owner_key_id == "owner")
    return {"bound": bound, "present": auth is not None,
            "owner_key_id": (auth.owner_key_id if auth else None)}


def bind_authority() -> dict:
    """Pin the offense approval authority to the cockpit owner key (owner_key_id='owner'), so tokens this
    cockpit signs are accepted by the offense broker. Idempotent. Writes ONLY the PUBLIC key under
    ``<base>/approval-authority.json`` (persist_authority validates fail-closed first)."""
    from vigil_integration.live.approval_broker import persist_authority
    kp = _owner_keypair()
    path = persist_authority(_base_dir(), owner_key_id="owner", owner_public_key_b64=kp.public_key_b64)
    return {"ok": True, "action": "offense_bind_authority", "authority_path": str(path)}


def list_offense_pending() -> dict:
    """The offense actions awaiting a signature (public-safe fields only). Read-only; total."""
    try:
        from vigil_integration.live.approval_broker import approvals_root, list_pending
        pend = [{"request_id": p.request_id, "tool_name": p.tool_name, "target": p.target,
                 "action_digest": p.action_digest, "args_preview": p.args_preview,
                 "created_at_iso": p.created_at_iso}
                for p in list_pending(approvals_root(_base_dir()))]
    except Exception:  # noqa: BLE001 — an absent/unreadable dir is simply "nothing pending"
        pend = []
    return {"ok": True, "base_dir": _base_dir(), "pending": pend}


def sign_pending(request_id: str, *, now: Optional[Any] = None) -> dict:
    """Approve ONE queued offense action: find its pending request, mint an owner-signed per-action token
    bound to its exact (tool_name, target, action_digest, nonce), and drop it in ``<base>/approvals/signed/``
    for the offense broker to verify + consume ONCE.

    Fail-closed: refuses if the authority is not bound to this owner key (the offense broker would reject
    the token anyway — refusing here gives an honest error instead of a silent no-op), and refuses an
    unknown/malformed request_id. The private key is used only inside ``mint_token`` and never written."""
    from vigil_integration.live.approval_broker import approvals_root, list_pending, write_signed_token
    from vigil_integration.live.approval_token import ApprovalAction, mint_token

    rid = str(request_id or "").strip()
    if not rid:
        return {"ok": False, "error": "no request_id"}
    base = _base_dir()
    kp = _owner_keypair()

    st = authority_status()
    if not st["bound"]:
        return {"ok": False, "error": "the offense approval authority is not bound to your owner key yet — "
                                      "bind it first (offense_bind_authority), then approve.",
                "needs_bind": True}

    match = None
    try:
        for p in list_pending(approvals_root(base)):
            if p.request_id == rid:
                match = p
                break
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"could not read the pending queue ({type(e).__name__})"}
    if match is None:
        return {"ok": False, "error": f"no pending offense approval with request_id {rid!r} "
                                      f"(it may have already been signed, consumed, or expired)"}

    t = float(now() if callable(now) else (now if now is not None else time.time()))
    action = ApprovalAction(tool_name=match.tool_name, target=match.target,
                            action_digest=match.action_digest)
    token = mint_token(action, owner_private_key_b64=kp.private_key_b64, key_id="owner",
                       nonce=match.nonce, not_before=t, not_after=t + _TOKEN_TTL_SECONDS)
    path = write_signed_token(approvals_root(base), rid, token)
    return {"ok": True, "action": "offense_approve", "request_id": rid,
            "tool_name": match.tool_name, "target": match.target, "signed_path": str(path)}


def deny_pending(request_id: str) -> dict:
    """Deny ONE queued offense action: remove its pending request so it clears from the queue. No token is
    ever written, so the offense broker finds none and the call is refused (fail-closed) — denying only
    removes the request the operator declined; it can never authorize anything. Total; safe on a
    path-validated request_id (a traversal attempt matches no pending and is a clean no-op)."""
    from vigil_integration.live.approval_broker import approvals_root, list_pending
    rid = str(request_id or "").strip()
    if not rid:
        return {"ok": False, "error": "no request_id"}
    base = _base_dir()
    removed = False
    try:
        root = approvals_root(base)
        for p in list_pending(root):        # match by CONTENT, then remove by the broker's own filename
            if p.request_id == rid:
                # the pending file is <root>/pending/<request_id>.json (approval_broker.publish_pending);
                # rebuild the path via the broker's own dir so we never join an attacker string.
                fp = root / "pending" / f"{p.request_id}.json"
                try:
                    fp.unlink()
                    removed = True
                except OSError:
                    pass
                break
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"could not read the pending queue ({type(e).__name__})"}
    return {"ok": True, "action": "offense_deny", "request_id": rid, "removed": removed}
