"""Device-signed, replay-resistant request envelope (Phase 9 W1-A) — the bridge auth keystone.

The phone (a device the owner AUTHORIZED via `sigil.mesh.authorize_device`) signs EACH request to the
desktop bridge with ITS OWN Ed25519 key over the canonical envelope core. There is NO wire bearer
secret: authentication IS the signature, verified against the owner-minted authorized-device set. This
mirrors the approval-record pattern (`agents.approvals._approval_message` / `verify_approval`) — same
canonical-JSON message, same fail-closed `verify_one`, same trust pinned to owner-minted device keys
(a rogue/revoked device cannot self-authorize; a tampered field breaks the signature).

Replay resistance is a deterministic, spine-anchored monotonic-nonce highwater PER DEVICE: an effectful
request must carry a nonce strictly greater than the highest nonce that device has ever been receipted
for. Reads still receipt (advancing the watermark) but skip the freshness gate (they have no side
effect). The receipt is an append-only spine event, so the watermark is tamper-evident memory.

This module is PURE by construction — NO wallclock, NO RNG. The caller supplies `nonce` and `ts` so the
JS phone client and Python reproduce the exact signed bytes (the parity contract) and so freshness is a
deterministic function of the spine. A wallclock timestamp-WINDOW check (is `ts` recent?) belongs to
the server transport layer, not here. Offense-free."""
from __future__ import annotations

from typing import Set, Tuple, Union

from ..reuse import canonical_json, sign, verify_one
from ..spine.store import SpineStore

# The request vocabulary the bridge accepts — a fail-closed allow-list. `panic`/`relay` are effectful;
# the `read:*` family is side-effect-free. An action outside this set is refused even if validly signed.
ACTIONS = frozenset({"panic", "relay", "read:snapshot", "read:pending", "read:record",
                     "read:stream", "read:recall"})

# The spine signal marking a consumed request. Its records form the per-device nonce highwater.
RECEIPT_SIGNAL = "mesh.request"


def envelope_message(core: dict) -> bytes:
    """The exact bytes signed/verified — canonical JSON of the core. This is the JS<->Python parity
    contract: a future JS client MUST produce these identical bytes. Mirrors
    `agents.approvals._approval_message` (return bytes; encode only if `canonical_json` gave a str)."""
    m = canonical_json(core)
    return m if isinstance(m, bytes) else m.encode()


def build_core(device_pubkey: str, action: str, args: dict, nonce, ts) -> dict:
    """The signed core. `nonce`/`ts` are caller-supplied (this module never reads a clock or RNG)."""
    return {"v": 1, "device": device_pubkey, "action": action, "args": args, "nonce": nonce, "ts": ts}


def sign_envelope(device_key, core: dict) -> dict:
    """Phone/test side: attach a DEVICE signature over the canonical core, producing the wire payload."""
    return {**core, "sig": sign(device_key.private_key_b64, envelope_message(core))}


def verify_envelope(payload, authorized: Set[str]) -> Tuple[bool, Union[dict, str]]:
    """Fail-closed authentication. Rebuild the core (payload minus `sig`); refuse if there is no sig /
    no device / the device is not in the owner-minted authorized set; then Ed25519-verify the signature
    over the canonical core; finally require the (now-authenticated) action to be in the `ACTIONS`
    allow-list. Mirrors `agents.approvals.verify_approval`. Returns (True, core) or (False, reason)."""
    p = payload.payload if hasattr(payload, "payload") else payload
    sig = p.get("sig")
    device = p.get("device")
    if not sig or not device:
        return False, "missing signature or device"
    if device not in authorized:                       # trust pinned to owner-minted device keys
        return False, "device is not authorized"
    core = {k: v for k, v in p.items() if k != "sig"}
    if not verify_one(device, envelope_message(core), sig):
        return False, "signature invalid"
    if core.get("action") not in ACTIONS:              # allow-list the authenticated action (fail-closed)
        return False, f"unknown action: {core.get('action')!r}"
    return True, core


def record_receipt(store: SpineStore, core: dict) -> int:
    """Append the append-only consumption receipt. Carries only the routing fields — never `args`
    (which may hold a subject) and never the signature; the record is auto-tier (an A0 event)."""
    return store.append(kind="event", source="mesh", actor="DEVICE",
                        payload={"signal": RECEIPT_SIGNAL, "device": core["device"],
                                 "action": core["action"], "nonce": core["nonce"],
                                 "ts": core["ts"], "tier": "A0", "decision": "auto"})


def device_nonce_highwater(store: SpineStore, device_pubkey: str) -> int:
    """The highest receipted nonce for this device (0 if none). Non-int nonces are tolerated (skipped)."""
    hi = 0
    for r in store.iter_records():
        p = r.payload
        if p.get("signal") == RECEIPT_SIGNAL and p.get("device") == device_pubkey:
            try:
                n = int(p.get("nonce"))
            except (TypeError, ValueError):
                continue
            if n > hi:
                hi = n
    return hi


def consume(store: SpineStore, payload, authorized: Set[str], *, effectful: bool) -> dict:
    """Authenticate, gate replay for effectful requests, receipt, return the core. Raises `ValueError`
    with the refusal reason on any failure (fail-closed). An effectful request requires a nonce strictly
    fresher than this device's highwater; a read skips that gate but still receipts (advancing it)."""
    ok, core = verify_envelope(payload, authorized)
    if not ok:
        raise ValueError(core)
    if effectful and int(core["nonce"]) <= device_nonce_highwater(store, core["device"]):
        raise ValueError("replay: nonce not fresh")
    record_receipt(store, core)
    return core
