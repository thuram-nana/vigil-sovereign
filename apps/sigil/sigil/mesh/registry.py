"""The mesh registry (Phase 7, WS-D). Two owner-signed ledgers on the one spine:

  • host_capability — each host advertises {os, screen, camera, gpu_vlm, always_on}, owner-signed, so
    an agent can route work to the best-capable ONLINE host from cited, tamper-evident records.
  • device authorization — a 1-of-N device ledger: the owner AUTHORIZES a phone's own Ed25519 device
    key with a signed `device_authorized` record (and `device_revoked` to remove it). The phone then
    approves A2/A3 items by signing with ITS key; `verify_approval(..., extra_pubkeys=authorized)`
    accepts it. Trust is pinned to owner-MINTED keys (RP-APPROVAL-2); the phone never holds the
    trust-root key, and can approve offline.

All reads are fail-closed: a descriptor/authorization that does not verify against the owner key is
ignored. Reuses `governor.authn` (the same signed-event primitive kill/promotion/approval use)."""
from __future__ import annotations

from typing import Optional, Set

from ..agents.approvals import SIGNAL as _APPROVAL_SIGNAL
from ..agents.approvals import _approval_message
from ..governor.authn import signed_payload, verify_signed
from ..governor.identity import owner_pubkey
from ..reuse import sha256_hex, sign
from ..spine.snapshot import SnapshotState
from ..spine.store import SpineStore

CAP_SIGNAL = "mesh.host_capability"
DEV_SIGNAL = "mesh.device"
_CAP_CORE = ("signal", "host_id", "os", "has_screen", "has_camera", "has_gpu_vlm", "always_on",
             "has_hid_inject", "has_camera_stream")
_DEV_CORE = ("signal", "state", "device_id", "device_pubkey")


# --- host capability advertisement -----------------------------------------------------------------
def advertise_capability(store: SpineStore, descriptor: dict, owner_key) -> int:
    core = {"signal": CAP_SIGNAL, "host_id": descriptor["host_id"], "os": descriptor["os"],
            "has_screen": bool(descriptor["has_screen"]), "has_camera": bool(descriptor["has_camera"]),
            "has_gpu_vlm": bool(descriptor["has_gpu_vlm"]), "always_on": bool(descriptor["always_on"]),
            "has_hid_inject": bool(descriptor.get("has_hid_inject", False)),
            "has_camera_stream": bool(descriptor.get("has_camera_stream", False))}
    payload = {**signed_payload(core, owner_key), "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="mesh", actor="OWNER", payload=payload)


def capability_map(store: SpineStore, trusted_pubkey: Optional[str] = None) -> dict:
    """Latest VERIFIED capability per host_id (forged/unsigned advertisements ignored)."""
    tp = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
    st = SnapshotState.load(store)
    # Fold the pruned prefix's folded summary forward over LIVE records only (right-biased LWW is
    # associative, so fold(prefix)+fold(live) == the old genesis scan). Empty snapshot (Slice C):
    # base_seq==0 => since_seq=-1 (a full genesis scan) + empty seed => BYTE-IDENTICAL to the old scan.
    # Pubkey-dependent fold: if the caller's trust anchor != the one the snapshot was folded under, the
    # pre-fold is invalid, so BYPASS it and re-scan from genesis (seed empty, since=-1).
    if tp == st.trusted_pubkey:
        latest, since = dict(st.capability_map), st.base_seq - 1
    else:
        latest, since = {}, -1
    for r in store.iter_records(since_seq=since):
        p = r.payload
        if p.get("signal") == CAP_SIGNAL and verify_signed(p, _CAP_CORE, tp):
            latest[p.get("host_id")] = {k: p.get(k) for k in _CAP_CORE if k != "signal"}
    return latest


# --- device authorization ledger -------------------------------------------------------------------
def authorize_device(store: SpineStore, device_id: str, device_pubkey: str, owner_key) -> int:
    core = {"signal": DEV_SIGNAL, "state": "authorized", "device_id": device_id, "device_pubkey": device_pubkey}
    payload = {**signed_payload(core, owner_key), "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="mesh", actor="OWNER", payload=payload)


def revoke_device(store: SpineStore, device_id: str, device_pubkey: str, owner_key) -> int:
    core = {"signal": DEV_SIGNAL, "state": "revoked", "device_id": device_id, "device_pubkey": device_pubkey}
    payload = {**signed_payload(core, owner_key), "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="mesh", actor="OWNER", payload=payload)


def authorized_devices(store: SpineStore, trusted_pubkey: Optional[str] = None) -> Set[str]:
    """The set of currently-authorized device pubkeys (owner-signed authorize, minus later revoke).
    An unsigned/forged authorization is ignored — a rogue device cannot self-authorize."""
    tp = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
    st = SnapshotState.load(store)
    # Fold the pruned prefix's folded device-authz summary forward over LIVE records only (per-device LWW,
    # keeping revoked, is associative, so fold(prefix)+fold(live) == the old genesis scan). Empty snapshot
    # (Slice C): base_seq==0 => since_seq=-1 (a full genesis scan) + empty seed => BYTE-IDENTICAL to the old
    # scan. Pubkey-dependent fold: if the caller's trust anchor != the one the snapshot was folded under, the
    # pre-fold is invalid, so BYPASS it and re-scan from genesis (seed empty, since=-1).
    if tp == st.trusted_pubkey:
        state, since = dict(st.mesh_dev_state), st.base_seq - 1   # COPY the cached sub-state; never mutate it
    else:
        state, since = {}, -1
    for r in store.iter_records(since_seq=since):
        p = r.payload
        if p.get("signal") == DEV_SIGNAL and p.get("state") in ("authorized", "revoked") \
                and verify_signed(p, _DEV_CORE, tp):
            state[p.get("device_pubkey")] = p["state"]      # latest verified state per device key
    return {pub for pub, st in state.items() if st == "authorized"}


class DeviceApprover:
    """Signs an approval with a DEVICE key (the phone). The record verifies via
    `verify_approval(record, owner_pubkey, extra_pubkeys=authorized_devices(store))` — i.e. only while
    the device remains authorized. Never touches the owner trust-root key."""
    def __init__(self, store: SpineStore, *, device_key):
        self.store = store
        self.device_key = device_key

    def _decide(self, seq: int, decision: str, approver: str, reason: str) -> int:
        msg = _approval_message(seq, decision, approver)
        sig = sign(self.device_key.private_key_b64, msg)
        payload = {"signal": _APPROVAL_SIGNAL, "approval": decision, "target_seq": seq,
                   "approver": approver, "reason": reason, "pubkey": self.device_key.public_key_b64,
                   "sig": sig, "msg_digest": sha256_hex(msg), "device": True, "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="mesh", actor="DEVICE", payload=payload, supersedes_id=seq)

    def approve(self, seq: int, *, approver: str = "device", reason: str = "") -> int:
        return self._decide(seq, "approved", approver, reason)

    def deny(self, seq: int, *, approver: str = "device", reason: str = "") -> int:
        return self._decide(seq, "denied", approver, reason)
