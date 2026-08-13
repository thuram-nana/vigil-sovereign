"""The mesh registry (Phase 7, WS-D). Two owner-signed ledgers on the one spine:

  • host_capability — each host advertises {os, screen, camera, gpu_vlm, always_on}, owner-signed, so
    an agent can route work to the best-capable ONLINE host from cited, tamper-evident records.
  • device authorization — a 1-of-N device ledger: the owner AUTHORIZES a phone's own Ed25519 device
    key with a signed `device_authorized` record (and `device_revoked` to remove it). The phone then
    approves A2/A3 items by signing with ITS key; `verify_approval(..., extra_pubkeys=authorized)`
    accepts it. Trust is pinned to owner-MINTED keys (RP-APPROVAL-2); the phone never holds the
    trust-root key, and can approve offline.

All reads are fail-closed: a descriptor/authorization that does not verify against the owner key is
ignored. Reuses `governor.authn` (the same signed-event primitive kill/promotion/approval use).

ANTI-REPLAY (this slice): the device ledger is the most dangerous of the last-writer-wins governance
records, because `authorized_devices()` IS the `extra_pubkeys` allowlist for A2/A3 approval
(`agents/approvals.py`), gesture remote-arm (`gesture/session.py`), the bridge daemon
(`bridge/server.py`), the actor gate (`agents/actor_gate.py`), the operator gate (`agents/operator.py`)
and the egress gate (`perception/egress.py`). Verifying the signature proved WHO authorized a device,
never WHEN that authorization counts — so anyone able to append could capture an owner-signed
`authorized`, wait for the owner to REVOKE that phone (lost, stolen, sold), then re-append the captured
bytes verbatim and re-arm a full approval identity across every one of those consumers at once. So
`issued_at` joins the signed device core and `authorized_devices` keeps a PER-DEVICE-PUBKEY high-water.
`revoked` — the safe direction — keeps NO freshness requirement, so a revoke always lands and its own
replay merely re-revokes.

The host_capability ledger carries the same guard, per host_id. It has NO safe direction — an
advertisement is the only transition — so freshness gates every one: a captured advertisement replayed
after the host truthfully re-advertises FEWER capabilities would otherwise resurrect the withdrawn ones
(`has_hid_inject` / `has_camera_stream` are the ones that route real HID injection and camera streaming
to a host), and one replayed at a host that had downgraded would silently re-route work to it."""
from __future__ import annotations

from typing import Optional, Set

from ..agents.approvals import SIGNAL as _APPROVAL_SIGNAL
from ..agents.approvals import _approval_message
from ..governor.authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed
from ..governor.identity import owner_pubkey
from ..reuse import sha256_hex, sign
from ..spine.snapshot import SnapshotState
from ..spine.store import SpineStore

CAP_SIGNAL = "mesh.host_capability"
DEV_SIGNAL = "mesh.device"
# `issued_at` MUST be inside each core: outside it, an attacker could re-stamp a captured record's
# freshness past the high-water without breaking the signature — exactly the replay this guard refuses.
_CAP_CORE = ("signal", "host_id", "os", "has_screen", "has_camera", "has_gpu_vlm", "always_on",
             "has_hid_inject", "has_camera_stream", "issued_at")
_DEV_CORE = ("signal", "state", "device_id", "device_pubkey", "issued_at")
# The advertised descriptor a consumer sees: the signed core MINUS the two bookkeeping fields. Defined
# once and used by BOTH `capability_map` and `snapshot.build()`, so the projected shape cannot drift
# between the live scan and the pruned-prefix fold (and so adding `issued_at` to the core did not
# silently change what `capability_map` returns).
_CAP_DESCRIPTOR_FIELDS = tuple(k for k in _CAP_CORE if k not in ("signal", "issued_at"))


def cap_descriptor(payload: dict) -> dict:
    return {k: payload.get(k) for k in _CAP_DESCRIPTOR_FIELDS}


# --- host capability advertisement -----------------------------------------------------------------
def advertise_capability(store: SpineStore, descriptor: dict, owner_key, *, issued_at: float) -> int:
    """Advertise a host's capabilities. `issued_at` is a REQUIRED, owner-set, strictly-increasing value:
    `capability_map` honors this advertisement only while it exceeds every one already honored for THIS
    host_id. Unlike the other four ledgers this one has NO safe direction — an advertisement is the only
    transition — so freshness gates every record, or a captured richer advertisement could be replayed to
    resurrect capabilities the host has since truthfully withdrawn. Required rather than defaulted: this
    module reads no clock, so "when" is the caller-with-the-owner-key's authority."""
    core = {"signal": CAP_SIGNAL, "host_id": descriptor["host_id"], "os": descriptor["os"],
            "has_screen": bool(descriptor["has_screen"]), "has_camera": bool(descriptor["has_camera"]),
            "has_gpu_vlm": bool(descriptor["has_gpu_vlm"]), "always_on": bool(descriptor["always_on"]),
            "has_hid_inject": bool(descriptor.get("has_hid_inject", False)),
            "has_camera_stream": bool(descriptor.get("has_camera_stream", False)),
            "issued_at": float(issued_at)}
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
        # PER-HOST_ID advertisement high-water, seeded from the SAME snapshot under the SAME pubkey
        # condition — otherwise the first hard prune would reset it and make every pruned advertisement
        # replayable. Per host and never global: one host's fresh advertisement must not refuse another
        # host's legitimate later one that carried a smaller issued_at.
        issued = dict(st.capability_map_issued_map())
    else:
        latest, since, issued = {}, -1, {}
    for r in store.iter_records(since_seq=since):
        p = r.payload
        if p.get("signal") == CAP_SIGNAL and verify_signed(p, _CAP_CORE, tp):
            hkey = p.get("host_id")
            at = as_issued_at(p.get("issued_at"))
            if at <= issued.get(hkey, NO_HIGHWATER):
                continue                            # REPLAY / stale re-append of an already-honored advert
            issued[hkey] = at                       # consume it so its own replay is refused hereafter
            latest[hkey] = cap_descriptor(p)
    return latest


# --- device authorization ledger -------------------------------------------------------------------
def authorize_device(store: SpineStore, device_id: str, device_pubkey: str, owner_key,
                     *, issued_at: float) -> int:
    """Authorize a device key — the DANGEROUS direction, and the one that hands out an approval identity.
    `issued_at` is a REQUIRED, owner-set, strictly-increasing value: `authorized_devices` honors this
    record only while it exceeds every authorization already honored for THIS device pubkey, so a replay
    of it after a revoke never re-arms the device. Required rather than defaulted because this module
    reads no clock — "when" is the caller-with-the-owner-key's authority, not the module's."""
    core = {"signal": DEV_SIGNAL, "state": "authorized", "device_id": device_id,
            "device_pubkey": device_pubkey, "issued_at": float(issued_at)}
    payload = {**signed_payload(core, owner_key), "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="mesh", actor="OWNER", payload=payload)


def revoke_device(store: SpineStore, device_id: str, device_pubkey: str, owner_key) -> int:
    """Revoke a device key — the SAFE direction. Carries a FIXED `issued_at` of 0.0 and is subject to NO
    freshness check: a revoke must ALWAYS land (it is how a lost phone is disarmed) and its own replay
    merely re-revokes. The constant keeps the record signature-valid under the new core."""
    core = {"signal": DEV_SIGNAL, "state": "revoked", "device_id": device_id,
            "device_pubkey": device_pubkey, "issued_at": 0.0}
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
        # PER-DEVICE-PUBKEY authorization high-water, seeded from the SAME snapshot under the SAME pubkey
        # condition — otherwise the first hard prune would reset it and make every pruned authorization
        # replayable. Per device and never global: one phone's fresh authorization must not refuse another
        # phone's legitimate later one that carried a smaller issued_at.
        issued = dict(st.mesh_dev_issued_map())
    else:
        state, since, issued = {}, -1, {}
    for r in store.iter_records(since_seq=since):
        p = r.payload
        if p.get("signal") == DEV_SIGNAL and p.get("state") in ("authorized", "revoked") \
                and verify_signed(p, _DEV_CORE, tp):
            dkey = p.get("device_pubkey")
            if p["state"] == "authorized":
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(dkey, NO_HIGHWATER):
                    continue                            # REPLAY / stale re-append — the device stays revoked
                issued[dkey] = at                       # consume it so its own replay is refused hereafter
            state[dkey] = p["state"]                    # latest verified (and, if authorized, FRESH) wins
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
