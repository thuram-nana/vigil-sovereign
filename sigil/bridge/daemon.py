"""BridgeDaemon (Phase 7, WS-D D-v) — the desktop-side API the phone talks to over WireGuard. It
reuses the owner-signed cores: the queue (`approvals.pending` with the authorized-device set), a
DEVICE-signed approval (accepted only while that device is authorized), a PANIC halt (any engage is
fail-safe), and a KERNEL command relay (`KernelDispatch` → the same WARDEN gate as voice/UI).

This module is the bridge LIBRARY CORE + API (the doctrine + crypto). The network TRANSPORT — an
HTTP server over WireGuard, reusing the WS-C two-plane server pattern bound to a `bind_ok` address —
is a documented NEXT slice, not shipped here. `bind_ok` is the bind predicate that transport MUST
use: loopback or a PRIVATE (WireGuard) address only — NEVER 0.0.0.0 / a public address."""
from __future__ import annotations

import ipaddress
from typing import List, Optional

from ..spine.store import SpineStore


def bind_ok(addr: str) -> bool:
    """True iff `addr` is safe to bind: loopback or a PRIVATE (e.g. WireGuard) address — never
    0.0.0.0 / a public / an unspecified address."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_unspecified:                          # 0.0.0.0 / :: → refuse
        return False
    return ip.is_loopback or ip.is_private


class BridgeDaemon:
    def __init__(self, store: Optional[SpineStore] = None, *, trusted_pubkey: Optional[str] = None):
        from ..governor.identity import owner_pubkey
        self.store = store or SpineStore()
        # the owner trust anchor — the persisted identity by default (injectable for tests)
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def _authorized(self):
        from ..mesh import authorized_devices
        return authorized_devices(self.store, self.trusted_pubkey)

    def pending(self) -> List[dict]:
        """The phone-facing queue — minimal fields only (no subject leaks over the tunnel)."""
        from ..agents.approvals import pending
        items = pending(self.store, self.trusted_pubkey, extra_pubkeys=self._authorized())
        return [{"seq": r.seq, "tier": r.payload.get("tier"), "kind": r.kind} for r in items]

    def recall(self, subject: str) -> Optional[dict]:
        """Read-only remote RECALL — "where did I last see X?" — answered from the owner's own
        GROUNDED on-screen OCR history. Returns the perception-recall provenance dict VERBATIM
        (seq/entry_hash/when/frame_sha256/quote) or None: A0, read-only, no VLM and no paraphrase —
        the served `quote` is the owner's verbatim captured OCR line, never an advisory VLM lead.

        This surfaces the owner's own on-screen text over the tunnel, so it leaks MORE than
        `pending()`'s minimal {seq,tier,kind} fields. The network SERVER (a later slice) MUST
        therefore gate this behind an authorized-device (device-signed) read request; this daemon
        method is only the read-only core."""
        from ..perception.recall import recall
        return recall(self.store, subject)

    def submit_device_approval(self, payload: dict) -> int:
        """Append a DEVICE-signed approval the phone produced — ONLY if the signing device is
        currently authorized AND the signature verifies (fail-closed). A rogue/revoked device or a
        forged signature is refused; the signed target_seq binds (no replay)."""
        from ..agents.approvals import SIGNAL as APPROVAL_SIGNAL
        from ..agents.approvals import verify_approval

        class _Rec:
            def __init__(self, p): self.payload = p
        authorized = self._authorized()
        if payload.get("signal") != APPROVAL_SIGNAL:
            raise ValueError("not an approval record")
        if payload.get("pubkey") not in authorized:
            raise ValueError("signing device is not authorized")
        if not verify_approval(_Rec(payload), self.trusted_pubkey, extra_pubkeys=authorized):
            raise ValueError("approval signature invalid")
        return self.store.append(kind="event", source="mesh", actor="DEVICE",
                                 payload={**payload, "tier": "A0", "decision": "auto"},
                                 supersedes_id=payload.get("target_seq"))

    def panic_engage(self, *, by: str = "phone") -> int:
        """Halt the mesh from the phone. ANY engage halts (fail-safe) — no signature needed for the
        SAFE direction. Release stays owner-only at the desktop (the dangerous direction is signed)."""
        from ..governor.killswitch import SIGNAL as KS_SIGNAL
        return self.store.append(kind="event", source="mesh", actor="DEVICE",
                                 payload={"signal": KS_SIGNAL, "state": "engaged", "by": by,
                                          "reason": "panic halt from phone", "tier": "A0", "decision": "auto"})

    def relay(self, text: str) -> str:
        """Relay a KERNEL command — the same T0-router + WARDEN gate + signed action log as voice/UI."""
        from ..voice.dispatch import KernelDispatch
        return KernelDispatch().send(text)
