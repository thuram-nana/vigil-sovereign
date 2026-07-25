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
import time
from typing import List, Optional

from ..spine.store import SpineStore


_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")   # carrier-grade NAT — the range Tailscale assigns tailnet IPs
_ULA6 = ipaddress.ip_network("fc00::/7")          # IPv6 unique-local (Tailscale fd7a::/48, WireGuard fd…/…)
_LINKLOCAL6 = ipaddress.ip_network("fe80::/10")   # IPv6 link-local
_DEDUP_WINDOW = 2048                               # bound the replay-dedup scan to the most recent N records


def bind_ok(addr: str) -> bool:
    """True iff `addr` is safe to bind: loopback, an IPv4 PRIVATE (RFC1918) / Tailscale-CGNAT address, or an
    IPv6 unique-local (fc00::/7) / link-local (fe80::/10) address — i.e. a WireGuard/Tailscale tunnel or LAN
    address. NEVER 0.0.0.0/:: (unspecified) and NEVER a globally-routable address.

    For IPv6 we use a POSITIVE allowlist rather than ``is_private``: Python classifies the globally-routable
    transition ranges Teredo (2001::/32) and 6to4 (2002::/16) as private, so trusting ``is_private`` would let
    an AF_INET6 caller bind a routable address. Only loopback / ULA / link-local (the ranges a real tunnel
    uses) are permitted; everything else — global unicast, Teredo, 6to4, IPv4-mapped, documentation — refused."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_unspecified:                          # 0.0.0.0 / :: → refuse
        return False
    if ip.version == 6:
        return ip.is_loopback or ip in _ULA6 or ip in _LINKLOCAL6
    return ip.is_loopback or ip.is_private or ip in _CGNAT4


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
        sig, tgt = payload.get("sig"), payload.get("target_seq")
        # Best-effort dedup OUTSIDE the append lock (a rare concurrent double-record is benign; holding the
        # lock across the scan would stall every writer). Fold the cold-archive snapshot forward: SEED the
        # dedup map from the pruned prefix's folded {(pubkey,sig): min_seq}, then min-seq-fold the LIVE records
        # [base_seq..T] only — approvals carry no freshness field, so replay-bloat stays bounded to the number
        # of DISTINCT captured bodies (now split across the snapshot + the live tail). Not a pubkey-dependent
        # fold (the dedup step calls no verify), so no rotated-anchor genesis-bypass is needed here.
        # BYTE-IDENTICAL under the empty Slice-C snapshot: base_seq==0 => since_seq=-1 (the old full genesis
        # scan) and st_map seeds empty, and since iter_records yields ASCENDING seq the min-seq the map holds
        # for the incoming key is exactly the FIRST match the old loop returned.
        from ..spine.snapshot import SnapshotState
        st = SnapshotState.load(self.store)
        st_map = dict(st.approval_dedup_map())          # COPY — never mutate the cached snapshot
        for r in self.store.iter_records(since_seq=st.base_seq - 1):
            p = r.payload
            if p.get("signal") == APPROVAL_SIGNAL:
                key = (p.get("pubkey"), p.get("sig"))
                cur = st_map.get(key)
                if cur is None or r.seq < cur:
                    st_map[key] = r.seq
        hit = st_map.get((payload.get("pubkey"), sig))
        if hit is not None:
            return hit                                  # already recorded — idempotent
        return self.store.append(kind="event", source="mesh", actor="DEVICE",
                                 payload={**payload, "tier": "A0", "decision": "auto"}, supersedes_id=tgt)

    def submit_arm_request(self, request: dict, *, now: Optional[float] = None) -> int:
        """Record a DEVICE-signed gesture arm request (the transport layer) — ONLY if the signing device
        is authorized, the signature verifies, AND the signed `ts` is FRESH (fail-closed). The live
        SessionGate RE-VERIFIES and enforces freshness / kill-switch / single-session / TTL when it
        consumes this via `arm_by_device`, so recording is necessary-but-not-sufficient to arm.

        The record-time FRESHNESS gate is what BOUNDS replay-bloat: a captured body older than
        ARM_FRESHNESS is REFUSED (not recorded), so a rotated pool of captured bodies ages out and can
        never grow the spine unbounded. The bounded-window dedup below then just collapses a RAPID
        (within-freshness) replay flood — the two together bound bloat at O(window) cost."""
        import math

        from ..gesture.session import ARM_FRESHNESS, ARM_REQUEST, _ARM_CORE, arm_request_message
        from ..reuse import verify_one
        authorized = self._authorized()
        if request.get("signal") != ARM_REQUEST:
            raise ValueError("not an arm request")
        pub = request.get("pubkey")
        if pub not in authorized:
            raise ValueError("signing device is not authorized")
        assert pub is not None  # None is never in the owner-minted authorized set (all str pubkeys)
        core = {k: request.get(k) for k in _ARM_CORE}
        try:                                            # verify_one RAISES on a malformed-length sig — refuse cleanly
            ok = verify_one(pub, arm_request_message(core), request.get("sig", ""))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            raise ValueError("arm request signature invalid")
        now = time.time() if now is None else now       # record-time freshness bounds aged-out replay bloat
        ts_raw = core.get("ts")
        if ts_raw is None:                               # missing ts → invalid (was: float(None) TypeError below)
            raise ValueError("invalid arm timestamp")
        try:
            ts = float(ts_raw)
        except (TypeError, ValueError):
            raise ValueError("invalid arm timestamp")
        if not math.isfinite(ts) or not (abs(now - ts) <= ARM_FRESHNESS):
            raise ValueError("stale or non-finite arm request — refused (not recorded)")
        sig = request.get("sig")
        # Bounded-window dedup OUTSIDE the append lock: collapses a rapid within-freshness replay flood
        # (a flood is always recent). Aged-out replays are already refused above, so this need not scan
        # the whole spine to bound bloat.
        for r in self.store.tail(_DEDUP_WINDOW):
            p = r.payload
            if p.get("signal") == ARM_REQUEST and p.get("pubkey") == pub and p.get("sig") == sig:
                return r.seq                            # already recorded — idempotent
        # record ONLY the signed core + pubkey + sig (never `**request` — no unsigned extras persisted)
        return self.store.append(kind="event", source="mesh", actor="DEVICE",
                                 payload={"signal": ARM_REQUEST, "device_id": core["device_id"],
                                          "nonce": core["nonce"], "ts": core["ts"],
                                          "ttl_seconds": core["ttl_seconds"], "pubkey": pub, "sig": sig,
                                          "tier": "A0", "decision": "auto"})

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
