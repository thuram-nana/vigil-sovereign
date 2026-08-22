"""Per-capability governed latch (SIGIL) — disable/enable gesture control and voice control with a
tamper-evident, owner-signed, append-only spine record instead of an unsigned `sigil.env` flag (the exact
attacker-writable hole G2's signed security manifest was built to close).

ASYMMETRIC AUTHENTICATION, mirroring the kill switch (`killswitch.py`): DISABLING a capability is always
the SAFE direction, so ANY `state:"disabled"` record takes effect (even unsigned — a forged/nuisance
disable is at worst a fail-safe DoS on that capability). RE-ENABLING is the dangerous direction, so an
`enabled` record is honored ONLY if it carries a valid OWNER signature over its core (a forged enable can
never revive a disabled capability). The DEFAULT (no record) is ENABLED — behavior-identical to today's
no-flag state — and a spine READ ERROR resolves to DISABLED (fail-closed toward the safe direction).
`capability` is inside the signed core, so an owner-signed `enable(voice)` can never be replayed as
`enable(gesture)`, and the distinct `signal` string domain-separates it from the kill-switch / promotion /
offense-gate signals. State is re-derived per check (rotation-aware change-token cache) so a toggle takes
effect within ~1-2 frames on the gesture loop; the pruned-prefix fold (snapshot `capability_latch`) keeps a
pruned `disable` from silently failing open, exactly like the kill-switch fold.

ANTI-REPLAY (this slice): `capability` in the core stops an `enable(voice)` being re-aimed at `gesture`,
but it never stopped that enable being re-appended VERBATIM at ITS OWN capability. Anyone who could
append to the spine could capture an owner-signed `enable(gesture)`, wait for the owner to disable
gesture, and re-append the captured bytes — genuine signature, cleanly-extending hash chain, capability
back on. So `issued_at` joins the signed core and the fold keeps a PER-CAPABILITY high-water: an enable
counts only while its `issued_at` strictly exceeds every enable already honored FOR THAT CAPABILITY.
Per-capability and not global, or a fresh `enable(voice)` would refuse a legitimate later
`enable(gesture)` that happened to carry a smaller `issued_at`. The SAFE direction (disable) keeps NO
freshness requirement and stays honored even unsigned — gating it would make a fail-safe fail open."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from ..spine.snapshot import SnapshotState
from . import key_history as _kh
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.capability"
# gesture / voice are physical-input capabilities; `autolearn` gates the Knowledge Engine's
# propose-to-learn drafting (K2). All three share the identical owner-signed latch semantics below:
# default ENABLED, disable is the fail-safe (unsigned) direction, re-enable requires an owner signature.
# `autolearn` enabled only permits DRAFTING/showing learn proposals — it never learns, applies, or mints
# a fact; each proposal still needs the owner's signed ACCEPT.
CAPABILITIES = frozenset({"gesture", "voice", "autolearn"})
# `issued_at` MUST be in the core: outside it, an attacker could re-stamp a captured enable's freshness
# past the high-water without breaking the signature — precisely the replay this guard refuses.
_CORE = ("signal", "capability", "state", "issued_at")

# Cache the authoritative per-capability verdict keyed by (resolved spine path, trusted pubkey, capability)
# with the store's ROTATION-AWARE change token, exactly as `killswitch._STATE_CACHE`: a disable/enable
# APPENDS a record → the token moves → the cache invalidates and the real owner-signed-enable-verifying scan
# re-runs; a matching token ⇒ no new records ⇒ the cached verdict is exact. Keyed on the pubkey so instances
# with different trust roots never share an entry. The FAIL-CLOSED error path is NEVER cached (a transient
# read error must not poison the cache into serving a stale disabled/enabled verdict).
_CAP_CACHE: dict[tuple[str, Optional[str], str], tuple[tuple, bool]] = {}
_CACHE_GUARD = threading.Lock()


class CapabilityGate:
    """The per-capability enable/disable latch. Constructor contract mirrors `KillSwitch`/`PromotionPolicy`:
    defaults the owner key / trusted pubkey from the persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    @staticmethod
    def _check(capability: str) -> str:
        if capability not in CAPABILITIES:
            raise ValueError(f"unknown capability {capability!r} (expected one of {sorted(CAPABILITIES)})")
        return capability

    def disable(self, capability: str, *, by: str = "owner", reason: str = "") -> int:
        """Disable a capability. Owner-signed for provenance/audit, but takes effect regardless of the
        signature — disabling is the SAFE direction. Carries a FIXED `issued_at` of 0.0: no freshness is
        required or checked here (a replayed disable merely re-disables), and the constant keeps the
        record signature-valid under the new core so its provenance still verifies."""
        core = {"signal": SIGNAL, "capability": self._check(capability), "state": "disabled",
                "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto",
                   "summary": f"capability {capability} DISABLED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def enable(self, capability: str, *, issued_at: float, by: str = "owner", reason: str = "") -> int:
        """Re-enable a capability — the DANGEROUS direction. Only meaningful if it verifies against the
        trusted owner key (a forged enable never revives a disabled capability) AND its `issued_at`
        strictly exceeds every enable already honored for THIS capability (a replayed one never does).
        `issued_at` is a required, owner-set, strictly-increasing value: this module reads no clock, so
        the authority over "when" stays with the caller holding the owner key."""
        core = {"signal": SIGNAL, "capability": self._check(capability), "state": "enabled",
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto",
                   "summary": f"capability {capability} ENABLED (owner-signed)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def is_enabled(self, capability: str) -> bool:
        """True iff `capability` is currently enabled. Cheap when the spine is unchanged since the last
        authoritative scan (matching change token). FAIL-CLOSED: any read/scan error → DISABLED (the safe
        direction), and the error path is never cached."""
        self._check(capability)
        try:
            token = self.store.change_token()
        except Exception:  # noqa: BLE001 — cannot even read the store ⇒ fail-closed toward disabled
            return False
        key = (str(Path(self.store.path).resolve()), self.trusted_pubkey, capability)
        with _CACHE_GUARD:
            cached = _CAP_CACHE.get(key)
            if cached is not None and cached[0] == token:
                return cached[1]
        try:
            enabled = self._scan_enabled(capability)
        except Exception:  # noqa: BLE001 — a hostile/corrupt spine must never crash the caller; fail-closed
            return False
        with _CACHE_GUARD:
            _CAP_CACHE[key] = (token, enabled)
        return enabled

    def is_disabled(self, capability: str) -> bool:
        return not self.is_enabled(capability)

    def state_all(self) -> dict[str, str]:
        """{capability: "enabled"|"disabled"} for the read plane / status output."""
        return {c: ("enabled" if self.is_enabled(c) else "disabled") for c in sorted(CAPABILITIES)}

    def _scan_enabled(self, capability: str) -> bool:
        """The AUTHORITATIVE scan: default ENABLED; honor ANY disable (fail-safe); re-enable only on an
        OWNER-SIGNED enable that verifies (fail-closed). Hard-prune fold (mirrors the kill-switch): seed from
        the folded snapshot prefix and fold only the LIVE window forward. The latch is PUBKEY-DEPENDENT (an
        enable re-enables only under the trusted pubkey it verifies against), so a caller whose trust anchor
        differs from the snapshot's bypasses the fold and re-scans from genesis. Byte-identical to a genesis
        scan under the Slice-C empty snapshot (base_seq==0, capability_latch=[]).

        The anti-replay high-water for THIS capability is seeded from the SAME snapshot under the SAME
        pubkey condition. It has to be: re-seeded to the bottom on every call, the first hard prune would
        make every enable in the pruned prefix replayable again."""
        st = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)  # W9-1 succession-aware
        if self.trusted_pubkey != st.trusted_pubkey:
            enabled = True                          # pubkey mismatch: folded latch invalid → genesis rescan
            since_seq = -1
            max_issued = NO_HIGHWATER               # ...and so is the folded high-water — restart it too
        else:
            enabled = st.capability_latch_map().get(capability, True)   # seed from the folded prefix (default on)
            since_seq = st.base_seq - 1
            # PER-CAPABILITY high-water: a missing row means no enable was honored for this capability in
            # the pruned prefix. Never a shared/global one — an enable(voice) must not refuse a legitimate
            # later enable(gesture) that carries a smaller issued_at.
            max_issued = st.capability_issued_map().get(capability, NO_HIGHWATER)
        for r in self.store.iter_records(since_seq=since_seq):
            p = r.payload
            if p.get("signal") != SIGNAL or p.get("capability") != capability:
                continue
            state = p.get("state")
            if state == "disabled":
                enabled = False                     # honor ANY disable — disabling is fail-safe
            elif state == "enabled" and verify_signed(p, _CORE, resolver.at(r.seq)):
                issued = as_issued_at(p.get("issued_at"))
                if issued <= max_issued:
                    continue                        # REPLAY / stale re-append of an already-honored enable
                max_issued = issued                 # consume it so its own replay is refused hereafter
                enabled = True                      # only an OWNER-SIGNED, FRESH enable re-enables
        return enabled
