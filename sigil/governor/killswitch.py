"""The kill switch (SIGIL §5) — a single latch that halts the agent mesh while leaving perception and
memory-read (A0 observe) alive. State is append-only on the spine.

ASYMMETRIC AUTHENTICATION (Phase 6 red-pen RP-2): halting is always the safe direction, so ANY
engage event halts (a nuisance forged-engage is at worst a fail-safe DoS). UN-halting is the
dangerous direction, so a RELEASE is honored ONLY if it is signed by the owner key and verifies
against the trusted pubkey — a forged release can never revive a halted mesh. Read fresh per decision
so a release (or engage) takes effect immediately."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from ..spine.snapshot import SnapshotState
from .authn import signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.killswitch"
_CORE = ("signal", "state")

# FIX 4 (audit CRITICAL): `is_engaged()` full-scans the spine on EVERY governor decision, so a batch of
# proposals is O(proposals × spine). Cache the authoritative verdict keyed by (resolved spine path,
# trusted pubkey) with the store's ROTATION-AWARE CHANGE TOKEN it was computed at. Every engage/release
# APPENDS a record → the token changes → the cache invalidates and we re-run the real, owner-signed-
# release-verifying scan. A matching token ⇒ no new records ⇒ the cached verdict is exact. The token
# (invariant 9 / A4) keys on the manifest generation + the resolved ACTIVE segment (size, inode), NOT a
# bare `store.path.stat()` — which would raise/freeze once a migration renames spine.jsonl away and then
# serve a STALE (un-halting) verdict indefinitely. Keyed on the pubkey too, so instances with different
# trust roots never share an entry. Shared across ALL callers on a path.
_STATE_CACHE: dict[tuple[str, Optional[str]], tuple[tuple, bool]] = {}
_CACHE_GUARD = threading.Lock()


class KillSwitch:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def engage(self, *, by: str = "owner", reason: str = "") -> int:
        core = {"signal": SIGNAL, "state": "engaged"}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def release(self, *, by: str = "owner", reason: str = "") -> int:
        core = {"signal": SIGNAL, "state": "released"}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def is_engaged(self) -> bool:
        """Cheap, correct kill-switch verdict (FIX 4). Cheap when the spine is unchanged since the last
        authoritative scan (a matching rotation-aware change token); a changed token — a new engage/release
        record, or a migration/rotation that moved the active segment — re-runs the real scan below and
        refreshes the shared cache. Semantics are IDENTICAL to a fresh scan, and (unlike a bare file-size
        check) a migration that renames spine.jsonl away can never freeze the token and serve a stale
        un-halting verdict."""
        key = (str(Path(self.store.path).resolve()), self.trusted_pubkey)
        token = self.store.change_token()
        with _CACHE_GUARD:
            cached = _STATE_CACHE.get(key)
            if cached is not None and cached[0] == token:
                return cached[1]
        engaged = self._scan_engaged()
        with _CACHE_GUARD:
            _STATE_CACHE[key] = (token, engaged)
        return engaged

    def _scan_engaged(self) -> bool:
        """The AUTHORITATIVE scan — unchanged semantics (not re-implemented): honor ANY engage (halting
        is fail-safe), and un-halt only on an OWNER-SIGNED release that verifies (fail-closed).

        Hard-prune fold (Slice C): seed the latch from the folded snapshot prefix `[0..base_seq)` and fold
        only the LIVE window `[base_seq..T]` forward. The latch is PUBKEY-DEPENDENT (a release un-halts only
        under the trusted pubkey it verifies against), so a caller whose trust anchor differs from the one
        the snapshot was folded under BYPASSES the snapshot and re-scans from genesis. Under the Slice-C
        empty snapshot (base_seq==0, killswitch_engaged=False, trusted_pubkey=""), BOTH branches seed False
        and window since_seq=-1 (the current full genesis scan), so this is BYTE-IDENTICAL to the old scan."""
        st = SnapshotState.load(self.store)
        if self.trusted_pubkey != st.trusted_pubkey:
            engaged = False                         # pubkey mismatch: folded latch invalid → genesis rescan
            since_seq = -1
        else:
            engaged = st.killswitch_engaged         # seed from the folded prefix (scalar bool; no mutation)
            since_seq = st.base_seq - 1
        for r in self.store.iter_records(since_seq=since_seq):
            p = r.payload
            if p.get("signal") != SIGNAL:
                continue
            state = p.get("state")
            if state == "engaged":
                engaged = True                      # honor ANY engage — halting is fail-safe
            elif state == "released" and verify_signed(p, _CORE, self.trusted_pubkey):
                engaged = False                     # only an OWNER-SIGNED release un-halts (fail-closed)
        return engaged
