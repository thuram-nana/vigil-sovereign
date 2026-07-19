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

from .authn import signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.killswitch"
_CORE = ("signal", "state")

# FIX 4 (audit CRITICAL): `is_engaged()` full-scans the spine on EVERY governor decision, so a batch of
# proposals is O(proposals × spine). Cache the authoritative verdict keyed by (resolved spine path,
# trusted pubkey) with the file size it was computed at. An append-only spine only changes by GROWTH,
# and every engage/release APPENDS a record → the size grows → the cache invalidates and we re-run the
# real, owner-signed-release-verifying scan. A matching size ⇒ no new records ⇒ the cached verdict is
# exact (O(1), a single `stat`). Keyed on the pubkey too, so instances with different trust roots (which
# would verify a signed release differently) never share an entry. Shared across ALL callers on a path.
_STATE_CACHE: dict[tuple[str, Optional[str]], tuple[int, bool]] = {}
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
        """Cheap, correct kill-switch verdict (FIX 4). O(1) `stat` when the spine is unchanged since the
        last authoritative scan; a grown (or first-seen / shrunk) file re-runs the real scan below and
        refreshes the shared cache. Semantics are IDENTICAL to a fresh scan — a new engage/release grows
        the file, so it is always honored on the next call."""
        key = (str(Path(self.store.path).resolve()), self.trusted_pubkey)
        try:
            size = self.store.path.stat().st_size
        except OSError:
            size = -1
        if size >= 0:
            with _CACHE_GUARD:
                cached = _STATE_CACHE.get(key)
                if cached is not None and cached[0] == size:
                    return cached[1]
        engaged = self._scan_engaged()
        if size >= 0:
            with _CACHE_GUARD:
                _STATE_CACHE[key] = (size, engaged)
        return engaged

    def _scan_engaged(self) -> bool:
        """The AUTHORITATIVE scan — unchanged semantics (not re-implemented): honor ANY engage (halting
        is fail-safe), and un-halt only on an OWNER-SIGNED release that verifies (fail-closed)."""
        engaged = False
        for r in self.store.iter_records():
            p = r.payload
            if p.get("signal") != SIGNAL:
                continue
            state = p.get("state")
            if state == "engaged":
                engaged = True                      # honor ANY engage — halting is fail-safe
            elif state == "released" and verify_signed(p, _CORE, self.trusted_pubkey):
                engaged = False                     # only an OWNER-SIGNED release un-halts (fail-closed)
        return engaged
