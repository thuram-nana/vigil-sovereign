"""The kill switch (SIGIL §5) — a single latch that halts the agent mesh while leaving perception and
memory-read (A0 observe) alive. State is append-only on the spine.

ASYMMETRIC AUTHENTICATION (Phase 6 red-pen RP-2): halting is always the safe direction, so ANY
engage event halts (a nuisance forged-engage is at worst a fail-safe DoS). UN-halting is the
dangerous direction, so a RELEASE is honored ONLY if it is signed by the owner key and verifies
against the trusted pubkey — a forged release can never revive a halted mesh. Read fresh per decision
so a release (or engage) takes effect immediately.

ANTI-REPLAY (this slice): a signature proves WHO wrote a release, never WHEN or HOW OFTEN it counts.
Anyone able to append to the spine could re-append a captured owner-signed release VERBATIM after a
later engage — the signature is genuine and the hash chain extends cleanly over the new record, so
the mesh un-halted. Signature dedup CANNOT fix this (Ed25519 is deterministic over a canonical core,
so a legitimate engage→release→engage→release re-signs BYTE-IDENTICALLY and a dedup would swallow the
second real release), and `record.seq` cannot either (assigned inside `store.append` AFTER signing, so
a replay just gets a fresh one). So a release carries an owner-set, strictly-increasing `issued_at`
INSIDE the signed core and the fold keeps a high-water: a release un-halts only while its `issued_at`
strictly exceeds every release already honored, and honoring one consumes that value so its own
replay is refused thereafter. Identical shape to `offense_gate.state()`. The SAFE direction (engage)
keeps NO freshness requirement at all — gating it would convert a fail-safe into a fail-open."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from ..spine.snapshot import SnapshotState
from . import key_history as _kh
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.killswitch"
# `issued_at` MUST be inside the core: outside it, an attacker could rewrite a captured release's
# freshness without breaking the signature, which is exactly the replay this guard refuses.
_CORE = ("signal", "state", "issued_at")

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
        """HALT the mesh — the SAFE direction. Takes effect whoever signs it and carries a FIXED
        `issued_at` of 0.0: engaging needs no freshness (its replay just re-halts an already-halted
        mesh), and demanding one would let a stale-clock caller fail to halt. The constant keeps the
        record signature-valid under the new core so `sigil governor status` still shows a verified
        provenance chain for the halt."""
        core = {"signal": SIGNAL, "state": "engaged", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def release(self, *, issued_at: float, by: str = "owner", reason: str = "") -> int:
        """UN-HALT the mesh — the DANGEROUS direction. `issued_at` is a REQUIRED, owner-set,
        strictly-increasing value (unix seconds): it must exceed every release already honored on this
        spine or the fold ignores it as a replay. Required rather than defaulted because this module
        reads NO clock — the authority over "when" belongs to the caller that holds the owner key
        (same contract as `offense_gate.open_gate`), and a silent default would be a forgeable one."""
        core = {"signal": SIGNAL, "state": "released", "issued_at": float(issued_at)}
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
        and window since_seq=-1 (the current full genesis scan), so this is BYTE-IDENTICAL to the old scan.

        The anti-replay high-water is seeded from the SAME snapshot under the SAME pubkey condition. It has
        to be: were it re-seeded to the bottom on every call, the first hard prune would make every release
        in the pruned prefix replayable again — the guard would be silently undone by the pruning work."""
        st = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)  # W9-1 succession-aware
        if self.trusted_pubkey != st.trusted_pubkey:
            engaged = False                         # pubkey mismatch: folded latch invalid → genesis rescan
            since_seq = -1
            max_issued = NO_HIGHWATER               # ...and so is the folded high-water — restart it too
        else:
            engaged = st.killswitch_engaged         # seed from the folded prefix (scalar bool; no mutation)
            since_seq = st.base_seq - 1
            max_issued = (NO_HIGHWATER if st.killswitch_issued_hw is None
                          else st.killswitch_issued_hw)   # None ⇒ no release honored in the pruned prefix
        for r in self.store.iter_records(since_seq=since_seq):
            p = r.payload
            if p.get("signal") != SIGNAL:
                continue
            state = p.get("state")
            if state == "engaged":
                engaged = True                      # honor ANY engage — halting is fail-safe
            elif state == "released" and verify_signed(p, _CORE, resolver.at(r.seq)):
                issued = as_issued_at(p.get("issued_at"))
                if issued <= max_issued:
                    continue                        # REPLAY / stale re-append of an already-honored release
                max_issued = issued                 # consume it so its own replay is refused hereafter
                engaged = False                     # only an OWNER-SIGNED, FRESH release un-halts
        return engaged
