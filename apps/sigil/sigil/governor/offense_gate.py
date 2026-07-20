"""
governor.offense_gate — the fail-closed, owner-signed, charter-bound, AUTO-EXPIRING gate that
must be OPEN for the offense side to act (VIGIL P7 / FATAL-2 completion).

It is the kill-switch's mirror image, with the asymmetry INVERTED. The kill-switch defaults to
CLEAR and treats *halting* as the fail-safe direction (any event can engage it; only an
owner-signed release un-halts). The offense gate defaults to **CLOSED** (offense denied) and
treats *closing* as the fail-safe direction: any event can close it, but only an owner-Ed25519-
signed OPEN that is (a) bound to exactly the currently-active charter and (b) not yet expired can
un-gate it. A forged, unsigned, wrong-charter, or expired "open" un-gates NOTHING.

Like the kill-switch, the state lives ONLY on the append-only, fsync'd spine and is re-derived on
every check, so it survives process restart as a fail-closed persistent latch. Unlike the
kill-switch it is time-dependent (it expires), so — critically — it is NEVER cached: an expiring
OPEN has no new append at ``not_after``, so a cached verdict would wrongly persist past expiry.

The signed core carries the charter binding AND the expiry, so neither can be rewritten without
breaking the signature. Control events are logged at tier A0/auto so the governance events that
operate the gate are never themselves offense-gated (deadlock avoidance, exactly as the
kill-switch engage/release are A0).

This is a SIGIL (sovereign) governance concept: it decides AUTO/DENY for offense-tier activity
inside SIGIL's own fail-closed governor and imports NO offense-engine module (``assert_no_offense``
holds). The offense worker consults it across the spine, never by importing it into an offense
process.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .authn import signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.offense_gate"

# Only these fields are authenticated by the owner signature. ``not_after`` and ``charter_hash``
# MUST be here or an attacker could rewrite the expiry / charter binding without breaking the sig.
_CORE = ("signal", "state", "charter_id", "charter_hash", "not_after")


class OffenseGateClosed(RuntimeError):
    """The offense gate is not OPEN for this charter at this time — offense must not proceed.
    Raised fail-closed; must not be silently caught (it is sovereignty refusing to run offense)."""


@dataclass(frozen=True)
class OffenseGateState:
    open: bool
    reason: str
    charter_id: str = ""
    not_after: float = 0.0


class OffenseGate:
    """Owner-signed, charter-bound, auto-expiring gate over offense activity, on the spine."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing key is the OWNER's (may be None → cannot open anything, the desired default).
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        # Verification is PINNED to the persisted owner identity, never a caller-supplied key.
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner transitions (both A0/auto so they are never themselves offense-gated) ----------

    def open_gate(
        self, *, charter_id: str, charter_hash: str, not_after: float, by: str = "owner", reason: str = ""
    ) -> int:
        """Owner-signed OPEN, bound to one charter (id+hash) and expiring at ``not_after`` (unix
        seconds). Only the owner key produces a signature the fold will honour."""
        if not charter_id or not charter_hash:
            raise ValueError("open_gate requires a charter_id and charter_hash to bind to")
        core = {
            "signal": SIGNAL,
            "state": "open",
            "charter_id": str(charter_id),
            "charter_hash": str(charter_hash),
            "not_after": float(not_after),
        }
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def close_gate(self, *, by: str = "owner", reason: str = "") -> int:
        """CLOSE offense (the fail-safe direction — honoured whoever signs it, like kill engage)."""
        core = {"signal": SIGNAL, "state": "closed", "charter_id": "", "charter_hash": "", "not_after": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason,
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- the fail-closed fold (never cached — the verdict is time-dependent) -------------------

    def state(self, *, charter_id: str, charter_hash: str, now: float) -> OffenseGateState:
        """Fold the spine to the gate's state for exactly (charter_id, charter_hash) at time
        ``now``. CLOSED unless the latest-winning event is an owner-signed OPEN bound to this
        charter with ``now < not_after``. Any close (even unsigned) closes it."""
        is_open = False
        reason = "default-closed: no owner-signed open on the spine"
        na = 0.0
        for record in self.store.iter_records():
            payload = record.payload if isinstance(record.payload, dict) else {}
            if payload.get("signal") != SIGNAL:
                continue
            st = payload.get("state")
            if st == "closed":
                is_open, reason, na = False, "closed by a close event", 0.0  # honour ANY close
            elif st == "open":
                # An OPEN counts ONLY if owner-signed AND bound to exactly this charter.
                if not verify_signed(payload, _CORE, self.trusted_pubkey):
                    continue  # forged/unsigned open — no effect
                if payload.get("charter_id") != charter_id or payload.get("charter_hash") != charter_hash:
                    continue  # open for a DIFFERENT charter — no effect on this one
                signed_na = _as_float(payload.get("not_after"))
                if now < signed_na:
                    is_open, reason, na = True, "owner-signed open, charter-bound, unexpired", signed_na
                else:
                    is_open, reason, na = False, "owner-signed open but EXPIRED", 0.0
        return OffenseGateState(
            open=is_open, reason=reason,
            charter_id=charter_id if is_open else "", not_after=na if is_open else 0.0,
        )

    def is_open(self, *, charter_id: str, charter_hash: str, now: float) -> bool:
        return self.state(charter_id=charter_id, charter_hash=charter_hash, now=now).open


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0  # unparseable expiry → treated as already-expired (fail-closed)


def assert_offense_gated(
    store, *, charter_id: str, charter_hash: str, now: float,
    owner_key=None, trusted_pubkey: Optional[str] = None,
) -> None:
    """Fail-closed assertion the offense worker makes before acting: raise ``OffenseGateClosed``
    unless the gate is OPEN for this charter at ``now``."""
    gate = OffenseGate(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    st = gate.state(charter_id=charter_id, charter_hash=charter_hash, now=now)
    if not st.open:
        raise OffenseGateClosed(f"offense gate is CLOSED for charter {charter_id!r}: {st.reason}")
