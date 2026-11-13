"""Report UNLOCKS — the owner-signed record that an org's full assessment reports are unlocked.

A `governor.report_unlock` record is written either by the billing signer (a verified credit purchase) or by
the owner (`source_kind=owner`: enterprise, goodwill, or a fraud / chargeback RELOCK). An unlock grants nothing
else — no credits, role, proof or testing authority.

PRECEDENCE (per org):
  * a BILLING record (`source_kind` in {topup, subscription}) may only carry `action=unlock`; the FIRST verified
    one per org wins (a later purchase, a replay or a billing "relock" is inert);
  * OWNER records are latest-wins by `issued_at` (strictly later replaces, so a replay is inert);
  * `is_unlocked(org)`: if the org has ANY owner record, its latest action decides; otherwise the org is
    unlocked iff a billing unlock exists. So an owner relock beats an earlier purchase, a later purchase does not
    override an owner relock, and an owner unlock after a relock unlocks again.

MODEL: owner-signed only; the tenant is inside the signed core. Verified under the owner pubkey valid at each
seq. Seeded across a hard prune from `SnapshotState.report_unlock_billing` / `report_unlock_owner`; the prune
tripwire `stranded_report_unlocks` refuses a prune whose seed would drop one. `apply_report_unlock` is the ONE
fold body (registry, snapshot build, prune tripwire).

No caller writes one yet (S2), and nothing reads it to lock a report: the records are inert until the
default-OFF preview projection consults them. FATAL-2: sovereign-side, `assert_no_offense` at import.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

REPORT_UNLOCK_SIGNAL = "governor.report_unlock"
ACTIONS = frozenset({"unlock", "relock"})
BILLING_SOURCES = frozenset({"topup", "subscription"})
SOURCE_OWNER = "owner"
SOURCES = BILLING_SOURCES | {SOURCE_OWNER}
_UNLOCK_CORE = ("signal", "org_id", "entry_id", "action", "source_kind", "source_ref", "issued_at")


@dataclass(frozen=True)
class Unlock:
    """The record that decides an org's unlock state."""
    org_id: str
    entry_id: str
    action: str
    source_kind: str
    source_ref: str
    issued_at: float


def _check_ref(v: object, name: str) -> str:
    s = str(v or "").strip()
    if len(s) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        raise ValueError(f"{name} must be a non-control string of <= 128 chars")
    return s


def apply_report_unlock(p, pubkey: Optional[str], billing: dict, owner: dict) -> bool:
    """Fold ONE record payload. `billing`: org -> [entry_id, source_kind, source_ref, issued_at] (first verified
    billing unlock wins); `owner`: org -> [entry_id, action, source_ref, issued_at] (strictly-later issued_at
    wins). Returns True when the state changed."""
    if not isinstance(p, dict) or p.get("signal") != REPORT_UNLOCK_SIGNAL:
        return False
    oid, eid = p.get("org_id"), p.get("entry_id")
    action, src = p.get("action"), p.get("source_kind")
    if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid and isinstance(action, str)
            and action in ACTIONS and isinstance(src, str) and src in SOURCES):
        return False
    if src in BILLING_SOURCES:
        if action != "unlock" or oid in billing:
            return False                              # billing may only unlock, and the first one wins
        if not verify_signed(p, _UNLOCK_CORE, pubkey):
            return False
        billing[oid] = [eid, src, str(p.get("source_ref") or ""), float(as_issued_at(p.get("issued_at")))]
        return True
    issued = float(as_issued_at(p.get("issued_at")))
    cur = owner.get(oid)
    if cur is not None and issued <= cur[3]:
        return False                                  # latest-wins: an older or equal record (or a replay) is inert
    if not verify_signed(p, _UNLOCK_CORE, pubkey):
        return False
    owner[oid] = [eid, str(action), str(p.get("source_ref") or ""), issued]
    return True


def seed_state(snap) -> "tuple[dict, dict]":
    billing: dict = {}
    owner: dict = {}
    for row in snap.report_unlock_billing:
        if (isinstance(row, (list, tuple)) and len(row) >= 5 and isinstance(row[0], str)
                and isinstance(row[2], str) and row[2] in BILLING_SOURCES and row[0] not in billing):
            billing[row[0]] = [str(row[1]), str(row[2]), str(row[3]), float(as_issued_at(row[4]))]
    for row in snap.report_unlock_owner:
        if (isinstance(row, (list, tuple)) and len(row) >= 5 and isinstance(row[0], str)
                and isinstance(row[2], str) and row[2] in ACTIONS and row[0] not in owner):
            owner[row[0]] = [str(row[1]), str(row[2]), str(row[3]), float(as_issued_at(row[4]))]
    return billing, owner


def _decide(org_id: str, billing: dict, owner: dict) -> Optional[Unlock]:
    """The record that decides `org_id`'s state, or None when it has no record. Owner precedence first."""
    o = owner.get(org_id)
    if o is not None:
        return Unlock(org_id, o[0], o[1], SOURCE_OWNER, o[2], o[3])
    b = billing.get(org_id)
    if b is not None:
        return Unlock(org_id, b[0], "unlock", b[1], b[2], b[3])
    return None


class _UnlockView:
    __slots__ = ("billing", "owner")

    def __init__(self, billing: dict, owner: dict) -> None:
        self.billing, self.owner = billing, owner


def _unlock_step(view: _UnlockView, r, resolver) -> None:
    apply_report_unlock(r.payload, resolver.at(r.seq), view.billing, view.owner)


_UNLOCK_FOLD = FoldCache("governor.report_unlock", step=_unlock_step)


class ReportUnlockRegistry:
    """Owner-signed report-unlock ledger on the spine. Construction mirrors `InvoiceRegistry`."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def _append(self, oid: str, eid: str, action: str, src: str, ref: str, issued_at: float) -> int:
        if self.owner_key is None:
            raise ValueError("report unlock requires the owner signing key")
        core = {"signal": REPORT_UNLOCK_SIGNAL, "org_id": oid, "entry_id": eid, "action": action,
                "source_kind": src, "source_ref": ref, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"reports {action} ({src}) -> {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def unlock(self, org_id: str, source_kind: str, *, source_ref: str, issued_at: float) -> int:
        """A BILLING unlock from a verified purchase (`source_kind` topup | subscription). Idempotent by
        construction: the fold keeps the first billing unlock per org. The entry id is derived from the source
        so a re-drive of the same event writes the same record."""
        oid = org_tenant_id(org_id)
        src = str(source_kind or "").strip()
        if src not in BILLING_SOURCES:
            raise ValueError(f"billing unlock source must be one of {sorted(BILLING_SOURCES)}")
        ref = _check_ref(source_ref, "source_ref")
        if not ref:
            raise ValueError("a billing unlock needs its source_ref (the verified event id)")
        eid = f"unlock:{src}:{ref}"
        if len(eid) > 128:                                # a long event id: a fixed-length derived id, same per ref
            import hashlib
            eid = f"unlock:{src}:sha256:{hashlib.sha256(ref.encode('utf-8')).hexdigest()}"
        return self._append(oid, eid, "unlock", src, ref, issued_at)

    def owner_set(self, org_id: str, action: str, *, reason: str, issued_at: float) -> int:
        """An OWNER unlock or relock (latest-wins by issued_at). `reason` is carried as the source_ref."""
        oid = org_tenant_id(org_id)
        a = str(action or "").strip()
        if a not in ACTIONS:
            raise ValueError(f"action must be one of {sorted(ACTIONS)}")
        ref = _check_ref(reason, "reason")
        if not ref:
            raise ValueError("an owner unlock/relock needs a reason")
        return self._append(oid, f"owner:{uuid.uuid4().hex}", a, SOURCE_OWNER, ref, issued_at)

    # -- reads -------------------------------------------------------------------------------------
    def _seed(self, snap) -> "tuple[tuple[dict, dict], int]":
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ({}, {}), -1                           # nothing pruned: the genesis scan is the whole fold
        return seed_state(snap), snap.base_seq - 1

    def _cached(self, reader: Callable):
        def seed(snap):
            st, since = self._seed(snap)
            return _UnlockView(*st), since

        return cached_read(_UNLOCK_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def _fold(self) -> "tuple[dict, dict]":
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (billing, owner), since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            apply_report_unlock(r.payload, resolver.at(r.seq), billing, owner)
        return billing, owner

    def unlock_of(self, org_id: str) -> Optional[Unlock]:
        """The record deciding `org_id`'s state (an unlock or an owner relock), or None."""
        if not isinstance(org_id, str) or not org_id:
            return None
        hit = self._cached(lambda v: _decide(org_id, v.billing, v.owner))
        if hit is not _UNCACHED:
            return hit
        return _decide(org_id, *self._fold())

    def is_unlocked(self, org_id: str) -> bool:
        u = self.unlock_of(org_id)
        return u is not None and u.action == "unlock"
