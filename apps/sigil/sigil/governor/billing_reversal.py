"""W5 — the owner-signed REVERSAL ledger: chargebacks and refunds, the arrears they leave, and the billing hold.

A payment the processor later takes back (a dispute, a refund) must take its credits back out of the wallet. Credits
already spent cannot leave the wallet (a balance never goes negative through spending, I2), so that part is recorded
as OWED (arrears). While an org owes credits it is on a billing HOLD: no new launch and no allowance extension
(``ui/launch_gate.py``) until a top-up repays the arrears. Every movement is an owner-signed ``governor.billing_reversal``
record, folded from the spine with the same idempotency, owner-key succession and hard-prune durability as the wallet.

THE MODEL (one record per STEP; the record is the commit point of the step):
  * ``remove``  — ``credits`` (> 0) leave the org's position for one PURCHASE: ``wallet`` of them were debited from the
    wallet (a ``governor.credit_debit`` with the same entry id, written just before), the other ``owed`` were booked
    as arrears (``credits == wallet + owed``; ``wallet`` <= the wallet's exact spendable balance at the time).
  * ``restore`` — ``credits`` (> 0) given back for one purchase (a dispute won): all of them are granted to the wallet
    (a ``governor.credit_grant``, kind ``reinstate``, written just before); the repay below then clears arrears first.
  * ``note``    — the purchase's processor facts changed without moving credits (no wallet record).
  * ``repay``   — ``credits`` (> 0) of arrears repaid from the wallet (a debit written just before): the ONLY step that
    lowers what an org owes. Run after every top-up (``BillingSigner``) and after every restore.
A purchase (``ref`` — the top-up's grant entry id, e.g. the Stripe Checkout Session id) carries its state after each
step: ``k`` (1, 2, ... consecutively; the entry id is ``rev:<ref>:<k>``), ``cap`` (the credits the purchase granted),
``removed``, and the facts the target is computed from — ``owner_refunded`` (credits the owner refunded with
``sigil billing-reversal refund``), ``processor_refunded`` and ``disputed`` (credits, the last facts the processor
reported). An org's repays are numbered too (``repay:<n>``, consecutively).

THE TARGET (one formula for every path): ``removed`` is moved to ``min(cap, max(processor_refunded, owner_refunded) +
disputed)``. It is always computed from the FRESHEST facts — the Stripe drain re-fetches the charge and its dispute for
every event — so a duplicate, replayed or out-of-order event finds the same target and changes nothing, a refund and a
dispute of the same charge never remove more than the purchase granted, and a won dispute gives back exactly the part
it removed. An owner refund made through Stripe as well is covered by the ``max``.

CRASH SAFETY: inside the cross-process settle lock (the same lock every metered reserve, extension and settle takes),
the WALLET record is written first and the step record second. A crash between them leaves a wallet record without its
step: the next step on that purchase (or the org's next repay) finds it by its entry id, ADOPTS the amount it moved
(``reason: recovered``, nothing owed) and then decides afresh — never a second wallet movement for one step. In every
window the wallet holds what the records say or less, and nothing owed is ever cleared without the credits that repay it.

The HOLD is derived, never latched: an org is on hold iff the fold says it owes credits (``owed`` > 0). Prune
durability: ``SnapshotState`` carries ``billing_reversal_owed`` / ``_ref`` / ``_seen`` (schema 12) and
``spine/prune.py::stranded_billing_reversals`` refuses a prune whose seed would drop any of it. ``apply_billing_reversal``
is the ONE fold body (registry, fold cache, snapshot build, prune tripwire).

Inert unless ``config.billing_reversals_enabled()`` (``VIGIL_BILLING_REVERSALS``): no caller writes or reads a record
while it is off. FATAL-2: sovereign-side, ``assert_no_offense`` at import.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any, Iterator, Optional, cast

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

REVERSAL_SIGNAL = "governor.billing_reversal"
RECORD_VERSION = 1
STEP_REMOVE, STEP_RESTORE, STEP_NOTE, STEP_REPAY = "remove", "restore", "note", "repay"
STEPS = frozenset({STEP_REMOVE, STEP_RESTORE, STEP_NOTE, STEP_REPAY})
#: What triggered a step: a dispute or a refund (from the processor, or the owner's refund verb), a top-up (or a
#: restore) that repays, or a wallet movement a crashed step left behind, adopted.
REASON_DISPUTE, REASON_REFUND, REASON_REPAY, REASON_RECOVERED = "dispute", "refund", "repay", "recovered"
REASONS = frozenset({REASON_DISPUTE, REASON_REFUND, REASON_REPAY, REASON_RECOVERED})
#: The refusal reason a held org's allowance extension returns (``LaunchGate.extend_reservation``) — W3 pauses on it.
BILLING_HOLD = "billing_hold"
#: The wallet grant kind of a restore (``governor.wallet.GRANT_KINDS``).
REINSTATE_GRANT_KIND = "reinstate"

_CORE = ("signal", "v", "org_id", "entry_id", "step", "cause", "ref", "k", "credits", "wallet", "owed", "cap",
         "removed", "owner_refunded", "processor_refunded", "disputed", "issued_at")
_INTS = ("k", "credits", "wallet", "owed", "cap", "removed", "owner_refunded", "processor_refunded", "disputed")
_REV_PREFIX = "rev:"
_REPAY_PREFIX = "repay:"
_MAX_REF = 96               # a purchase id (a Stripe session id is 66 characters): rev:<ref>:<k> stays under 128
_MAX_TRIGGER = 128


class ReversalRefused(ValueError):
    """A reversal VIGIL cannot account for safely (a purchase whose credits changed, a malformed step): nothing moved.
    The billing drain QUARANTINES the envelope for the owner (never a guessed movement)."""


class ReversalRetry(RuntimeError):
    """Nothing moved, and a later retry may succeed (the settle lock is busy; the purchase is not credited yet). The
    billing drain defers the envelope for a bounded retry (NET-2b), else quarantines it."""

    transient = True


def _check_ref(ref: object) -> str:
    """A purchase id: non-empty, at most ``_MAX_REF`` printable characters, no ``:`` (the entry-id separator)."""
    s = str(ref or "").strip() if isinstance(ref, str) else ""
    if not s or len(s) > _MAX_REF or ":" in s or any(not (0x21 <= ord(c) <= 0x7e) for c in s):
        raise ReversalRefused("a reversal names its purchase by a printable id of at most 96 characters without ':'")
    return s


def _nonneg_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def rev_entry_id(ref: str, k: int) -> str:
    """The entry id of step ``k`` of purchase ``ref`` (the step record and its wallet record share it)."""
    return f"{_REV_PREFIX}{ref}:{int(k)}"


def repay_entry_id(n: int) -> str:
    """The entry id of an org's ``n``-th repay (the step record and its wallet debit share it)."""
    return f"{_REPAY_PREFIX}{int(n)}"


def _well_formed(p: dict) -> Optional[tuple]:
    """The step's fields when the record obeys every invariant of its step, else None."""
    if p.get("v") != RECORD_VERSION:
        return None
    step, cause, ref, eid = p.get("step"), p.get("cause"), p.get("ref"), p.get("entry_id")
    if step not in STEPS or cause not in REASONS or not isinstance(ref, str) or not isinstance(eid, str):
        return None
    vals = [p.get(f) for f in _INTS]
    if not all(_nonneg_int(v) for v in vals):
        return None
    k, credits, wallet, owed, cap, removed, o, sr, d = (cast(int, v) for v in vals)  # all nonneg ints (checked above)
    if k < 1:
        return None
    if step == STEP_REPAY:
        if (eid != repay_entry_id(k) or not ref or len(ref) > _MAX_TRIGGER or credits < 1
                or not credits == wallet == owed or any((cap, removed, o, sr, d))):
            return None
        return step, ref, k, credits, wallet, owed, cap, removed, o, sr, d
    try:
        if _check_ref(ref) != ref:
            return None
    except ReversalRefused:
        return None
    if eid != rev_entry_id(ref, k) or cap < 1 or removed > cap:
        return None
    if step == STEP_REMOVE and not (credits >= 1 and credits == wallet + owed):
        return None
    if step == STEP_RESTORE and not (credits >= 1 and credits == wallet and owed == 0):
        return None
    if step == STEP_NOTE and (credits or wallet or owed):
        return None
    return step, ref, k, credits, wallet, owed, cap, removed, o, sr, d


class ReversalFold:
    """The folded reversal ledger: per org the arrears booked (``owed_up``) and repaid (``owed_down``) and the last
    repay index (``repays``); per (org, purchase) its latest state ``[k, cap, removed, owner_refunded,
    processor_refunded, disputed]`` (``refs``); and the consumed ``(org, entry_id)`` keys (``seen``)."""

    __slots__ = ("owed_up", "owed_down", "repays", "refs", "seen")

    def __init__(self, owed_up: Optional[dict] = None, owed_down: Optional[dict] = None,
                 repays: Optional[dict] = None, refs: Optional[dict] = None, seen: Optional[set] = None) -> None:
        self.owed_up: dict = {} if owed_up is None else owed_up
        self.owed_down: dict = {} if owed_down is None else owed_down
        self.repays: dict = {} if repays is None else repays
        self.refs: dict = {} if refs is None else refs
        self.seen: set = set() if seen is None else seen

    def owed(self, org_id: str) -> int:
        return max(0, self.owed_up.get(org_id, 0) - self.owed_down.get(org_id, 0))


def apply_billing_reversal(p: Any, pubkey: Optional[str], st: ReversalFold) -> bool:
    """Fold ONE record payload into ``st`` — THE reversal fold body (registry, fold cache, ``SnapshotState.build``, the
    prune tripwire). Verified under ``pubkey`` (the owner key valid at the record's seq); a record whose ``(org_id,
    entry_id)`` was already folded is ignored (a replay folds once); an owner-signed record that breaks its step's
    invariants is consumed and counts nothing (a later copy never counts either). Returns True when ``st`` changed."""
    if not isinstance(p, dict) or p.get("signal") != REVERSAL_SIGNAL:
        return False
    oid, eid = p.get("org_id"), p.get("entry_id")
    if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
        return False
    key = (oid, eid)
    if key in st.seen:
        return False
    if not verify_signed(p, _CORE, pubkey):
        return False                                  # fail-closed: unsigned / forged / wrong epoch consumes nothing
    st.seen.add(key)
    rec = _well_formed(p)
    if rec is None:
        return True                                   # consumed, counts nothing
    step, ref, k, _credits, _wallet, owed, cap, removed, o, sr, d = rec
    if step == STEP_REPAY:
        st.repays[oid] = max(st.repays.get(oid, 0), k)
        st.owed_down[oid] = st.owed_down.get(oid, 0) + owed
        return True
    if step == STEP_REMOVE:
        st.owed_up[oid] = st.owed_up.get(oid, 0) + owed
    cur = st.refs.get((oid, ref))
    if cur is None or k > cur[0]:
        st.refs[(oid, ref)] = [k, cap, removed, o, sr, d]
    return True


def seed_fold(snap) -> ReversalFold:
    """The fold the snapshot seed carries (``billing_reversal_owed`` / ``_ref`` / ``_seen``); malformed rows are
    skipped."""
    st = ReversalFold()
    for row in snap.billing_reversal_owed:
        if (isinstance(row, (list, tuple)) and len(row) >= 4 and isinstance(row[0], str)
                and all(_nonneg_int(v) for v in row[1:4])):
            st.owed_up[row[0]], st.owed_down[row[0]], st.repays[row[0]] = int(row[1]), int(row[2]), int(row[3])
    for row in snap.billing_reversal_ref:
        if (isinstance(row, (list, tuple)) and len(row) >= 8 and isinstance(row[0], str) and isinstance(row[1], str)
                and all(_nonneg_int(v) for v in row[2:8])):
            st.refs[(row[0], row[1])] = [int(v) for v in row[2:8]]
    for row in snap.billing_reversal_seen:
        if isinstance(row, (list, tuple)) and len(row) >= 2 and isinstance(row[0], str) and isinstance(row[1], str):
            st.seen.add((row[0], row[1]))
    return st


def fold_rows(st: ReversalFold) -> "tuple[list, list, list]":
    """The snapshot rows of ``st`` (``billing_reversal_owed``, ``_ref``, ``_seen``) — the inverse of :func:`seed_fold`."""
    orgs = sorted(set(st.owed_up) | set(st.owed_down) | set(st.repays))
    owed = [[o, st.owed_up.get(o, 0), st.owed_down.get(o, 0), st.repays.get(o, 0)] for o in orgs]
    refs = [[o, r, *st.refs[(o, r)]] for (o, r) in sorted(st.refs)]
    seen = [[o, e] for (o, e) in sorted(st.seen)]
    return owed, refs, seen


def _reversal_step(view: ReversalFold, r, resolver) -> None:
    apply_billing_reversal(r.payload, resolver.at(r.seq), view)


_REVERSAL_FOLD = FoldCache("governor.billing_reversal", step=_reversal_step)


@dataclass(frozen=True)
class PurchaseState:
    """A purchase's reversal state (all zero before its first step)."""
    k: int = 0
    cap: int = 0
    removed: int = 0
    owner_refunded: int = 0
    processor_refunded: int = 0
    disputed: int = 0


@dataclass(frozen=True)
class StepResult:
    """What a reconcile or a repay did: ``seq`` of the last step record appended (None: nothing), the purchase's
    ``removed`` after it, the org's ``owed`` after it, and the credits it ``moved`` (removed > 0, given back < 0)."""
    seq: Optional[int]
    removed: int
    owed: int
    moved: int = 0
    repaid: int = 0


class BillingReversalLedger:
    """The owner-signed reversal ledger on the spine (construction mirrors ``WalletRegistry``). ``wallet`` is the
    ``WalletRegistry`` the steps move credits in (default: one over the same store and keys)."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None, wallet=None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        if wallet is None:
            from .wallet import WalletRegistry
            wallet = WalletRegistry(store, owner_key=self.owner_key, trusted_pubkey=self.trusted_pubkey)
        self.wallet = wallet

    # -- reads -----------------------------------------------------------------------------------------------------
    def _seed(self, snap) -> "tuple[ReversalFold, int]":
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ReversalFold(), -1
        return seed_fold(snap), snap.base_seq - 1

    def _cached(self, reader):
        return cached_read(_REVERSAL_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=self._seed,
                           reader=reader)

    def _fold(self) -> ReversalFold:
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        st, since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            apply_billing_reversal(r.payload, resolver.at(r.seq), st)
        return st

    def _read(self, reader):
        hit = self._cached(reader)
        return reader(self._fold()) if hit is _UNCACHED else hit

    def owed(self, org_id: str) -> int:
        """The credits ``org_id`` owes after reversals (0 for an unknown org). An org that owes credits is on hold."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        return int(self._read(lambda v: v.owed(org_id)))

    def on_hold(self, org_id: str) -> bool:
        return self.owed(org_id) > 0

    def holds(self) -> "list[tuple[str, int]]":
        """Every org that owes credits, with what it owes, in org order (the owner's alarm roster)."""
        return self._read(lambda v: sorted((o, v.owed(o)) for o in set(v.owed_up) if v.owed(o) > 0))

    def purchase(self, org_id: str, ref: str) -> PurchaseState:
        key = (str(org_id), str(ref))
        row = self._read(lambda v: list(v.refs.get(key) or ()))
        return PurchaseState(*row) if row else PurchaseState()

    def repays(self, org_id: str) -> int:
        return int(self._read(lambda v: v.repays.get(org_id, 0)))

    def has_entry(self, org_id: str, entry_id: str) -> bool:
        key = (str(org_id), str(entry_id))
        return bool(self._read(lambda v: key in v.seen))

    # -- the owner-signed record -------------------------------------------------------------------------------------
    def _append(self, oid: str, entry_id: str, step: str, cause: str, ref: str, k: int, *, credits: int,
                wallet: int, owed: int, state: PurchaseState, issued_at: float, note: str = "") -> int:
        if self.owner_key is None:
            raise ValueError("a reversal step requires the owner signing key")
        core = {"signal": REVERSAL_SIGNAL, "v": RECORD_VERSION, "org_id": oid, "entry_id": entry_id, "step": step,
                "cause": cause, "ref": ref, "k": int(k), "credits": int(credits), "wallet": int(wallet),
                "owed": int(owed), "cap": state.cap, "removed": state.removed, "owner_refunded": state.owner_refunded,
                "processor_refunded": state.processor_refunded, "disputed": state.disputed,
                "issued_at": float(issued_at)}
        if _well_formed(core) is None:
            raise ReversalRefused(f"refusing a malformed {step} step for {oid}")
        why = f"billing reversal {step} {credits} ({cause}) {oid} {ref}"
        if note:
            why += f" — {note}"
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner", "tier": "A0",
                   "decision": "auto", "reason": why}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    @contextlib.contextmanager
    def _money_lock(self) -> Iterator[None]:
        """The spine lock, then the cross-process settle lock (the lock order of ``launch_settlement``): every wallet
        draw a reserve, an extension or a settle makes holds it too, so a reversal's sizing and debit never interleave
        with one. A busy lock is a retry (nothing moved)."""
        from ..spine.store import spine_lock
        from .launch_settlement import settle_lock
        with contextlib.ExitStack() as held:
            held.enter_context(spine_lock(getattr(self.store, "path", "")))
            try:
                held.enter_context(settle_lock(self.store))
            except OSError:
                raise ReversalRetry("the billing settle lock is busy; the reversal is retried") from None
            yield

    def _live_wallet_amount(self, signal: str, oid: str, eid: str) -> Optional[int]:
        """The credits of the verified wallet record ``(signal, oid, eid)`` in the live spine (the first one: the one the
        wallet fold counted), or None."""
        from .wallet import CREDIT_GRANT_SIGNAL, _DEBIT_CORE, _GRANT_CORE, _as_credits
        core = _GRANT_CORE if signal == CREDIT_GRANT_SIGNAL else _DEBIT_CORE
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        for r in self.store.iter_records(since_seq=-1):
            p = r.payload
            if (isinstance(p, dict) and p.get("signal") == signal and p.get("org_id") == oid
                    and p.get("entry_id") == eid and verify_signed(p, core, resolver.at(r.seq))):
                return _as_credits(p.get("credits"))
        return None

    def _orphan(self, signal: str, oid: str, eid: str) -> Optional[int]:
        """The amount of a wallet record a crashed step left without its step record, or None when there is none.
        Raises ``ReversalRefused`` when one exists but its amount left the live spine (never guessed)."""
        from .wallet import CREDIT_GRANT_SIGNAL
        present = (self.wallet.has_grant_entry(oid, eid) if signal == CREDIT_GRANT_SIGNAL
                   else self.wallet.has_debit_entry(oid, eid))
        if not present:
            return None
        amount = self._live_wallet_amount(signal, oid, eid)
        if amount is None:
            raise ReversalRefused(f"the wallet record {eid} of {oid} has no step record and its amount is no longer on "
                                  f"the live spine — reconcile by hand")
        return amount

    def _adopt_purchase_orphan(self, oid: str, ref: str, st: PurchaseState, now: float) -> PurchaseState:
        """Commit the wallet movement a crashed step ``st.k + 1`` left behind (``reason: recovered``), if any."""
        from .wallet import CREDIT_DEBIT_SIGNAL, CREDIT_GRANT_SIGNAL
        k = st.k + 1
        eid = rev_entry_id(ref, k)
        if self.has_entry(oid, eid):
            raise ReversalRefused(f"step {eid} of {oid} is recorded but the fold did not apply it — reconcile by hand")
        taken = self._orphan(CREDIT_DEBIT_SIGNAL, oid, eid)
        if taken is not None:
            after = PurchaseState(k, st.cap, min(st.cap, st.removed + taken), st.owner_refunded,
                                  st.processor_refunded, st.disputed)
            self._append(oid, eid, STEP_REMOVE, REASON_RECOVERED, ref, k, credits=taken, wallet=taken, owed=0,
                         state=after, issued_at=now)
            return after
        given = self._orphan(CREDIT_GRANT_SIGNAL, oid, eid)
        if given is not None:
            after = PurchaseState(k, st.cap, max(0, st.removed - given), st.owner_refunded,
                                  st.processor_refunded, st.disputed)
            self._append(oid, eid, STEP_RESTORE, REASON_RECOVERED, ref, k, credits=given, wallet=given, owed=0,
                         state=after, issued_at=now)
            return after
        return st

    # -- the reconcile -------------------------------------------------------------------------------------------------
    def reconcile(self, org_id: str, ref: str, *, cap: int, reason: str, now: float,
                  processor_refunded: Optional[int] = None, disputed: Optional[int] = None,
                  owner_refund: int = 0, unused_only: bool = False, note: str = "") -> StepResult:
        """Move purchase ``ref``'s removed credits to ``min(cap, max(processor_refunded, owner_refunded) + disputed)``.

        ``processor_refunded`` / ``disputed`` are the processor's freshest facts in credits (None keeps the last ones
        recorded); ``owner_refund`` adds to ``owner_refunded`` (the owner's refund verb). With ``unused_only`` the step
        is refused (``ReversalRefused``, nothing moved) unless the wallet's spendable balance covers all it would
        remove — an owner refund only ever returns UNUSED credits. A removal debits ``min(delta, spendable)`` from the
        wallet and books the rest as owed; a give-back grants it to the wallet, then repays arrears from it. Decided
        and written under the money lock (``ReversalRetry`` when busy); nothing is written when nothing changes (a
        duplicate or out-of-order event). ``note`` (the owner's words, at most 200 printable characters) rides in the
        step record's human-readable reason only."""
        oid = org_tenant_id(org_id)
        pref = _check_ref(ref)
        note = " ".join(str(note or "").split())[:200]
        if any(not c.isprintable() for c in note):
            raise ReversalRefused("the note must be printable text")
        if reason not in (REASON_DISPUTE, REASON_REFUND):
            raise ReversalRefused("a reconcile is triggered by a dispute or a refund")
        for name, v in (("cap", cap), ("owner_refund", owner_refund)):
            if not _nonneg_int(v):
                raise ReversalRefused(f"{name} must be a non-negative integer of credits")
        for name, ov in (("processor_refunded", processor_refunded), ("disputed", disputed)):
            if ov is not None and not _nonneg_int(ov):
                raise ReversalRefused(f"{name} must be a non-negative integer of credits")
        if cap < 1:
            raise ReversalRefused("a purchase that granted no credits has nothing to reverse")
        with self._money_lock():
            st = self.purchase(oid, pref)
            if st.k and st.cap != cap:
                raise ReversalRefused(f"purchase {pref} of {oid} granted {st.cap} credits, not {cap} — reconcile by hand")
            st = PurchaseState(st.k, cap, st.removed, st.owner_refunded, st.processor_refunded, st.disputed)
            st = self._adopt_purchase_orphan(oid, pref, st, now)
            sr = st.processor_refunded if processor_refunded is None else int(processor_refunded)
            d = st.disputed if disputed is None else int(disputed)
            o = min(cap, st.owner_refunded + int(owner_refund))
            target = min(cap, max(sr, o) + d)
            delta = target - st.removed
            k = st.k + 1
            eid = rev_entry_id(pref, k)
            after = PurchaseState(k, cap, target, o, sr, d)
            seq: Optional[int] = None
            if delta > 0:
                spendable = self.wallet.balance(oid).spendable
                if unused_only and delta > spendable:
                    raise ReversalRefused(f"an owner refund returns unused credits only: removing {delta} needs "
                                          f"{delta} spendable credits, {oid} has {spendable}")
                take = min(delta, spendable)
                if take > 0:
                    self.wallet.debit(oid, take, engagement_id="", entry_id=eid, issued_at=now)
                seq = self._append(oid, eid, STEP_REMOVE, reason, pref, k, credits=delta, wallet=take,
                                   owed=delta - take, state=after, issued_at=now, note=note)
            elif delta < 0:
                give = -delta
                self.wallet.grant(oid, give, REINSTATE_GRANT_KIND, source_ref=pref, entry_id=eid, issued_at=now)
                seq = self._append(oid, eid, STEP_RESTORE, reason, pref, k, credits=give, wallet=give, owed=0,
                                   state=after, issued_at=now, note=note)
                rep = self._repay_locked(oid, eid, now)
                seq = rep[0] if rep[0] is not None else seq
            elif (o, sr, d) != (st.owner_refunded, st.processor_refunded, st.disputed):
                seq = self._append(oid, eid, STEP_NOTE, reason, pref, k, credits=0, wallet=0, owed=0, state=after,
                                   issued_at=now, note=note)
            else:
                after = st
            return StepResult(seq, after.removed, self.owed(oid), moved=delta if seq is not None else 0)

    # -- the repay -----------------------------------------------------------------------------------------------------
    def repay(self, org_id: str, trigger: str, *, now: float) -> StepResult:
        """Repay the org's arrears from its wallet: ``min(owed, spendable)`` credits (exactly once per debt — each
        repay is numbered, and the next one first adopts a debit a crashed one left). ``trigger`` (the top-up's entry id,
        or the restore step's) is recorded for audit. A no-op that writes nothing when the org owes nothing."""
        oid = org_tenant_id(org_id)
        trig = str(trigger or "").strip()
        if not trig or len(trig) > _MAX_TRIGGER or any(ord(c) < 0x20 or ord(c) == 0x7f for c in trig):
            raise ReversalRefused("a repay names its trigger by a printable id of at most 128 characters")
        with self._money_lock():
            seq, repaid = self._repay_locked(oid, trig, now)
            return StepResult(seq, 0, self.owed(oid), repaid=repaid)

    def _repay_locked(self, oid: str, trigger: str, now: float) -> "tuple[Optional[int], int]":
        from .wallet import CREDIT_DEBIT_SIGNAL
        nil = PurchaseState()
        seq: Optional[int] = None
        repaid = 0
        n = self.repays(oid) + 1
        eid = repay_entry_id(n)
        orphan = self._orphan(CREDIT_DEBIT_SIGNAL, oid, eid)
        if orphan is not None and not self.has_entry(oid, eid):
            # a crashed repay debited the wallet and wrote no record: commit exactly what it took (every lowering of
            # what is owed goes through these numbered repays, so the org still owes at least that much)
            seq = self._append(oid, eid, STEP_REPAY, REASON_RECOVERED, trigger, n, credits=orphan, wallet=orphan,
                               owed=orphan, state=nil, issued_at=now)
            repaid += orphan
            n += 1
            eid = repay_entry_id(n)
        owed = self.owed(oid)
        if owed <= 0:
            return seq, repaid
        x = min(owed, self.wallet.balance(oid).spendable)
        if x <= 0:
            return seq, repaid
        self.wallet.debit(oid, x, engagement_id="", entry_id=eid, issued_at=now)
        seq = self._append(oid, eid, STEP_REPAY, REASON_REPAY, trigger, n, credits=x, wallet=x, owed=x, state=nil,
                           issued_at=now)
        return seq, repaid + x
