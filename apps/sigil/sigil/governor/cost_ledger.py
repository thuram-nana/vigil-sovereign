"""EC-4 — the per-tenant TOKEN-COST ENVELOPE ledger (owner-signed reserve/settle; sovereign plane).

Money-grade cost accounting — the deliberate CONTRAST to ``vigil_core/token_budget.py`` (per-tool, per-UTC-day,
WARN+THROTTLE, fail-OPEN "metering must never break a call"): this is per-TENANT, lifetime, owner-signed,
append-only, snapshot-seeded, prune-durable and fail-CLOSED. The two are complementary — the token budget is
engine back-pressure; this is the sovereign money record that attributes real Anthropic cost to a tenant so
margin per tenant is visible + auditable on the signed spine.

A launch RESERVES a token envelope (the hard cap ``units_reserved * ENVELOPE_TOKENS_PER_CREDIT``) against the
tenant's cost account before it runs, and SETTLES to the ACTUAL tokens the run recorded afterwards, clamped to
the reserved envelope — so a forged over-report can never charge a tenant (or draw the pool) past what was
reserved. Reserved-but-unsettled = the IN-FLIGHT envelope (the pool draw held pending, held OUT of committed
cost); Σ settled actual = the COMMITTED real cost per tenant.

MODEL (both directions owner-signed + verified; a forged record of either kind is inert in the fold — a cost
ledger has NO honored-unsigned direction, exactly like the wallet):
  * ``governor.cost_reserve`` — reserves ``tokens`` for ONE launch, ``entry_id = reserve-cost:{slug}:{nonce}``.
  * ``governor.cost_settle``  — settles that launch to ``tokens`` ACTUAL, ``entry_id = settle-cost:{slug}:{nonce}``;
    paired to its reserve by the shared ``{slug}:{nonce}`` SUFFIX (mirrors the postpaid reserve/settle pairing).

Idempotent per ``(signal, org_id, entry_id)`` (a replay — incl. one re-appended after a hard prune — counts
once); ``tokens`` clamped >= 0 so a forged NEGATIVE record cannot refund the pool / lower a tenant's cost.
Snapshot-seeded from ``SnapshotState`` + guarded by prune tripwires (``stranded_active_cost_reserves`` for an
in-flight reserve below the prune boundary, ``stranded_cost_ledger`` for the per-org aggregate) so a hard prune
can neither zero a tenant's committed cost nor re-open reserve/settle replay. Keyed on the owner-signed
``org_id`` — a tenant can never be charged another tenant's cost.

DEFAULT-OFF: this is the ledger primitive only. Wiring it into the live launch-gate money path (reserve on
``reserve_launch``, settle from the ACTUAL recorded tokens on ``settle_launch``), the global pool meter (EC-5),
and the keyless engine's actual-token delivery are later slices; the owner ratifies ``ENVELOPE_TOKENS_PER_CREDIT``
and the per-tier $ cost rate before any production go-live.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors wallet._fold)
from .authn import signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id validation == tenant-id validation; same-plane reuse)
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed — mirrors wallet._fold)
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402
from .ledger_view import PairedLedgerView  # noqa: E402

COST_RESERVE_SIGNAL = "governor.cost_reserve"
COST_SETTLE_SIGNAL = "governor.cost_settle"

# The reserve/settle entry_id scheme — SHARED by the gate (which will write the pair, ui/launch_gate.py) and
# this ledger's in-flight pairing (which reads them), single-sourced HERE so the two can never drift. A
# cost_reserve under RESERVE_COST_PREFIX whose matching SETTLE_COST_PREFIX record has NOT yet landed is an
# IN-FLIGHT launch (reserved, not settled) — its envelope is held OUT of committed cost (`in_flight_envelope`).
RESERVE_COST_PREFIX = "reserve-cost:"
SETTLE_COST_PREFIX = "settle-cost:"

# The owner-signed authenticated CORE of each record. `entry_id` is inside it so a captured record cannot be
# re-stamped with a fresh idempotency key; `tokens`/`org_id` are inside it so a record for (orgA, N) can never
# be re-aimed at another org or have its amount rewritten without breaking the signature. `issued_at` is
# audit/ordering only (the ledger is additive, idempotency is by entry_id — which is why entry_id MUST be signed).
_RESERVE_CORE = ("signal", "org_id", "entry_id", "tokens", "engagement_id", "issued_at")
_SETTLE_CORE = ("signal", "org_id", "entry_id", "tokens", "engagement_id", "issued_at")


def _as_tokens(v: object) -> int:
    """A tokens value read off the spine → a non-negative int. CLAMPED to >= 0 (mirrors wallet._as_credits):
    the fold SUMS signed per-record values, so a NEGATIVE record must not CANCEL real cost (a fail-OPEN
    refund / pool-draw bypass). Junk / NaN / an over-large int (OverflowError) → 0."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float, str)):
        try:
            n = int(v)
        except (TypeError, ValueError, OverflowError):
            return 0
        return n if n > 0 else 0
    return 0


def _check_tokens(tokens: int, *, allow_zero: bool) -> int:
    """Validate a tokens amount at BINDING time (a clean ValueError now, never a silent bad record later). A
    reserve of 0 is meaningless (refused); a settle of 0 is legitimate (a run that consumed no real tokens —
    e.g. fully cache-served — must still settle its reservation, mirroring the postpaid settle-at-0 invariant)."""
    if isinstance(tokens, bool) or not isinstance(tokens, int):
        raise ValueError("tokens must be a non-negative integer")
    if tokens < 0 or (tokens == 0 and not allow_zero):
        raise ValueError("tokens must be a positive integer" if not allow_zero
                         else "tokens must be a non-negative integer")
    return tokens


def _check_entry_id(entry_id: str, *, prefix: str = "") -> str:
    """The idempotency key for one ledger entry (reserve-cost:/settle-cost: + {slug}:{nonce} from the gate).
    Bounded + non-control so it round-trips the signed core and the snapshot rows verbatim. NOT auto-generated:
    the suffix pairing is load-bearing, so the caller always supplies it. `prefix` (when given) is ENFORCED at
    bind so the prefix-AGNOSTIC fold (reserved_total/committed/was_reserved sum EVERY owner-signed record) and
    the prefix-GATED in-flight pairing (which keys on the {slug}:{nonce} SUFFIX after the prefix) can never
    disagree on what a reservation is — a reserve MUST be under RESERVE_COST_PREFIX, a settle under SETTLE_COST_PREFIX."""
    e = str(entry_id or "").strip()
    if not e or len(e) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in e):
        raise ValueError("entry_id must be a non-empty, non-control string of <= 128 chars")
    if prefix and not e.startswith(prefix):
        raise ValueError(f"entry_id must start with {prefix!r} (reserve/settle prefixes are load-bearing)")
    return e


_SKIP = object()          # `_apply_cost_record`: the record was not counted


def _apply_cost_record(r, resolver, reserved: dict, settled: dict, seen: set):
    """Fold ONE spine record into (reserved, settled, seen) — THE cost-ledger fold body, shared by the full
    `_fold` and the verified fold cache (Front C S0d) so the two can never diverge. Returns the counted record's
    `(signal, org_id, entry_id, tokens)`, or `_SKIP` (not a cost record, malformed, unverified, or a replay)."""
    p = r.payload
    if not isinstance(p, dict):
        return _SKIP
    sig = p.get("signal")
    if sig != COST_RESERVE_SIGNAL and sig != COST_SETTLE_SIGNAL:
        return _SKIP
    oid = p.get("org_id")
    eid = p.get("entry_id")
    if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
        return _SKIP
    core = _RESERVE_CORE if sig == COST_RESERVE_SIGNAL else _SETTLE_CORE
    if not verify_signed(p, core, resolver.at(r.seq)):
        return _SKIP                                      # fail-closed: unsigned/forged/wrong-epoch record
    # Idempotency key namespaced by SIGNAL (direction) so a reserve + a settle are disjoint dedup spaces
    # even if a caller reuses the raw entry_id — mirrors wallet. (In practice the prefixes already differ.)
    key = (sig, oid, eid)
    if key in seen:
        return _SKIP
    seen.add(key)
    amount = _as_tokens(p.get("tokens"))
    if sig == COST_RESERVE_SIGNAL:
        reserved[oid] = reserved.get(oid, 0) + amount
    else:
        settled[oid] = settled.get(oid, 0) + amount
    return sig, oid, eid, amount


def _new_cost_view(reserved: dict, settled: dict, seen: set) -> PairedLedgerView:
    return PairedLedgerView(reserved, settled, seen, up_signal=COST_RESERVE_SIGNAL,
                            reserve_prefix=RESERVE_COST_PREFIX, settle_prefix=SETTLE_COST_PREFIX)


def _cost_step(view: PairedLedgerView, r, resolver) -> None:
    hit = _apply_cost_record(r, resolver, view.up, view.down, view.seen)
    if hit is not _SKIP:
        view.pair(*hit)


_COST_FOLD = FoldCache("governor.cost_ledger", step=_cost_step)


@dataclass(frozen=True)
class TenantCost:
    """A tenant's current cost position, every field derived from the spine (never a stored counter)."""
    org_id: str
    committed_tokens: int    # Σ settled ACTUAL tokens (the attributed real cost, lifetime)
    reserved_tokens: int     # Σ reserved envelope tokens (lifetime)
    in_flight_tokens: int     # Σ reserved envelope of reserves whose settle has not landed (the pending pool draw)


@dataclass(frozen=True)
class GlobalCostPosition:
    """The GLOBAL (cross-tenant) cost position — the scalar the EC-5 pool meter draws against. `used` =
    committed + in_flight (Σ settled ACTUAL tokens + Σ in-flight reserved envelope, across ALL tenants)."""
    committed_tokens: int    # Σ settled ACTUAL tokens, ALL tenants
    in_flight_tokens: int    # Σ reserved envelope of reserved-but-unsettled launches, ALL tenants

    @property
    def used_tokens(self) -> int:
        """The total GLOBAL pool draw: committed real cost + the pending (in-flight) reserved envelope."""
        return self.committed_tokens + self.in_flight_tokens


class CostEnvelopeLedger:
    """Owner-signed per-tenant token-cost envelope ledger on the spine. Construction mirrors ``WalletRegistry``:
    the owner signing key + trusted pubkey default to the persisted owner identity; tests inject explicit keys."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def reserve(self, org_id: str, tokens: int, *, entry_id: str, engagement_id: str = "",
                issued_at: float) -> int:
        """Owner-sign a cost-envelope RESERVE for a launch — the hard token cap it may spend. `entry_id` is the
        gate's ``reserve-cost:{slug}:{nonce}``. Requires the owner signing key (an unsigned reserve is inert in
        the fold). Idempotent per `entry_id`. Returns the record seq."""
        if self.owner_key is None:
            raise ValueError("cost reserve requires the owner signing key")
        oid = org_tenant_id(org_id)
        t = _check_tokens(tokens, allow_zero=False)
        eid = _check_entry_id(entry_id, prefix=RESERVE_COST_PREFIX)
        core = {"signal": COST_RESERVE_SIGNAL, "org_id": oid, "entry_id": eid, "tokens": t,
                "engagement_id": str(engagement_id or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"cost reserve {t} tok -> {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def settle(self, org_id: str, tokens: int, *, entry_id: str, reserved_cap: Optional[int] = None,
               engagement_id: str = "", issued_at: float) -> int:
        """Owner-sign a cost SETTLE — the ACTUAL tokens the run recorded, CLAMPED to `reserved_cap` (the signed
        reserved envelope) when supplied, so a forged over-report can never charge past the reservation. `entry_id`
        is the gate's ``settle-cost:{slug}:{nonce}`` (same {slug}:{nonce} suffix as its reserve). A settle of 0 is
        allowed (a run that consumed no real tokens). Idempotent per `entry_id`. Returns the record seq."""
        if self.owner_key is None:
            raise ValueError("cost settle requires the owner signing key")
        oid = org_tenant_id(org_id)
        t = _check_tokens(tokens, allow_zero=True)
        if reserved_cap is not None:
            cap = _as_tokens(reserved_cap)
            if t > cap:
                t = cap                                       # clamp actual to the reserved envelope (fail-closed)
        eid = _check_entry_id(entry_id, prefix=SETTLE_COST_PREFIX)
        core = {"signal": COST_SETTLE_SIGNAL, "org_id": oid, "entry_id": eid, "tokens": t,
                "engagement_id": str(engagement_id or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"cost settle {t} tok <- {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _seed(self, snap) -> "tuple[tuple[dict, dict, set], int]":
        """((reserved, settled, seen), since): the HARD-PRUNE SEED from `snap`, or the empty genesis start when
        the trusted pubkey differs from the snapshot's."""
        if self.trusted_pubkey != snap.trusted_pubkey:
            # Anchor mismatch (rotated key / empty identity) ⇒ bypass the snapshot and full-scan from genesis,
            # mirroring wallet._fold. Unreachable with a real prune today (SnapshotState.load fails closed on any
            # real prune), so this branch is only taken under the empty snapshot, where genesis-scan == the fold.
            return ({}, {}, set()), -1
        return (dict(snap.cost_reserved_map()), dict(snap.cost_settled_map()), set(snap.cost_seen_set())), \
            snap.base_seq - 1

    def _cached(self, reader):
        """`reader(view)` over the verified incremental cost-ledger fold (`fold_read.cached_read`, flag-gated),
        else `_UNCACHED` (the caller then runs the full `_fold` / pairing scans)."""
        def seed(snap):
            st, since = self._seed(snap)
            return _new_cost_view(*st), since

        return cached_read(_COST_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed, reader=reader)

    def _fold(self) -> tuple[dict[Any, int], dict[Any, int], set]:
        """Fold the spine into (reserved_total, settled_total, seen) where `seen` is the set of consumed
        ``(signal, org_id, entry_id)`` idempotency keys. Each signed record is authenticated under the owner
        pubkey valid AT ITS SEQ; a record already in `seen` is ignored (replay/double-count guard). HARD-PRUNE
        SEED (mirrors wallet._fold): seed the per-org totals + the `seen` set from ``SnapshotState``, then fold
        the LIVE window only — so a pruned record stays counted + its entry_id stays consumed. A rotated/empty
        anchor BYPASSES the snapshot and full-scans from genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (reserved, settled, seen), since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_cost_record(r, resolver, reserved, settled, seen)
        return reserved, settled, seen

    def _in_flight(self, org_id: str) -> int:
        """Σ reserved-envelope tokens of this tenant's IN-FLIGHT launches — owner-signed cost_reserves under
        ``RESERVE_COST_PREFIX`` whose matching ``SETTLE_COST_PREFIX`` record has NOT yet landed (reserved, not
        settled). A pairing scan by the ``{slug}:{nonce}`` entry_id SUFFIX (mirrors postpaid in_flight). The
        per-reserve AMOUNTS come from the LIVE window only — ``stranded_active_cost_reserves`` fail-closed refuses
        a prune that would archive an UNSETTLED reserve, so the live window always holds every genuinely in-flight
        reserve + its paired settle. But the consumed-entry_id SEEN-SET is SNAPSHOT-SEEDED exactly as
        :meth:`_fold`, so a replay whose entry_id was consumed BEFORE a hard prune (e.g. a re-appended
        already-settled reserve whose paired settle was itself pruned, so it cannot pair live) is ignored here
        too — WITHOUT the seed it would resurrect as a PHANTOM in-flight pool draw. Fail-closed verify + idempotent."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        reserves: dict[str, int] = {}     # in-flight suffix -> reserved tokens (first-mint-wins, idempotent)
        settled: set[str] = set()         # suffixes whose settle record has landed
        if self.trusted_pubkey != snap.trusted_pubkey:
            seen: set = set()             # anchor mismatch (rotated/empty key) => genesis scan, mirror _fold
            since = -1
        else:
            seen = set(snap.cost_seen_set())   # seed the consumed-entry_id set so a pre-prune replay is ignored
            since = snap.base_seq - 1          # scan the LIVE window only (tripwire keeps every real in-flight here)
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig != COST_RESERVE_SIGNAL and sig != COST_SETTLE_SIGNAL:
                continue
            if p.get("org_id") != org_id:
                continue
            eid = p.get("entry_id")
            if not (isinstance(eid, str) and eid):
                continue
            core = _RESERVE_CORE if sig == COST_RESERVE_SIGNAL else _SETTLE_CORE
            if not verify_signed(p, core, resolver.at(r.seq)):
                continue                                      # fail-closed: never let a forged record move it
            key = (sig, org_id, eid)
            if key in seen:
                continue                                      # idempotent + prune-durable (seeded from snapshot)
            seen.add(key)
            if sig == COST_RESERVE_SIGNAL and eid.startswith(RESERVE_COST_PREFIX):
                reserves[eid[len(RESERVE_COST_PREFIX):]] = _as_tokens(p.get("tokens"))
            elif sig == COST_SETTLE_SIGNAL and eid.startswith(SETTLE_COST_PREFIX):
                settled.add(eid[len(SETTLE_COST_PREFIX):])
        return sum(amt for suf, amt in reserves.items() if suf not in settled)

    def committed_cost(self, org_id: str) -> int:
        """The tenant's attributed REAL cost = Σ settled actual tokens (fail-closed 0 on empty id). The scalar
        the EC-6 reconciliation compares against credits charged."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        hit = self._cached(lambda v: v.down.get(org_id, 0))
        if hit is not _UNCACHED:
            return hit
        _reserved, settled, _ = self._fold()
        return settled.get(org_id, 0)

    def in_flight_envelope(self, org_id: str) -> int:
        """Σ reserved envelope of this tenant's reserved-but-unsettled launches (the pending pool draw)."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        hit = self._cached(lambda v: v.in_flight.get(org_id, 0))
        if hit is not _UNCACHED:
            return hit
        return self._in_flight(org_id)

    def reserved_total(self, org_id: str) -> int:
        """Σ reserved envelope ever (lifetime; fail-closed 0 on empty id)."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        hit = self._cached(lambda v: v.up.get(org_id, 0))
        if hit is not _UNCACHED:
            return hit
        reserved, _settled, _ = self._fold()
        return reserved.get(org_id, 0)

    def was_reserved(self, org_id: str, entry_id: str) -> bool:
        """True iff a cost_reserve for `(org_id, entry_id)` has been folded (prune-durable discriminator reading
        the seeded seen-set; mirrors postpaid.was_accrued). Used by the settle seam to bind a settle to a real
        reserve, and by the prune tripwire."""
        if not (isinstance(org_id, str) and org_id and isinstance(entry_id, str) and entry_id):
            return False
        key = (COST_RESERVE_SIGNAL, org_id, entry_id)
        hit = self._cached(lambda v: key in v.seen)
        if hit is not _UNCACHED:
            return hit
        _reserved, _settled, seen = self._fold()
        return key in seen

    def was_settled(self, org_id: str, entry_id: str) -> bool:
        """True iff a cost_settle for `(org_id, entry_id)` has been folded (the seeded seen-set, prune-durable;
        mirrors `was_reserved`). The launch settle roll-forward writes a missing ``settle-cost:`` entry only when this
        is False, so a re-settle never appends a duplicate. Fail-closed (False) on an empty id."""
        if not (isinstance(org_id, str) and org_id and isinstance(entry_id, str) and entry_id):
            return False
        key = (COST_SETTLE_SIGNAL, org_id, entry_id)
        hit = self._cached(lambda v: key in v.seen)
        if hit is not _UNCACHED:
            return bool(hit)
        _reserved, _settled, seen = self._fold()
        return key in seen

    def tenant_cost(self, org_id: str) -> TenantCost:
        """The full cost position for `org_id` (fail-closed: unknown/empty reads all-zero)."""
        if not isinstance(org_id, str) or not org_id:
            return TenantCost(org_id="", committed_tokens=0, reserved_tokens=0, in_flight_tokens=0)
        hit = self._cached(lambda v: TenantCost(org_id=org_id, committed_tokens=v.down.get(org_id, 0),
                                                reserved_tokens=v.up.get(org_id, 0),
                                                in_flight_tokens=v.in_flight.get(org_id, 0)))
        if hit is not _UNCACHED:
            return hit
        reserved, settled, _ = self._fold()
        return TenantCost(org_id=org_id, committed_tokens=settled.get(org_id, 0),
                          reserved_tokens=reserved.get(org_id, 0), in_flight_tokens=self._in_flight(org_id))

    def tenant_costs(self) -> list[TenantCost]:
        """Every tenant with cost-ledger activity, in org_id order (the per-tenant margin view)."""
        hit = self._cached(lambda v: [TenantCost(org_id=str(o), committed_tokens=v.down.get(o, 0),
                                                 reserved_tokens=v.up.get(o, 0),
                                                 in_flight_tokens=v.in_flight.get(str(o), 0))
                                      for o in sorted(set(v.up) | set(v.down))])
        if hit is not _UNCACHED:
            return hit
        reserved, settled, _ = self._fold()
        orgs = sorted(set(reserved) | set(settled))
        return [TenantCost(org_id=str(o), committed_tokens=settled.get(o, 0),
                           reserved_tokens=reserved.get(o, 0), in_flight_tokens=self._in_flight(str(o)))
                for o in orgs]

    def global_position(self) -> GlobalCostPosition:
        """The GLOBAL (cross-tenant) cost position in ONE O(spine) pass — the read EC-5's pool meter draws
        against. Returns ``GlobalCostPosition(committed, in_flight)`` where committed = Σ settled ACTUAL tokens
        and in_flight = Σ reserved envelope of reserved-but-unsettled launches, summed across ALL tenants.

        This is an EQUIVALENCE-ORACLE match for ``sum over tenant_costs() of (committed + in_flight)`` but in a
        SINGLE spine scan — folding the settled total and the global reserve/settle suffix-pairing together —
        rather than ``tenant_costs()``'s O(orgs × spine) per-org ``_in_flight`` loop. Every discipline of the
        per-tenant fold is preserved verbatim: fail-closed ``verify_signed`` under the succession-aware resolver
        at each record's seq (a forged / replayed / wrong-epoch record never moves the pool), the SnapshotState
        hard-prune seed (committed seeded from the folded settled map; the consumed-entry_id ``seen`` set seeded
        so a pre-prune replay cannot resurrect as a PHANTOM in-flight draw), and the ``{org_id}:{suffix}`` pairing
        (the suffix after the prefix, keyed per org so cross-tenant suffix collisions never pair). The in-flight
        reserve AMOUNTS come from the LIVE window only — ``stranded_active_cost_reserves`` fail-closed refuses a
        prune that would archive an unsettled reserve, exactly as ``_in_flight`` relies on.

        With the fold cache on (Front C S0d) this is O(1): `PairedLedgerView` keeps both scalars in step."""
        hit = self._cached(lambda v: GlobalCostPosition(committed_tokens=v.down_total,
                                                        in_flight_tokens=v.in_flight_total))
        if hit is not _UNCACHED:
            return hit
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        reserves: dict[tuple[str, str], int] = {}   # (org_id, suffix) -> reserved tokens of an in-flight reserve
        settled_suffixes: set[tuple[str, str]] = set()   # (org_id, suffix) whose settle record has landed
        if self.trusted_pubkey != snap.trusted_pubkey:
            # Anchor mismatch (rotated/empty key) ⇒ bypass the snapshot and genesis-scan, mirroring _fold/_in_flight.
            committed = 0
            seen: set = set()
            since = -1
        else:
            committed = sum(snap.cost_settled_map().values())   # seed Σ settled from the folded prefix (== _fold)
            seen = set(snap.cost_seen_set())                    # seed consumed entry_ids (prune-durable, no phantoms)
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig != COST_RESERVE_SIGNAL and sig != COST_SETTLE_SIGNAL:
                continue
            oid = p.get("org_id")
            eid = p.get("entry_id")
            if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
                continue
            core = _RESERVE_CORE if sig == COST_RESERVE_SIGNAL else _SETTLE_CORE
            if not verify_signed(p, core, resolver.at(r.seq)):
                continue                                        # fail-closed: unsigned/forged/wrong-epoch is inert
            key = (sig, oid, eid)
            if key in seen:
                continue                                        # idempotent + prune-durable (seeded from snapshot)
            seen.add(key)
            amount = _as_tokens(p.get("tokens"))
            if sig == COST_SETTLE_SIGNAL:
                committed += amount                             # Σ settled ACTUAL (global committed cost)
                if eid.startswith(SETTLE_COST_PREFIX):
                    settled_suffixes.add((oid, eid[len(SETTLE_COST_PREFIX):]))
            elif eid.startswith(RESERVE_COST_PREFIX):
                reserves[(oid, eid[len(RESERVE_COST_PREFIX):])] = amount
        in_flight = sum(amt for k, amt in reserves.items() if k not in settled_suffixes)
        return GlobalCostPosition(committed_tokens=committed, in_flight_tokens=in_flight)
