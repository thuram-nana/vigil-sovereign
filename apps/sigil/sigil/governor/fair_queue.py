"""Fair cross-tenant launch queue — the SOVEREIGN, PURE ordering layer for consumer PR-F.

When many tenants start assessments at once, the keyless offense fleet drains them with bounded concurrency. A
naive FIFO (the engine's :class:`~framework.v2.engagement_scheduler.EngagementScheduler`, which orders STRICTLY by
enqueue sequence) lets ONE tenant that floods the queue sit at the head and STARVE every other tenant until its
backlog clears. This module is the sovereign-side answer: a pure, deterministic FAIR ORDER across tenants so no
tenant starves another, and an honest "queued" position so load surfaces as a truthful wait rather than a silent
drop.

What this is, and — load-bearing — what it is NOT:

  * FAIRNESS IS CROSS-TENANT ORDERING ONLY. :func:`fair_order` re-orders the HEAD-selection across tenants. It
    NEVER parallelizes one target: :func:`admit` admits AT MOST ONE runnable slot per ``(tenant, target)`` — the
    SERIAL-PER-TARGET invariant (target safety: one scan per target at a time). That composes with, and never
    weakens, the engine's own slug lease + serial-proof-per-host governor, which remain the authority on the run
    path. This layer only decides the ORDER in which distinct targets are offered and surfaces the wait.
  * DETERMINISTIC. Given the same items, running set and capacity, the order and the admission are a pure function
    — reproducible and offline-checkable. The tie-break is total (``seq`` then ``target`` then ``job_id``), so
    equal ranks never reorder non-deterministically.
  * MINTS NO FACT. A queue position is a UI notice; only the oracle mints a FACT. Nothing here signs, publishes or
    records anything — it is a pure function over data the caller already holds.
  * IDOR-SAFE BY CONSTRUCTION. :func:`position_of` answers "where is MY launch" with COUNTS only (how many are
    ahead, how deep the queue) — never another tenant's identity, host or target. A caller can only name its own
    launch because ``target`` is the one-way ``_customer_slug(org_id, host)`` hash it can re-derive solely for its
    own ``org_id`` (``target_authorization._customer_slug``). The per-customer route passes the cross-tenant item
    list in and returns ONLY the resulting :class:`QueuePosition`, after confirming the ``(tenant, target)`` is the
    session's own org.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); stdlib only — it imports NO engine/offense module (it
reuses the scheduler's CONCEPT of a durable FIFO, never its code). DEFAULT-OFF at the call sites (the PR-F flag);
this module itself is inert until a caller invokes it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from ..reuse import assert_no_offense

assert_no_offense()


@dataclass(frozen=True)
class QueueItem:
    """One pending launch in the cross-tenant queue.

      * ``tenant``  — the ``org_id`` whose fairness share this launch draws on (grouping key for fairness).
      * ``seq``     — the global ARRIVAL order (monotonic; e.g. the spine seq / publish order at which the launch
                      was started). The deterministic tie-break AND the within-tenant FIFO order.
      * ``target``  — the OPAQUE per-``(org, host)`` slug (``cust_<hash>`` from ``_customer_slug``), the
                      SERIAL-PER-TARGET key. It already encodes the tenant, so two tenants never share a target.
      * ``job_id``  — the opaque launch nonce/id (a final, total tie-break; never a cross-tenant identity).
    """

    tenant: str
    seq: int
    target: str
    job_id: str = ""


@dataclass(frozen=True)
class Admission:
    """The result of :func:`admit`: which items may run NOW (fair across tenants, serial per target, within
    capacity) and which are honestly QUEUED, in fair order. Both are counts-and-items the caller may surface; the
    per-customer route reduces them to a single :class:`QueuePosition` for the asking tenant."""

    admitted: "tuple[QueueItem, ...]" = ()
    queued: "tuple[QueueItem, ...]" = ()


@dataclass(frozen=True)
class QueuePosition:
    """A tenant's OWN launch position — COUNTS only, never another tenant's identity (IDOR-safe).

      * ``state``       — ``"admitted"`` (may run now) or ``"queued"`` (honestly waiting).
      * ``ahead``       — how many launches are ahead of this one in fair order (0 when admitted).
      * ``queue_depth`` — the total number of queued launches across all tenants (a count, no identities).
    """

    state: str
    ahead: int
    queue_depth: int


def _fifo_key(it: QueueItem) -> "tuple[int, str, str]":
    """The TOTAL within-tenant order: arrival ``seq``, then ``target``, then ``job_id``. Total (never a tie) so
    ranks are deterministic even if two items of one tenant somehow share a ``seq``."""
    return (int(it.seq), str(it.target), str(it.job_id))


def _ranks(items: "Sequence[QueueItem]") -> "list[int]":
    """For each item, its 0-based RANK within its own tenant's FIFO (0 = that tenant's oldest). This is the
    virtual 'round' of start-time fair queueing with equal weights: round r holds each tenant's r-th oldest."""
    per_tenant: "dict[str, list[int]]" = {}
    for i in sorted(range(len(items)), key=lambda i: _fifo_key(items[i])):
        per_tenant.setdefault(items[i].tenant, []).append(i)
    rank = [0] * len(items)
    for idxs in per_tenant.values():
        for r, i in enumerate(idxs):
            rank[i] = r
    return rank


def fair_order(items: "Sequence[QueueItem]") -> "list[QueueItem]":
    """The deterministic FAIR cross-tenant order. The sort key is ``(rank_within_tenant, seq, target, job_id)``:

      * ROUND-ROBIN FAIRNESS — every tenant's rank-0 (oldest) launch precedes every tenant's rank-1 launch, etc.
        A tenant that floods N launches only ever competes with others at each round, so a single-launch tenant at
        rank 0 is served before the flooder's rank-1..N backlog — it can NEVER be starved by the flood.
      * PER-TENANT FIFO — within one tenant, rank increases strictly with ``_fifo_key``, so a tenant's launches
        keep their own arrival order.
      * TOTAL + DETERMINISTIC — the ``(seq, target, job_id)`` tail makes the order total; the same input always
        yields the same output.

    Pure: no store, no clock, no mutation of ``items``."""
    rank = _ranks(items)
    order = sorted(range(len(items)), key=lambda i: (rank[i],) + _fifo_key(items[i]))
    return [items[i] for i in order]


def _running_keys(running: "Iterable[object]") -> "set[tuple[str, str]]":
    """Normalize a ``running`` argument to a set of ``(tenant, target)`` keys. Accepts :class:`QueueItem`s or
    bare ``(tenant, target)`` pairs, so a caller can pass either the live running items or just their keys."""
    keys: "set[tuple[str, str]]" = set()
    for r in running:
        if isinstance(r, QueueItem):
            keys.add((r.tenant, r.target))
        elif isinstance(r, (tuple, list)) and len(r) == 2:
            keys.add((str(r[0]), str(r[1])))
    return keys


def admit(items: "Sequence[QueueItem]", *, running: "Iterable[object]" = (),
          capacity: Optional[int] = None) -> Admission:
    """Decide which pending launches may run NOW and which are honestly queued, in fair order.

    Walk :func:`fair_order` once and, for each item:

      * SERIAL-PER-TARGET — if its ``(tenant, target)`` is already running, OR a sibling of the SAME target was
        already admitted in this pass, it is QUEUED (never a second concurrent run of one target). A target that
        is busy does NOT consume a capacity slot (it cannot run), so it never displaces a different target.
      * CAPACITY — otherwise, admit it while fewer than ``capacity`` have been admitted; the rest are QUEUED.
        ``capacity`` is the cross-tenant concurrency bound the caller derives from the gateway/cost-pool
        (``governor.cost_pool``): ``None`` = unbounded cross-tenant concurrency (but serial-per-target STILL
        holds); ``<= 0`` = admit nothing (everything honestly queued — e.g. a REFUSE_NEW pool posture).

    Returns an :class:`Admission`. Pure + deterministic."""
    cap = None if capacity is None else int(capacity)
    busy = _running_keys(running)
    admitted: "list[QueueItem]" = []
    queued: "list[QueueItem]" = []
    for it in fair_order(items):
        key = (it.tenant, it.target)
        if key in busy:
            # SERIAL-PER-TARGET: this target is already running or already admitted this pass — never parallelize
            # one target. It waits; it does NOT take a capacity slot it could not use.
            queued.append(it)
            continue
        if cap is not None and len(admitted) >= max(0, cap):
            queued.append(it)
            continue
        admitted.append(it)
        busy.add(key)  # claim the target so no sibling of it is admitted concurrently in this same pass
    return Admission(admitted=tuple(admitted), queued=tuple(queued))


def position_of(items: "Sequence[QueueItem]", *, tenant: str, target: str, seq: int,
                running: "Iterable[object]" = (), capacity: Optional[int] = None) -> Optional[QueuePosition]:
    """The asking tenant's OWN launch position — a :class:`QueuePosition` of COUNTS only, or ``None`` if no such
    launch is pending. IDOR-safe: the caller names its launch by ``(tenant, target, seq)`` — a tuple it can only
    produce for its OWN org (``target == _customer_slug(org_id, host)`` is a one-way hash it can re-derive solely
    for its own ``org_id``) — and the reply carries no other tenant's identity, host or target.

    ``ahead`` for a queued launch is the number of launches dequeued before it (its index in the fair queue);
    ``queue_depth`` is the total queued count. For an admitted launch both the state is ``"admitted"`` and
    ``ahead`` is 0. Pure."""
    want = (str(tenant), str(target), int(seq))
    adm = admit(items, running=running, capacity=capacity)
    for it in adm.admitted:
        if (it.tenant, it.target, int(it.seq)) == want:
            return QueuePosition(state="admitted", ahead=0, queue_depth=len(adm.queued))
    for ahead, it in enumerate(adm.queued):
        if (it.tenant, it.target, int(it.seq)) == want:
            return QueuePosition(state="queued", ahead=ahead, queue_depth=len(adm.queued))
    return None


def make_items(rows: "Iterable[Mapping[str, object]]") -> "tuple[QueueItem, ...]":
    """Normalize caller rows (``{"tenant", "seq", "target", "job_id"?}``) into validated :class:`QueueItem`s. A row
    missing ``tenant`` / ``target``, or whose ``seq`` is not an int, is DROPPED (a malformed queue source can never
    inject a phantom position). The live cross-tenant source — enumerating every org's started-but-not-yet-running
    lease from the seam and grouping by the lease's signed ``org_id`` — is the caller's job (see the module TODO);
    this helper keeps THIS layer pure and the source adapter a thin, obvious seam."""
    out: "list[QueueItem]" = []
    for row in rows:
        tenant = str(row.get("tenant") or "")
        target = str(row.get("target") or "")
        if not tenant or not target:
            continue
        seq_raw = row.get("seq")
        if isinstance(seq_raw, bool) or not isinstance(seq_raw, (int, float, str)):
            continue  # a malformed / missing seq (None, a dict, a bool) can never inject a phantom position
        try:
            seq = int(seq_raw)
        except (TypeError, ValueError):
            continue
        out.append(QueueItem(tenant=tenant, seq=seq, target=target, job_id=str(row.get("job_id") or "")))
    return tuple(out)
