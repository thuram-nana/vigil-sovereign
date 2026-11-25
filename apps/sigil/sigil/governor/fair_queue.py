"""Fair cross-tenant launch queue — the SOVEREIGN side of the tenant-fair claim (consumer PR-F, plan Area 5).

When ``VIGIL_CUSTOMER_FAIR_QUEUE`` is on, the engine's durable job queue (``framework.v2.engagement_scheduler``)
claims tenant-fair instead of by arrival: the oldest job of the tenant with the fewest jobs running, then the least
recent service (``vigil_core.fair_share`` — ONE policy, imported by both planes). This module is that same policy
seen from the sovereign plane:

  * :func:`fair_order` / :func:`admit` / :func:`position_of` — the policy over caller-supplied items: the order the
    claimer serves them, which may run now within a TOTAL concurrency bound, and one launch's place. They are
    STATEFUL like the claimer: the running set and the persisted service history (:class:`FairState`) are inputs,
    and :func:`admit` returns the history after its admissions, so a caller draining one freed slot at a time stays
    fair (a pending-set-only rank reverts to arrival order under exactly that drain).
  * :func:`read_launch_positions` — the LIVE source of the customer launches read: it reads the engine queue's own
    files (read-only, bounded, lock-free) and returns, for ONE org's own pending launches, how many jobs the
    scheduler will claim before each. The launches read shows that count as "queued"; nothing else consumes it.

What it is NOT: it orders and counts; it authorizes nothing. Every claimed job still passes the slug lease and the
run gate, and a target is never parallelized (a job whose slug is running waits). It mints NO FACT — a queue
position is a UI notice — and it reads no model identifier.

IDOR. Nothing here knows who is asking. A target slug is ``_customer_slug(org, host)``, an UNKEYED hash anyone who
knows the org id and host can compute, so naming a slug proves nothing and :func:`position_of` answers for whatever
tenant it is handed. Isolation comes from the CALLER: the launches read passes the org bound to the session
principal (never a request field) and annotates only that org's own verified leases, with a count — never another
tenant's id, host, slug or nonce.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); imports the shared ``vigil_core`` leaf and stdlib only —
no engine module. DEFAULT-OFF at its call site (the launches read checks the flag before calling it).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.fair_share import (  # noqa: E402
    FairJob, FairState, QueueSnapshot, claim_order, pick_next, read_queue_snapshot, record_service,
)

#: The engine queue lives here under the cross-plane base directory — where ``vigil launch-drain`` puts it by default.
QUEUE_SUBDIR = "jobs"
#: A queue larger than this yields no position at all (an exact answer or none, never a guess).
SNAPSHOT_LIMIT = 10_000


@dataclass(frozen=True)
class QueueItem:
    """One launch in the cross-tenant queue.

      * ``tenant``  — the ``org_id`` whose fair share this launch draws on.
      * ``seq``     — the global ARRIVAL order (the queue's sequence number).
      * ``target``  — the per-``(org, host)`` slug (``cust_<hash>``): the SERIAL-PER-TARGET key.
      * ``job_id``  — the opaque launch / job id (a final tie-break).
    """

    tenant: str
    seq: int
    target: str
    job_id: str = ""


@dataclass(frozen=True)
class Admission:
    """:func:`admit` 's answer: the launches admitted now (in claim order), those honestly QUEUED (in the order the
    claimer will serve them), and the service history AFTER the admissions — feed it to the next call."""

    admitted: "tuple[QueueItem, ...]" = ()
    queued: "tuple[QueueItem, ...]" = ()
    state: FairState = FairState()


@dataclass(frozen=True)
class QueuePosition:
    """One launch's place — COUNTS only.

      * ``state``       — ``"admitted"`` (may run now) or ``"queued"``.
      * ``ahead``       — how many queued launches the claimer serves before this one (0 when admitted).
      * ``queue_depth`` — how many launches are queued in total.
    """

    state: str
    ahead: int
    queue_depth: int


def _job(it: QueueItem) -> FairJob:
    return FairJob(tenant=str(it.tenant), seq=int(it.seq), slug=str(it.target), job_id=str(it.job_id))


def _item(j: FairJob) -> QueueItem:
    return QueueItem(tenant=j.tenant, seq=j.seq, target=j.slug, job_id=j.job_id)


def _running_jobs(running: "Iterable[object]") -> "list[FairJob]":
    """``running`` as policy jobs. Accepts :class:`QueueItem` s or bare ``(tenant, target)`` pairs; each counts once
    toward its tenant's running total and makes its target busy."""
    out: "list[FairJob]" = []
    for r in running:
        if isinstance(r, QueueItem):
            out.append(_job(r))
        elif isinstance(r, (tuple, list)) and len(r) == 2:
            out.append(FairJob(tenant=str(r[0]), seq=-1, slug=str(r[1])))
    return out


def fair_order(items: "Sequence[QueueItem]", *, running: "Iterable[object]" = (),
               state: "Optional[FairState]" = None) -> "list[QueueItem]":
    """The order the claimer serves ``items`` in, given what is ``running`` and the service history ``state``
    (``vigil_core.fair_share.claim_order``): fewest running first, then least recent service, then arrival; each
    tenant's own launches keep their arrival order; a launch whose target is running waits. Pure + deterministic."""
    return [_item(j) for j in claim_order([_job(i) for i in items], _running_jobs(running), state)]


def admit(items: "Sequence[QueueItem]", *, running: "Iterable[object]" = (), capacity: Optional[int] = None,
          state: "Optional[FairState]" = None) -> Admission:
    """Which pending launches may run NOW, which are QUEUED, and the service history after.

    ``capacity`` is the TOTAL cross-tenant concurrency bound: the launches already ``running`` count toward it, so
    ``capacity - len(running)`` slots are free (``None`` = unbounded; a bound at or under the running count admits
    nothing — every launch honestly queued, e.g. a REFUSE_NEW cost-pool posture). Each free slot goes to the policy's
    next pick among launches whose target is free: a launch whose target is running (or was just admitted) waits
    and never takes a slot, so one target is never parallelized. Pure + deterministic."""
    run = _running_jobs(running)
    pending = [_job(i) for i in items]
    free = None if capacity is None else max(0, int(capacity) - len(run))
    st = state or FairState()
    admitted: "list[FairJob]" = []
    while pending and (free is None or len(admitted) < free):
        nxt = pick_next(pending, run, st)                  # serial only: a busy target is never admitted
        if nxt is None:
            break
        pending.remove(nxt)
        run.append(nxt)
        admitted.append(nxt)
        st = record_service(st, nxt.tenant)
    queued = claim_order(pending, run, st)
    return Admission(admitted=tuple(_item(j) for j in admitted), queued=tuple(_item(j) for j in queued), state=st)


def position_of(items: "Sequence[QueueItem]", *, tenant: str, target: str, seq: int,
                running: "Iterable[object]" = (), capacity: Optional[int] = None,
                state: "Optional[FairState]" = None) -> Optional[QueuePosition]:
    """The place of the launch ``(tenant, target, seq)`` — a :class:`QueuePosition` of counts, or None when no such
    launch is pending. It answers for whatever ``tenant`` it is handed: the CALLER must bind ``tenant`` to the
    session principal (see the module docstring). Pure."""
    want = (str(tenant), str(target), int(seq))
    adm = admit(items, running=running, capacity=capacity, state=state)
    for it in adm.admitted:
        if (it.tenant, it.target, int(it.seq)) == want:
            return QueuePosition(state="admitted", ahead=0, queue_depth=len(adm.queued))
    for ahead, it in enumerate(adm.queued):
        if (it.tenant, it.target, int(it.seq)) == want:
            return QueuePosition(state="queued", ahead=ahead, queue_depth=len(adm.queued))
    return None


def make_items(rows: "Iterable[Mapping[str, object]]") -> "tuple[QueueItem, ...]":
    """Normalize caller rows (``{"tenant", "seq", "target", "job_id"?}``) into :class:`QueueItem` s. A row missing
    ``tenant`` / ``target``, or whose ``seq`` is not an int, is DROPPED (a malformed source can never inject a
    phantom position)."""
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


# ----------------------------------------------------------------------------------- the live launches source ----
def launch_positions(org_id: str, snapshot: QueueSnapshot) -> "dict[tuple[str, str], int]":
    """``{(slug, nonce): ahead}`` for ``org_id`` 's OWN pending launch jobs in ``snapshot``: ``ahead`` is how many
    jobs (of any tenant) the scheduler claims before that one if nothing finishes meanwhile. Only the asking org's
    jobs are keys; other tenants contribute to the counts and nothing else. Pure."""
    out: "dict[tuple[str, str], int]" = {}
    if not org_id:
        return out
    for i, j in enumerate(claim_order(snapshot.pending, snapshot.running, snapshot.state)):
        if j.tenant == org_id and j.slug and j.nonce:
            out.setdefault((j.slug, j.nonce), i)
    return out


def default_queue_root() -> str:
    """The engine job queue's root as the shipped units lay it out: ``<cross-plane base>/jobs`` (``vigil launch-drain``
    roots its queue there unless told otherwise)."""
    from vigil_core.seam_base import resolve_seam_base
    return os.path.join(resolve_seam_base(), QUEUE_SUBDIR)


def read_launch_positions(org_id: str, *, root: "Optional[str]" = None) -> "dict[tuple[str, str], int]":
    """:func:`launch_positions` over the LIVE queue (read-only, lock-free, bounded): ``{}`` when there is no queue, it
    is larger than :data:`SNAPSHOT_LIMIT`, or nothing of ``org_id`` 's is pending — the caller then shows no
    position, never a guessed one."""
    snap = read_queue_snapshot(root or default_queue_root(), limit=SNAPSHOT_LIMIT)
    return {} if snap is None else launch_positions(org_id, snap)
