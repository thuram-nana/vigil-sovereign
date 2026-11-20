"""FAIR SHARE — the ONE tenant-fair claim policy for the cross-tenant job queue (consumer PR-F, plan Area 5).

The engine's durable job queue (``framework.v2.engagement_scheduler``) claims strictly by arrival sequence: one
tenant that floods it sits at the head and every other tenant waits behind that tenant's whole backlog. This leaf
is the policy that replaces "lowest sequence wins" when ``VIGIL_CUSTOMER_FAIR_QUEUE`` is on, and it is the SAME
code on both planes: the engine claims with :func:`choose`, and the sovereign "queued" surface predicts the claim
order with :func:`claim_order` (which is :func:`choose` repeated), so the position a customer is shown is the
order the scheduler actually serves.

THE POLICY (deficit round-robin over tenants, the plan's item 1). The next job claimed is the oldest job of the
tenant with:

  1. the FEWEST jobs running now (read from the queue's ``running/`` directory), then
  2. the LEAST RECENT service (the tick at which the scheduler last claimed for it; never served sorts first), then
  3. the oldest head job (arrival ``seq``, then ``slug``, then ``job_id`` — a total order).

It is STATEFUL on purpose. A queue drains one freed slot at a time; a policy that only looks at the pending set
reverts to arrival order under such a drain, because every tenant's oldest job ties and the oldest of those wins.
Here the inputs a drain changes — who is running, and who was served last — decide the order, and the service
history is persisted by the claimer as :class:`FairState` (one small JSON document, :func:`dump_state` /
:func:`load_state`). So a tenant with G jobs running and a long backlog cannot take the next slot from a tenant
with none running, and with one free slot per tick N tenants are each served once in the first N claims.

SERIAL PER TARGET. A pending job whose ``slug`` already has a job running is skipped (one live run per slug — the
engine's slug lease remains the authority; this only keeps the claim from picking a job that would bounce). Only
when EVERY pending job waits on a busy slug does :func:`choose` fall back to the plain fair order, so a claimer is
never told "empty" while jobs are queued (the caller then sees the slug busy, exactly as before).

WHAT THIS IS NOT. It orders work; it authorizes nothing. It mints no FACT, signs nothing, decides no money, and
never lifts a gate: every claimed job still passes the run boundary's slug lease and authorization gate. A queue
position derived from it is a UI notice — counts only.

ON-DISK SNAPSHOT. :func:`scan_job_dir` / :func:`read_queue_snapshot` read the engine queue's own files (``queue/``,
``running/`` and ``fair/state.json`` under the queue root) into :class:`FairJob` s, so the engine claimer and the
sovereign read parse ONE format with ONE function. The files are untrusted at rest: every read is bounded, refuses
a symlink, and degrades a torn or hostile file to an anonymous job instead of raising.

FATAL-2: stdlib ONLY (``dataclasses``, ``heapq``, ``json``, ``os``, ``re``) — no ``framework.*``, no ``sigil.*``,
no ``vigil_integration.*`` — so the sovereign plane and the keyless engine both import this one leaf.
"""
from __future__ import annotations

import heapq
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

#: The queue root's sub-directories this leaf reads (the engine scheduler's own layout).
QUEUE_DIR = "queue"
RUNNING_DIR = "running"
#: Where the claimer keeps the fairness state, under the queue root.
FAIR_DIR = "fair"
STATE_NAME = "state.json"

_NAME_RE = re.compile(r"^([0-9]{1,20})\.json$")
_MAX_JOB_BYTES = 256 * 1024         # one job file (an EngagementJob is a few hundred bytes)
_MAX_STATE_BYTES = 4 * 1024 * 1024  # the fairness state (one int per live tenant)
_MAX_STATE_TENANTS = 100_000
_MAX_FIELD = 256                    # every string read from a file is clipped to this
_NEVER = -1                         # the "last served" tick of a tenant never served


@dataclass(frozen=True)
class FairJob:
    """One queued (or running) job as the policy sees it.

      * ``tenant`` — the fairness group: the job's ``org_id`` (``""`` is the one untenanted group).
      * ``seq``    — the global arrival order (the queue file's sequence number).
      * ``slug``   — the serial-per-target key: one live run per slug (``""`` = no serial key).
      * ``job_id`` — the queue's opaque job id (a final tie-break).
      * ``nonce``  — a customer launch's opaque lease nonce, used only to MATCH a launch to its job; never ordered on.
    """

    tenant: str
    seq: int
    slug: str = ""
    job_id: str = ""
    nonce: str = ""


@dataclass(frozen=True)
class FairState:
    """The persisted service history: ``tick`` counts claims, ``served`` holds each live tenant's last-service tick
    as sorted ``(tenant, tick)`` pairs (frozen, so a state can never be mutated in place)."""

    tick: int = 0
    served: "tuple[tuple[str, int], ...]" = ()

    def served_map(self) -> "dict[str, int]":
        return dict(self.served)


@dataclass(frozen=True)
class QueueSnapshot:
    """What the queue root holds right now: the pending jobs, the running jobs and the fairness state."""

    pending: "tuple[FairJob, ...]" = ()
    running: "tuple[FairJob, ...]" = ()
    state: FairState = FairState()


# --------------------------------------------------------------------------------------------------- the policy ----
def _job_key(j: FairJob) -> "tuple[int, str, str, str]":
    """The TOTAL within-tenant order: arrival ``seq``, then ``slug``, then ``job_id``, then ``nonce``."""
    return (int(j.seq), str(j.slug), str(j.job_id), str(j.nonce))


def running_counts(running: "Iterable[FairJob]") -> "dict[str, int]":
    """How many jobs each tenant has running."""
    counts: "dict[str, int]" = {}
    for j in running:
        counts[j.tenant] = counts.get(j.tenant, 0) + 1
    return counts


def busy_slugs(running: "Iterable[FairJob]") -> "set[str]":
    """The slugs that have a job running (a pending job on one of these must wait — serial per target)."""
    return {j.slug for j in running if j.slug}


def _tenant_key(tenant: str, head: FairJob, counts: "Mapping[str, int]", served: "Mapping[str, int]") -> tuple:
    return (counts.get(tenant, 0), served.get(tenant, _NEVER), _job_key(head), tenant)


def pick_next(pending: "Sequence[FairJob]", running: "Sequence[FairJob]" = (), state: "Optional[FairState]" = None,
              *, serial: bool = True) -> "Optional[FairJob]":
    """The job the policy serves next, or None. Each tenant's candidate is its OLDEST pending job (skipping, when
    ``serial``, every job whose slug has a job running); the winner is the candidate of the tenant with the fewest
    running jobs, then the least recent service, then the oldest candidate. Pure and deterministic."""
    counts = running_counts(running)
    busy = busy_slugs(running) if serial else set()
    served = (state or FairState()).served_map()
    heads: "dict[str, FairJob]" = {}
    for j in pending:
        if serial and j.slug and j.slug in busy:
            continue
        cur = heads.get(j.tenant)
        if cur is None or _job_key(j) < _job_key(cur):
            heads[j.tenant] = j
    best: "Optional[FairJob]" = None
    best_key: "Optional[tuple]" = None
    for t, h in heads.items():
        k = _tenant_key(t, h, counts, served)
        if best_key is None or k < best_key:
            best, best_key = h, k
    return best


def choose(pending: "Sequence[FairJob]", running: "Sequence[FairJob]" = (),
           state: "Optional[FairState]" = None) -> "Optional[FairJob]":
    """THE claim decision: :func:`pick_next` over the jobs whose slug is free; if every pending job waits on a busy
    slug, the plain fair order (so a claimer is never told "empty" while jobs are queued). None only when nothing
    is pending."""
    return pick_next(pending, running, state) or pick_next(pending, running, state, serial=False)


def record_service(state: "Optional[FairState]", tenant: str, *,
                   live: "Optional[Iterable[str]]" = None) -> FairState:
    """The state after the scheduler claims a job for ``tenant``: the tick advances and becomes ``tenant`` 's last
    service. ``live`` (the tenants that still have a job pending or running) prunes every other tenant, so the
    state stays one entry per live tenant; a pruned tenant that returns is simply 'never served' again."""
    st = state or FairState()
    tick = int(st.tick) + 1
    served = st.served_map()
    if live is not None:
        keep = set(live)
        keep.add(tenant)
        served = {t: s for t, s in served.items() if t in keep}
    served[tenant] = tick
    return FairState(tick=tick, served=tuple(sorted(served.items())))


def claim_order(pending: "Sequence[FairJob]", running: "Sequence[FairJob]" = (),
                state: "Optional[FairState]" = None) -> "list[FairJob]":
    """The order the scheduler WILL claim ``pending`` in if no job finishes and none arrives meanwhile: :func:`choose`
    applied repeatedly, each claimed job then counted as running and its tenant as just served. Equal to that naive
    repetition (pinned by a property test), computed with a heap in O(n log n) so a read can afford it.

    Phase 1 serves the jobs whose slug is free (a claimed job's slug becomes busy); phase 2 orders the jobs left
    waiting on a busy slug by the plain fair order — exactly what repeated :func:`choose` does, because the busy set
    only grows. Keys only ever grow (more running, a later tick, a later head), so a stale heap entry can only sit
    too LOW and is re-pushed when popped: the min of the heap is always the true next claim."""
    st = state or FairState()
    counts = running_counts(running)
    busy = busy_slugs(running)
    served = st.served_map()
    tick = int(st.tick)
    per: "dict[str, list[FairJob]]" = {}
    for j in pending:
        per.setdefault(j.tenant, []).append(j)
    for lst in per.values():
        lst.sort(key=_job_key)
    out: "list[FairJob]" = []

    def serve(t: str, j: FairJob) -> None:
        nonlocal tick
        out.append(j)
        counts[t] = counts.get(t, 0) + 1
        tick += 1
        served[t] = tick
        if j.slug:
            busy.add(j.slug)

    # -- phase 1: serial (a job whose slug is busy waits) ---------------------------------------------------------
    ptr = {t: 0 for t in per}
    blocked: "dict[str, list[FairJob]]" = {t: [] for t in per}

    def head(t: str) -> "Optional[FairJob]":
        lst = per[t]
        while ptr[t] < len(lst) and lst[ptr[t]].slug and lst[ptr[t]].slug in busy:
            blocked[t].append(lst[ptr[t]])
            ptr[t] += 1
        return lst[ptr[t]] if ptr[t] < len(lst) else None

    heap: "list[tuple]" = []
    for t in per:
        h = head(t)
        if h is not None:
            heapq.heappush(heap, _tenant_key(t, h, counts, served))
    while heap:
        popped = heapq.heappop(heap)
        t = popped[3]
        h = head(t)
        if h is None:
            continue
        cur = _tenant_key(t, h, counts, served)
        if cur != popped:
            heapq.heappush(heap, cur)        # stale (another tenant's claim made this head's slug busy) — re-rank
            continue
        ptr[t] += 1
        serve(t, h)
        nh = head(t)
        if nh is not None:
            heapq.heappush(heap, _tenant_key(t, nh, counts, served))

    # -- phase 2: every job left waits on a busy slug — the plain fair order --------------------------------------
    rest = {t: lst for t, lst in blocked.items() if lst}
    idx = {t: 0 for t in rest}
    heap = [_tenant_key(t, lst[0], counts, served) for t, lst in rest.items()]
    heapq.heapify(heap)
    while heap:
        t = heapq.heappop(heap)[3]
        j = rest[t][idx[t]]
        idx[t] += 1
        serve(t, j)
        if idx[t] < len(rest[t]):
            heapq.heappush(heap, _tenant_key(t, rest[t][idx[t]], counts, served))
    return out


# --------------------------------------------------------------------------------------------- the state codec ----
def dump_state(state: FairState) -> str:
    """The state as the claimer persists it (canonical, sorted)."""
    return json.dumps({"v": 1, "tick": int(state.tick), "served": dict(state.served)},
                      sort_keys=True, separators=(",", ":"))


def parse_state(raw: Any) -> FairState:
    """A :class:`FairState` from a decoded state document — TOTAL: anything malformed degrades to an empty or
    partial state (a torn state only costs one round of service history, never a crash or a phantom tenant). The
    tick is kept at or above every served tick, so it stays monotonic even if its own field was damaged."""
    if not isinstance(raw, dict):
        return FairState()
    served: "dict[str, int]" = {}
    src = raw.get("served")
    if isinstance(src, dict):
        for t, s in src.items():
            if len(served) >= _MAX_STATE_TENANTS:
                break
            if isinstance(t, str) and len(t) <= _MAX_FIELD and isinstance(s, int) and not isinstance(s, bool) \
                    and s >= 0:
                served[t] = s
    tick = raw.get("tick")
    tick = tick if isinstance(tick, int) and not isinstance(tick, bool) and tick >= 0 else 0
    tick = max([tick, *served.values()])
    return FairState(tick=tick, served=tuple(sorted(served.items())))


def load_state(path: "str | os.PathLike") -> FairState:
    """The persisted state at ``path`` (empty when absent, oversized, a symlink or malformed — never raises)."""
    doc = _read_json(path, _MAX_STATE_BYTES)
    return parse_state(doc)


# ------------------------------------------------------------------------------------------ the on-disk reader ----
def _clip(value: Any) -> str:
    s = value if isinstance(value, str) else ("" if value is None else str(value))
    return s[:_MAX_FIELD]


def _read_json(path: "str | os.PathLike", limit: int) -> Any:
    """``json.loads`` of a regular file, bounded to ``limit`` bytes and never through a symlink; None on anything
    else (absent, too big, unreadable, not JSON)."""
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(limit + 1)
    except OSError:
        return None
    if len(raw) > limit:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def job_from_doc(doc: Any, seq: int) -> FairJob:
    """A :class:`FairJob` from one queue file's decoded document (the engine's ``EngagementJob`` JSON: ``slug``,
    ``job_id`` and ``params`` — whose ``tenant_id`` (a ``SecurityJob``) or ``tenant`` (a fleet job) is the fairness
    group, and whose ``extra.nonce`` names a customer launch). ``seq`` is the FILE's sequence number. A torn or
    hostile document degrades to the anonymous job ``FairJob("", seq)`` — still claimable, so the claimer's own
    torn-file handling drops it, exactly as on the arrival-order path."""
    if not isinstance(doc, dict):
        return FairJob(tenant="", seq=int(seq))
    params = doc.get("params")
    params = params if isinstance(params, dict) else {}
    tenant = params.get("tenant_id")
    if not isinstance(tenant, str) or not tenant:
        tenant = params.get("tenant")
    extra = params.get("extra")
    nonce = extra.get("nonce") if isinstance(extra, dict) else None
    return FairJob(tenant=_clip(tenant if isinstance(tenant, str) else ""), seq=int(seq),
                   slug=_clip(doc.get("slug") if isinstance(doc.get("slug"), str) else ""),
                   job_id=_clip(doc.get("job_id") if isinstance(doc.get("job_id"), str) else ""),
                   nonce=_clip(nonce if isinstance(nonce, str) else ""))


def scan_job_dir(path: "str | os.PathLike", *, limit: "Optional[int]" = None) -> "Optional[list[tuple[str, FairJob]]]":
    """``[(file name, FairJob)]`` for every ``<seq>.json`` in one queue sub-directory, in sequence order; ``[]`` when
    the directory is absent; None when it holds more than ``limit`` job files (a caller that must be exact — the
    sovereign read — then shows nothing rather than a wrong position)."""
    try:
        names = os.listdir(os.fspath(path))
    except OSError:
        return []
    found: "list[tuple[int, str]]" = []
    for name in names:
        m = _NAME_RE.match(name)
        if m:
            found.append((int(m.group(1)), name))
            if limit is not None and len(found) > limit:
                return None
    found.sort()
    out: "list[tuple[str, FairJob]]" = []
    for seq, name in found:
        out.append((name, job_from_doc(_read_json(os.path.join(os.fspath(path), name), _MAX_JOB_BYTES), seq)))
    return out


def read_queue_snapshot(root: "str | os.PathLike", *, limit: "Optional[int]" = 10_000) -> "Optional[QueueSnapshot]":
    """The pending jobs, running jobs and fairness state under a queue root, or None when the root holds no queue
    or more than ``limit`` pending or running files (never a guessed answer). Read-only and lock-free: the claimer
    replaces the state atomically, so a read sees the old or the new document, never a torn one."""
    base = os.fspath(root)
    if not os.path.isdir(os.path.join(base, QUEUE_DIR)):
        return None
    pending = scan_job_dir(os.path.join(base, QUEUE_DIR), limit=limit)
    running = scan_job_dir(os.path.join(base, RUNNING_DIR), limit=limit)
    if pending is None or running is None:
        return None
    state = load_state(os.path.join(base, FAIR_DIR, STATE_NAME))
    return QueueSnapshot(pending=tuple(j for _n, j in pending), running=tuple(j for _n, j in running), state=state)


__all__ = [
    "FAIR_DIR", "QUEUE_DIR", "RUNNING_DIR", "STATE_NAME",
    "FairJob", "FairState", "QueueSnapshot",
    "busy_slugs", "choose", "claim_order", "dump_state", "job_from_doc", "load_state", "parse_state", "pick_next",
    "read_queue_snapshot", "record_service", "running_counts", "scan_job_dir",
]
