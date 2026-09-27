"""
worldmodel.graph — the in-memory typed attack-graph.

WorldModel is a directed, typed multigraph. Nodes are keyed by id;
edges are keyed by the triple (src, dst, kind), so the same relationship
re-asserted from a new observation *upserts* rather than duplicating.

Adjacency is a plain dict-of-dicts — no external graph library — held in
two directions so both forward reachability and reverse ("who can reach
me?") queries are O(degree):

    _out[src][dst][kind] -> Edge      # outgoing
    _in[dst][src][kind]  -> Edge      # incoming (same Edge object)

Upsert semantics (add_node / add_edge) are the load-bearing behaviour:

  - attrs merge  — incoming keys overlay existing, keys not re-asserted
    are retained (the graph accretes knowledge, never forgets it);
  - confidence reconciles to the **max** — re-observing a fact never
    lowers belief in it; the higher-confidence assertion also donates
    its provenance, so the surviving provenance points at the strongest
    evidence (ties: the incoming assertion wins, keeping provenance
    fresh);
  - first_seen = min, last_seen = max of the two sequence ints.

All sequence numbers are caller-supplied monotonic ints; the graph never
reads a wallclock, so every operation is deterministic and replayable.

ORDER INDEXES (performance, #828). Every read that promises "deterministic
order" used to re-`sorted()` the whole node dict / adjacency dict on EVERY
call — `all_nodes`, `nodes_of_kind`, `all_edges`, `edges_of_kind`, `neighbors`.
Those sorts exist ONLY to pin the order, never to compute anything, so keeping
the same order in a MAINTAINED index is behaviour-preserving by construction:
the iteration order is `sorted(...)` of exactly the same key set, it is simply
not re-paid per call.

    _node_ids      sorted list of every node id          -> all_nodes
    _kind_ids      kind value -> sorted list of node ids -> nodes_of_kind
    _out_dsts      src -> sorted list of dsts            -> neighbors / all_edges
    _in_srcs       dst -> sorted list of srcs            -> neighbors(incoming=True)
    _kind_pairs    edge-kind value -> sorted (src,dst)   -> edges_of_kind
    _out[s][d] / _in[d][s] are themselves held in sorted-kind-key order (see
    `_put_kind`), so the innermost `sorted()` is gone too.

A bucket is APPENDED to on write and NORMALISED (``list.sort()``) on the first
read after a write that landed out of order — never with ``insort``, whose O(n)
memmove per insert would make graph construction quadratic and reintroduce
exactly the class of blow-up this index exists to remove. Keys usually arrive
ascending (ids are generated in order), in which case the bucket is never dirty
and the sort never runs at all. Because the normalisation is literally
``list.sort()`` over the same key set, the order a reader sees is ``sorted(...)``
— identical to the pre-index code — and the worst case (mutate, read, mutate,
read) is one sort per read, i.e. exactly the pre-index cost, never worse.

What the index DOES cost unconditionally is per-WRITE bookkeeping: one list
append plus one comparison per node / per new adjacency key, plus one
uncontended lock acquire/release per call (see CONCURRENCY below). Measured by
`tests/bench_graph.py` — which is committed and re-runnable, and which asserts
each indexed reader returns the pre-index result BEFORE timing it, so no
speedup here is over a different answer:

    bench_graph --sizes 1000,10000 --order asc,desc --repeat 3 --heap

    reader          speedup over the pre-index body   (asc and desc fixtures,
                                                       N = 1k and 10k)
    nodes_of_kind     46x .. 60x
    edges_of_kind     43x .. 57x
    all_edges        2.2x .. 2.9x
    all_nodes        1.5x .. 1.6x
    neighbors        1.1x .. 1.1x

    bench_graph --sizes 1000,10000 --repeat 5 --compare-rev 838e0b42

    CONSTRUCTION     ~+18% (N=1k) .. ~+32% (N=10k) SLOWER than pre-index
                     (this host; the N=10k figure reads +29%..+32% across
                     methods and runs — take the high end)

So the envelope is ~1.1x at the floor to ~60x at the ceiling, and it is the
whole-collection readers (`nodes_of_kind`, `edges_of_kind`) that carry it,
because those are the ones that used to sort every node or every edge to return
a slice of them. The high-ratio readers vary by tens of percent run to run; re-
run the command for your own host rather than trusting the last digit.

Two earlier claims here are WITHDRAWN, not restated:

  * "1.5x–250x faster reads". Nothing reproduces 250x; the ceiling measures
    ~60x.
  * "~15x on the repeated list-then-scan shape `knowledge/operators` pays". The
    real consumer is `saturate()`, and `bench_graph --mode operators
    --compare-rev 838e0b42` measures ~1.0x–1.1x across repeated runs at N=200 and
    N=800 (mostly 1.01x–1.07x, occasionally noisier on a loaded host) — i.e. no
    meaningful win on that shape at all. A previous revision replaced the
    withdrawn 15x with "3.5x–4.5x" in the same breath; that figure came from a
    hand-rolled loop that called `nodes_of_kind` per node rather than from
    `saturate`, was never committed, and is withdrawn too. The lesson is in the
    rule this file now follows: every number here comes from a
    committed harness or from a command printed beside it.

Memory is the third axis, and an earlier revision omitted it while claiming to
state the cost in full. `bench_graph --heap` reports 9.25 MB at N=1,000 and
92.19 MB at N=10,000, against 8.83 / 88.09 MB pre-index — so the key-only
indexes cost about +4.8% / +4.7%. Read `heap()`'s docstring before quoting the
absolute number: it is allocation during build plus one full read, not the
graph's resident size, so it is an upper bound; the revision-to-revision delta
is the meaningful part. The lock adds 96 bytes per WorldModel. `docs/SCALE.md`
reports whole-process campaign figures of 97–102 MB, against which this is a
sub-rounding contribution; it is noted there too rather than left to be
inferred.

CONCURRENCY. Pre-index, every reader was a pure function of `_nodes`/`_out`/
`_in` and every ordering step was ONE `sorted(...)` C call, so two readers could
not interfere and no writer could make a reader raise. The index broke both:
a READ now MUTATES (the lazy `list.sort()` plus the dirty-flag clear), and the
readers walk live lists and dicts instead of taking a C-level snapshot.

Failure rates below come from `tests/race_graph.py`, which is committed and
which takes `--rev`, so a number about the UNLOCKED index stays re-derivable
now that the tree is locked:

    race_graph --rev 8d8d8c30 --trials 15      # the unlocked index
    race_graph              --trials 15        # the current tree

                        switchinterval  0.005      1e-6
    read ‖ read (7,500 dirty buckets)   15/15      15/15
    read ‖ write                         0/15      15/15
    write ‖ write, AEGIS shape            1/15      15/15
    write ‖ write, writes-only control    1/15      15/15
    ...and every one of those eight cells is 0/15 on the current tree.

  * read ‖ read — two `all_edges()` iterating the shared `_dirty_out` set while
    one of them cleared it: `RuntimeError: Set changed size during iteration`.
    NO writer needed. Reachability at the DEFAULT interval is HOST-DEPENDENT and
    must not be quoted as a bucket count: a second reader has to be scheduled
    INSIDE the dirty loop, so the loop must outrun the 5 ms GIL quantum.
    `race_graph --mode dirtyloop` times it — on this host it crosses 5 ms
    between 3,000 (3.65 ms, 0/15) and 7,500 buckets (6.63 ms, 15/15); a reviewer
    on a faster machine measured 4.84 ms at 7,500 (still under, 0/15) and
    14.74 ms at 20,000 (fires). Same rule, different crossover. An earlier
    revision of this comment asserted "~7,500 buckets" as if it were portable.
  * read ‖ write — `_normalize` sorted and THEN cleared the flag, so an append
    landing between the two left a bucket unsorted with a CLEAN flag. A reader
    returned out-of-order results with NO exception, and because the flag was
    clear the wrong order was PERMANENT — every later read stayed wrong, and a
    subsequent `remove_node` then bisected an unsorted list and escalated it to
    a `KeyError`. Note the 0/15 at the default interval: this one needs a fast
    switch interval to reproduce on demand, which makes it rarer in production
    and worse, not better — it is the silent mode.
  * write ‖ write/evict — `_discard_sorted`'s `bisect_left` + `del seq[i]` raced
    `_append_key`'s `append`, `_node_ids` drifted from `_nodes` (75 ids against
    64 nodes, measured), and the next `all_nodes()` raised `KeyError`.

That last one shipped. `aegis.middleware.AegisWSGIMiddleware` holds ONE `Aegis`
— hence one `ActorGraph`, hence one `WorldModel` — and calls `observe()` on
EVERY request with no lock of its own, from a multi-threaded WSGI server;
`aegis.detect_http` is the same shape at the raw HTTP boundary, and
`aegis.integrate` reads `world.all_nodes()` on the verdict-projection path.
`race_graph --mode aegis` drives exactly that through the real `ActorGraph` at
`max_actors=64` (so the bounded window evicts), 4 threads x 300 observations:
1/15 at the DEFAULT switch interval, i.e. a crash in the defensive data plane
on stock interpreter settings.

`--mode aegis-control` is the same run with the concurrent read removed, and it
matters: the PRE-INDEX `all_nodes` is `[self._nodes[k] for k in
sorted(self._nodes)]`, and while `sorted()` is atomic the COMPREHENSION is not,
so a concurrent `remove_node` could already `KeyError` it. That race predates
this slice. With the read removed, the surviving 1/15 and 15/15 are the index
desyncing under write‖write — the defect this slice actually introduced.

The fix is `_lock`: ONE `threading.RLock` per WorldModel, held by every method
that touches an index — INCLUDING the readers, because a read normalises.
Deliberately NOT thread-local dirty state: two threads would then sort on
different schedules and iteration order would stop being a function of the key
set alone, which is the one property this whole index exists to preserve. The
lock is re-entrant so a locked method may call another, and per-instance so
unrelated graphs never serialise against each other.

Scope, stated honestly, because a lock invites more faith than it earns:

  * It makes each individual method atomic. It is NOT a transaction across
    calls — a caller needing `add_node` + `add_edge` to be atomic against
    another thread still holds its own lock.
  * It restores the pre-index guarantee that a reader cannot raise and cannot
    return unsorted output — and, per the last bullet, slightly exceeds it.
  * It does not make this a general concurrent graph, and it does not make the
    engine's own scan path parallel (see `docs/SCALE.md` — the scan is serial
    BY DESIGN, and that is unchanged).
  * It is a LEAF lock and must stay one: nothing executed while it is held may
    call back out. All four readers that take a caller-supplied `kind` or
    `edge_kinds` — `nodes_of_kind`, `edges_of_kind`, `neighbors`, `reachable` —
    evaluate `.value` / drain the iterable BEFORE taking the lock, so a foreign
    object's `.value` property or a generator argument cannot run under it. No
    shipped call site passes anything but an enum member or a materialised list,
    so the hoist costs nothing today; it keeps the "leaf" claim true by
    construction, and `test_caller_controlled_code_never_runs_under_the_index_lock`
    probes all four and fails if any evaluation moves back under the lock.
  * It is NOT free on reads, and the earlier "1.0x–1.15x" here was too kind.
    `bench_graph --compare-rev 8d8d8c30` measures locked/unlocked at 1.01x
    (all_edges), 1.01–1.03x (all_nodes), 1.01–1.05x (edges_of_kind), 1.04–1.16x
    (nodes_of_kind) and 1.25–1.28x (`neighbors`). `neighbors` is the worst case
    precisely because it is the CHEAPEST reader — it does the least work per
    call, so a fixed acquire/release is the largest share of it. The index's
    own win over pre-index (the table above) dwarfs this in every case.
  * On writes the lock's own share is a few percent — it reads between ~1% and
    ~6% across runs on this (loaded) host, i.e. at or under the measurement
    noise floor, so treat it as "a few percent, bounded above by ~6%" rather
    than a point estimate. It is the small part of the +18%..+32% construction
    cost; the index bookkeeping is the rest.
  * It also closes a PRE-EXISTING race the index did not introduce, described
    two paragraphs up. The locked graph is therefore strictly safer than the
    pre-index graph, not merely restored to it — in two distinct ways: the
    pre-index code fails on the CONCURRENT-READER shape with in-flight errors
    but an intact graph, while the unlocked index fails WRITES-ONLY with
    permanent state corruption.
  * `copy.deepcopy` and `pickle` would have broken outright — an `RLock` is not
    picklable — so `__getstate__`/`__setstate__` drop and recreate it. See
    those methods; this was a silent capability regression on a public model
    class, caught in review, not by a test, and there is now a test.

The indexes are keys only — never Node/Edge objects — so an upsert that
replaces a stored object cannot leave them stale. `_assert_index_consistent`
re-derives every index from `_nodes`/`_out`/`_in`, and additionally asserts the
lazy contract (a bucket NOT flagged dirty is already sorted). It is a TEST-ONLY
invariant with no production call site — deliberately, because it is O(V log V
+ E log E) and would erase the win it guards — so the tests call it as the
thing the fast readers are allowed to assume, and production relies on the lock
plus the append/normalise discipline to keep it true.
"""

from __future__ import annotations

import threading
from bisect import bisect_left
from collections import deque
from collections.abc import Iterable, Iterator

from ..common.errors import CrucibleError
from .models import (
    GROUNDING_GROUNDED,
    GROUNDING_UNGROUNDED,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
    classify_provenance,
)

# In STRICT grounding mode, a write whose provenance classifies as UNGROUNDED (an LLM
# assertion, a bare assumption) has its belief SEEDED at this low floor instead of its
# asserted confidence — so a hallucinated fact cannot enter the graph at high belief.
# Default mode leaves belief untouched (only the grounding tag is recorded).
_UNGROUNDED_BELIEF_FLOOR = 0.2

# The single dirty-slot key for the whole-graph `_node_ids` bucket.
_NODE_IDS = "\0node-ids"


class WorldModelError(CrucibleError):
    """Recoverable world-model error — e.g. an edge referencing a node
    that is not present. The world-model records observations; it makes
    no trust decision, so this is a plain CrucibleError, never an
    EthicsViolation."""


# Pseudo-count added to the Beta belief per observation. One observation of
# confidence c contributes _BELIEF_WEIGHT*c corroboration and *(1-c) refutation.
_BELIEF_WEIGHT = 1.0

# The veracity firewall's demotion marker (``scanner/campaign.py`` writes ``demoted:<oracle>`` when a
# retained proof does not re-fire). Named here because ``_sticky_grounded`` must let it through.
_DEMOTION_PREFIX = "demoted:"


def _is_demotion(provenance: str) -> bool:
    """True for the veracity firewall's demotion marker.

    A demotion is a SAFETY-CRITICAL DOWNGRADE and must not be outvoted by the confidence tiebreak: the
    firewall writes it with the finding's own confidence, and a demotion that lost the tiebreak would
    leave a finding whose proof no longer re-fires still reading as a fact. It cannot be abused in the
    other direction, because ``demoted:`` classifies as ungrounded by construction — letting it always
    win can only ever LOWER grounding, which is exactly the firewall's one authority."""
    return (provenance or "").strip().lower().startswith(_DEMOTION_PREFIX)


def _sticky_grounded(existing_prov: str, winning_prov: str) -> str:
    """GROUNDED is sticky on upsert: a node/edge an oracle already grounded is not demoted to a lead
    by a later non-grounded re-observation that merely happens to carry higher confidence.

    Without this, a high-confidence sensor lead re-asserted on an oracle-confirmed node wins the
    max-confidence tiebreak, rewrites the provenance pointer to itself, and the fact silently becomes
    a lead (belief-floored in strict mode). This can only KEEP grounding — it never turns a lead into
    a fact, so the lead→fact direction the whole model forbids is untouched. When the incoming write
    is ITSELF grounded (a second oracle), the winner stands.

    WHERE THE DEMOTION EXCEPTION ACTUALLY LIVES. ``demoted:`` is the marker the veracity firewall
    writes when a recorded-confirmed finding's RETAINED PROOF DID NOT RE-FIRE. It is the
    anti-hallucination layer exercising its one authority — it may only ever demote — and it MUST win,
    or a stale or tampered finding reads back out of the graph as a grounded fact. An earlier version
    of this function blocked exactly that write, inverting the firewall.

    That is fixed at the CALL SITES (``add_node`` / ``add_edge``), which divert a demoting write before
    this function is consulted. The ``_is_demotion`` branch below is therefore defensive depth, not the
    live protection — measured over 27,000 write sequences, it is never entered, because a demotion
    reaching here as the tiebreak winner implies the existing write was not grounded and the first
    branch already returned. It is kept so this function is correct in isolation, and labelled so a
    reader does not mistake it for the guarantee: DELETING THE CALL-SITE CHECKS WOULD RE-INVERT THE
    FIREWALL even though this branch still looked like protection."""
    if classify_provenance(existing_prov) != GROUNDING_GROUNDED:
        return winning_prov
    if classify_provenance(winning_prov) == GROUNDING_GROUNDED:
        return winning_prov
    if (winning_prov or "").strip().lower().startswith(_DEMOTION_PREFIX):
        return winning_prov          # the veracity firewall's demote-only authority is absolute
    return existing_prov


def _seed_belief(confidence: float, alpha: float, beta: float) -> tuple[float, float]:
    """Belief for a first-seen fact. If alpha/beta are still the Beta(1,1) prior
    (not carried in from a reload), seed them from the asserted confidence; else
    keep the supplied belief so a persisted belief survives round-tripping."""
    if alpha == 1.0 and beta == 1.0:
        return (1.0 + _BELIEF_WEIGHT * confidence, 1.0 + _BELIEF_WEIGHT * (1.0 - confidence))
    return alpha, beta


def _update_belief(alpha: float, beta: float, confidence: float) -> tuple[float, float]:
    """Conjugate update on re-observation: a high-confidence re-observation adds
    mostly to alpha (corroboration), a low-confidence one mostly to beta
    (refutation) — so belief_mean rises on agreement and FALLS on a failed
    re-check (which max-confidence can never express)."""
    return (alpha + _BELIEF_WEIGHT * confidence, beta + _BELIEF_WEIGHT * (1.0 - confidence))


def _put_kind(bucket: dict[str, Edge], kv: str, edge: Edge) -> None:
    """Store ``edge`` under kind-key ``kv`` in an adjacency bucket, KEEPING the
    bucket's iteration order equal to ``sorted(bucket)``.

    Index mutation: the caller MUST hold ``WorldModel._lock``.

    Python dicts iterate in insertion order, so a bucket that is only ever
    appended to in ascending key order iterates sorted for free. The rare
    out-of-order insert re-orders in place (these buckets hold at most one
    entry per EdgeKind and in practice one or two), which is what lets
    ``neighbors`` / ``all_edges`` drop their innermost ``sorted()`` call
    without changing a single element's position.

    Re-assigning an existing key keeps its position, exactly as the previous
    ``bucket[kv] = stored`` did."""
    if kv in bucket:
        bucket[kv] = edge
        return
    bucket[kv] = edge
    if len(bucket) > 1:
        keys = list(bucket)
        if keys[-1] < keys[-2]:          # the new key landed out of order
            ordered = sorted(bucket.items())
            bucket.clear()
            bucket.update(ordered)


def _append_key(seq: list, key: object, dirty: set, slot: object) -> None:
    """Append ``key`` to an index bucket, flagging it dirty only if the append
    broke sortedness. Ascending keys (the normal case) cost one list append and
    never schedule a sort.

    Index mutation: the caller MUST hold ``WorldModel._lock``. The append and the
    ``dirty.add`` are two steps, and a reader that normalised between them would
    clear a flag that was never set and leave the bucket unsorted-but-clean."""
    seq.append(key)
    if len(seq) > 1 and key < seq[-2]:
        dirty.add(slot)


def _normalize(seq: list, dirty: set, slot: object) -> list:
    """Return ``seq`` in sorted order, sorting in place iff it is flagged dirty.
    This is the ONLY place a bucket's order is established, and it is a plain
    ``list.sort()`` over the same key set — so every reader sees exactly the
    ``sorted(...)`` order the pre-index code computed.

    Index mutation (a READ normalises): the caller MUST hold ``WorldModel._lock``.
    ``sort()`` then ``discard()`` is two steps; an append landing between them
    leaves the bucket unsorted with a CLEAN flag, which is permanent, silent
    wrong order for the life of the graph."""
    if slot in dirty:
        seq.sort()
        dirty.discard(slot)
    return seq


def _discard_sorted(seq: list | None, value: object) -> None:
    """Remove ``value`` from a SORTED list, if present (O(log n) + memmove).
    Callers must `_normalize` first — removal is rare (only `remove_node`), so
    paying a normalising sort there is cheaper than a linear scan everywhere.

    Index mutation: the caller MUST hold ``WorldModel._lock``. ``bisect_left``
    then ``del seq[i]`` is two steps over one list; an append racing between
    them desyncs the index from ``_nodes`` and the next ``all_nodes()`` raises
    ``KeyError``."""
    if not seq:
        return
    i = bisect_left(seq, value)
    if i < len(seq) and seq[i] == value:
        del seq[i]


def _kind_key(kind: object) -> object:
    """The dict key a NodeKind indexes under.

    ``NodeKind`` is a ``str`` enum, so ``node.kind == "host"`` is True — and on
    the shipped interpreter ``hash(NodeKind.HOST) == hash("host")`` is True as
    well. (Measured on CPython 3.13.14: ``NodeKind.__hash__ is str.__hash__``,
    and ``{NodeKind.HOST: 1}.get("host") == 1``. Since 3.11 a mixin enum
    inherits the mixin's ``__hash__``, so a member and its bare value already
    collide in one dict. An earlier revision of this docstring claimed the
    opposite — that ``Enum.__hash__`` hashes the *name* and the two therefore
    differ — and that claim was simply false; it is corrected here.)

    So on THIS interpreter the helper is not what makes member/value lookups
    agree. It is kept because that agreement is an implementation detail of the
    mixin, not a language guarantee: drop the ``str`` mixin, or run where
    ``Enum.__hash__`` wins, and a member-keyed write and a value-keyed read
    would silently split one bucket in two — a wrong ANSWER, not a crash.
    Normalising both sides onto ``.value`` pins it: the bucket is keyed by
    value, the lookup is by value, and anything that is neither a member nor
    its value misses (empty result) — which is what the old ``n.kind == kind``
    comprehension did too.

    Consequence for mutation testing: replacing this body with the identity is
    an EQUIVALENT mutant on CPython >= 3.11, not an uncovered one."""
    return getattr(kind, "value", kind)


class WorldModel:
    """A typed attack-graph. Construct empty, then accrete facts."""

    def __init__(self, *, strict_grounding: bool = False) -> None:
        self._nodes: dict[str, Node] = {}
        # kind is stored by its str value so keys are JSON-friendly.
        self._out: dict[str, dict[str, dict[str, Edge]]] = {}
        self._in: dict[str, dict[str, dict[str, Edge]]] = {}
        # Anti-hallucination P2: when True, an UNGROUNDED write (LLM/assumption
        # provenance) is seeded at a low belief floor. Default False = belief unchanged;
        # only the provenance grounding tag is recorded on every write.
        self._strict_grounding = strict_grounding
        # --- order indexes (see the module docstring). Keys only, never objects,
        # so an upsert that replaces a stored Node/Edge cannot stale them. Each is
        # held in exactly the order the corresponding reader used to re-sort into.
        self._node_ids: list[str] = []                       # sorted node ids
        self._kind_ids: dict[object, list[str]] = {}         # kind value -> sorted node ids
        self._out_dsts: dict[str, list[str]] = {}            # src -> sorted dsts
        self._in_srcs: dict[str, list[str]] = {}             # dst -> sorted srcs
        self._kind_pairs: dict[str, list[tuple[str, str]]] = {}  # edge kind -> sorted (src,dst)
        # Buckets whose last append landed out of order and therefore owe a sort
        # before their next read. `_NODE_IDS` is the single slot for `_node_ids`.
        self._dirty_nodes: set[object] = set()
        self._dirty_kinds: set[object] = set()
        self._dirty_out: set[str] = set()
        self._dirty_in: set[str] = set()
        self._dirty_pairs: set[str] = set()
        # The index lock (see CONCURRENCY in the module docstring). Re-entrant so a
        # locked method may call another; uncontended acquire/release is ~0.06 us,
        # which is noise against the read wins it protects.
        self._lock = threading.RLock()

    def _grounded_seed_confidence(self, confidence: float, grounding: str) -> float:
        if self._strict_grounding and grounding == GROUNDING_UNGROUNDED:
            return min(confidence, _UNGROUNDED_BELIEF_FLOOR)
        return confidence

    # -- nodes --------------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        """Idempotent upsert. If a node with this id exists, merge attrs,
        reconcile confidence to the max, widen the seen-window, and adopt
        the higher-confidence assertion's provenance. Returns the stored
        node (the merged one on upsert). Kind may not change once set.

        Alongside the scalar confidence, a Beta(alpha, beta) belief accumulates:
        the first assertion seeds it from the confidence; each re-observation is
        a conjugate update (a high-confidence re-observation corroborates ->
        alpha; a low-confidence one refutes -> beta), so belief_mean DROPS on a
        failed re-observation even though max-confidence cannot."""
        with self._lock:
            existing = self._nodes.get(node.id)
            if existing is None:
                g = classify_provenance(node.provenance)
                a, b = _seed_belief(self._grounded_seed_confidence(node.confidence, g),
                                    node.alpha, node.beta)
                stored = node.model_copy(update={"alpha": a, "beta": b, "grounding": g})
                self._nodes[node.id] = stored
                self._out.setdefault(node.id, {})
                self._in.setdefault(node.id, {})
                self._out_dsts.setdefault(node.id, [])
                self._in_srcs.setdefault(node.id, [])
                _append_key(self._node_ids, node.id, self._dirty_nodes, _NODE_IDS)
                kk = _kind_key(node.kind)
                _append_key(self._kind_ids.setdefault(kk, []), node.id, self._dirty_kinds, kk)
                return stored
            if existing.kind != node.kind:
                raise WorldModelError(
                    f"node {node.id!r} kind conflict: "
                    f"{existing.kind.value} != {node.kind.value}"
                )
            merged_attrs = dict(existing.attrs)
            merged_attrs.update(node.attrs)
            # max confidence wins; on a tie the incoming assertion donates
            # provenance so the surviving pointer stays fresh.
            if node.confidence >= existing.confidence:
                provenance, confidence = node.provenance, node.confidence
            else:
                provenance, confidence = existing.provenance, existing.confidence
            # A demotion bypasses the confidence tiebreak entirely (see _is_demotion): the firewall's
            # downgrade must land even when the fact it demotes was asserted more confidently.
            provenance = node.provenance if _is_demotion(node.provenance) else \
                _sticky_grounded(existing.provenance, provenance)
            alpha, beta = _update_belief(existing.alpha, existing.beta, node.confidence)
            merged = existing.model_copy(
                update={
                    "attrs": merged_attrs,
                    "confidence": confidence,
                    "alpha": alpha,
                    "beta": beta,
                    "provenance": provenance,
                    "grounding": classify_provenance(provenance),  # follows the winning provenance
                    "first_seen": min(existing.first_seen, node.first_seen),
                    "last_seen": max(existing.last_seen, node.last_seen),
                }
            )
            self._nodes[node.id] = merged
            return merged

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def remove_node(self, node_id: str) -> bool:
        """Remove a node and every edge incident to it (both directions). Returns True if the
        node existed. Additive/opt-in — used by bounded producers (e.g. AEGIS's per-actor
        windowing) to evict an aged-out actor so the graph does not grow without bound; nothing
        in the batch engagement path calls it, so existing behaviour is unchanged."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return False
            # Outgoing first, then incoming — the pre-index ordering, kept verbatim so
            # this reads identically to base. It is NOT load-bearing for the index: a
            # reviewer swapped the two loops and the index stayed consistent, because
            # `_discard_sorted` and `dict.pop(k, None)` are both idempotent and a
            # self-loop is therefore dropped once either way.
            for dst in list(self._out.get(node_id, {})):
                for kv in self._out[node_id][dst]:
                    self._drop_pair(kv, node_id, dst)
                self._in.get(dst, {}).pop(node_id, None)
                _discard_sorted(_normalize(self._in_srcs.get(dst) or [], self._dirty_in, dst),
                                node_id)
            for src in list(self._in.get(node_id, {})):
                for kv in self._in[node_id][src]:
                    self._drop_pair(kv, src, node_id)
                self._out.get(src, {}).pop(node_id, None)
                _discard_sorted(_normalize(self._out_dsts.get(src) or [], self._dirty_out, src),
                                node_id)
            self._out.pop(node_id, None)
            self._in.pop(node_id, None)
            self._out_dsts.pop(node_id, None)
            self._in_srcs.pop(node_id, None)
            self._dirty_out.discard(node_id)
            self._dirty_in.discard(node_id)
            _discard_sorted(_normalize(self._node_ids, self._dirty_nodes, _NODE_IDS), node_id)
            kk = _kind_key(node.kind)
            bucket = self._kind_ids.get(kk)
            if bucket is not None:
                _discard_sorted(_normalize(bucket, self._dirty_kinds, kk), node_id)
            self._nodes.pop(node_id, None)
            return True

    def _drop_pair(self, kv: str, src: str, dst: str) -> None:
        """Drop one (src, dst) from the per-edge-kind index (edge removal path).

        Private; called only from ``remove_node``, which already holds ``_lock``."""
        pairs = self._kind_pairs.get(kv)
        if pairs:
            _discard_sorted(_normalize(pairs, self._dirty_pairs, kv), (src, dst))

    def nodes_of_kind(self, kind: NodeKind) -> list[Node]:
        """All nodes of a kind, in deterministic (id-sorted) order.

        Served from the maintained per-kind bucket: the bucket holds exactly the
        ids the old ``n.kind == kind`` filter kept, in the same sorted order, so
        the returned list is element-for-element what the full re-sort produced —
        at O(|kind|) instead of O(|V| log|V|) per call."""
        # `_kind_key` reads `kind.value` — a caller-supplied attribute, and on a
        # foreign object potentially a property with arbitrary code behind it.
        # Evaluate it BEFORE taking the lock: nothing the caller controls should
        # run while this graph is held. Same reason the dict lookup below is the
        # first thing inside, not the `.value` read.
        kk = _kind_key(kind)
        with self._lock:
            ids = self._kind_ids.get(kk)
            if not ids:
                return []
            nodes = self._nodes
            return [nodes[i] for i in _normalize(ids, self._dirty_kinds, kk)]

    def all_nodes(self) -> list[Node]:
        with self._lock:
            nodes = self._nodes
            return [nodes[k] for k in _normalize(self._node_ids, self._dirty_nodes, _NODE_IDS)]

    # -- edges --------------------------------------------------------------

    def add_edge(self, edge: Edge) -> Edge:
        """Idempotent upsert keyed by (src, dst, kind). Both endpoints
        must already be present (add their nodes first). Merge semantics
        mirror add_node. Returns the stored (merged) edge."""
        with self._lock:
            if edge.src not in self._nodes:
                raise WorldModelError(f"edge references unknown src node {edge.src!r}")
            if edge.dst not in self._nodes:
                raise WorldModelError(f"edge references unknown dst node {edge.dst!r}")
            kv = edge.kind.value
            existing = self._out.get(edge.src, {}).get(edge.dst, {}).get(kv)
            if existing is not None:
                merged_attrs = dict(existing.attrs)
                merged_attrs.update(edge.attrs)
                if edge.confidence >= existing.confidence:
                    provenance, confidence = edge.provenance, edge.confidence
                else:
                    provenance, confidence = existing.provenance, existing.confidence
                provenance = edge.provenance if _is_demotion(edge.provenance) else \
                    _sticky_grounded(existing.provenance, provenance)
                alpha, beta = _update_belief(existing.alpha, existing.beta, edge.confidence)
                stored = existing.model_copy(
                    update={
                        "attrs": merged_attrs,
                        "confidence": confidence,
                        "alpha": alpha,
                        "beta": beta,
                        "provenance": provenance,
                        "grounding": classify_provenance(provenance),
                        "first_seen": min(existing.first_seen, edge.first_seen),
                        "last_seen": max(existing.last_seen, edge.last_seen),
                    }
                )
            else:
                g = classify_provenance(edge.provenance)
                a, b = _seed_belief(self._grounded_seed_confidence(edge.confidence, g),
                                    edge.alpha, edge.beta)
                stored = edge.model_copy(update={"alpha": a, "beta": b, "grounding": g})
            out_adj = self._out.setdefault(edge.src, {})
            if edge.dst not in out_adj:
                out_adj[edge.dst] = {}
                _append_key(self._out_dsts.setdefault(edge.src, []), edge.dst,
                            self._dirty_out, edge.src)
            in_adj = self._in.setdefault(edge.dst, {})
            if edge.src not in in_adj:
                in_adj[edge.src] = {}
                _append_key(self._in_srcs.setdefault(edge.dst, []), edge.src,
                            self._dirty_in, edge.dst)
            if existing is None:
                _append_key(self._kind_pairs.setdefault(kv, []), (edge.src, edge.dst),
                            self._dirty_pairs, kv)
            _put_kind(out_adj[edge.dst], kv, stored)
            _put_kind(in_adj[edge.src], kv, stored)
            return stored

    def get_edge(self, src: str, dst: str, kind: EdgeKind) -> Edge | None:
        return self._out.get(src, {}).get(dst, {}).get(kind.value)

    def edges_of_kind(self, kind: EdgeKind) -> list[Edge]:
        """All edges of a kind, in deterministic (src, dst)-sorted order.

        The per-kind index holds the (src, dst) pairs sorted, and tuple order IS
        the old nested "sorted srcs, then sorted dsts" order — so this returns
        the identical list in O(|kind|) rather than O(|V| log|V| + |E| log|E|)."""
        # `kind.value` is caller-controlled (a `.value` property on a foreign
        # object could run code); read it BEFORE the lock, like `nodes_of_kind`.
        kv = kind.value
        with self._lock:
            pairs = self._kind_pairs.get(kv)
            if not pairs:
                return []
            out_adj = self._out
            return [out_adj[s][d][kv] for s, d in _normalize(pairs, self._dirty_pairs, kv)]

    def all_edges(self) -> list[Edge]:
        """Every edge, in deterministic (src, dst, kind)-sorted order.

        `_node_ids` is the sorted key set of `_out` (every node gets an `_out`
        entry on insert and loses it on removal), `_out_dsts[src]` is its sorted
        dst list, and each innermost bucket is held in sorted-kind order — so
        this walks the same three levels in the same order with no sort at all."""
        with self._lock:
            out: list[Edge] = []
            out_adj = self._out
            dsts = self._out_dsts
            dirty = self._dirty_out
            if dirty:
                # Normalise every owed adjacency bucket once. Iterate a SNAPSHOT and
                # discard per bucket, never `for src in dirty` + `dirty.clear()`: the
                # live-set iteration raised `RuntimeError: Set changed size during
                # iteration` the moment a second reader cleared the same set, and the
                # bulk clear would drop a slot a writer flagged mid-loop. `tuple(set)`
                # is a single C-level copy, so it cannot itself observe a mutation.
                for src in tuple(dirty):
                    bucket = dsts.get(src)
                    if bucket is not None:
                        bucket.sort()
                    dirty.discard(src)
            for src in _normalize(self._node_ids, self._dirty_nodes, _NODE_IDS):
                adj = out_adj[src]
                for dst in dsts[src]:
                    out.extend(adj[dst].values())
            return out

    # -- traversal ----------------------------------------------------------

    def neighbors(
        self,
        node_id: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
        *,
        incoming: bool = False,
    ) -> list[Edge]:
        """Outgoing edges from `node_id` (or incoming when incoming=True),
        optionally filtered to a set of edge kinds. Deterministic order.
        Unknown node -> empty list (traversal is total, not partial)."""
        # Drain the caller's iterable BEFORE taking the lock — it may be a
        # generator, and running caller code under the lock is how a leaf lock
        # stops being a leaf lock. (See CONCURRENCY: `_lock` is safe precisely
        # because nothing under it can call back out.)
        allowed = {k.value for k in edge_kinds} if edge_kinds is not None else None
        with self._lock:
            if incoming:
                adj, order, dirty = self._in, self._in_srcs, self._dirty_in
            else:
                adj, order, dirty = self._out, self._out_dsts, self._dirty_out
            buckets = adj.get(node_id)
            if not buckets:
                return []
            out: list[Edge] = []
            for other in _normalize(order[node_id], dirty, node_id):
                bucket = buckets[other]
                if allowed is None:
                    out.extend(bucket.values())
                else:
                    out.extend(e for kv, e in bucket.items() if kv in allowed)
            return out

    def reachable(
        self,
        src: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
    ) -> set[str]:
        """Set of node ids reachable from `src` by following edges of the
        given kinds (any kind when None). Excludes `src` itself unless a
        cycle returns to it. Unknown `src` -> empty set. BFS; each node
        visited once, so cycles terminate."""
        # Drain the caller's iterable BEFORE the lock — it may be a generator,
        # and running caller code under the lock is how a leaf lock stops being
        # one. Same reason `neighbors` does it here.
        allowed = {k.value for k in edge_kinds} if edge_kinds is not None else None
        with self._lock:
            if src not in self._nodes:
                return set()
            # `src` enters `seen` only if a cycle routes back to it; that
            # signal is intentionally preserved.
            seen: set[str] = set()
            queue: deque[str] = deque([src])
            while queue:
                cur = queue.popleft()
                for dst, kinds in self._out.get(cur, {}).items():
                    if allowed is not None and not (allowed & kinds.keys()):
                        continue
                    if dst not in seen:
                        seen.add(dst)
                        queue.append(dst)
            return seen

    def out_edges(
        self,
        node_id: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
    ) -> Iterator[Edge]:
        """Iterator over outgoing edges (deterministic order). Used by the
        query layer's path enumeration."""
        yield from self.neighbors(node_id, edge_kinds)

    # -- sizing -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        with self._lock:
            return sum(
                len(kinds)
                for dsts in self._out.values()
                for kinds in dsts.values()
            )

    # -- copy / pickle ------------------------------------------------------

    def __getstate__(self) -> dict:
        """Snapshot WITHOUT the lock, so `copy.deepcopy` and `pickle` keep
        working.

        A `threading.RLock` is not picklable, so merely holding one as an
        attribute silently broke both on a public model class — they work at
        both the pre-index and the unlocked-index revisions, and a reviewer
        caught the regression here. No shipped caller deepcopies or pickles a
        `WorldModel` (`store.to_dict`/`from_dict` is the supported snapshot
        path), but "no current caller" is not a reason to drop a capability a
        class already had.

        The lock guards only the shallow `__dict__.copy()` here; the deep
        traversal of `_nodes`/`_out`/`_in` happens AFTER release, in the
        deepcopy/pickle machinery that consumes this state. So a deepcopy racing
        a concurrent writer can still raise `RuntimeError: dictionary changed
        size during iteration` — which is EXACTLY what the pre-index revision
        (838e0b42) does under the same race, measured identically. This restores
        base parity, no more: it fails LOUDLY (never a silently torn copy), and
        callers that copy a graph while another thread mutates it must serialise
        that themselves, as they had to at base."""
        with self._lock:
            state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state: dict) -> None:
        """Restore, giving the new object its OWN fresh lock. A copy must never
        share a lock with its original: they are independent graphs, and sharing
        would serialise them against each other for nothing."""
        self.__dict__.update(state)
        self._lock = threading.RLock()

    # -- index invariant ----------------------------------------------------

    def _assert_index_consistent(self) -> None:
        """Re-derive every order index from `_nodes` / `_out` / `_in` and assert
        it matches. This is the contract the fast readers are allowed to assume —
        it is NOT called on the hot path; the test-suite calls it after mutation
        sequences so a future index bug is caught at the source rather than as a
        mysterious ordering change downstream."""
        # the lazy contract first: a bucket NOT flagged dirty must already be sorted
        with self._lock:
            if _NODE_IDS not in self._dirty_nodes:
                assert self._node_ids == sorted(self._node_ids), "clean node index is unsorted"
            for kk, ids in self._kind_ids.items():
                if kk not in self._dirty_kinds:
                    assert ids == sorted(ids), f"clean kind index unsorted for {kk!r}"
            for src, lst in self._out_dsts.items():
                if src not in self._dirty_out:
                    assert lst == sorted(lst), f"clean out index unsorted for {src!r}"
            for dst, lst in self._in_srcs.items():
                if dst not in self._dirty_in:
                    assert lst == sorted(lst), f"clean in index unsorted for {dst!r}"
            for kv, pairs in self._kind_pairs.items():
                if kv not in self._dirty_pairs:
                    assert pairs == sorted(pairs), f"clean edge-kind index unsorted for {kv!r}"
            # dirty slots may not name a bucket that no longer exists
            assert self._dirty_out <= set(self._out_dsts), "stale dirty out slot"
            assert self._dirty_in <= set(self._in_srcs), "stale dirty in slot"
            # then the content itself (normalising as a reader would)
            _normalize(self._node_ids, self._dirty_nodes, _NODE_IDS)
            for kk in list(self._kind_ids):
                _normalize(self._kind_ids[kk], self._dirty_kinds, kk)
            for src in list(self._out_dsts):
                _normalize(self._out_dsts[src], self._dirty_out, src)
            for dst in list(self._in_srcs):
                _normalize(self._in_srcs[dst], self._dirty_in, dst)
            for kv in list(self._kind_pairs):
                _normalize(self._kind_pairs[kv], self._dirty_pairs, kv)
            assert self._node_ids == sorted(self._nodes), "node id index drifted"
            assert sorted(self._out) == self._node_ids, "_out key set != node id index"
            assert sorted(self._in) == self._node_ids, "_in key set != node id index"
            want_kinds: dict[object, list[str]] = {}
            for nid, node in self._nodes.items():
                want_kinds.setdefault(_kind_key(node.kind), []).append(nid)
            for key, ids in want_kinds.items():
                assert self._kind_ids.get(key) == sorted(ids), f"kind index drifted for {key!r}"
            for key, ids in self._kind_ids.items():
                assert ids == sorted(want_kinds.get(key, [])), f"stale kind index for {key!r}"
            for src, adj in self._out.items():
                assert self._out_dsts.get(src) == sorted(adj), f"out index drifted for {src!r}"
                for dst, bucket in adj.items():
                    assert list(bucket) == sorted(bucket), f"out bucket unsorted {src!r}->{dst!r}"
            for dst, adj in self._in.items():
                assert self._in_srcs.get(dst) == sorted(adj), f"in index drifted for {dst!r}"
                for src, bucket in adj.items():
                    assert list(bucket) == sorted(bucket), f"in bucket unsorted {src!r}<-{dst!r}"
            want_pairs: dict[str, list[tuple[str, str]]] = {}
            for src, adj in self._out.items():
                for dst, bucket in adj.items():
                    for kv in bucket:
                        want_pairs.setdefault(kv, []).append((src, dst))
            for kv, pairs in want_pairs.items():
                assert self._kind_pairs.get(kv) == sorted(pairs), f"edge-kind index drifted for {kv!r}"
            for kv, pairs in self._kind_pairs.items():
                assert pairs == sorted(want_pairs.get(kv, [])), f"stale edge-kind index for {kv!r}"
