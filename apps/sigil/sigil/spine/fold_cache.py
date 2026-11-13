"""Front C S0a — the verified FOLD CACHE: chain-anchored, incremental memoization of a spine fold.

THE WALL THIS REMOVES. Every registry read (`CustomerRegistry.by_email` on each customer login, …) re-folds
the signed spine from the start and re-verifies every grant's Ed25519 signature on every call. Measured at
~160–200 µs per record, that is minutes per login lookup at 1M customers
(docs/decisions/FRONT-C-1M-SCALE-DESIGN.md §2). The registries are LEFT folds in seq order (already written
associatively for `SnapshotState`), so the state after record N extends EXACTLY by folding records N+1…; with
this cache each signature is verified once, when its record is first folded, and a read costs O(new records).

TRUST MODEL (design §7.2). The spine stays the ONLY source of truth. This is an IN-MEMORY cache of a fold this
same process computed from verified records — nothing is persisted, so there is nothing new to tamper with —
and it is trusted only while it is provably a prefix of the current spine:

  * CHAIN ANCHOR — an entry remembers the `(seq, entry_hash)` of the last record it folded. Every read
    re-reads that record; if it is missing or its `entry_hash` differs (a restore, rollback, re-genesis,
    rewrite or reset spine) the entry is DISCARDED and the fold rebuilt from the spine. `entry_hash` links
    `prev_hash`, so an equal anchor means an equal prefix of CHAINED content (kind, source, actor, payload, parent
    links) for any chain that `SpineStore.verify()` accepts. A record's `ts` and `schema_version` are outside the
    content digest and `entry_hash`: an in-place edit of them before the anchor passes `verify()` AND the anchor
    (the budget fold buckets agent spend by `ts`), and only `audit()` sees it. An in-place edit that BREAKS the
    chain before the anchor is not re-read here either: it is what `verify()` and the chain check exist to catch.
    `audit()` (S0d) rebuilds every cached fold from the spine and compares it with the cached state (`sigil verify
    --folds`, the cockpit's periodic audit, `vigil doctor`).
    The anchor is proven, and the new records read, from the END of the active segment when the store offers
    `tail_after` (S0d — no seq index is built, so a per-request store pays O(new records), not O(segment)); an
    anchor that is the last record of the segment before the active one is proven against the manifest's
    `boundary_hash` for it, so a gzip-sealed anchor is never decompressed;
  * CONTINUITY — every record folded must CHAIN from the one before it (`seq == prev + 1` and `prev_hash ==` the
    previous `entry_hash`; the first record after an anchor chains from the anchor; a seeded read starts exactly
    after its seed; the first record of a pass from the very start links from the live window's base — GENESIS,
    or the retained boundary after a prune), and every pass must reach the tip the store read from disk when it was
    opened (re-read from disk before a pass is declared short). A read that skips a record — `iter_records`
    reading to the live end of a file another process is still appending to (a half-written line is skipped as
    malformed and the NEXT record is yielded), including the very first record of a fresh spine, or a stale seq
    index or `.idx` sidecar — is never folded into an entry: a catch-up discards the entry and rebuilds; a
    rebuild raises `FoldDiscontinuity` and the caller answers from its full fold. Without this a single torn
    read was cached for the life of the process (the entry anchored past the hole: a debit or a kill-switch
    engage missing for good). The audit tells a torn tail from an edit: a hole inside the range the entry had
    already folded is persistent, so it is a MISMATCH and the entry is discarded;
  * KEY ROTATION — a fold verifies each record under the owner key valid at its seq. A newly appended
    owner-key-history record can change those windows (including for EARLIER seqs: a fork or broken chain
    denies all), so meeting one while extending discards the entry. A rebuild whose resolver did not see a
    history record it then folds (a concurrent rotation) is returned but not cached;
  * IDENTITY — one entry per (fold, resolved spine path), tagged with the caller's key: the trusted owner
    pubkey, the genesis pin and the loaded snapshot BY VALUE (a prune moves its boundary; its rows are the
    seed). A different key rebuilds and replaces the entry, so memory stays bounded to one folded state per
    fold and spine;
  * FAIL-SAFE — any error while validating or extending discards the entry and rebuilds from the spine; an
    error in the REBUILD propagates exactly as the caller's full fold would raise it.

THREAD-SAFE (the cockpit is a ThreadingHTTPServer). Each entry has its own lock, held while it is extended
AND while the caller's `reader` runs, so no reader ever sees a half-extended state.

DEFAULT-OFF (`VIGIL_FOLD_CACHE_ENABLED`, `config.fold_cache_enabled`). With it unset every registry runs its
unchanged full fold, and this module is never consulted. FATAL-2: sovereign-only; no governor import here.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

__all__ = ["FoldCache", "FoldDiscontinuity", "clear_all"]

# governor.key_history.KEY_HISTORY_KIND — repeated (not imported) so the spine package keeps no governor import;
# tests pin the two equal.
KEY_HISTORY_KIND = "owner_key_history"

T = TypeVar("T")

_REGISTRY: "list[FoldCache]" = []
_REGISTRY_LOCK = threading.Lock()


def clear_all() -> None:
    """Drop every cached fold (tests). Never needed for correctness: every entry re-proves its anchor and key."""
    with _REGISTRY_LOCK:
        caches = list(_REGISTRY)
    for c in caches:
        c.clear()


_MISSING = object()


class FoldDiscontinuity(Exception):
    """A fold pass read a record that does not CHAIN from the one before it (`seq != prev + 1`, or `prev_hash` is not
    the previous record's `entry_hash`): a torn read of a record another process was still writing, a stale seq
    index, a duplicate-seq line. The state built from that read is not a fold of any prefix of the spine, so it is
    never cached; the caller answers from its full fold instead (exactly as with the cache off)."""


def _slots_of(cls) -> "tuple[str, ...]":
    names: list = []
    for k in cls.__mro__:
        sl = k.__dict__.get("__slots__", ())
        names.extend([sl] if isinstance(sl, str) else sl)
    return tuple(n for n in names if n not in ("__dict__", "__weakref__"))


def _first_difference(a, b, path: str = "state") -> "Optional[str]":
    """The path of the first difference between two folded states, or None when they are equal. Compares by
    VALUE through dicts, lists, tuples and `__slots__` objects (the registries' views); floats treat NaN as
    equal to NaN; anything else (sets, frozen dataclasses, primitives) by `==`."""
    if type(a) is not type(b):
        return f"{path}: {type(a).__name__} != {type(b).__name__}"
    if isinstance(a, float):
        return None if (a == b or (a != a and b != b)) else path
    if isinstance(a, dict):
        if a.keys() != b.keys():
            return f"{path}: keys differ"
        for k, v in a.items():
            d = _first_difference(v, b[k], f"{path}[{k!r}]")
            if d is not None:
                return d
        return None
    if isinstance(a, (list, tuple)):
        if len(a) != len(b):
            return f"{path}: length {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = _first_difference(x, y, f"{path}[{i}]")
            if d is not None:
                return d
        return None
    slots = _slots_of(type(a))
    if slots:
        for n in slots:
            d = _first_difference(getattr(a, n, _MISSING), getattr(b, n, _MISSING), f"{path}.{n}")
            if d is not None:
                return d
        return None
    return None if a == b else path


def _store_tip(store) -> "Optional[int]":
    """The tip seq the store read from DISK when it was opened (`next_seq - 1`; the last record of the active
    segment, or of the last sealed one — never through the seq index or its sidecar), or None for a store that
    does not expose one. A fold pass that ends BELOW it skipped records (a stale or planted index hid the tail)."""
    try:
        n = store.next_seq
    except Exception:  # noqa: BLE001 — a store without a tip: the check is skipped
        return None
    return n - 1 if isinstance(n, int) else None


def _disk_tip(store) -> "Optional[int]":
    """The tip as the spine's files say NOW (`SpineStore.disk_tip`: an O(tail) read, never the seq index), or None
    when undecidable. Consulted only when a pass ends below `_store_tip`: a long-lived store's in-memory tip can
    sit above the disk (a truncated tail), and that alone must not turn every read into a rebuild."""
    fn = getattr(store, "disk_tip", None)
    if fn is None:
        return None
    try:
        return fn()
    except Exception:  # noqa: BLE001 — undecidable: keep the stricter in-memory tip
        return None


def _ends_below_tip(store, seq: int, tip: "Optional[int]") -> bool:
    """True when a pass that folded up to `seq` skipped records: it ends below the tip the store read at open
    AND below the tip on disk now."""
    if tip is None or seq >= tip:
        return False
    fresh = _disk_tip(store)
    return fresh is None or seq < fresh


def _live_base(store) -> "Optional[str]":
    """The prev_hash the spine's first LIVE record links from (GENESIS, or the retained boundary after a prune),
    or None for a store that does not expose one. An anchor-less pass checks its first record against it, so a
    torn read that skipped the first record of a fresh spine cannot be cached as the whole spine."""
    try:
        return store._live_base_prev_hash()
    except Exception:  # noqa: BLE001 — undecidable here: the pass checks nothing extra (the full fold's own rule)
        return None


def _store_identity(store) -> str:
    try:
        return str(Path(store.path).resolve())
    except Exception:  # noqa: BLE001 — an unresolvable path still gets a stable identity
        return repr(getattr(store, "path", id(store)))


@dataclass
class _Entry:
    key: tuple
    state: Any
    ctx: Any
    seq: int                            # last folded seq, or the build's start (-1 = from genesis)
    entry_hash: Optional[str] = None    # that record's entry_hash — the chain anchor (None: nothing folded)
    dead: bool = False                  # discarded while another thread waited on `lock`
    lock: threading.Lock = field(default_factory=threading.Lock)


class FoldCache:
    """One named incremental fold.

    ``build()`` returns ``(state, ctx, since_seq, horizon_seq)`` — the fresh starting state (e.g. a snapshot
    seed), the per-build context (e.g. the owner-key resolver), the seq the full fold starts AFTER, and the
    last seq the context's history scan read. ``step(state, record, ctx)`` folds ONE record in place — the
    registry's own loop body, shared with its uncached fold. ``reader(state)`` derives the caller's answer
    and runs under the entry lock; it must return an immutable value or a COPY, never a reference into the
    state — the state is extended in place by later reads, outside any lock the caller holds."""

    def __init__(self, name: str, *, step: Callable[[Any, Any, Any], None]) -> None:
        self.name = name
        self._step = step
        self._entries: "dict[tuple, _Entry]" = {}
        self._lock = threading.Lock()
        with _REGISTRY_LOCK:
            _REGISTRY.append(self)

    def clear(self) -> None:
        with self._lock:
            for e in self._entries.values():
                e.dead = True
            self._entries.clear()

    # -- validation + extension (caller holds e.lock) ----------------------------------------------------
    @staticmethod
    def _anchor_holds(store, e: _Entry) -> bool:
        if e.entry_hash is None:
            return True                            # nothing folded yet: extending from the build's start IS
            #                                        the full fold (the key pins the seed it started from)
        rec = store.get(e.seq)
        return rec is not None and rec.seq == e.seq and rec.entry_hash == e.entry_hash

    def _extend(self, store, e: _Entry) -> bool:
        """Fold every record after the anchor into `e`. False if one is an owner-key-history record (the
        resolver must be rebuilt). Raises on a fold/read error — the caller discards `e`."""
        base = _live_base(store) if e.entry_hash is None and e.seq < 0 else None
        return self._fold_into(e, store.iter_records(since_seq=e.seq), base)

    def _fold_into(self, e: _Entry, records, base: "Optional[str]" = None) -> bool:
        """Fold `records` into `e`; False (rebuild) at the first one that does not chain — from the anchor, or,
        for an entry that has folded nothing yet: right after its seed, or from `base` (the live window's first
        prev_hash — passed only for a pass from the very start)."""
        for r in records:
            if e.entry_hash is not None and (r.seq != e.seq + 1 or r.prev_hash != e.entry_hash):
                return False                       # not chained from the anchor / the previous record: rebuild
            if e.entry_hash is None and ((e.seq >= 0 and r.seq != e.seq + 1)
                                         or (base is not None and r.prev_hash != base)):
                return False                       # an anchor-less pass must start at the live window's base
            if r.kind == KEY_HISTORY_KIND:
                return False
            self._step(e.state, r, e.ctx)
            e.seq, e.entry_hash = r.seq, r.entry_hash
        return True

    def _catch_up(self, store, e: _Entry) -> bool:
        """Prove the anchor and fold the records appended since (caller holds `e.lock`). The store's tail fast
        path first (`tail_after`: no seq index built); the indexed `get` + `iter_records` when it cannot decide."""
        tip = _store_tip(store)
        tail = getattr(store, "tail_after", None)
        if tail is not None and e.entry_hash is not None:
            delta = tail(e.seq, e.entry_hash)
            if delta is False:
                return False
            if delta is not None:
                return self._fold_into(e, delta) and not _ends_below_tip(store, e.seq, tip)
        return self._anchor_holds(store, e) and self._extend(store, e) and not _ends_below_tip(store, e.seq, tip)

    def _discard(self, ident: tuple, e: _Entry) -> None:
        e.dead = True
        with self._lock:
            if self._entries.get(ident) is e:
                del self._entries[ident]

    # -- the one read path ---------------------------------------------------------------------------------
    def read(self, store, key: tuple, *, build: Callable[[], "tuple[Any, Any, int, int]"],
             reader: Callable[[Any], T]) -> T:
        """`reader(state)` over the fold of `store`, extending a cached entry over the records appended since
        the last read, or rebuilding it from the spine when it cannot be proven a prefix of the spine."""
        ident = (_store_identity(store),)
        key = tuple(key)
        with self._lock:
            e = self._entries.get(ident)
        if e is not None:
            with e.lock:
                if not e.dead and e.key == key:
                    try:
                        if self._catch_up(store, e):
                            return reader(e.state)
                    except Exception:  # noqa: BLE001 — any doubt: discard and rebuild from the spine
                        pass
                    self._discard(ident, e)
        return self._rebuild(store, ident, key, build, reader)

    def _rebuild(self, store, ident: tuple, key: tuple, build, reader):
        tip = _store_tip(store)
        state, ctx, since, horizon = build()
        e = _Entry(key=key, state=state, ctx=ctx, seq=since)
        base = _live_base(store)
        cacheable = True
        for r in store.iter_records(since_seq=since):
            if e.entry_hash is not None and (r.seq != e.seq + 1 or r.prev_hash != e.entry_hash):
                raise FoldDiscontinuity(f"{self.name}: seq {r.seq} does not chain from seq {e.seq}")
            if e.entry_hash is None and since >= 0 and r.seq != since + 1:
                raise FoldDiscontinuity(f"{self.name}: the read after seq {since} starts at seq {r.seq}")
            if e.entry_hash is None and since < 0 and base is not None and r.prev_hash != base:
                raise FoldDiscontinuity(f"{self.name}: the first record read (seq {r.seq}) does not link from "
                                        f"the live window's base")
            if r.kind == KEY_HISTORY_KIND and r.seq > horizon:
                cacheable = False                  # a rotation the resolver did not see: answer, don't keep
            self._step(state, r, ctx)
            e.seq, e.entry_hash = r.seq, r.entry_hash
        if _ends_below_tip(store, e.seq, tip):
            raise FoldDiscontinuity(f"{self.name}: the read ended at seq {e.seq}, below the tip {tip}")
        with e.lock:
            out = reader(state)
            if cacheable:
                with self._lock:
                    old = self._entries.get(ident)
                    if old is not None:
                        old.dead = True
                    self._entries[ident] = e
        return out

    # -- S0d: rebuild-and-compare ----------------------------------------------------------------------------
    def audit(self, store, key: tuple, *, build: Callable[[], "tuple[Any, Any, int, int]"]) -> dict:
        """Rebuild this fold of `store` from the spine with `build` (the caller's fresh build for `key`) and compare
        it with the cached entry — the S0d proof that the incremental cache still equals a full fold. It catches
        what the anchor check does not re-read (an in-place edit BEFORE the anchor) and any defect in a view's
        incremental bookkeeping. Entries keep no build of their own (it would pin the request's store and
        registry for the entry's lifetime), so audits run through the registries' own read path
        (`governor.fold_read.auditing`).

        The fresh fold runs OUTSIDE the entry lock (reads keep being served meanwhile); then, under the lock, the
        entry is brought to the current tip, the fresh fold catches up to the same seq, and the two states are
        compared by value. Returns `{"fold", "status", ...}` with status `match`, `MISMATCH` (+ `seq`,
        `difference`; also a hole in the spine inside the range the entry had folded — an edit, never a torn
        read), `empty` (no entry for this store) or `skipped` (+ `reason`: cached under another key, the
        entry was replaced, the anchor moved, or an owner-key rotation landed mid-audit — the next read rebuilds
        anyway). A MISMATCH discards the entry: the spine is the source of truth, so the next read rebuilds from
        it; the report keeps the evidence. Never writes the spine."""
        ident = (_store_identity(store),)
        with self._lock:
            e = self._entries.get(ident)
        if e is None:
            return {"fold": self.name, "status": "empty"}
        if e.key != tuple(key):
            return {"fold": self.name, "status": "skipped", "reason": "the entry is cached under another key"}
        try:
            return self._audit_entry(store, ident, e, build)
        except Exception:
            # The fresh fold RAISES (a lost segment, an unverifiable prune head): the full fold raises on this spine
            # too, so the warm entry must not keep answering. Discard it — the next read rebuilds and raises.
            self._discard(ident, e)
            raise

    def _hole(self, store, ident: tuple, e: _Entry, at: int, after: int, folded: int, base) -> dict:
        """The fresh fold met a record that does not chain (at seq `at`, after seq `after`). A torn read only
        happens at the live END of the spine: when the hole lies inside what the entry had already folded
        (`after < folded`), those bytes were complete when it folded them, so the hole is an edit to the spine
        (a deleted or rewritten record, a truncated segment) — persistent, and the full fold reads the spine
        differently from the entry. Discard it (the next read rebuilds, meets the hole and answers UNCACHED, as
        the full fold does) and report a MISMATCH. Past the entry's seq it may be a torn tail, and a hole met while
        the live window was rebased under the read (a hard prune committing mid-audit) is not an edit: skip."""
        if after < folded and _live_base(store) == base:
            self._discard(ident, e)
            return {"fold": self.name, "status": "MISMATCH", "seq": folded,
                    "difference": f"the spine is not contiguous at seq {at} (after seq {after}), inside the "
                                  f"cached range: an edit before the anchor"}
        return {"fold": self.name, "status": "skipped",
                "reason": f"the fresh fold's read is not contiguous at seq {at} (re-run the audit)"}

    def _audit_entry(self, store, ident: tuple, e: _Entry, build) -> dict:
        folded = e.seq                                     # what the entry had folded when the audit began
        base = _live_base(store)                           # BEFORE the build: a rebase during it is then seen
        state, ctx, since, horizon = build()
        fseq, fhash = since, None
        for r in store.iter_records(since_seq=since):
            if fhash is not None and (r.seq != fseq + 1 or r.prev_hash != fhash):
                return self._hole(store, ident, e, r.seq, fseq, folded, base)
            if fhash is None and ((since >= 0 and r.seq != since + 1)
                                  or (since < 0 and base is not None and r.prev_hash != base)):
                return self._hole(store, ident, e, r.seq, fseq, folded, base)
            if r.kind == KEY_HISTORY_KIND and r.seq > horizon:
                return {"fold": self.name, "status": "skipped", "reason": "owner-key rotation during the audit"}
            self._step(state, r, ctx)
            fseq, fhash = r.seq, r.entry_hash
        with e.lock:
            if e.dead:
                return {"fold": self.name, "status": "skipped", "reason": "entry replaced during the audit"}
            try:
                ok = self._catch_up(store, e)
            except Exception as exc:  # noqa: BLE001 — the read path would discard it too
                ok, why = False, f"{type(exc).__name__}: {exc}"
            else:
                why = "the anchor no longer holds or an owner-key rotation landed"
            if not ok:
                self._discard(ident, e)
                return {"fold": self.name, "status": "skipped", "reason": why + " (rebuilt on the next read)"}
            if fseq < e.seq:
                for r in store.iter_records(since_seq=fseq):
                    if r.seq > e.seq:
                        break
                    if fhash is not None and (r.seq != fseq + 1 or r.prev_hash != fhash):
                        return self._hole(store, ident, e, r.seq, fseq, e.seq, base)   # below the caught-up entry: an edit
                    if r.kind == KEY_HISTORY_KIND:
                        return {"fold": self.name, "status": "skipped", "reason": "owner-key rotation during the audit"}
                    self._step(state, r, ctx)
                    fseq, fhash = r.seq, r.entry_hash
            if fseq != e.seq:
                return {"fold": self.name, "status": "skipped",
                        "reason": f"the fresh fold reached seq {fseq}, the entry seq {e.seq}"}
            diff = _first_difference(e.state, state)
            if diff is None:
                return {"fold": self.name, "status": "match", "seq": e.seq}
            if _live_base(store) != base:                  # a hard prune rebased the live window mid-audit
                return {"fold": self.name, "status": "skipped", "reason": "the live window moved during the audit"}
            self._discard(ident, e)
            return {"fold": self.name, "status": "MISMATCH", "seq": e.seq, "difference": diff}
