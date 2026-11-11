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
    `prev_hash`, so an equal anchor means an equal prefix for any chain that `SpineStore.verify()` accepts.
    An in-place edit that BREAKS the chain before the anchor is not re-read here: it is what `verify()` and
    the chain check exist to catch, and `audit()` (S0d) rebuilds every cached fold from the spine and
    compares it with the cached state (`sigil verify --folds`, the cockpit's periodic audit, `vigil doctor`).
    The anchor is proven, and the new records read, from the END of the active segment when the store offers
    `tail_after` (S0d — no seq index is built, so a per-request store pays O(new records), not O(segment)); an
    anchor that is the last record of the segment before the active one is proven against the manifest's
    `boundary_hash` for it, so a gzip-sealed anchor is never decompressed;
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

__all__ = ["FoldCache", "clear_all"]

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
    and runs under the entry lock."""

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
        return self._fold_into(e, store.iter_records(since_seq=e.seq))

    def _fold_into(self, e: _Entry, records) -> bool:
        for r in records:
            if r.kind == KEY_HISTORY_KIND:
                return False
            self._step(e.state, r, e.ctx)
            e.seq, e.entry_hash = r.seq, r.entry_hash
        return True

    def _catch_up(self, store, e: _Entry) -> bool:
        """Prove the anchor and fold the records appended since (caller holds `e.lock`). The store's tail fast
        path first (`tail_after`: no seq index built); the indexed `get` + `iter_records` when it cannot decide."""
        tail = getattr(store, "tail_after", None)
        if tail is not None and e.entry_hash is not None:
            delta = tail(e.seq, e.entry_hash)
            if delta is False:
                return False
            if delta is not None:
                return self._fold_into(e, delta)
        return self._anchor_holds(store, e) and self._extend(store, e)

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
        state, ctx, since, horizon = build()
        e = _Entry(key=key, state=state, ctx=ctx, seq=since)
        cacheable = True
        for r in store.iter_records(since_seq=since):
            if r.kind == KEY_HISTORY_KIND and r.seq > horizon:
                cacheable = False                  # a rotation the resolver did not see: answer, don't keep
            self._step(state, r, ctx)
            e.seq, e.entry_hash = r.seq, r.entry_hash
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
        `difference`), `empty` (no entry for this store) or `skipped` (+ `reason`: cached under another key, the
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
        state, ctx, since, horizon = build()
        fseq = since
        for r in store.iter_records(since_seq=since):
            if r.kind == KEY_HISTORY_KIND and r.seq > horizon:
                return {"fold": self.name, "status": "skipped", "reason": "owner-key rotation during the audit"}
            self._step(state, r, ctx)
            fseq = r.seq
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
                    if r.kind == KEY_HISTORY_KIND:
                        return {"fold": self.name, "status": "skipped", "reason": "owner-key rotation during the audit"}
                    self._step(state, r, ctx)
                    fseq = r.seq
            if fseq != e.seq:
                return {"fold": self.name, "status": "skipped",
                        "reason": f"the fresh fold reached seq {fseq}, the entry seq {e.seq}"}
            diff = _first_difference(e.state, state)
            if diff is None:
                return {"fold": self.name, "status": "match", "seq": e.seq}
            self._discard(ident, e)
            return {"fold": self.name, "status": "MISMATCH", "seq": e.seq, "difference": diff}
