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
    the chain check exist to catch, and the S0d rebuild-and-compare in `sigil verify` / `vigil doctor` will
    compare every cached fold with a full fold;
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
        for r in store.iter_records(since_seq=e.seq):
            if r.kind == KEY_HISTORY_KIND:
                return False
            self._step(e.state, r, e.ctx)
            e.seq, e.entry_hash = r.seq, r.entry_hash
        return True

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
                        if self._anchor_holds(store, e) and self._extend(store, e):
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
