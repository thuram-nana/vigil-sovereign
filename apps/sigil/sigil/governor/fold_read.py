"""Front C S0 — the ONE read path from an owner-signed registry onto the verified fold cache.

Every owner-signed registry fold depends on the same inputs beyond the spine records themselves: the TRUSTED
owner pubkey it verifies under, the GENESIS pin the owner-key succession is walked from once a rotation exists,
and the loaded SNAPSHOT — bound BY VALUE: its boundary moves the live window and its rows ARE the seed, so a
different seed under the same boundary also rebuilds (1.8 us to compare the empty no-prune identity; O(seed)
when a prune exists, the same order as `SnapshotState.load` itself). `cached_read` binds exactly
those into the cache key, builds the per-entry owner-key resolver with its scan horizon, and asks the registry
only for its seed — so no registry can forget one of them (`spine/fold_cache.py` holds the trust model).

`UNCACHED` means "no cached answer": the flag is off, the registry's view declared it cannot answer
(`view.poisoned`), or — for a `live_window` fold, whose full path is a plain scan that never loads the snapshot —
the snapshot could not be loaded (the full path would still answer, so the cache declines rather than raise). The
caller then runs its unchanged full fold.

FATAL-2: sovereign-side. No framework/strix import.
"""
from __future__ import annotations

import contextlib
import contextvars
from typing import Any, Callable, Iterator, Optional

from ..config import fold_cache_enabled
from ..reuse import assert_no_offense
from ..spine.fold_cache import FoldCache
from ..spine.snapshot import SnapshotState
from . import key_history as _kh
from .identity import genesis_owner_pubkey

assert_no_offense()

__all__ = ["UNCACHED", "audit_with", "auditing", "cached_read", "cached_unsigned_read"]

UNCACHED = object()

# S0d rebuild-and-compare: while set, every cached read also audits its cache once (results keyed by fold name).
_AUDIT: "contextvars.ContextVar[Optional[dict]]" = contextvars.ContextVar("fold_cache_audit", default=None)


@contextlib.contextmanager
def auditing() -> "Iterator[dict]":
    """Within this block every cached read first AUDITS its fold cache — rebuilds it from the spine with the read's
    own fresh build (same key) and compares (`FoldCache.audit`) — once per fold, then reads as usual. Yields the
    results, keyed by fold name. Through the registries' own read path, so no entry keeps a build (a request's
    store / registry) alive between reads."""
    results: dict = {}
    token = _AUDIT.set(results)
    try:
        yield results
    finally:
        _AUDIT.reset(token)


def audit_with(fn: Callable[[], Any]) -> "list[dict]":
    """Run `fn` (cached reads) under `auditing()`; the audit results in fold-name order."""
    with auditing() as results:
        fn()
    return [results[k] for k in sorted(results)]


def _maybe_audit(cache: FoldCache, store, key: tuple, build) -> None:
    results = _AUDIT.get()
    if results is not None and cache.name not in results:
        results[cache.name] = cache.audit(store, key, build=build)


def _snapshot(store, live_window: bool):
    if not live_window:
        return SnapshotState.load(store)               # raises exactly as the seeded full fold would
    try:
        return SnapshotState.load(store)
    except Exception:  # noqa: BLE001 — the live-window full scan never loads it: decline, never raise
        return None


def cached_read(cache: FoldCache, store, *, trusted_pubkey, seed: Callable[[Any], "tuple[Any, int]"],
                reader: Callable[[Any], Any], live_window: bool = False) -> Any:
    """`reader(view)` over `cache`'s verified fold of `store`, or `UNCACHED`.

    `seed(snap) -> (view, since_seq)` builds the registry's fresh starting view from the loaded snapshot (its
    hard-prune seed, or the empty genesis start under the pubkey bypass) and the seq the full fold starts after
    — the same starting point its uncached fold uses. `SnapshotState.load` raises exactly as the full fold
    would on an unverifiable prune head.

    `live_window=True` is for a fold whose full path scans the live window from genesis WITHOUT loading the
    snapshot: the snapshot still keys the entry (a prune moves the live window, so the entry rebuilds), but a load
    failure answers `UNCACHED` instead of raising."""
    if not fold_cache_enabled():
        return UNCACHED
    snap = _snapshot(store, live_window)
    if snap is None:
        return UNCACHED
    key = (trusted_pubkey, genesis_owner_pubkey(), snap)

    def build():
        resolver, horizon = _kh.key_resolver_with_horizon(store, current=trusted_pubkey)
        with _kh.pinned_resolver(store, current=trusted_pubkey, resolver=resolver):
            view, since = seed(snap)                   # the seed is judged with the resolver this build folds with
        return view, resolver, since, horizon

    def guarded(view):
        return UNCACHED if getattr(view, "poisoned", False) else reader(view)

    _maybe_audit(cache, store, key, build)
    return cache.read(store, key, build=build, reader=guarded)


def cached_unsigned_read(cache: FoldCache, store, *, seed: Callable[[Any], "tuple[Any, int]"],
                         reader: Callable[[Any], Any], live_window: bool = False) -> Any:
    """As `cached_read`, for a fold that verifies NO owner signature (the agent budget meter): it depends on the
    records and the loaded snapshot only, so the key is the snapshot by value and the build carries no
    resolver. An owner-key-history record still forces a rebuild (harmless: nothing here reads a key).
    `live_window` as in `cached_read`."""
    if not fold_cache_enabled():
        return UNCACHED
    snap = _snapshot(store, live_window)
    if snap is None:
        return UNCACHED

    def build():
        view, since = seed(snap)
        return view, None, since, float("inf")

    def guarded(view):
        return UNCACHED if getattr(view, "poisoned", False) else reader(view)

    _maybe_audit(cache, store, (snap,), build)
    return cache.read(store, (snap,), build=build, reader=guarded)
