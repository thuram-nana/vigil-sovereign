"""Front C S0 — the ONE read path from an owner-signed registry onto the verified fold cache.

Every owner-signed registry fold depends on the same inputs beyond the spine records themselves: the TRUSTED
owner pubkey it verifies under, the GENESIS pin the owner-key succession is walked from once a rotation exists,
and the loaded SNAPSHOT — bound BY VALUE: its boundary moves the live window and its rows ARE the seed, so a
different seed under the same boundary also rebuilds (1.8 us to compare the empty no-prune identity; O(seed)
when a prune exists, the same order as `SnapshotState.load` itself). `cached_read` binds exactly
those into the cache key, builds the per-entry owner-key resolver with its scan horizon, and asks the registry
only for its seed — so no registry can forget one of them (`spine/fold_cache.py` holds the trust model).

`UNCACHED` means "no cached answer": the flag is off, or the registry's view declared it cannot answer
(`view.poisoned`). The caller then runs its unchanged full fold.

FATAL-2: sovereign-side. No framework/strix import.
"""
from __future__ import annotations

from typing import Any, Callable

from ..config import fold_cache_enabled
from ..reuse import assert_no_offense
from ..spine.fold_cache import FoldCache
from ..spine.snapshot import SnapshotState
from . import key_history as _kh
from .identity import genesis_owner_pubkey

assert_no_offense()

__all__ = ["UNCACHED", "cached_read"]

UNCACHED = object()


def cached_read(cache: FoldCache, store, *, trusted_pubkey, seed: Callable[[Any], "tuple[Any, int]"],
                reader: Callable[[Any], Any]) -> Any:
    """`reader(view)` over `cache`'s verified fold of `store`, or `UNCACHED`.

    `seed(snap) -> (view, since_seq)` builds the registry's fresh starting view from the loaded snapshot (its
    hard-prune seed, or the empty genesis start under the pubkey bypass) and the seq the full fold starts after
    — the same starting point its uncached fold uses. `SnapshotState.load` raises exactly as the full fold
    would on an unverifiable prune head."""
    if not fold_cache_enabled():
        return UNCACHED
    snap = SnapshotState.load(store)
    key = (trusted_pubkey, genesis_owner_pubkey(), snap)

    def build():
        resolver, horizon = _kh.key_resolver_with_horizon(store, current=trusted_pubkey)
        view, since = seed(snap)
        return view, resolver, since, horizon

    def guarded(view):
        return UNCACHED if getattr(view, "poisoned", False) else reader(view)

    return cache.read(store, key, build=build, reader=guarded)
