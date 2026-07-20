"""Merkle accumulator for the cold-archive hard-prune (C2).

Each prune commits, in its owner-signed `kind="snapshot"` record, a `delta_merkle_root` (a binary Merkle
tree over THIS prune's new leaves = the `entry_hash` of every pruned record `[K_prev..K-1]`, in seq order)
and a running `cumulative_merkle_root = H(prior_cumulative ‖ delta)`. The accumulator lets prune #N commit
what the archive holds WITHOUT mounting the offline archive, and lets any verifier handed the archive
re-derive each `delta` from the real archived leaves and re-chain the accumulator to prove the pruned
prefix is exactly what was committed — any single pruned record carries a Merkle inclusion proof.

Design choices that matter for soundness:
- DOMAIN SEPARATION: a leaf is hashed with a `L:` prefix, an interior node with `N:`, so no interior hash
  can be presented as a leaf (a second-preimage class this closes).
- DUP-LAST-ON-ODD (C2): an odd level duplicates its LAST node before pairing. This is the classic CVE-2012-2459
  ambiguity source ONLY when the tree size is not otherwise bound — here the leaf COUNT (`base_count`) is
  committed in the signed head alongside the root, so a re-derivation over a different leaf multiset that
  happens to collide the root is still rejected by the count mismatch. We keep dup-last for simplicity and
  bind the count out-of-band.
- Deterministic + offline: no wallclock, no randomness — a verifier re-runs it byte-identically.
"""
from __future__ import annotations

from ..reuse.canonical import sha256_hex

_LEAF = "L:"   # domain tag for a leaf
_NODE = "N:"   # domain tag for an interior node
_ACC = "C:"    # domain tag for the cumulative accumulator step


def merkle_root(leaves: list[str]) -> str:
    """Binary Merkle root over hex-string `leaves` (the pruned records' `entry_hash`, in seq order). Odd
    levels duplicate the LAST node. Empty leaves -> "" (the no-prune identity). Pure + deterministic."""
    if not leaves:
        return ""
    level = [sha256_hex((_LEAF + leaf).encode("utf-8")) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])                         # dup-last-on-odd
        level = [sha256_hex((_NODE + level[i] + level[i + 1]).encode("utf-8"))
                 for i in range(0, len(level), 2)]
    return level[0]


def chain_cumulative(prior_cumulative: str, delta_root: str) -> str:
    """The running accumulator step: `H(prior ‖ delta)`. `prior_cumulative == ""` for the first prune, so
    the first cumulative is `H("" ‖ delta0)` — distinct from `delta0` itself (domain-tagged), so a verifier
    cannot confuse the first accumulator with a bare delta."""
    return sha256_hex((_ACC + prior_cumulative + "|" + delta_root).encode("utf-8"))
