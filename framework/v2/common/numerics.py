"""
common.numerics — small numeric primitives with an OPT-IN numpy fast path (WS-G).

Every function here has a pure-Python implementation that is the DEFAULT. The
numpy path fires only when acceleration is explicitly opted in
(``CRUCIBLE_FAST_NUMERICS`` + numpy importable — see
``common.capabilities.fast_numerics_enabled``).

Design invariant — **byte-identity**: the accelerated primitives operate on
INTEGERS, so numpy int64 reductions are associativity-exact and produce
bit-for-bit the same result as the pure-Python loop (small integer sums are
exactly representable as float64). The opt-in flag is therefore a *second
belt*, not a correctness crutch: even if the fast path fires it returns the
same value the default path would. This is why an environment that happens to
have numpy installed (the regression-gate env does) stays byte-identical with
the flag unset.

Any exception on the numpy path degrades silently to pure Python — an optional
accelerator must never be able to break a routine that works without it.
"""

from __future__ import annotations

from collections.abc import Sequence

from .capabilities import fast_numerics_enabled


def hashed_bincount(
    indices: Sequence[int], signs: Sequence[int], size: int
) -> list[float]:
    """Scatter-add signed unit weights into ``size`` buckets::

        vec[indices[k]] += signs[k]   for every k

    Returns ``list[float]`` of length ``size``. Pure integer accumulation, so
    the result is independent of summation order — the numpy path is
    byte-identical to the Python loop. This is the hot inner step of the
    feature-hashing lexical embedder (``memory.embed.LexicalEmbedder``): one
    scatter-add per token, run for every recorded engagement text and every
    similarity query.
    """
    if len(indices) != len(signs):
        raise ValueError("indices and signs must be the same length")
    if size <= 0:
        raise ValueError("size must be positive")
    if fast_numerics_enabled():
        try:
            return _hashed_bincount_np(indices, signs, size)
        except Exception:  # noqa: BLE001 - accelerator must never break the routine
            pass
    return _hashed_bincount_py(indices, signs, size)


def _hashed_bincount_py(
    indices: Sequence[int], signs: Sequence[int], size: int
) -> list[float]:
    vec = [0.0] * size
    for i, s in zip(indices, signs):
        vec[i] += s
    return vec


def _hashed_bincount_np(
    indices: Sequence[int], signs: Sequence[int], size: int
) -> list[float]:
    import numpy as np  # local import: never touched on the default path

    acc = np.zeros(size, dtype=np.int64)
    if len(indices):
        idx = np.asarray(indices, dtype=np.int64)
        sgn = np.asarray(signs, dtype=np.int64)
        # scatter-add with duplicate indices accumulated (np.add.at, not
        # fancy-index assignment) — exact integer arithmetic.
        np.add.at(acc, idx, sgn)
    return [float(x) for x in acc.tolist()]


__all__ = ["hashed_bincount"]
