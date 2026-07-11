"""Tests for common.numerics — opt-in numpy fast path, byte-identical (WS-G).

Contract: the DEFAULT (flag off) is the pure-Python loop; the opt-in numpy path
returns bit-for-bit the same list[float]. Because the accumulation is integer,
byte-identity is guaranteed, not merely approximate.
"""

from __future__ import annotations

import pytest

from framework.v2.common import capabilities as cap
from framework.v2.common import numerics


def test_default_matches_pure_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRUCIBLE_FAST_NUMERICS", raising=False)
    idx = [0, 3, 3, 1, 7, 3, 0]
    sgn = [1, -1, 1, 1, -1, 1, 1]
    assert numerics.hashed_bincount(idx, sgn, 8) == numerics._hashed_bincount_py(idx, sgn, 8)


def test_scatter_add_semantics() -> None:
    # bucket 3 gets -1+1+1 = 1; bucket 0 gets 1+1 = 2; bucket 7 gets -1
    out = numerics._hashed_bincount_py([0, 3, 3, 3, 0, 7], [1, -1, 1, 1, 1, -1], 8)
    assert out == [2.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, -1.0]


def test_empty_input_is_zero_vector() -> None:
    assert numerics.hashed_bincount([], [], 4) == [0.0, 0.0, 0.0, 0.0]


def test_length_mismatch_raises() -> None:
    with pytest.raises(ValueError):
        numerics.hashed_bincount([0, 1], [1], 4)


def test_bad_size_raises() -> None:
    with pytest.raises(ValueError):
        numerics.hashed_bincount([0], [1], 0)


@pytest.mark.skipif(not cap.has_numpy(), reason="numpy not installed — fast path unexercised")
def test_numpy_path_byte_identical_to_python() -> None:
    import random

    rng = random.Random(1234)
    size = 256
    for _ in range(50):
        n = rng.randint(0, 40)
        idx = [rng.randrange(size) for _ in range(n)]
        sgn = [rng.choice((-1, 1)) for _ in range(n)]
        py = numerics._hashed_bincount_py(idx, sgn, size)
        np_ = numerics._hashed_bincount_np(idx, sgn, size)
        assert py == np_, f"byte-identity broke on idx={idx} sgn={sgn}"


@pytest.mark.skipif(not cap.has_numpy(), reason="numpy not installed — fast path unexercised")
def test_opt_in_flag_routes_to_numpy_but_same_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_FAST_NUMERICS", "1")
    assert cap.fast_numerics_enabled() is True
    idx = [0, 5, 5, 250, 5]
    sgn = [1, 1, -1, 1, 1]
    assert numerics.hashed_bincount(idx, sgn, 256) == numerics._hashed_bincount_py(idx, sgn, 256)


def test_numpy_hiccup_degrades_to_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the numpy path raises for any reason, the routine still returns the
    correct pure-Python result (accelerator must never break the routine)."""
    monkeypatch.setenv("CRUCIBLE_FAST_NUMERICS", "1")
    monkeypatch.setattr(cap, "has_numpy", lambda: True)  # force the gate open

    def _boom(*_a: object, **_k: object) -> list[float]:
        raise RuntimeError("simulated numpy failure")

    monkeypatch.setattr(numerics, "_hashed_bincount_np", _boom)
    idx, sgn = [0, 1, 1], [1, 1, 1]
    assert numerics.hashed_bincount(idx, sgn, 4) == [1.0, 2.0, 0.0, 0.0]
