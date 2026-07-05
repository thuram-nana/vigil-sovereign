"""
Sequencer — session-token randomness analysis. Weak token sets (sequential,
duplicate, mostly-constant, tiny alphabet, too-short) are flagged; a
high-entropy set is not. Deterministic (a seeded PRNG stands in for a CSPRNG).
"""

from __future__ import annotations

import random

from framework.v2.scanner.sequencer import analyze, collect_tokens


def _strong(n: int = 40, length: int = 32) -> list[str]:
    r = random.Random(1234)
    hexch = "0123456789abcdef"
    return ["".join(r.choice(hexch) for _ in range(length)) for _ in range(n)]


def test_sequential_tokens_are_weak() -> None:
    res = analyze([str(1000 + i) for i in range(30)])
    assert res.weak and res.sequential
    assert any("sequential" in w for w in res.weaknesses)
    assert res.severity == "High"


def test_duplicate_tokens_are_weak() -> None:
    toks = _strong(20)
    toks[5] = toks[0]  # a repeat
    res = analyze(toks)
    assert res.weak and res.unique_ratio < 1.0
    assert any("duplicate" in w for w in res.weaknesses)


def test_mostly_constant_tokens_are_weak() -> None:
    r = random.Random(7)
    toks = ["SESSION-" + "".join(r.choice("0123456789abcdef") for _ in range(2)) for _ in range(30)]
    res = analyze(toks)
    assert res.weak and res.constant_positions >= 6
    assert any("constant" in w for w in res.weaknesses)


def test_tiny_alphabet_is_weak() -> None:
    r = random.Random(3)
    toks = ["".join(r.choice("01") for _ in range(20)) for _ in range(30)]
    res = analyze(toks)
    assert res.weak and res.charset_size <= 4


def test_high_entropy_tokens_are_not_weak() -> None:
    res = analyze(_strong())
    assert not res.weak, f"strong tokens flagged weak: {res.weaknesses}"
    assert not res.sequential
    assert res.estimated_bits > 64.0
    assert res.randomness_quality >= 0.5
    assert res.severity == "Info"


def test_collect_tokens_gathers_nonempty() -> None:
    seq = iter(["a", "", "b", None, "c"])
    got = collect_tokens(lambda: next(seq, None), 5)
    assert got == ["a", "b", "c"]
