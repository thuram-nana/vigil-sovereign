"""
scanner.sequencer — session-token / nonce randomness analysis.

A session token is only as strong as its unpredictability. Burp's Sequencer
collects many tokens and runs FIPS-style randomness tests; this is the same idea
at the level a scanner can act on autonomously: collect N tokens and detect the
*clear* weaknesses that make a token guessable — it is sequential/incrementing,
it repeats, most of its characters are constant, or it draws on a tiny alphabet —
and report a lower-bound entropy estimate.

This is a deterministic *measurement* over observed bytes (like the passive
checks), not a probabilistic probe, so it carries a verdict rather than an oracle
signal. It is honest about sample size: a "not weak" verdict means no weakness was
found in the sample, not a certificate of cryptographic strength (which, as Burp
notes, needs thousands of samples). Pure stdlib, deterministic.
"""

from __future__ import annotations

import base64
import binascii
import math
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field


class SequencerResult(BaseModel):
    """The randomness verdict for a set of tokens."""

    model_config = ConfigDict(extra="forbid")

    sample_size: int
    unique_ratio: float = Field(ge=0.0, le=1.0)
    charset_size: int
    length: int = Field(description="Common token length, or 0 if they vary.")
    constant_positions: int
    estimated_bits: float = Field(description="Observed lower-bound Shannon entropy across positions.")
    randomness_quality: float = Field(ge=0.0, le=1.0, description="Mean per-position entropy / the sample ceiling.")
    sequential: bool
    weak: bool
    severity: str = Field(description="High if weak, else Info")
    weaknesses: list[str] = Field(default_factory=list)


def collect_tokens(issue: Callable[[], str | None], n: int) -> list[str]:
    """Call ``issue`` up to ``n`` times, collecting the non-empty tokens it
    returns (e.g. a fresh session cookie per login)."""
    tokens: list[str] = []
    for _ in range(n):
        t = issue()
        if t:
            tokens.append(t)
    return tokens


def analyze(tokens: list[str], *, min_bits: float = 64.0) -> SequencerResult:
    """Measure the randomness of ``tokens`` and flag the weaknesses that make a
    session token predictable."""
    n = len(tokens)
    weaknesses: list[str] = []
    if n < 2:
        return SequencerResult(
            sample_size=n, unique_ratio=1.0, charset_size=len(set("".join(tokens))),
            length=len(tokens[0]) if tokens else 0, constant_positions=0,
            estimated_bits=0.0, randomness_quality=0.0, sequential=False,
            weak=False, severity="Info",
            weaknesses=["too few samples to analyze"] if n else ["no tokens"],
        )

    unique = len(set(tokens))
    unique_ratio = unique / n
    if unique < n:
        weaknesses.append(f"duplicate tokens issued ({n - unique} of {n} repeat)")

    charset = sorted(set("".join(tokens)))
    charset_size = len(charset)
    if charset_size <= 4:
        weaknesses.append(f"tiny alphabet ({charset_size} distinct characters)")

    sequential = _is_sequential(tokens)
    if sequential:
        weaknesses.append("tokens are sequential / arithmetically predictable")

    # per-position Shannon entropy (only when tokens share a length)
    lengths = {len(t) for t in tokens}
    length = next(iter(lengths)) if len(lengths) == 1 else 0
    constant_positions = 0
    estimated_bits = 0.0
    quality = 0.0
    if length:
        ceiling = math.log2(n)  # max entropy any single position can show in n samples
        per_pos: list[float] = []
        for i in range(length):
            col = [t[i] for t in tokens]
            h = _shannon(col)
            per_pos.append(h)
            if h == 0.0:
                constant_positions += 1
        estimated_bits = sum(per_pos)
        quality = (sum(min(h, ceiling) for h in per_pos) / (length * ceiling)) if ceiling > 0 else 0.0
        if constant_positions > length / 2:
            weaknesses.append(f"{constant_positions}/{length} character positions are constant")
        if quality < 0.5:
            weaknesses.append(f"low per-position randomness (quality {quality:.2f})")
        if estimated_bits < min_bits and quality >= 0.5:
            # enough sample-limited randomness but the token is simply too short
            weaknesses.append(f"observed entropy ~{estimated_bits:.0f} bits below the {min_bits:.0f}-bit floor")

    weak = bool(sequential or unique < n or charset_size <= 4
                or (length and (constant_positions > length / 2 or quality < 0.5)))
    return SequencerResult(
        sample_size=n, unique_ratio=round(unique_ratio, 3), charset_size=charset_size,
        length=length, constant_positions=constant_positions,
        estimated_bits=round(estimated_bits, 1), randomness_quality=round(quality, 3),
        sequential=sequential, weak=weak, severity="High" if weak else "Info",
        weaknesses=weaknesses,
    )


def _shannon(values: list[str]) -> float:
    n = len(values)
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _try_int(token: str) -> int | None:
    """Interpret a token as an integer via decimal, hex, or base64-big-endian."""
    for base in (10, 16):
        try:
            return int(token, base)
        except ValueError:
            pass
    with _suppress():
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad)
        if raw:
            return int.from_bytes(raw, "big")
    return None


def _is_sequential(tokens: list[str]) -> bool:
    """True if the tokens decode to integers forming an arithmetic progression or
    packed into a tiny range — i.e. an attacker can enumerate them."""
    ints = [_try_int(t) for t in tokens]
    if any(v is None for v in ints):
        return False
    vals = sorted(v for v in ints if v is not None)
    if len(vals) < 2 or vals[-1] == vals[0]:
        return False
    diffs = [b - a for a, b in zip(vals, vals[1:])]
    if len(set(diffs)) == 1:            # perfect arithmetic sequence
        return True
    span = vals[-1] - vals[0]
    return span <= len(vals) * 16       # packed into a tiny, enumerable range


class _suppress:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return isinstance(exc[1], (ValueError, binascii.Error)) if exc[1] else True
