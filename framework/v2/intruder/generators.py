"""
intruder.generators — the payload-set vocabulary.

Each generator streams payload strings lazily and deterministically (no clock, no
randomness), so a 10k-payload attack costs no memory up front and replays
identically. This mirrors Burp Intruder's payload types; each one drives a
different attack:

  * ``simple_list``   — a fixed set (wordlists, known values)
  * ``from_iterable`` — stream from any iterable / file lines
  * ``numbers``       — sequential ids (enumeration, IDOR sweeps)
  * ``brute_force``   — every string over a charset in a length range
  * ``null_payloads`` — N copies of one value, unchanged (race / once-token)
  * ``case_variations`` / ``char_case`` — case mutations (filter/WAF bypass)
  * ``char_blocks``   — growing blocks of a char (length/buffer probing)
  * ``bit_flipper``   — flip each bit of a base value (padding/HMAC/CBC probes)
  * ``dates``         — a date range in a format
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Iterator


def simple_list(items: Iterable[object]) -> Iterator[str]:
    """Yield each item as a string, in order."""
    for it in items:
        yield str(it)


def from_iterable(lines: Iterable[str]) -> Iterator[str]:
    """Stream payloads from any iterable of strings (e.g. an open file), one per
    line, stripped of a trailing newline. Never loads it all into memory."""
    for line in lines:
        yield line.rstrip("\n")


def numbers(start: int, stop: int, step: int = 1) -> Iterator[str]:
    """Sequential integers ``start`` (inclusive) → ``stop`` (exclusive)."""
    if step == 0:
        raise ValueError("step must be non-zero")
    for n in range(start, stop, step):
        yield str(n)


def brute_force(charset: str, min_len: int, max_len: int) -> Iterator[str]:
    """Every string over ``charset`` from ``min_len`` to ``max_len`` inclusive,
    shortest-first, in charset order. Deterministic and lazy — but note the count
    is |charset|^len, so bound the lengths."""
    if min_len < 0 or max_len < min_len:
        raise ValueError("require 0 <= min_len <= max_len")
    if not charset:
        raise ValueError("charset must be non-empty")
    for length in range(min_len, max_len + 1):
        if length == 0:
            yield ""
            continue
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def null_payloads(base: str, count: int) -> Iterator[str]:
    """``count`` copies of ``base`` unchanged — the same request repeated. Drives
    once-only-token / rate-limit / race probing (with the single-value positions
    held constant, N identical requests are fired)."""
    if count < 0:
        raise ValueError("count must be >= 0")
    for _ in range(count):
        yield base


def case_variations(base: str) -> Iterator[str]:
    """lower / UPPER / Title / original, de-duplicated, stable order."""
    seen: set[str] = set()
    for v in (base.lower(), base.upper(), base.title(), base):
        if v not in seen:
            seen.add(v)
            yield v


def char_blocks(char: str, min_len: int, max_len: int, step: int = 1) -> Iterator[str]:
    """Growing blocks of ``char``: len ``min_len``..``max_len`` by ``step`` —
    length/buffer/limit probing."""
    if len(char) != 1:
        raise ValueError("char must be a single character")
    for length in range(min_len, max_len + 1, step):
        yield char * length


def bit_flipper(base: str) -> Iterator[str]:
    """Flip each bit of ``base`` (UTF-8 bytes) in turn, yielding one mutated
    value per bit — CBC/padding-oracle, token-structure and HMAC probing. The
    original is not yielded; only the single-bit mutations."""
    data = bytearray(base.encode("utf-8"))
    for i in range(len(data)):
        for bit in range(8):
            mutated = bytearray(data)
            mutated[i] ^= 1 << bit
            yield mutated.decode("utf-8", errors="surrogatepass") if _decodable(mutated) \
                else mutated.hex()


def _decodable(data: bytearray) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def dates(start_ordinal: int, count: int, fmt: str = "%Y-%m-%d", step_days: int = 1) -> Iterator[str]:
    """A date range from a proleptic-Gregorian ordinal (``date.toordinal()``),
    ``count`` dates apart by ``step_days``, formatted with ``fmt``. Ordinals keep
    it wallclock-free and deterministic."""
    import datetime

    for i in range(count):
        d = datetime.date.fromordinal(start_ordinal + i * step_days)
        yield d.strftime(fmt)
