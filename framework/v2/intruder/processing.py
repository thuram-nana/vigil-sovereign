"""
intruder.processing — the payload-processing pipeline.

A raw payload is rarely what should hit the wire: a signed field wants
``value + sha256(value)``; a WAF wants a base64/URL layer; a hex sink wants hex; a
noisy set wants a skip rule. Burp Intruder applies an ordered list of processing
rules to each payload before sending. This is that pipeline — a list of pure
``str -> str | None`` rules (``None`` drops the payload), composed by
:class:`PayloadProcessor` and applied lazily over any generator by :func:`processed`.

Because it is just a generator transformer, it composes with every attack type
with no engine change: ``render_attack(t, positions, [processed(gen, proc)], ...)``.
Everything is deterministic — same payload in, same bytes out.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import re
import urllib.parse
from collections.abc import Callable, Iterator

Rule = Callable[[str], "str | None"]


# ---------------------------------------------------------------------------
# rule constructors (each returns a str -> str|None)
# ---------------------------------------------------------------------------


def add_prefix(prefix: str) -> Rule:
    return lambda s: prefix + s


def add_suffix(suffix: str) -> Rule:
    return lambda s: s + suffix


def match_replace(pattern: str, repl: str) -> Rule:
    rx = re.compile(pattern)
    return lambda s: rx.sub(repl, s)


def substring(start: int, length: int | None = None) -> Rule:
    return lambda s: s[start: (start + length) if length is not None else None]


def to_case(mode: str) -> Rule:
    fns = {"lower": str.lower, "upper": str.upper, "title": str.title}
    if mode not in fns:
        raise ValueError("mode must be lower/upper/title")
    fn = fns[mode]
    return lambda s: fn(s)


def url_encode(safe: str = "") -> Rule:
    return lambda s: urllib.parse.quote(s, safe=safe)


def url_encode_all() -> Rule:
    """Percent-encode every byte (aggressive WAF-bypass encoding)."""
    return lambda s: "".join(f"%{b:02X}" for b in s.encode("utf-8"))


def base64_encode() -> Rule:
    return lambda s: base64.b64encode(s.encode("utf-8")).decode("ascii")


def hex_encode() -> Rule:
    return lambda s: binascii.hexlify(s.encode("utf-8")).decode("ascii")


def html_encode() -> Rule:
    return lambda s: html.escape(s)


def hash_with(algorithm: str) -> Rule:
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"unknown hash algorithm {algorithm!r}")
    return lambda s: hashlib.new(algorithm, s.encode("utf-8")).hexdigest()


def add_raw(sep: str = "") -> Rule:
    """Append the (already-processed) value with a copy of itself — used to send
    ``value`` alongside a derived form. On its own it just doubles; chain it after
    a hash to send ``value + hash`` style pairs by composing two processors."""
    return lambda s: s + sep + s


def skip_if(pattern: str) -> Rule:
    """Drop (yield nothing for) a payload matching ``pattern``."""
    rx = re.compile(pattern)
    return lambda s: None if rx.search(s) else s


def skip_unless(pattern: str) -> Rule:
    rx = re.compile(pattern)
    return lambda s: s if rx.search(s) else None


# ---------------------------------------------------------------------------
# processor
# ---------------------------------------------------------------------------


class PayloadProcessor:
    """An ordered pipeline of rules. ``process`` returns the transformed payload,
    or None if any rule dropped it."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def process(self, payload: str) -> str | None:
        s: str | None = payload
        for rule in self.rules:
            s = rule(s)  # type: ignore[arg-type]
            if s is None:
                return None
        return s


def processed(generator: "Iterator[str]", processor: PayloadProcessor) -> Iterator[str]:
    """Apply ``processor`` to each payload, skipping any it drops. Lazy."""
    for payload in generator:
        out = processor.process(payload)
        if out is not None:
            yield out
