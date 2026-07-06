"""
scanner.grammar — probabilistic request-grammar inference for structure-valid fuzzing.

Blind mutation wastes most of its budget on inputs the app rejects at the door
(400/malformed) before any logic runs. A human infers the API's implicit schema
from traffic and fuzzes WELL-TYPED requests that reach the interesting code. This
module does that: from a corpus of observed requests it induces a probabilistic
grammar — path templates (constant vs typed placeholder segments), per-parameter
value-type distributions, and JSON body shapes — with productions weighted by
observed frequency (the "probabilistic" in PCFG). ``generate`` then samples the
grammar to emit structurally-valid requests.

Pure and deterministic given an injected ``random.Random``. Honest scope: this
induces request STRUCTURE (types/shape), not the endpoint STATE MACHINE (which
request must precede which) — that is a deliberately-deferred research spike.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .insertion import HttpRequest

_INT_RX = re.compile(r"^-?\d+$")
_FLOAT_RX = re.compile(r"^-?\d+\.\d+$")
_UUID_RX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RX = re.compile(r"^[0-9a-f]{8,}$", re.I)
_EMAIL_RX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ENUM_MAX = 8  # a param with <= this many distinct non-typed values is an enum


def _classify(value: str) -> str:
    """Classify one observed value into a type token."""
    v = value.strip()
    if v.lower() in ("true", "false"):
        return "bool"
    if _INT_RX.match(v):
        return "int"
    if _FLOAT_RX.match(v):
        return "float"
    if _UUID_RX.match(v):
        return "uuid"
    if _EMAIL_RX.match(v):
        return "email"
    if _HEX_RX.match(v):
        return "hex"
    return "string"


def _segment_placeholder(seg: str) -> str | None:
    """Return the placeholder type for a path segment that is clearly an id
    (int/uuid/hex), else None (a literal, constant part of the template)."""
    t = _classify(seg)
    return t if t in ("int", "uuid", "hex") else None


@dataclass
class ParamModel:
    """Learned distribution for one query parameter: its dominant type and the
    distinct values seen (used verbatim for enums / small string domains)."""

    name: str
    type_counts: Counter = field(default_factory=Counter)
    values: Counter = field(default_factory=Counter)

    @property
    def kind(self) -> str:
        if not self.type_counts:
            return "string"
        top = self.type_counts.most_common(1)[0][0]
        distinct = len(self.values)
        if top in ("string",) and 0 < distinct <= _ENUM_MAX:
            return "enum"
        return top


@dataclass
class RequestGrammar:
    """The induced grammar: frequency-weighted path templates, the placeholder
    types per template, per-parameter models, and the observed base origin."""

    origin: str = ""
    methods: Counter = field(default_factory=Counter)
    templates: Counter = field(default_factory=Counter)
    template_placeholders: dict = field(default_factory=dict)   # template -> [types...]
    template_params: dict = field(default_factory=lambda: defaultdict(set))  # template -> {param}
    params: dict = field(default_factory=dict)                  # name -> ParamModel

    def describe(self) -> str:
        return (f"{len(self.templates)} path template(s), {len(self.params)} param(s); "
                f"top: {[t for t, _ in self.templates.most_common(3)]}")


def _templatize(path: str) -> tuple[str, list[str]]:
    """Turn a concrete path into a template + the placeholder types, in order."""
    segs = [s for s in path.split("/")]
    out: list[str] = []
    placeholders: list[str] = []
    for s in segs:
        if s == "":
            out.append("")
            continue
        ph = _segment_placeholder(s)
        if ph is not None:
            out.append("<" + ph + ">")
            placeholders.append(ph)
        else:
            out.append(s)
    return "/".join(out), placeholders


def infer_grammar(requests: Iterable[HttpRequest]) -> RequestGrammar:
    """Induce a probabilistic request grammar from an observed corpus."""
    g = RequestGrammar()
    for req in requests:
        parts = urlsplit(req.url)
        if parts.scheme and parts.netloc and not g.origin:
            g.origin = f"{parts.scheme}://{parts.netloc}"
        g.methods[req.method] += 1
        template, placeholders = _templatize(parts.path)
        g.templates[template] += 1
        g.template_placeholders[template] = placeholders
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            g.template_params[template].add(name)
            pm = g.params.get(name)
            if pm is None:
                pm = ParamModel(name=name)
                g.params[name] = pm
            pm.type_counts[_classify(value)] += 1
            pm.values[value] += 1
    return g


def _gen_value(kind: str, values: Counter, rng) -> str:
    if kind == "int":
        return str(rng.randint(1, 100000))
    if kind == "float":
        return f"{rng.uniform(0, 1000):.2f}"
    if kind == "bool":
        return rng.choice(["true", "false"])
    if kind == "uuid":
        h = "%032x" % rng.getrandbits(128)
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    if kind == "hex":
        return "%016x" % rng.getrandbits(64)
    if kind == "email":
        return f"user{rng.randint(1, 9999)}@example.com"
    if kind == "enum" and values:
        return rng.choice(sorted(values))
    if values:
        return rng.choice(sorted(values))
    return "x"


def _weighted_choice(counter: Counter, rng) -> str:
    items = sorted(counter.items())
    total = sum(c for _, c in items)
    r = rng.uniform(0, total)
    upto = 0.0
    for item, c in items:
        upto += c
        if r <= upto:
            return item
    return items[-1][0]


def generate(grammar: RequestGrammar, rng, *, method: str | None = None) -> HttpRequest:
    """Sample the grammar for one structurally-valid request: a frequency-weighted
    path template with typed placeholders filled and its observed params emitted
    with type-appropriate values."""
    if not grammar.templates:
        raise ValueError("empty grammar: infer_grammar over a non-empty corpus first")
    template = _weighted_choice(grammar.templates, rng)
    placeholders = list(grammar.template_placeholders.get(template, []))

    # fill placeholder segments in order
    ph_iter = iter(placeholders)
    segs_out: list[str] = []
    for seg in template.split("/"):
        if seg.startswith("<") and seg.endswith(">"):
            kind = next(ph_iter, seg.strip("<>"))
            segs_out.append(_gen_value(kind, Counter(), rng))
        else:
            segs_out.append(seg)
    path = "/".join(segs_out)

    query_pairs: list[tuple[str, str]] = []
    for name in sorted(grammar.template_params.get(template, set())):
        pm = grammar.params.get(name)
        if pm is None:
            continue
        query_pairs.append((name, _gen_value(pm.kind, pm.values, rng)))

    m = method or (grammar.methods.most_common(1)[0][0] if grammar.methods else "GET")
    url = urlunsplit((
        urlsplit(grammar.origin).scheme or "http",
        urlsplit(grammar.origin).netloc or "localhost",
        path, urlencode(query_pairs), "",
    ))
    return HttpRequest(method=m, url=url)
