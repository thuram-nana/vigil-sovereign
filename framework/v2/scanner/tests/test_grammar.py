"""
Wave 11 — probabilistic request-grammar inference.

From a corpus of observed requests the scanner induces path templates, per-param
value types, and frequency-weighted productions, then generates structurally-valid
requests. Generated inputs satisfy the API's implicit schema at a materially
higher rate than blind mutation — reaching logic instead of bouncing off a 400.
"""

from __future__ import annotations

import random
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.grammar import generate, infer_grammar
from framework.v2.scanner.insertion import HttpRequest

_BASE = "http://api.test"

# a corpus: GET /api/users/<int>?page=<int>&sort=<enum: name|date>
_CORPUS = [
    HttpRequest(method="GET", url=f"{_BASE}/api/users/{i}?page={p}&sort={s}")
    for i, p, s in [
        (1, 1, "name"), (2, 1, "date"), (42, 2, "name"), (7, 3, "date"),
        (99, 1, "name"), (13, 2, "date"), (256, 4, "name"), (5, 1, "date"),
    ]
]


def _is_schema_valid(req: HttpRequest) -> bool:
    """The API's implicit schema: /api/users/<int>, page is an int, sort in
    {name, date}."""
    parts = urlsplit(req.url)
    segs = parts.path.strip("/").split("/")
    if len(segs) != 3 or segs[0] != "api" or segs[1] != "users" or not segs[2].isdigit():
        return False
    q = parse_qs(parts.query)
    if "page" in q and not q["page"][0].isdigit():
        return False
    if "sort" in q and q["sort"][0] not in ("name", "date"):
        return False
    return True


def test_grammar_reproduces_the_observed_shape() -> None:
    g = infer_grammar(_CORPUS)
    assert "/api/users/<int>" in g.templates
    assert g.params["page"].kind == "int"
    assert g.params["sort"].kind == "enum"
    assert set(g.params["sort"].values) == {"name", "date"}


def test_generated_requests_are_schema_valid() -> None:
    g = infer_grammar(_CORPUS)
    rng = random.Random(0)
    gen = [generate(g, rng) for _ in range(50)]
    assert all(_is_schema_valid(r) for r in gen), \
        [r.url for r in gen if not _is_schema_valid(r)][:3]


def test_grammar_beats_blind_mutation_on_reaching_logic() -> None:
    g = infer_grammar(_CORPUS)
    rng = random.Random(1)

    grammar_valid = sum(_is_schema_valid(generate(g, rng)) for _ in range(100))

    # blind mutation baseline: random single-character edits of a seed URL
    seed = f"{_BASE}/api/users/1?page=1&sort=name"
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789/?=&"
    blind_valid = 0
    for _ in range(100):
        chars = list(seed)
        for _ in range(rng.randint(1, 4)):
            j = rng.randrange(len(chars))
            chars[j] = rng.choice(alphabet)
        try:
            if _is_schema_valid(HttpRequest(method="GET", url="".join(chars))):
                blind_valid += 1
        except Exception:
            pass

    assert grammar_valid == 100                       # grammar is always well-typed
    assert grammar_valid > blind_valid + 30           # materially better than blind
