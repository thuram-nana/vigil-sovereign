"""``mine_js`` JWT scan: linear time, and EXACTLY the spans the pattern's own ``finditer`` gave.

A JWT segment cannot hold a dot, so the pattern's first segment is the whole run of segment characters
after an ``eyJ``; ``finditer`` re-read that run from every ``eyJ`` inside it before failing at the missing
dot, so a crawled bundle of ``eyJa-`` repeated cost n^2. ``_jwt_spans`` measures each run once and is held
here to the pattern's ``finditer`` on an exhaustive small alphabet, a seeded random corpus, real-shaped
tokens and near-misses, and the adversarial shapes at sizes ``finditer`` still finishes on.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import subprocess
import sys

import pytest

from framework.v2.scanner import discovery

_TIME_BOUND_S = 2.0
_CHILD_TIMEOUT_S = 30.0

_CHILD = r"""
import json, sys, time
from framework.v2.scanner.discovery import mine_js
case = sys.argv[1]
if case == "heads_without_dot":
    src = "eyJa-" * 400_000
elif case == "first_dot_no_second":
    src = "eyJa-" * 400_000 + "." + "x"
elif case == "shared_second_segment":
    src = "-eyJ" * 200_000 + "aaaaaa.eyJ" + "b" * 800_000
elif case == "third_without_boundary":
    src = ("eyJ" + "a" * 6 + ".eyJ" + "b" * 6 + "." + "c" * 400_000 + "\u00e9 ") * 3
else:
    raise SystemExit("unknown case " + case)
t0 = time.perf_counter()
out = mine_js(src)
print(json.dumps({"elapsed": time.perf_counter() - t0, "secrets": [s.kind for s in out.secrets]}))
"""


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    return env


def _legacy(src: str) -> list[tuple[int, int]]:
    return [m.span() for m in discovery._JWT.finditer(src)]


def _token(rng: random.Random) -> str:
    seg = lambda: "".join(rng.choice("aZ09_-") for _ in range(rng.randint(5, 12)))  # noqa: E731
    return ("eyJ" + seg() + rng.choice([".", ".", ".", "-"]) + rng.choice(["eyJ", "eyJ", "eyJ", "ey"]) + seg()
            + rng.choice([".", ".", ".", ""]) + seg() + rng.choice(["", "-", "_", "\u00e9", " ", ".", "\u0661"]))


def test_the_pattern_is_unchanged():
    assert discovery._JWT.pattern == r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"
    assert ("jwt", discovery._JWT) in discovery._SECRET_PATTERNS


def test_every_short_string_over_the_pattern_alphabet():
    # 7 tokens around each part's length floor, every string of up to 6 of them (137,257 strings).
    alphabet = ["eyJaaaaa", ".eyJaaaaa", ".aaaaa", "a", "-", ".", "\u00e9"]
    total = found = 0
    for n in range(7):
        for parts in itertools.product(alphabet, repeat=n):
            src = "".join(parts)
            want = _legacy(src)
            assert discovery._jwt_spans(src) == want, repr(src)
            total += 1
            found += bool(want)
    assert total == 137257 and found > 300


def test_random_and_token_shaped_sources():
    rng = random.Random(0x1A7)
    alphabet = ["eyJ", "a", "B", "0", "_", "-", ".", " ", "\u00e9", "\u0661", "\n", "'", "eyJhbGci", "aaaaaa", "x."]
    found = 0
    for _ in range(20000):
        src = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        assert discovery._jwt_spans(src) == _legacy(src), repr(src)
        found += bool(_legacy(src))
    for _ in range(8000):
        src = "".join(_token(rng) + rng.choice(["", " ", ";", "-", "."]) for _ in range(rng.randint(1, 4)))
        want = _legacy(src)
        assert discovery._jwt_spans(src) == want, repr(src)
        found += len(want)
    for n in range(40):                                  # the adversarial shapes at sizes finditer finishes on
        for src in ("eyJa-" * n, "eyJa-" * n + ".x", "eyJaaaaaa." * n, "eyJaaaaaa.eyJ" * n,
                    "eyJ" + "a" * 6 + ".eyJ" + "b" * 6 + "." + "c" * n + "\u00e9", "-eyJ" * n + "aaaaaa.eyJaaaaaa.aaaaaa"):
            assert discovery._jwt_spans(src) == _legacy(src), repr(src)
    assert found > 4000


def test_mined_secrets_are_unchanged(monkeypatch):
    rng = random.Random(0x1A8)
    corpus = ["const t = '" + _token(rng) + "'; const k = 'AKIA" + "A" * 16 + "';" for _ in range(1500)]
    got = [discovery.mine_js(src).secrets for src in corpus]
    monkeypatch.setattr(discovery, "_jwt_spans", _legacy)
    want = [discovery.mine_js(src).secrets for src in corpus]
    assert got == want
    assert sum(any(s.kind == "jwt" for s in w) for w in want) > 300


@pytest.mark.parametrize("case", ["heads_without_dot", "first_dot_no_second", "shared_second_segment",
                                  "third_without_boundary"])
def test_a_bundle_of_near_miss_tokens_is_scanned_at_once(case):
    # `eyJa-` x 400,000: finditer re-read the 2 MB run from each of the 400,000 heads. Child interpreter:
    # a quadratic scan never returns to an in-process assertion.
    try:
        proc = subprocess.run([sys.executable, "-c", _CHILD, case], capture_output=True, text=True,
                              timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"mine_js({case}) did not finish within {_CHILD_TIMEOUT_S:.0f} s: super-linear scan")
    assert proc.returncode == 0, proc.stderr[-2000:]
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert "jwt" not in res["secrets"]
    assert res["elapsed"] < _TIME_BOUND_S, f"mine_js({case}) took {res['elapsed']:.2f} s"


def test_child_harness_refuses_an_unknown_case():
    proc = subprocess.run([sys.executable, "-c", _CHILD, "no-such-case"], capture_output=True, text=True,
                          timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    assert proc.returncode != 0 and "unknown case" in proc.stderr
