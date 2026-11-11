"""``mine_js`` string-literal scan: linear time, and EXACTLY the literals the legacy pattern found.

The legacy ``_JS_STRING`` pattern let a backslash be read two ways (the head of an escape pair, or a plain
character), so k backslash pairs after an opening quote with no later closing quote were explored 2^k ways:
a crawled page holding ``"`` + ``\\a`` x 40 stalled the campaign's JS-mining step for good. A regex with a
disjoint alternation is linear but finds DIFFERENT literals (the legacy pattern falls back to reading the
backslash as a plain character when no later quote exists), so the scan is a small generator instead and
this file holds it to the legacy pattern, kept here as a literal.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import re
import subprocess
import sys

import pytest

from framework.v2.scanner import discovery

_LEGACY_JS_STRING = re.compile(r"""(['"`])((?:\\.|(?!\1).)*?)\1""", re.S)

_BASE = "https://t.example/"
_TIME_BOUND_S = 2.0
_CHILD_TIMEOUT_S = 30.0

# The adversarial shapes: ``prefix + unit * n + middle + unit2 * n`` for n backslash pairs. Each mines the
# SAME endpoints for every n (checked below on the legacy pattern at small n), so the large-n result is known
# without ever running the legacy pattern on it.
_SHAPES = {
    "unclosed": ('var a="x', "\\a", "", ""),
    "closed_then_backslashes": ('var a="/api/x\\"', "\\a", "", ""),
    "three_quote_types": ("var a='/api/y';\"", "\\a", "`", "\\b"),
}
_CHILD = r"""
import json, sys, time
from framework.v2.scanner.discovery import mine_js
prefix, unit, middle, unit2 = json.loads(sys.argv[1])
src = prefix + unit * 200_000 + middle + unit2 * 200_000
t0 = time.perf_counter()
out = mine_js(src, base_url=sys.argv[2])
print(json.dumps({"elapsed": time.perf_counter() - t0, "endpoints": out.endpoints}))
"""


def _shape(case: str, n: int) -> str:
    prefix, unit, middle, unit2 = _SHAPES[case]
    return prefix + unit * n + middle + unit2 * n


def _legacy(src: str) -> list[tuple[int, int, str, str]]:
    return [(m.start(), m.end(), m.group(1), m.group(2)) for m in _LEGACY_JS_STRING.finditer(src)]


def _new(src: str) -> list[tuple[int, int, str, str]]:
    return list(discovery._js_string_literals(src))


def test_every_short_string_over_the_quote_alphabet_scans_as_the_legacy_pattern_did():
    # Exhaustive: all 335,923 strings of length <= 7 over the characters the pattern distinguishes.
    alphabet = ['"', "'", "`", "\\", "a", "\n"]
    total = found = 0
    for n in range(8):
        for chars in itertools.product(alphabet, repeat=n):
            src = "".join(chars)
            want = _legacy(src)
            assert _new(src) == want, repr(src)
            total += 1
            found += bool(want)
    assert total == 335923 and found > 100000


def test_random_sources_scan_as_the_legacy_pattern_did():
    rng = random.Random(0x15C4)
    alphabet = ['"', '"', "'", "'", "`", "\\", "\\", "\\\\", '\\"', "\\'", "a", "/", "/api/v1", "\n", " ", "${x}",
                "https://h.example/p", "\u00e9", "\\n", "x='", '="']
    literals = 0
    for _ in range(6000):
        src = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
        want = _legacy(src)
        assert _new(src) == want, repr(src)
        literals += len(want)
    # the adversarial shapes at sizes the legacy pattern still finishes on
    for n in range(13):
        for src in ('var a="x' + "\\a" * n, 'var a="/api/x\\"' + "\\a" * n, "'" + "\\'" * n, '"' + "\\" * n,
                    '"' + "\\" * n + '"', "`" + "\\`" * n + "`" + "\\a" * n):
            assert _new(src) == _legacy(src), repr(src)
    assert literals > 3000


def test_realistic_script_yields_the_same_literals_and_endpoints():
    src = r'''
      const base = "https://api.example.com/v2";
      fetch('/api/users?id=' + id, {headers: {"X-Token": `Bearer ${tok}`}});
      var s = 'it\'s', t = "say \"hi\"", u = `multi
      line /not/an/endpoint`;
      axios.post("/api/orders", body); var re = /\/x\//; var w = "C:\\dir\\";
      const tail = 'unterminated \
    '''
    assert _new(src) == _legacy(src)
    got = discovery.mine_js(src, base_url="https://t.example/app/").endpoints
    assert "https://api.example.com/v2" in got and "https://t.example/api/orders" in got


def test_mined_endpoints_are_unchanged_on_a_generated_corpus(monkeypatch):
    rng = random.Random(0xE9D)
    parts = ['"', "'", "`", "\\", "/api/a", "/b/c?d=1", "https://x.example/y", "//cdn.example/z", " ", "\n", "a",
             '\\"', "\\'", "+", "fetch(", ");"]
    corpus = ["".join(rng.choice(parts) for _ in range(rng.randint(0, 12))) for _ in range(3000)]
    got = [discovery._mine_endpoints(src, _BASE) for src in corpus]
    monkeypatch.setattr(discovery, "_js_string_literals", lambda src: iter(_legacy(src)))
    want = [discovery._mine_endpoints(src, _BASE) for src in corpus]
    assert got == want
    assert sum(bool(w) for w in want) > 100


def _legacy_endpoints(monkeypatch, case: str) -> list[str]:
    """What the legacy pattern mines from ``case``: the same for every small n, hence for every n."""
    with monkeypatch.context() as mp:
        # raising=False: this derivation must also run on the pre-fix module (which has no such function and
        # IS the legacy scan), so the time-bound below fails there for the right reason, the timeout.
        mp.setattr(discovery, "_js_string_literals", lambda src: iter(_legacy(src)), raising=False)
        seen = {json.dumps(discovery.mine_js(_shape(case, n), base_url=_BASE).endpoints) for n in range(9)}
    assert len(seen) == 1, (case, seen)
    return json.loads(seen.pop())


@pytest.mark.parametrize("case", ["unclosed", "closed_then_backslashes", "three_quote_types"])
def test_backslash_runs_with_no_closing_quote_are_scanned_at_once(case, monkeypatch):
    # 200,000 backslash pairs after an opening quote: the legacy pattern tried 2^200000 readings. The child
    # interpreter is the point: a regex gone exponential never returns to an in-process assertion.
    expected = _legacy_endpoints(monkeypatch, case)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    try:
        proc = subprocess.run([sys.executable, "-c", _CHILD, json.dumps(_SHAPES[case]), _BASE],
                              capture_output=True, text=True, timeout=_CHILD_TIMEOUT_S, env=env, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"mine_js({case}) did not finish within {_CHILD_TIMEOUT_S:.0f} s: super-linear scan")
    assert proc.returncode == 0, proc.stderr[-2000:]
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert res["endpoints"] == expected
    assert res["elapsed"] < _TIME_BOUND_S, f"mine_js({case}) took {res['elapsed']:.2f} s"
