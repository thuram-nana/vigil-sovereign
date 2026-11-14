"""SCHOLAR's HTML strip runs in linear time and gives EXACTLY the text the legacy substitutions gave.

``_strip_html`` reads third-party pages (up to the fetch cap). Two of its substitutions re-scanned to the
end of the page from every opener that could not finish: ``<(script|style)[^>]*>.*?</\\1>`` from every
``<script>`` with no closer after it, and ``<[^>]+>`` from every ``<`` with no ``>`` after it — quadratic
on a page of either repeated. ``_strip_scripts`` and ``_strip_tags`` are held here to the legacy patterns
(kept as literals) on an exhaustive small alphabet, a seeded random corpus with the case-folding letters
the backreference treats specially, and the adversarial shapes at sizes the legacy patterns still finish on;
the time bounds run in a child interpreter.
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

from sigil.agents import sources

_LEGACY_TAG = re.compile(r"<[^>]+>")
_LEGACY_WS = re.compile(r"\s+")
_LEGACY_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)

_TIME_BOUND_S = 2.0
_CHILD_TIMEOUT_S = 30.0

_CHILD = r"""
import json, sys, time
from sigil.agents.sources import _strip_html
case = sys.argv[1]
if case == "openers":
    html = "<script>" * 250_000
elif case == "heads_without_gt":
    html = "<script" * 280_000
elif case == "lt_only":
    html = "<" * 2_000_000
elif case == "both_names":
    html = "<style><script>" * 140_000 + "</scripts>"
elif case == "heads_then_one_gt":
    html = "<script<style" * 150_000 + ">"
else:
    raise SystemExit("unknown case " + case)
t0 = time.perf_counter()
out = _strip_html(html)
print(json.dumps({"elapsed": time.perf_counter() - t0, "out_len": len(out)}))
"""


@pytest.fixture(autouse=True)
def _scan_and_pattern_agree():
    """Every opener the scan removes is a real match of _SCRIPT (the pattern's ``.sub`` is the fallback)."""
    sources._STRIP_SCAN_MISSES[0] = 0
    yield
    assert sources._STRIP_SCAN_MISSES[0] == 0, "the scan named an opener _SCRIPT does not match"


def _legacy_strip_html(html: str) -> str:
    return _LEGACY_WS.sub(" ", _LEGACY_TAG.sub(" ", _LEGACY_SCRIPT.sub(" ", html))).strip()


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    return env


def test_the_patterns_are_unchanged():
    assert (sources._SCRIPT.pattern, sources._SCRIPT.flags) == (_LEGACY_SCRIPT.pattern, _LEGACY_SCRIPT.flags)
    assert sources._TAG.pattern == _LEGACY_TAG.pattern and sources._WS.pattern == _LEGACY_WS.pattern


def test_every_short_page_over_the_markup_alphabet():
    # 9 tokens, every page of up to 5 of them (66,430 pages).
    alphabet = ["<script>", "</script>", "<STYLE x>", "</style>", "<script", "<", ">", "a", "</SCRIPT>"]
    total = changed = 0
    for n in range(6):
        for parts in itertools.product(alphabet, repeat=n):
            html = "".join(parts)
            assert sources._strip_scripts(html) == _LEGACY_SCRIPT.sub(" ", html), repr(html)
            assert sources._strip_tags(html) == _LEGACY_TAG.sub(" ", html), repr(html)
            want = _legacy_strip_html(html)
            assert sources._strip_html(html) == want, repr(html)
            total += 1
            changed += _LEGACY_SCRIPT.sub(" ", html) != html
    assert total == 66430 and changed > 5000


def test_random_pages_with_case_folded_names():
    """The backreference compares names by simple lowercase, while the name itself matches case-folded
    letters (long s, dotted/dotless i): a closer must repeat the opener's name in THAT sense."""
    rng = random.Random(0x5C1)
    alphabet = ["<script>", "</script>", "<style>", "</style>", "<SCRIPT>", "</ScRiPt>", "<ſcript>",
                "</ſcript>", "</script >", "<scrİpt>", "</scrIpt>", "</scrİpt>", "<scrıpt>",
                "</scrıpt>", "<script", "<style a=1>", ">", "<", "a", " ", "\n", "<b>", "</p>", "</", "x",
                "<styKe>", "</style>", "é", "\t", "<scripts>", "</scripts>"]
    changed = 0
    for _ in range(60000):
        html = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14)))
        want = _LEGACY_SCRIPT.sub(" ", html)
        assert sources._strip_scripts(html) == want, repr(html)
        assert sources._strip_html(html) == _legacy_strip_html(html), repr(html)
        changed += want != html
    for n in range(40):                                      # the adversarial shapes at legacy-finishable sizes
        for html in ("<script>" * n, "<script" * n, "<" * n, "<style><script>" * n + "</scripts>",
                     "<script<style" * n + ">", "<script>" * n + "</script>", "<" * n + ">" + "<" * n,
                     "<style>x</style>" * n + "<script>"):
            assert sources._strip_html(html) == _legacy_strip_html(html), repr(html)
    assert changed > 15000


def test_real_pages_are_unchanged():
    page = ("<html><head><style>body{color:red}</style><script type='x'>var a = '<b>';</script></head>"
            "<body><h1>Title</h1><p>Some   text\n here</p><SCRIPT>x()</SCRIPT></body></html>")
    assert sources._strip_html(page) == _legacy_strip_html(page) == "Title Some text here"


@pytest.mark.parametrize("case", ["openers", "heads_without_gt", "lt_only", "both_names", "heads_then_one_gt"])
def test_two_megabytes_of_unclosed_markup_are_stripped_at_once(case):
    try:
        proc = subprocess.run([sys.executable, "-c", _CHILD, case], capture_output=True, text=True,
                              timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"_strip_html({case}) did not finish within {_CHILD_TIMEOUT_S:.0f} s: super-linear strip")
    assert proc.returncode == 0, proc.stderr[-2000:]
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert res["elapsed"] < _TIME_BOUND_S, f"_strip_html({case}) took {res['elapsed']:.2f} s"


def test_child_harness_refuses_an_unknown_case():
    proc = subprocess.run([sys.executable, "-c", _CHILD, "no-such-case"], capture_output=True, text=True,
                          timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    assert proc.returncode != 0 and "unknown case" in proc.stderr
