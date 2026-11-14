"""The console's context masker: the URL-userinfo password and JWT masks run in linear time and give EXACTLY
the text the patterns' own ``.sub`` gave.

Both patterns are made of classes that exclude the character that must follow them, so every part of a
match is a whole run of its class; ``.sub`` re-read a long run from every position in it before failing,
so ``a`` or ``eyJa-`` repeated through an uploaded file cost n^2. The linear scans are held here to the
patterns (kept as literals) on an exhaustive small alphabet, a seeded random corpus, URL- and token-shaped
text, and the adversarial shapes at sizes ``.sub`` still finishes on; the time bounds run in a child
interpreter.
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

from framework.v2.console import actions

_LEGACY_URL_PASSWORD_RE = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^/@\s:]+):[^/@\s]+@")
_LEGACY_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}")
_URL_REPL = r"\1:" + actions.MASK + "@"

_TIME_BOUND_S = 2.0
_CHILD_TIMEOUT_S = 30.0

_CHILD = r"""
import json, sys, time
from framework.v2.console import actions
case = sys.argv[1]
if case == "letters":
    text = "a" * 1_000_000 + "://x"
elif case == "schemes":
    text = "a://b:" * 160_000
elif case == "jwt_heads":
    text = "eyJa-" * 200_000
elif case == "jwt_first_dot":
    text = "eyJa-" * 200_000 + ".x"
elif case == "jwt_shared_second":
    text = "-eyJ" * 200_000 + "aaaaaa." + "b" * 800_000
else:
    raise SystemExit("unknown case " + case)
t0 = time.perf_counter()
out = actions._redact_context_text(text)
print(json.dumps({"elapsed": time.perf_counter() - t0, "unchanged": out == text}))
"""


@pytest.fixture(autouse=True)
def _scans_and_patterns_agree():
    """Every start a scan names is a real match of its pattern (the pattern's ``.sub`` is the fallback)."""
    actions._CTX_SCAN_MISSES[0] = 0
    yield
    assert actions._CTX_SCAN_MISSES[0] == 0, "a scan named a start where its pattern does not match"


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    return env


def test_the_patterns_and_their_order_are_unchanged():
    assert actions._URL_USERINFO_PASSWORD_RE.pattern == _LEGACY_URL_PASSWORD_RE.pattern
    assert actions._URL_USERINFO_PASSWORD_RE.flags == _LEGACY_URL_PASSWORD_RE.flags
    assert actions._CTX_JWT_RE.pattern == _LEGACY_JWT_RE.pattern
    rxs = [rx for rx, _repl in actions._CTX_SECRET_SUBS]
    assert (actions._URL_USERINFO_PASSWORD_RE, _URL_REPL) in actions._CTX_SECRET_SUBS
    assert (actions._CTX_JWT_RE, actions.MASK) in actions._CTX_SECRET_SUBS
    assert set(actions._CTX_LINEAR_SUBS) == {actions._URL_USERINFO_PASSWORD_RE, actions._CTX_JWT_RE}
    assert all(rx in rxs for rx in actions._CTX_LINEAR_SUBS)


def test_url_password_every_short_string():
    # 10 tokens, every string of up to 5 of them (111,111 strings), the case-folded scheme letters included.
    alphabet = ["a", "a://", "u:", "p@", ":", "@", "/", " ", "\u017f", "1"]
    total = changed = 0
    for n in range(6):
        for parts in itertools.product(alphabet, repeat=n):
            text = "".join(parts)
            want = _LEGACY_URL_PASSWORD_RE.sub(_URL_REPL, text)
            assert actions._sub_url_userinfo_password(text, _URL_REPL) == want, repr(text)
            total += 1
            changed += want != text
    assert total == 111111 and changed > 500


def test_url_password_random_and_url_shaped_text():
    rng = random.Random(0x0517)
    alphabet = ["a", "B", "1", "+", ".", "-", ":", "/", "//", "://", "@", " ", "\n", "\t", "x:y@", "https://", "u",
                "\u212a", "\u017f", "\u0130", "\u00e9", "\u3000", "_", "%40", "?q=1", "#f"]
    changed = 0
    for _ in range(40000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 20)))
        want = _LEGACY_URL_PASSWORD_RE.sub(_URL_REPL, text)
        assert actions._sub_url_userinfo_password(text, _URL_REPL) == want, repr(text)
        changed += want != text
    for n in range(60):                                  # the adversarial shapes at sizes .sub finishes on
        for text in ("a" * n, "a" * n + "://x", "a://b:" * n, "1a" * n + "://u:p@h", "a:" * n + "//u:p@h",
                     "x://" + "u" * n + ":" + "p" * n, "a://u:" + ":" * n + "@"):
            assert actions._sub_url_userinfo_password(text, _URL_REPL) == \
                _LEGACY_URL_PASSWORD_RE.sub(_URL_REPL, text), repr(text)
    assert changed > 1000


def test_ctx_jwt_every_short_string():
    alphabet = ["eyJaaaaa", ".aaaaa", "a", "-", ".", "\u00e9", " "]
    total = changed = 0
    for n in range(7):
        for parts in itertools.product(alphabet, repeat=n):
            text = "".join(parts)
            want = _LEGACY_JWT_RE.sub(actions.MASK, text)
            assert actions._sub_ctx_jwt(text, actions.MASK) == want, repr(text)
            total += 1
            changed += want != text
    assert total == 137257 and changed > 150


def test_ctx_jwt_random_and_token_shaped_text():
    rng = random.Random(0x0518)
    seg = lambda: "".join(rng.choice("aZ09_-") for _ in range(rng.randint(3, 10)))  # noqa: E731
    changed = 0
    for _ in range(20000):
        text = "".join(rng.choice(["", " ", "x", "-", "."]) + "eyJ" + seg() + rng.choice([".", ".", "-"]) + seg()
                       + rng.choice([".", ".", ""]) + seg() for _ in range(rng.randint(1, 3)))
        want = _LEGACY_JWT_RE.sub(actions.MASK, text)
        assert actions._sub_ctx_jwt(text, actions.MASK) == want, repr(text)
        changed += want != text
    for n in range(40):
        for text in ("eyJa-" * n, "eyJa-" * n + ".x", "eyJaaaaaa." * n, "-eyJ" * n + "aaaaaa.aaaaaa.aaaa"):
            assert actions._sub_ctx_jwt(text, actions.MASK) == _LEGACY_JWT_RE.sub(actions.MASK, text), repr(text)
    assert changed > 5000


def test_redacted_context_is_unchanged(monkeypatch):
    """End to end through every mask, in order: only the two substitutions changed."""
    rng = random.Random(0x0519)
    parts = ["Authorization: Bearer abcdef123456", "postgres://admin:hunter2@db:5432/x", "token=abc", "eyJhbGciOi."
             "eyJzdWIiOi.c2lnbmF0dXJl", "see https://user:pw@host/p", " ", "\n", "a" * 30, "x://u:p@", "AKIA" + "A" * 16]
    corpus = ["".join(rng.choice(parts) for _ in range(rng.randint(0, 8))) for _ in range(3000)]
    got = [actions._redact_context_text(text) for text in corpus]
    monkeypatch.setattr(actions, "_CTX_LINEAR_SUBS", {})
    want = [actions._redact_context_text(text) for text in corpus]
    assert got == want
    assert sum(w != c for w, c in zip(want, corpus)) > 2000


@pytest.mark.parametrize("case", ["letters", "schemes", "jwt_heads", "jwt_first_dot", "jwt_shared_second"])
def test_a_megabyte_of_near_misses_is_masked_at_once(case):
    try:
        proc = subprocess.run([sys.executable, "-c", _CHILD, case], capture_output=True, text=True,
                              timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"_redact_context_text({case}) did not finish within {_CHILD_TIMEOUT_S:.0f} s")
    assert proc.returncode == 0, proc.stderr[-2000:]
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert res["unchanged"] is True
    assert res["elapsed"] < _TIME_BOUND_S, f"_redact_context_text({case}) took {res['elapsed']:.2f} s"


def test_child_harness_refuses_an_unknown_case():
    proc = subprocess.run([sys.executable, "-c", _CHILD, "no-such-case"], capture_output=True, text=True,
                          timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    assert proc.returncode != 0 and "unknown case" in proc.stderr
