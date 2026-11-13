"""Four oracle regexes that were super-linear on attacker-shaped input, and their copies in the standalone
``docs/proof-carrying-finding/verify_vf.py``, now run in linear time and decide EXACTLY what they did.

Each fix carries two kinds of test, run against BOTH modules:

* a DIFFERENTIAL test that keeps the legacy pattern as a literal here and compares old vs new on a
  deterministic corpus (seeded ``random.Random`` plus the adversarial shapes at sizes the legacy pattern
  still finishes on): the rewrite must not move a single verdict; and
* a TIME-BOUND test on an input the legacy pattern needs minutes, hours or forever for. It runs in a child
  interpreter, because a regex that has gone super-linear never returns to an in-process assertion; the
  legacy pattern is never run on that input.

The four defects:

  ``_ZONE_RR_HEADER_RE``  nested ``(?:\\d+[smhdw]?)+``: exponential in a digit run (target-published TXT text)
  ``_SFX_TAG_RE.sub``     every ``<`` rescanned to the end of a body with no later ``>``: quadratic
  ``_TXT_STRING_RE``      a string that cannot match retried from every escaped quote inside it: quadratic
  ``_SQL_TAUT_RE``        adjacent ``\\s*\\(?\\s*`` split a whitespace run n ways: quadratic (AEGIS inline path)
"""
from __future__ import annotations

import importlib.util
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

from framework.v2.verify import oracles

_REPO = Path(__file__).resolve().parents[6]
_VERIFY_VF = _REPO / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _load_vf():
    spec = importlib.util.spec_from_file_location("redos_verify_vf", _VERIFY_VF)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod             # registered before exec (dataclass annotation resolution)
    spec.loader.exec_module(mod)
    return mod


_MODULES = {"oracles": oracles, "verify_vf": _load_vf()}
_BOTH = pytest.mark.parametrize("which", sorted(_MODULES))

# ------------------------------------------------------------------------------------------------------
# The LEGACY patterns, verbatim. They are the specification the rewrites are held to.
# ------------------------------------------------------------------------------------------------------
_LEGACY_ZONE_RR_HEADER_RE = re.compile(r"(?i)^[^\s\"=]+(?:\s+(?:(?:\d+[smhdw]?)+|IN|CH|CS|HS))*\s+TXT$")
_LEGACY_SFX_TAG_RE = re.compile(r"<[^>]+>")
_LEGACY_TXT_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_LEGACY_SQL_TAUT_RE = re.compile(
    r"""(?i)^(OR|AND|XOR)\b\s*\(?\s*['"]?([A-Za-z0-9_]+)['"]?\s*(?:=|<=>|\bLIKE\b)\s*['"]?([A-Za-z0-9_]+)['"]?""")

_TIME_BOUND_S = 2.0          # the call itself, measured inside the child
_CHILD_TIMEOUT_S = 30.0      # the child as a whole (interpreter start + import + the call)

_CHILD = r"""
import importlib.util, json, sys, time
which, case = sys.argv[1], sys.argv[2]
if which == "verify_vf":
    spec = importlib.util.spec_from_file_location("redos_child_vf", sys.argv[3])
    m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m; spec.loader.exec_module(m)
else:
    from framework.v2.verify import oracles as m
if case == "zone":
    arg = "a " + "0" * 5000 + '! "v=DMARC1; p=none"'
    fn = m._resolve_txt_record
elif case == "sfx":
    arg = "<" * 2_000_000
    fn = lambda body: m._sfx_substantive_body(200, body)
elif case == "txt":
    arg = '"' + '\\"!' * 300_000 + '\\\n"'
    fn = m._txt_records
elif case == "txt_unclosed":
    arg = '"' + '\\"!' * 300_000
    fn = m._resolve_txt_record
elif case == "sql":
    arg = "'OR" + " " * 1_000_000
    fn = lambda payload: m.sql_injection_breakout_oracle(payload).fired
else:
    raise SystemExit("unknown case " + case)
t0 = time.perf_counter()
out = fn(arg)
print(json.dumps({"elapsed": time.perf_counter() - t0, "out": out}))
"""


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    return env


def _timed_child(which: str, case: str) -> dict:
    """Run one adversarial case in a child interpreter; a child that does not come back is the defect."""
    try:
        proc = subprocess.run([sys.executable, "-c", _CHILD, which, case, str(_VERIFY_VF)],
                              capture_output=True, text=True, timeout=_CHILD_TIMEOUT_S, env=_child_env(),
                              check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{which}:{case} did not finish within {_CHILD_TIMEOUT_S:.0f} s: super-linear regex")
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _assert_fast(which: str, case: str, expected_out) -> None:
    res = _timed_child(which, case)
    assert res["out"] == expected_out
    assert res["elapsed"] < _TIME_BOUND_S, f"{which}:{case} took {res['elapsed']:.2f} s"


def _rand_text(rng: random.Random, alphabet: list[str], max_len: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_len)))


def test_child_harness_refuses_an_unknown_case():
    """The time-bound tests are only as good as the child: an unknown case must fail, not pass silently."""
    proc = subprocess.run([sys.executable, "-c", _CHILD, "oracles", "no-such-case", str(_VERIFY_VF)],
                          capture_output=True, text=True, timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    assert proc.returncode != 0


# ------------------------------------------------------------------------------------------------------
# 0. the standalone verifier carries the SAME patterns (the fixes land in lockstep)
# ------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["_ZONE_RR_HEADER_RE", "_SFX_TAG_RE", "_TXT_STRING_BODY_RE", "_SQL_TAUT_RE"])
def test_standalone_verifier_carries_the_same_pattern(name):
    a, b = getattr(oracles, name), getattr(_MODULES["verify_vf"], name)
    assert (a.pattern, a.flags) == (b.pattern, b.flags)


# ------------------------------------------------------------------------------------------------------
# 1. _ZONE_RR_HEADER_RE: exponential
# ------------------------------------------------------------------------------------------------------
_ZONE_ALPHABET = ["0", "1", "7", "s", "m", "H", "D", "w", "x", " ", " ", "\t", "IN", "CH", "TXT", " TXT", "_dmarc.",
                  "example.", "=", '"', "!", "١", "ſ", " ", "\n", "-", "3600", "1h30m"]


def _zone_corpus() -> list[str]:
    rng = random.Random(0x20A1)
    corpus = [_rand_text(rng, _ZONE_ALPHABET, 9) for _ in range(4000)]
    # headers that DO match, with every TTL shape the token admits, then near-misses of each
    ttls = ["3600", "1h", "1H30M", "1h30m15", "0", "1w2d3h4m5s", "12", "5s", "IN", "CH", "CS", "HS", "in", ""]
    for _ in range(2000):
        toks = [rng.choice(ttls) for _ in range(rng.randint(0, 4))]
        head = " ".join(["_dmarc.example."] + [t for t in toks if t] + ["TXT"])
        corpus.append(head)
        corpus.append(head.replace("TXT", rng.choice(["TXT!", "TX", "txt", " TXT ", "A"])))
        corpus.append(head.replace("h", rng.choice(["hh", "hm", "x", "h ", ""]), 1))
    # the adversarial shapes, at sizes the legacy pattern still finishes on
    corpus += ["a " + "0" * n + "!" for n in range(15)]
    corpus += ["a " + "1h" * n + "!" for n in range(9)]
    corpus += ["a " + "0" * n + " TXT" for n in range(15)]
    corpus += ["a " + "0" * n + "hh TXT" for n in range(15)]
    return corpus


@_BOTH
def test_zone_header_matches_exactly_what_the_legacy_pattern_did(which):
    new = _MODULES[which]._ZONE_RR_HEADER_RE
    assert new.pattern != _LEGACY_ZONE_RR_HEADER_RE.pattern, "the ambiguous TTL token is back"
    assert new.flags == _LEGACY_ZONE_RR_HEADER_RE.flags
    matched = 0
    for head in _zone_corpus():
        old_m, new_m = _LEGACY_ZONE_RR_HEADER_RE.match(head), new.match(head)
        assert (old_m is None) == (new_m is None), repr(head)
        if old_m is not None and new_m is not None:
            matched += 1
            assert old_m.span() == new_m.span(), repr(head)
    assert matched > 500          # the corpus really exercises the accepting side


@_BOTH
def test_zone_header_near_miss_with_a_long_ttl_returns_at_once(which):
    # 5000 digits ahead of a `!`: the legacy token split the run 2^4999 ways before refusing.
    _assert_fast(which, "zone", None)


# ------------------------------------------------------------------------------------------------------
# 2. _SFX_TAG_RE.sub: quadratic
# ------------------------------------------------------------------------------------------------------
_SFX_ALPHABET = ["<", "<", ">", ">", "a", " ", "\n", "<b>", "</p>", "<!--", "error", "<<", ">>", "\x00", "é"]


@_BOTH
def test_tag_strip_is_byte_identical_to_the_legacy_substitution(which):
    strip = _MODULES[which]._sfx_strip_tags
    rng = random.Random(0x5F7A)
    corpus = [_rand_text(rng, _SFX_ALPHABET, 14) for _ in range(6000)]
    corpus += ["<" * n for n in range(40)]
    corpus += ["<" * n + ">" + "<" * n for n in range(40)]
    corpus += ["<a>" * n + "<" * n for n in range(40)]
    corpus += ["", ">", "<>", "<a", "a>", "<a><", "x<y>z<", "<html><body>Welcome back, alice</body></html>"]
    changed = 0
    for body in corpus:
        want = _LEGACY_SFX_TAG_RE.sub(" ", body)
        assert strip(body) == want, repr(body)
        changed += want != body
    assert changed > 1000


@_BOTH
def test_substantive_body_verdict_is_unchanged_on_real_pages(which):
    sub = _MODULES[which]._sfx_substantive_body
    assert sub(200, "<html><body><h1>Account</h1><p>Welcome back, alice: balance 12.50</p></body></html>") is True
    assert sub(200, "<html><body>Internal Server Error</body></html>") is False
    assert sub(200, "<p>Forbidden</p><p>you may not view this page at all</p>") is False
    assert sub(403, "<html><body><h1>Account</h1><p>Welcome back, alice</p></body></html>") is False


@_BOTH
def test_two_megabytes_of_unclosed_tags_are_stripped_at_once(which):
    # 2 MB of `<` and no `>`: the legacy substitution rescanned to the end from every `<` (~35 min).
    _assert_fast(which, "sfx", True)


# ------------------------------------------------------------------------------------------------------
# 3. _TXT_STRING_RE: quadratic
# ------------------------------------------------------------------------------------------------------
def _legacy_resolve_txt_record(mod, line: str) -> str | None:
    """``_resolve_txt_record`` as it was, on the legacy ``finditer``."""
    if '"' not in line:
        bare = line.strip()
        return None if "\\" in bare else bare
    spans = list(_LEGACY_TXT_STRING_RE.finditer(line))
    if not spans:
        return None
    head = line[: spans[0].start()].strip()
    if head and not _LEGACY_ZONE_RR_HEADER_RE.match(head):
        return None
    prev = spans[0].end()
    for span in spans[1:]:
        if line[prev : span.start()].strip():
            return None
        prev = span.end()
    if line[prev:].strip():
        return None
    return "".join(mod._decode_txt_escapes(span.group(1)) for span in spans).strip()


_TXT_ALPHABET = ['"', '"', '"', "\\", "\\", "\n", " ", "a", "=", ";", '\\"', "\\\n", "\\\\", "\\065", "(", ")", "\r",
                 "v=DMARC1; p=none", '"v=spf1 -all"', "_dmarc.example. 3600 IN TXT ", "!", "\t"]


def _txt_corpus() -> list[str]:
    rng = random.Random(0x7C7)
    corpus = [_rand_text(rng, _TXT_ALPHABET, 10) for _ in range(8000)]
    corpus += ['"' + '\\"!' * n + '\\\n"' for n in range(30)]          # the adversarial shape
    corpus += ['"' + '\\"!' * n for n in range(30)]                     # ... never closed
    corpus += ['"' + '\\"!' * n + '"' for n in range(30)]               # ... closed cleanly
    corpus += ['"a" "b\\\n" "c"', '"a\\\nb"', '"a" "b', '"a\\', '"\\', '"', '""', '"a" x "b"', 'x "a"',
               '_dmarc.example. 1h IN TXT "v=DMARC1;" " p=reject"', '"v=DMARC1; p=none" "\\\n"']
    return corpus


@_BOTH
def test_record_resolution_is_identical_to_the_legacy_scan(which):
    mod = _MODULES[which]
    resolved = refused = 0
    for line in _txt_corpus():
        want = _legacy_resolve_txt_record(mod, line)
        assert mod._resolve_txt_record(line) == want, repr(line)
        resolved += want is not None
        refused += want is None
    assert resolved > 1000 and refused > 1000


@_BOTH
def test_string_spans_equal_the_legacy_matches_wherever_a_line_is_not_refused(which):
    mod = _MODULES[which]
    seen = with_backslash_lf = 0
    for line in _txt_corpus():
        got = mod._txt_string_spans(line)
        legacy = [(m.start(), m.end(), m.group(1)) for m in _LEGACY_TXT_STRING_RE.finditer(line)]
        if got is None:
            # refused: some quote starts no legacy match, so it sits outside every legacy span
            covered: set[int] = set()
            for start, end, _content in legacy:
                covered.update(range(start, end))
            assert any(c == '"' and i not in covered for i, c in enumerate(line)), repr(line)
            with_backslash_lf += "\\\n" in line
        else:
            assert got == legacy, repr(line)
            seen += bool(got)
    assert seen > 1000 and with_backslash_lf > 100


@_BOTH
def test_txt_records_are_identical_through_the_tokenizer(which, monkeypatch):
    """End to end: the blob -> records split feeds only tokenizer-balanced lines to the resolver."""
    mod = _MODULES[which]
    corpus = _txt_corpus()
    got = [mod._txt_records(blob) for blob in corpus]
    monkeypatch.setattr(mod, "_resolve_txt_record", lambda line: _legacy_resolve_txt_record(mod, line))
    want = [mod._txt_records(blob) for blob in corpus]
    assert got == want
    assert sum(r is not None and r != [] for r in want) > 500


@_BOTH
def test_a_string_with_backslash_newline_no_longer_rescans_from_every_quote(which):
    # `"` + `\"!` x 300000 + backslash, LF, `"`: balanced for the tokenizer, unmatchable for the legacy
    # pattern, which then retried from each of the 300000 escaped quotes (hours).
    _assert_fast(which, "txt", None)


@_BOTH
def test_a_string_that_never_closes_is_refused_at_once(which):
    _assert_fast(which, "txt_unclosed", None)


# ------------------------------------------------------------------------------------------------------
# 4. _SQL_TAUT_RE: quadratic
# ------------------------------------------------------------------------------------------------------
_SQL_TOKENS = ["OR", "or", "AND", "XOR", "Or", " ", " ", "  ", "\t", "\n", "(", "(", ")", "'", '"', "1", "1", "a",
               "A", "x_1", "=", "=", "<=>", "LIKE", " like ", "==", "<=", " ", " ", "ORDER", "é", "0"]


def _sql_corpus() -> list[str]:
    rng = random.Random(0x5A1)
    corpus = [_rand_text(rng, _SQL_TOKENS, 9) for _ in range(6000)]
    ops = ["OR", "and", "XoR"]
    for _ in range(3000):                      # well-formed tautologies and near-misses of them
        a = rng.choice(["1", "a", "'a'", '"x"', "'1", "x_1"])
        b = rng.choice([a, "2", "'b'", a.upper()])
        corpus.append(rng.choice(ops) + rng.choice([" ", "", "  ", " (", "( ", " ( ", "((", " \t(\n"])
                      + a + rng.choice(["=", " = ", "<=>", " LIKE ", " like", "LIKE", "==", " "]) + b
                      + rng.choice(["", ")", " --", "'"]))
    corpus += ["OR" + " " * n for n in range(40)]                       # the adversarial shape
    corpus += ["OR" + " " * n + "(" + " " * n for n in range(40)]
    corpus += ["OR" + " " * n + "1=1" for n in range(40)]
    corpus += ["OR" + " " * n + "(" + " " * n + "1=1" for n in range(40)]
    return corpus


@_BOTH
def test_sql_tautology_span_and_groups_are_identical_to_the_legacy_pattern(which):
    new = _MODULES[which]._SQL_TAUT_RE
    assert new.pattern != _LEGACY_SQL_TAUT_RE.pattern, "the adjacent optional whitespace is back"
    assert new.groups == _LEGACY_SQL_TAUT_RE.groups == 3
    matched = 0
    for s in _sql_corpus():
        old_m, new_m = _LEGACY_SQL_TAUT_RE.match(s), new.match(s)
        assert (old_m is None) == (new_m is None), repr(s)
        if old_m is not None and new_m is not None:
            matched += 1
            assert (old_m.span(), old_m.groups()) == (new_m.span(), new_m.groups()), repr(s)
    assert matched > 1000


@_BOTH
def test_sql_structure_verdict_is_unchanged(which):
    structure = _MODULES[which]._sql_structure_at_start
    assert structure(" OR 1=1 --") == "OR tautology (1=1)"
    assert structure(" or ( 'a' = 'a'") == "OR tautology (a=a)"
    assert structure("OR" + " " * 64 + "(" + " " * 64 + "7 LIKE 7") == "OR tautology (7=7)"
    assert structure("AND(x LIKE X)") == "AND tautology (x=X)"
    assert structure(" OR 1=2") == ""
    assert structure("t drop the ball") == ""


@_BOTH
def test_a_megabyte_of_whitespace_after_the_operator_is_refused_at_once(which):
    # `'OR` + 1,000,000 spaces through the SQLi oracle: the two adjacent `\s*` split the run a million ways.
    _assert_fast(which, "sql", False)
