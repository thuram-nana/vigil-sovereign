"""Tests for safe_parse — the resource-governed parse helpers every posture parser is meant to route through.

The contract: neither helper raises on caller input; a completed in-budget parse is ``ok``, a provably
out-of-bounds or malformed document is ``error``, and an environmental inability to parse (no PyYAML) is
``inconclusive`` — never a silent success and never a CLEAN. These tests attack the byte cap, depth, node
count, alias/anchor bombs, unsafe tags, and malformed input from both the false-success and crash directions.
"""
from __future__ import annotations

import json

import pytest

from vigil_integration.live.safe_parse import (
    ParseBudget,
    ParseResult,
    safe_json,
    safe_yaml,
)

try:
    import yaml as _yaml  # noqa: F401

    _HAVE_YAML = True
except Exception:  # noqa: BLE001
    _HAVE_YAML = False


# --------------------------------------------------------------------------- budget construction

def test_budget_rejects_nonpositive():
    for bad in ({"max_bytes": 0}, {"max_depth": -1}, {"max_nodes": 0}, {"max_aliases": 0}):
        with pytest.raises(ValueError):
            ParseBudget(**bad)


def test_budget_rejects_bool():
    # bool is an int subclass; a budget of True must not be silently accepted.
    with pytest.raises(ValueError):
        ParseBudget(max_bytes=True)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- happy paths

def test_json_happy():
    r = safe_json('{"a": 1, "b": [1, 2, 3], "c": {"d": true}}')
    assert isinstance(r, ParseResult)
    assert r.ok and r.outcome == "ok"
    assert r.value == {"a": 1, "b": [1, 2, 3], "c": {"d": True}}
    assert r.reason == ""


def test_json_accepts_bytes():
    r = safe_json(b'{"x": 42}')
    assert r.ok and r.value == {"x": 42}


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_happy():
    r = safe_yaml("a: 1\nb:\n  - x\n  - y\nc:\n  d: true\n")
    assert r.ok and r.outcome == "ok"
    assert r.value == {"a": 1, "b": ["x", "y"], "c": {"d": True}}


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_benign_alias_ok():
    # A small, benign anchor/alias is legitimate YAML and must parse within budget.
    doc = "base: &b {k: 1}\nuse: *b\n"
    r = safe_yaml(doc)
    assert r.ok
    assert r.value == {"base": {"k": 1}, "use": {"k": 1}}


# --------------------------------------------------------------------------- oversize (rejected BEFORE parse)

def test_json_oversize_rejected():
    payload = json.dumps({"k": "v" * 1000})
    r = safe_json(payload, ParseBudget(max_bytes=50))
    assert not r.ok and r.outcome == "error" and r.reason == "oversize"


def test_oversize_measured_before_parse_even_when_malformed():
    # Garbage bytes over the cap must be refused as oversize, proving the size gate runs before json.loads.
    r = safe_json(b"\xff" * 500 + b"not json", ParseBudget(max_bytes=100))
    assert not r.ok and r.reason == "oversize"


def test_oversize_counts_utf8_bytes_not_chars():
    # A short string of multibyte chars exceeds a byte budget its char count would pass.
    s = '"' + ("一" * 40) + '"'  # 42 chars, but 3 bytes each for the CJK run -> ~122 bytes
    r = safe_json(s, ParseBudget(max_bytes=60))
    assert not r.ok and r.reason == "oversize"


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_oversize_rejected():
    r = safe_yaml("k: " + "v" * 1000, ParseBudget(max_bytes=50))
    assert not r.ok and r.reason == "oversize"


# --------------------------------------------------------------------------- depth / recursion

def test_json_too_deep_by_walk():
    # A structure that parses fine but exceeds our depth bound -> typed error, not a crash.
    depth = 30
    doc = "[" * depth + "]" * depth
    r = safe_json(doc, ParseBudget(max_depth=5, max_bytes=10_000))
    assert not r.ok and r.outcome == "error" and r.reason == "too_deep"


def test_json_pathologically_deep_does_not_crash():
    # Very deep nesting may overflow the C scanner (RecursionError) — must be caught as too_deep, never raise.
    doc = "[" * 20000 + "]" * 20000
    r = safe_json(doc, ParseBudget(max_bytes=10_000_000))
    assert not r.ok and r.outcome == "error" and r.reason == "too_deep"


# --------------------------------------------------------------------------- node count

def test_json_too_many_nodes():
    doc = json.dumps(list(range(500)))
    r = safe_json(doc, ParseBudget(max_nodes=50, max_bytes=100_000))
    assert not r.ok and r.reason == "too_many_nodes"


# --------------------------------------------------------------------------- alias / anchor bomb

@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_billion_laughs_is_error():
    # Classic exponential alias expansion. Either the alias-count cap or the node-count walk must reject it;
    # in no case may it succeed or hang.
    bomb = """
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
"""
    r = safe_yaml(bomb, ParseBudget(max_nodes=10_000, max_aliases=1000, max_bytes=100_000))
    assert not r.ok and r.outcome == "error"
    assert r.reason in ("too_many_nodes", "alias_bomb")


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_alias_cap_trips():
    doc = "a: &a 1\nb: [" + ",".join(["*a"] * 20) + "]\n"
    r = safe_yaml(doc, ParseBudget(max_aliases=5, max_bytes=100_000))
    assert not r.ok and r.reason == "alias_bomb"


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_recursive_anchor_cycle_detected():
    # A self-referential structure would loop a naive walk; must be reported, not hung.
    doc = "a: &a [*a]\n"
    r = safe_yaml(doc, ParseBudget(max_nodes=100_000, max_bytes=100_000))
    assert not r.ok and r.outcome == "error"
    assert r.reason in ("cycle", "too_many_nodes")


# --------------------------------------------------------------------------- unsafe tags refused

@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_python_object_tag_refused():
    doc = "!!python/object/apply:os.system ['echo pwned']\n"
    r = safe_yaml(doc)
    assert not r.ok and r.outcome == "error" and r.reason == "unsafe_tag"


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_python_name_tag_refused():
    doc = "x: !!python/name:os.system\n"
    r = safe_yaml(doc)
    assert not r.ok and r.reason == "unsafe_tag"


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_unknown_custom_tag_refused():
    doc = "x: !SomeCustomTag {a: 1}\n"
    r = safe_yaml(doc)
    assert not r.ok and r.outcome == "error" and r.reason == "unsafe_tag"


# --------------------------------------------------------------------------- malformed

def test_json_malformed():
    r = safe_json("{not valid json,,,}")
    assert not r.ok and r.outcome == "error" and r.reason == "malformed"


def test_json_malformed_bad_bytes():
    r = safe_json(b"\xff\xfe\x00bad")
    assert not r.ok and r.outcome == "error" and r.reason == "malformed"


@pytest.mark.skipif(not _HAVE_YAML, reason="PyYAML not installed")
def test_yaml_malformed():
    r = safe_yaml("a: [1, 2\n  - broken: : :\n")
    assert not r.ok and r.outcome == "error" and r.reason == "malformed"


# --------------------------------------------------------------------------- never raises

@pytest.mark.parametrize(
    "bad",
    ["", "   ", "\x00\x01\x02", "[", "{", '{"a":', "￿", b"\x80\x81"],
)
def test_helpers_never_raise(bad):
    rj = safe_json(bad)
    assert isinstance(rj, ParseResult) and rj.outcome in ("ok", "error", "inconclusive")
    if _HAVE_YAML:
        ry = safe_yaml(bad)
        assert isinstance(ry, ParseResult) and ry.outcome in ("ok", "error", "inconclusive")


def test_default_budget_used_when_none():
    r = safe_json('{"ok": 1}', None)
    assert r.ok
