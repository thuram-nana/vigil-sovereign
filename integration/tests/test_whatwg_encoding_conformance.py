"""W16-STD-1 criterion (c): WHATWG encoding determination is a FIXED label table — NOT a regex — pinned by a
conformance corpus.

A body-dependent predicate (meta-refresh, host-header reflected into markup, any markup scan) is only sound
over the document the target really served, which means resolving the Content-Type charset LABEL the way a
browser does: through the WHATWG Encoding Standard's 'get an encoding' table. Resolving through Python's codec
registry instead — the pre-existing defect — decoded labels a browser REJECTS (utf-7, EBCDIC) and REMAPPED
others differently (iso-8859-1 -> windows-1252, bare utf-16 -> host byte order), each a false-FACT or
false-CLEAN surface.

The determination itself (body_decode._whatwg_codec + _LABEL_TO_CODEC) is already a fixed table, not a regex.
What this file adds is the CONFORMANCE CORPUS that pins it to the spec and makes any drift falsifiable:
docs/capability-matrix/whatwg-encoding-conformance.json is an INDEPENDENT restatement of the WHATWG table
(authored from the spec, not from the code), and this test asserts the implementation conforms to every row —
including the byte-level decode remaps that matter for markup, and the labels that MUST be refused.

Framework-free (pure vigil_integration.live.body_decode + stdlib), so it runs in the required P5 sovereign leg
with no ci.yml offense-leg entry.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_integration.live.body_decode import _whatwg_codec, decode_body

_CORPUS = (Path(__file__).resolve().parents[2]
           / "docs" / "capability-matrix" / "whatwg-encoding-conformance.json")


def _corpus() -> dict:
    return json.loads(_CORPUS.read_text(encoding="utf-8"))


def _resolution() -> list[dict]:
    return _corpus()["resolution"]


def _vectors() -> list[dict]:
    return _corpus()["decode_vectors"]


# ---------------------------------------------------------------------------------------------------
# 1. Label resolution conforms to the spec table for every corpus row.
# ---------------------------------------------------------------------------------------------------
def test_every_corpus_label_resolves_exactly_as_the_spec_prescribes():
    """The load-bearing check: _whatwg_codec maps each label to the (codec, status) the WHATWG table says.
    Data-driven, so a single map regression (an added label, a wrong remap, a codec that stopped being
    byte-faithful) turns this red without any code change to the test."""
    mismatches = []
    for e in _resolution():
        codec, status = _whatwg_codec(e["label"])
        if codec != e["codec"] or status != e["status"]:
            mismatches.append(f"{e['label']!r}: got ({codec!r},{status!r}) want ({e['codec']!r},{e['status']!r})")
    assert not mismatches, "WHATWG label resolution drifted from the corpus:\n  " + "\n  ".join(mismatches)


def test_label_resolution_is_case_and_surrounding_whitespace_insensitive():
    """WHATWG lower-cases and strips ASCII whitespace before the table lookup. A corpus 'ok' row must resolve
    identically when shouted or padded — otherwise a real 'Charset=UTF-8 ' header would be misjudged."""
    ok = next(e for e in _resolution() if e["status"] == "ok")
    for variant in (ok["label"].upper(), f"  {ok['label']}\t", f"\n{ok['label']} "):
        codec, status = _whatwg_codec(variant)
        assert (codec, status) == (ok["codec"], "ok"), f"{variant!r} did not resolve like {ok['label']!r}"


# ---------------------------------------------------------------------------------------------------
# 2. The byte-level decode remaps a browser performs are reproduced faithfully.
# ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("vec", _vectors(), ids=lambda v: v["label"])
def test_decode_vectors_produce_the_characters_a_browser_would(vec):
    """Resolving the label is necessary but not sufficient: the CODEC must decode the same CHARACTERS a
    browser does. Each vector carries bytes that decode differently under the naive codec than under the
    WHATWG-faithful one (latin1 0x93 is a curly quote, not a C1 control; bare utf-16 is LE, not host order),
    so a wrong codec choice would produce the wrong text and fail here."""
    raw = bytes.fromhex(vec["bytes_hex"])
    d = decode_body(raw, [("content-type", f"text/html; charset={vec['label']}")])
    assert d.body_semantically_available, f"{vec['label']}: faithful bytes were marked unavailable ({d.reason})"
    assert d.charset == vec["codec"], f"{vec['label']}: resolved to {d.charset}, expected {vec['codec']}"
    assert vec["expect_text"] in d.text, (
        f"{vec['label']}: decoded {d.text!r}, expected to contain {vec['expect_text']!r} — {vec['why']}")


# ---------------------------------------------------------------------------------------------------
# 3. NEGATIVE CONTROLS — the refused labels are actually refused, and the corpus is non-vacuous.
# ---------------------------------------------------------------------------------------------------
def test_every_non_ok_label_is_refused_by_the_decoder_not_silently_decoded():
    """A label the table does not accept ('unsupported' WHATWG CJK/replacement, or an 'unknown' non-WHATWG
    label) must leave the body UNAVAILABLE, so a body-dependent negative over it is INCONCLUSIVE, never a
    CLEAN over bytes a browser would not read the same way. This is the direction that guards false-CLEAN and
    false-FACT alike."""
    leaked = []
    ascii_markup = b'<meta http-equiv="refresh" content="0;url=//evil.example/">'
    for e in _resolution():
        if e["status"] == "ok":
            continue
        d = decode_body(ascii_markup, [("content-type", f"text/html; charset={e['label']}")])
        if d.body_semantically_available:
            leaked.append(e["label"])
    assert not leaked, f"labels VIGIL must refuse were decoded and marked available: {leaked}"


def test_the_corpus_exercises_all_three_resolution_outcomes():
    """Non-vacuity: the corpus is only a real conformance test if it covers acceptance AND both refusal
    reasons. A corpus of only 'ok' rows would pass a decoder that accepts everything."""
    statuses = {e["status"] for e in _resolution()}
    assert statuses == {"ok", "unsupported", "unknown"}, (
        f"the corpus must exercise every resolution outcome; got {sorted(statuses)}")
    for status in ("ok", "unsupported", "unknown"):
        assert sum(1 for e in _resolution() if e["status"] == status) >= 3, (
            f"too few {status!r} rows to be a meaningful control")


def test_the_corpus_proves_whatwg_semantics_not_a_naive_codec_lookup():
    """The corpus must witness the SPECIFIC ways WHATWG differs from Python's codec registry — otherwise a
    trivial `codecs.lookup(label)` implementation would satisfy it. Two witnesses the pre-existing defect
    tripped on: iso-8859-1/latin1 must resolve to windows-1252 (Python decodes it as real iso-8859-1), and
    utf-7 must be REFUSED (Python decodes it, turning `+ADw-` into a live `<` a browser never renders)."""
    for latin in ("iso-8859-1", "latin1"):
        row = next((e for e in _resolution() if e["label"] == latin), None)
        assert row is not None and row["codec"] == "cp1252" and row["status"] == "ok", (
            f"{latin} must resolve to windows-1252 (cp1252), not real iso-8859-1")
    utf7 = next((e for e in _resolution() if e["label"] == "utf-7"), None)
    assert utf7 is not None and utf7["status"] != "ok" and utf7["codec"] is None, (
        "utf-7 must be refused — it is not a WHATWG encoding, and Python's codec would decode a false sink")
    # and the refusal is real at the decoder, over the exact BLOCK-1 false-FACT bytes
    d = decode_body(b"+ADw-meta http-equiv=refresh content=0;url=//evil.example/+AD4-",
                    [("content-type", "text/html; charset=utf-7")])
    assert not d.body_semantically_available and "evil.example" not in d.text, (
        "utf-7 bytes decoded into a live meta sink — the WHATWG determination was bypassed")


def test_the_conformance_check_is_load_bearing():
    """Mutation control: a corpus row with a deliberately WRONG expectation MUST be caught by the same
    comparison the real test uses, proving test #1 is not a no-op that would pass on any implementation."""
    poisoned = dict(next(e for e in _resolution() if e["status"] == "ok"))
    poisoned["codec"] = "utf-7"  # a codec the WHATWG map will never return
    codec, status = _whatwg_codec(poisoned["label"])
    assert not (codec == poisoned["codec"] and status == poisoned["status"]), (
        "a poisoned expectation was not distinguishable from a real one — the conformance check is vacuous")
