"""Tests for body_decode — the load-bearing decode step for every body-dependent web predicate.

The contract, after an adversarial review found several false-CLEAN paths: ``body_semantically_available`` is
True ONLY when the COMPLETE served document was recovered under a DETERMINISTICALLY-determined charset. Every
heuristic or host-dependent path (undeclared charset, NUL-recovery, br/zstd) must yield unavailable
(INCONCLUSIVE), never CLEAN/FACT. These tests attack malformed/truncated/concatenated streams, conflicting
HTTP/meta charsets, and host-dependent decoders in BOTH the false-FACT and false-CLEAN directions.
"""
from __future__ import annotations

import zlib

import pytest

from vigil_integration.live.body_decode import (
    MAX_DECODED_BYTES,
    MAX_EXPANSION_RATIO,
    MAX_RAW_BYTES,
    decode_body,
)

# ASCII markup with a redirect sink — valid under every ASCII-superset charset.
HTML = (b'<html><head><meta http-equiv="refresh" content="0;url=//evil.example/">'
        b"</head><body>hi</body></html>")
UTF8 = [("content-type", "text/html; charset=utf-8")]


def _gzip(b: bytes) -> bytes:
    obj = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    return obj.compress(b) + obj.flush()


def _zlib_deflate(b: bytes) -> bytes:
    return zlib.compress(b, 9)


def _raw_deflate(b: bytes) -> bytes:
    obj = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return obj.compress(b) + obj.flush()


# ---- happy paths: the COMPLETE document is faithfully recovered under a DECLARED charset ----

@pytest.mark.parametrize("enc,comp", [
    ("gzip", _gzip),
    ("deflate", _zlib_deflate),
    ("deflate", _raw_deflate),   # some servers send RAW deflate with no zlib header
    ("identity", lambda b: b),
    ("", lambda b: b),
])
def test_declared_charset_roundtrip_is_available(enc, comp):
    d = decode_body(comp(HTML), [("content-encoding", enc), *UTF8])
    assert d.decoded is True and d.body_semantically_available is True
    assert "evil.example" in d.text
    assert d.reason == "" and d.raw_sha256 and d.raw_len == len(comp(HTML))


def test_json_defaults_to_utf8_per_rfc8259():
    d = decode_body(b'{"redirect":"//evil/"}', [("content-type", "application/json")])
    assert d.body_semantically_available is True and d.charset_source == "json-default"
    assert "evil" in d.text


# ---- completeness: truncated / concatenated streams are NEVER available (false-CLEAN class) ----

@pytest.mark.parametrize("enc,comp,label", [
    ("gzip", _gzip, "gzip"),
    ("deflate", _zlib_deflate, "deflate"),
    ("deflate", _raw_deflate, "raw deflate"),
])
def test_truncated_compressed_stream_is_refused_via_eof(enc, comp, label):
    """A gzip/deflate stream with its tail removed decompresses with an EMPTY unconsumed_tail; only obj.eof
    tells complete from truncated. Without it a prefix of the document reads as the whole thing and a
    body-dependent negative over the prefix is a false CLEAN."""
    full = comp(HTML)
    d = decode_body(full[:-4], [("content-encoding", enc), *UTF8])
    assert d.body_semantically_available is False, f"{label}: truncated stream marked available"
    assert "truncated" in d.reason


def test_concatenated_gzip_members_are_refused_via_unused_data():
    """Concatenated members are legal; the stdlib stops after the first and leaves the rest in unused_data.
    Returning only member one silently drops member two's markup — a false CLEAN."""
    two = _gzip(b"<html>safe</html>") + _gzip(b'<meta http-equiv="refresh" content="0;url=//evil/">')
    d = decode_body(two, [("content-encoding", "gzip"), *UTF8])
    assert d.body_semantically_available is False
    assert "trailing" in d.reason or "concatenated" in d.reason


# ---- bombs: refused WHILE inflating, never a truncated prefix marked decoded ----

@pytest.mark.parametrize("enc,comp,label", [
    ("gzip", _gzip, "gzip"),
    ("deflate", _zlib_deflate, "deflate"),
    ("deflate", _raw_deflate, "raw deflate"),
])
def test_decompression_bomb_is_refused_not_silently_truncated(enc, comp, label):
    big = b"A" * (MAX_DECODED_BYTES + 5_000_000)
    d = decode_body(comp(big), [("content-encoding", enc), *UTF8])
    assert d.decoded is False and d.body_semantically_available is False, f"{label}: bomb decoded"
    assert "bound" in d.reason and not d.text


def test_bomb_refusal_uses_the_expansion_ratio_not_only_the_flat_cap():
    body = b"B" * (3000 * MAX_EXPANSION_RATIO * 2)   # under the flat cap, over the ratio cap
    raw = _raw_deflate(body)
    assert len(body) < MAX_DECODED_BYTES and len(raw) * MAX_EXPANSION_RATIO < len(body)
    d = decode_body(raw, [("content-encoding", "deflate"), *UTF8])
    assert d.body_semantically_available is False and f"ratio {MAX_EXPANSION_RATIO}" in d.reason


def test_legitimate_largish_low_compressibility_body_is_not_a_false_bomb():
    """The bomb guard must not reject an ordinary largish page. Low-compressibility data keeps the expansion
    ratio non-binding (len(raw) stays close to len(body)), so reading limit+1 leaves it available."""
    import hashlib
    blocks, h = [], b"seed"
    while sum(len(b) for b in blocks) < 300_000:
        h = hashlib.sha256(h).digest()                             # sha256 output is incompressible
        blocks.append(h)
    body = b"".join(blocks)[:300_000]
    raw = _gzip(body)
    assert len(raw) * MAX_EXPANSION_RATIO > len(body)               # ratio is not the binding constraint
    d = decode_body(raw, [("content-encoding", "gzip"), ("content-type", "application/octet-stream")])
    # It decompressed completely without tripping the bomb guard; charset is a separate concern here.
    assert "bound" not in d.reason and "ratio" not in d.reason


# ---- charset: deterministic determination only (the WHATWG-order + Rule-4 fixes) ----

def test_transport_charset_outranks_meta():
    """WHATWG gives the transport charset priority over the in-document <meta> prescan (after BOM). The old
    order let an attacker-controlled <meta charset> override the header and reason over different text."""
    body = "<html><head><meta charset='utf-16'></head><body>café</body></html>".encode("utf-8")
    d = decode_body(body, [("content-type", "text/html; charset=utf-8")])
    assert d.charset_source == "header" and d.body_semantically_available is True
    assert "café" in d.text


def test_bom_outranks_transport_and_meta():
    body = b"\xff\xfe" + "<meta http-equiv=refresh content=0;url=//evil/>".encode("utf-16-le")
    d = decode_body(body, [("content-type", "text/html; charset=iso-8859-1")])
    assert d.charset_source == "bom" and d.body_semantically_available is True
    assert "evil" in d.text


def test_undeclared_charset_is_inconclusive_not_clean():
    """No BOM, no transport charset: the remaining steps (meta prescan + locale fallback) are a specified
    algorithm we do not reproduce soundly (Rule 4). Under-claim to INCONCLUSIVE rather than guess."""
    d = decode_body(HTML, [("content-type", "text/html")])
    assert d.body_semantically_available is False and d.charset_source == "undeclared"
    assert "undeclared" in d.reason


def test_undeclared_utf16_records_a_hint_but_stays_unavailable():
    body = "<meta http-equiv=refresh content=0;url=//evil/>".encode("utf-16-le")   # no BOM, no declaration
    d = decode_body(body, [("content-type", "text/html")])
    assert d.body_semantically_available is False
    assert any("UTF-16" in n or "UTF-32" in n for n in d.notes)


def test_meta_charset_alone_does_not_establish_availability():
    """A body whose only encoding signal is <meta charset> must remain INCONCLUSIVE — no hand-rolled meta
    parse is trusted to adjudicate."""
    body = b'<html><head><meta charset="utf-8"></head><body>hi</body></html>'
    d = decode_body(body, [("content-type", "text/html")])
    assert d.body_semantically_available is False


# ---- unsupported / undecodable: refuse deterministically, never claim the body was empty ----

@pytest.mark.parametrize("enc", ["br", "zstd", "compress", "gzip, br"])
def test_optional_or_chained_encodings_are_unsupported_regardless_of_host(enc):
    """Adjudication must not depend on which optional modules happen to be installed — br/zstd are treated as
    unsupported deterministically so an offline re-verification agrees with the original run."""
    d = decode_body(b"whatever", [("content-encoding", enc), *UTF8])
    assert d.body_semantically_available is False and "unsupported" in d.reason.lower()


def test_malformed_gzip_is_refused():
    d = decode_body(b"\x1f\x8b not really gzip", [("content-encoding", "gzip"), *UTF8])
    assert d.body_semantically_available is False and "malformed" in d.reason.lower()


def test_unknown_charset_label_is_refused():
    d = decode_body(HTML, [("content-type", "text/html; charset=made-up-9000")])
    assert d.body_semantically_available is False and "unknown charset" in d.reason


def test_strict_decode_failure_is_refused_not_mangled():
    body = b"\xff\xfe\xfa invalid utf8 \x80\x81"
    d = decode_body(body, [("content-type", "text/html; charset=utf-8")])
    assert d.body_semantically_available is False and "not valid" in d.reason


def test_residual_nul_under_declared_encoding_is_refused_not_recovered():
    """NUL surviving a strict decode under a DECLARED charset means the declaration is wrong. Recovering the
    true encoding by heuristics is a diagnostic LEAD, not proof — it must not establish availability."""
    body = "<meta http-equiv=refresh content=0;url=//evil/>".encode("utf-16-le")   # NUL-laden as latin-1
    d = decode_body(body, [("content-type", "text/html; charset=iso-8859-1")])
    assert d.body_semantically_available is False
    assert "NUL" in d.reason


# ---- read bound + truncation are self-enforced (finding 7) ----

def test_read_bound_is_self_enforced():
    d = decode_body(b"x" * (MAX_RAW_BYTES + 10), UTF8)
    assert d.truncated is True and d.body_semantically_available is False


def test_caller_truncated_flag_is_honoured():
    d = decode_body(HTML, UTF8, truncated=True)
    assert d.truncated is True and d.body_semantically_available is False


def test_cannot_decompress_a_truncated_compressed_stream():
    d = decode_body(_gzip(HTML)[:20], [("content-encoding", "gzip"), *UTF8], truncated=True)
    assert d.body_semantically_available is False
