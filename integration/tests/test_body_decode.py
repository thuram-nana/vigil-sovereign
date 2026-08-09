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
    assert d.body_semantically_available is False and "not a recognized WHATWG encoding label" in d.reason


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


# ---- WHATWG "get an encoding" charset resolution (red-pen BLOCK-1..4) ----

@pytest.mark.parametrize("label", [
    "utf-7", "cp037", "cp500", "koi8-r-x", "rot13", "punycode", "hz", "iso-2022-jp",
    "hz-gb-2312", "iso-2022-cn", "iso-2022-kr", "replacement", "big5", "shift_jis", "euc-jp",
    "x-user-defined", "made-up-9000",
    # NOT byte-faithful to the WHATWG index (differential caught CPython table divergences) -> refused:
    "gbk", "gb2312", "gb18030", "koi8-u",
])
def test_labels_a_browser_rejects_or_we_cannot_decode_faithfully_are_refused(label):
    """BLOCK-1: resolving through Python's codec registry decoded labels a browser IGNORES (utf-7, EBCDIC,
    the replacement set) — a false-FACT (utf-7 `+ADw-`) and false-CLEAN (EBCDIC over an ASCII sink) surface.
    Only WHATWG labels mapped to a byte-faithful codec may decode; everything else is INCONCLUSIVE."""
    d = decode_body(b"+ADw-meta http-equiv=refresh content=0;url=//evil/+AD4-",
                    [("content-type", f"text/html; charset={label}")])
    assert d.body_semantically_available is False, f"{label} was decoded"
    assert not d.text


def test_utf7_would_have_been_a_false_fact():
    """The concrete BLOCK-1 false-FACT: utf-7 `+ADw-...+AD4-` decodes to a live <meta> sink under Python but
    a browser (utf-7 is not a WHATWG encoding) renders the literal text. Must be refused."""
    d = decode_body(b"+ADw-meta http-equiv=refresh content=0;url=//evil.example/+AD4-",
                    [("content-type", "text/html; charset=utf-7")])
    assert d.body_semantically_available is False
    assert "evil.example" not in d.text


def test_ebcdic_would_have_been_a_false_clean():
    d = decode_body(b'<meta http-equiv="refresh" content="0;url=//evil.example/">',
                    [("content-type", "text/html; charset=cp037")])
    assert d.body_semantically_available is False


def test_bare_utf16_resolves_to_utf16le_not_host_byte_order():
    """BLOCK-2: CPython's `utf-16` codec (no BOM) uses sys.byteorder — host-dependent, so the verdict flipped
    with the machine. WHATWG's `utf-16` label is fixed UTF-16LE. Resolution must be deterministic."""
    body = "<meta http-equiv=refresh content=0;url=//evil.example/>".encode("utf-16-le")
    d = decode_body(body, [("content-type", "text/html; charset=utf-16")])
    assert d.body_semantically_available is True and d.charset == "utf-16-le"
    assert "evil.example" in d.text


def test_explicit_utf16le_and_be_stay_deterministic():
    body_le = "hi//evil/".encode("utf-16-le")
    body_be = "hi//evil/".encode("utf-16-be")
    dle = decode_body(body_le, [("content-type", "text/html; charset=utf-16le")])
    dbe = decode_body(body_be, [("content-type", "text/html; charset=utf-16be")])
    assert dle.charset == "utf-16-le" and "evil" in dle.text
    assert dbe.charset == "utf-16-be" and "evil" in dbe.text


@pytest.mark.parametrize("label", ["iso-8859-1", "latin1", "ascii", "us-ascii", "cp819", "l1"])
def test_latin1_family_maps_to_windows_1252(label):
    """BLOCK-3: WHATWG maps these labels to windows-1252, where 0x80-0x9F are typographic characters, not the
    C1 controls Python's iso-8859-1 produces. VIGIL must read the same text a browser does."""
    d = decode_body(b"quote \x93hi\x94 dash\x97end", [("content-type", f"text/html; charset={label}")])
    assert d.body_semantically_available is True and d.charset == "cp1252"
    assert "“" in d.text and "—" in d.text        # curly quote + em dash (windows-1252)


@pytest.mark.parametrize("label,codec", [
    ("unicode-1-1-utf-8", "utf-8"), ("utf8", "utf-8"), ("x-mac-cyrillic", "mac_cyrillic"),
    ("iso-8859-9", "cp1254"), ("iso-8859-11", "cp874"), ("euc-kr", "cp949"), ("windows-949", "cp949"),
    ("koi8-r", "koi8-r"), ("tis-620", "cp874"),
])
def test_valid_whatwg_labels_resolve_to_their_faithful_codec(label, codec):
    """BLOCK-4: valid WHATWG labels Python's registry rejects or remaps differently must be accepted and
    resolved to the WHATWG-faithful codec."""
    d = decode_body("<p>ok</p>".encode("utf-8"), [("content-type", f"text/html; charset={label}")])
    assert d.charset == codec, f"{label} resolved to {d.charset}, expected {codec}"


def test_conflicting_duplicate_content_type_is_ambiguous():
    d = decode_body(b"<p>hi</p>", [("content-type", "text/html"),
                                    ("content-type", "text/html; charset=utf-7")])
    assert d.body_semantically_available is False and "ambiguous" in d.reason


def test_repeated_content_encoding_headers_are_rfc_combined_not_last_wins():
    """RE-ATTACK HIGH: per RFC 7230 §3.2.2 two `Content-Encoding: gzip` headers == `gzip, gzip` == gzip twice.
    last-wins silently decompressed ONE layer and marked a double-encoded body available (false CLEAN). Both
    spellings must be treated identically — a multi-layer chain we do not implement is refused."""
    gz = _gzip(b"<p>secret</p>")
    two_headers = decode_body(gz, [("content-encoding", "gzip"), ("content-encoding", "gzip"), *UTF8])
    comma_form = decode_body(gz, [("content-encoding", "gzip, gzip"), *UTF8])
    assert two_headers.body_semantically_available is False, "two gzip headers slipped through as one layer"
    assert comma_form.body_semantically_available is False
    assert two_headers.reason == comma_form.reason, "RFC-equivalent spellings must give the same verdict"
    # a genuinely single-encoded body still decodes
    assert decode_body(gz, [("content-encoding", "gzip"), *UTF8]).body_semantically_available is True


def test_conflicting_content_encoding_layers_are_refused():
    d = decode_body(_gzip(HTML), [("content-encoding", "gzip"), ("content-encoding", "identity"), *UTF8])
    assert d.body_semantically_available is False and "unsupported" in d.reason


def test_label_is_case_and_whitespace_insensitive():
    d = decode_body("<p>x</p>".encode("utf-8"), [("content-type", "text/html; charset= UTF-8 ")])
    assert d.charset == "utf-8" and d.body_semantically_available is True
