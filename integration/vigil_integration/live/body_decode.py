"""body_decode — turn raw HTTP response bytes into a body VIGIL may actually reason about, or refuse.

A body-dependent predicate (meta-refresh, host-header reflected into HTML, any markup scan) is only sound
over the document the target really served. The previous capture did ``raw.decode("utf-8", "replace")`` with
no ``Content-Encoding`` and no declared charset, so a gzip/Brotli response became replacement characters and
a UTF-16 page was misread — while the request still counted as an established channel. A body-dependent
check would then find nothing and be recorded as a channel-confirmed CLEAN over a document VIGIL never read.
That is a realistic false-CLEAN on ordinary CDN infrastructure, so this module makes the decode a first-class,
inspectable step whose failure modes are all INCONCLUSIVE rather than clean.

The governing rule, after an adversarial review found several false-CLEAN paths, is CONSERVATISM by
construction: ``body_semantically_available`` is True ONLY when

  * the compressed layer was reversed COMPLETELY — the stream reached its end-of-stream marker
    (``obj.eof``), nothing was left over (no ``unused_data`` — a second concatenated member is data we did
    not examine), and it stayed inside both the absolute and the expansion-ratio bound; AND
  * the charset was determined the way a browser does — a byte-order mark, or the transport's ``Content-Type``
    charset LABEL resolved through the WHATWG "get an encoding" map (:func:`_whatwg_codec`) to a Python codec
    proven byte-faithful to the WHATWG index. Labels a browser rejects (``utf-7``, EBCDIC, the ``replacement``
    set) and encodings we cannot decode faithfully offline (Big5, Shift_JIS, ``x-user-defined``) are refused,
    NOT resolved through Python's codec registry — which accepts them and disagrees with the browser. Transport
    outranks the in-document ``<meta>`` prescan per WHATWG; AND
  * the bytes decode STRICTLY under that codec (no replacement characters, no residual NUL).

Everything that would require guessing — an undeclared charset (the HTML ``<meta>`` prescan and its
locale-dependent fallback are a specified algorithm we do not reproduce soundly, so approximating it would
violate Claim-Discipline rule 4), a UTF-16/32 document recovered by heuristics, a Brotli/Zstandard body whose
decoder may or may not be installed on this host — yields INCONCLUSIVE, with a non-authoritative hint recorded
for triage but NEVER used to establish availability. Under-claiming (INCONCLUSIVE) is the safe direction; the
capability upgrades when a spec-compliant encoding sniffer and vendored streaming decoders are added, not by
lowering the bar.

Decompression is bounded three ways — a cap on the raw bytes we will accept, a cap on decompressed output,
and a maximum expansion ratio — refused WHILE inflating so a decompression bomb cannot exhaust the prober.

Pure stdlib; no framework imports (FATAL-2 safe).
"""

from __future__ import annotations

import codecs
import hashlib
import zlib
from dataclasses import dataclass, field

# Bounds. `RAW` is what we are willing to read off the wire; `DECODED` is what we are willing to hold after
# decompression; `RATIO` stops a small compressed body from expanding into the decoded cap.
MAX_RAW_BYTES = 2_000_000
MAX_DECODED_BYTES = 8_000_000
MAX_EXPANSION_RATIO = 100

# Encodings we can faithfully AND deterministically reverse with the stdlib. Anything else (br, zstd,
# compress, a multi-layer chain we do not implement) is UNSUPPORTED — which must read as "we could not see
# the document", never as "nothing here". br/zstd are deliberately NOT probed for on the host: adjudication
# must not depend on which optional modules happen to be installed, or an offline re-verification could
# disagree with the original run.
_IDENTITY = ("", "identity")

# Byte-order marks are DEFINITIVE per the HTML encoding sniffing algorithm — they outrank even a declared
# charset. Detecting them is unambiguous byte-prefix matching (not a spec approximation), and it is what
# turns an undeclared UTF-16 page from "unreadable" into a document we can actually reason about.
_BOMS = ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe\x00\x00", "utf-32-le"),
         (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
_PRESCAN_BYTES = 1024   # window for the non-authoritative triage hint only


class _UnusableStream(ValueError):
    """A compressed stream we will not treat as a faithful, complete document."""


class _BoundedExpansion(_UnusableStream):
    """Decompressed output exceeded its absolute cap or its expansion ratio (bomb guard)."""


class _IncompleteStream(_UnusableStream):
    """The compressed stream ended without its end-of-stream marker — we hold a truncated prefix."""


class _TrailingData(_UnusableStream):
    """Bytes remained after the first member — a concatenated stream we did not (and must not silently) read."""


def _bounded_inflate(raw: bytes, obj: "zlib._Decompress", label: str) -> bytes:
    """Reverse one compressed layer through ``obj`` COMPLETELY, under hard bounds, or raise.

    Three ways this refuses rather than returns a partial document — each was a reproduced false-CLEAN:

      * ``_BoundedExpansion`` — the output would exceed the absolute cap or the expansion ratio. We feed
        ``limit + 1`` as ``max_length`` so a body sitting EXACTLY on the cap is not falsely flagged, and treat
        either overflow (``len(out) > limit``) or a non-empty ``unconsumed_tail`` as the bomb signal. The
        bomb is refused WHILE inflating — we never materialise more than the cap even transiently.
      * ``_IncompleteStream`` — ``obj.eof`` is False. A gzip/deflate stream with its tail removed decompresses
        cleanly with an EMPTY ``unconsumed_tail``; only ``eof`` distinguishes a complete stream from a
        truncated one. Without this check a prefix of the document is treated as the whole thing, and a
        body-dependent negative over a prefix is a false CLEAN. ``flush()`` does not substitute for ``eof``.
      * ``_TrailingData`` — ``obj.unused_data`` is non-empty. Concatenated gzip members are legal; the stdlib
        decompressor stops after the FIRST and puts the rest in ``unused_data``. Returning only member one
        silently drops whatever markup member two carried — another false CLEAN. Bounded member-by-member
        support can come later; until then a multi-member body is unavailable.
    """
    limit = min(MAX_DECODED_BYTES, max(len(raw), 1) * MAX_EXPANSION_RATIO)
    out = obj.decompress(raw, limit + 1)
    if len(out) > limit or obj.unconsumed_tail:
        raise _BoundedExpansion(
            f"{label} body exceeds the decoded bound ({limit} bytes / ratio {MAX_EXPANSION_RATIO})")
    if not obj.eof:
        raise _IncompleteStream(f"{label} stream is truncated (no end-of-stream marker)")
    if obj.unused_data:
        raise _TrailingData(
            f"{label} stream carries {len(obj.unused_data)} trailing bytes (concatenated members are not "
            f"decoded), so the body cannot be treated as complete")
    return out


def _decompress(raw: bytes, encoding: str) -> bytes:
    """Reverse one Content-Encoding layer under hard bounds and completeness checks, or raise."""
    if encoding == "gzip":
        obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        obj = zlib.decompressobj()      # zlib-wrapped; the raw-deflate fallback is handled by the caller
    else:                               # pragma: no cover - guarded by the caller's allow-list
        raise ValueError(f"unsupported encoding {encoding!r}")
    return _bounded_inflate(raw, obj, encoding)


def _charset_of(content_type: str) -> str:
    """The ``charset`` parameter of a Content-Type header (RFC 7231 media-type parameter — a well-defined
    header parse, not the HTML sniffing algorithm)."""
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip('"\'').lower()
    return ""


def _media_type(content_type: str) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _bom_charset(payload: bytes) -> str:
    for bom, name in _BOMS:
        if payload.startswith(bom):
            return name
    return ""


def _undeclared_hint(payload: bytes) -> str:
    """A non-authoritative triage hint for an undeclared body — NEVER an availability input.

    Deliberately not the HTML ``<meta>`` prescan (a specified algorithm we do not reproduce soundly). Only a
    structural observation: NUL bytes early in the stream point at a UTF-16/UTF-32 document."""
    if b"\x00" in payload[:_PRESCAN_BYTES]:
        return "NUL bytes early in the body suggest an undeclared UTF-16/UTF-32 document"
    return ""


# The WHATWG Encoding Standard "get an encoding" step: a FIXED label -> encoding map. A browser resolves the
# transport (or document) charset through THIS table, not through whatever codecs a runtime happens to
# register. Resolving through Python's codec registry instead — the previous behaviour — made VIGIL decode
# labels a browser REJECTS (utf-7, EBCDIC cp037, hz, iso-2022-*) and disagree with the browser on remapped
# labels (iso-8859-1 / latin1 -> windows-1252) and on bare `utf-16` (host byte order vs the standard's fixed
# UTF-16LE). Every one of those is a false-FACT or false-CLEAN surface (red-pen BLOCK-1..4). So the label is
# now resolved the WHATWG way, to a Python codec PROVEN byte-faithful to the WHATWG index, and everything
# else is refused (INCONCLUSIVE).
#
# Faithful subset (checked by a byte-level differential against the WHATWG index files): UTF-8, UTF-16LE/BE
# (bare `utf-16` -> LE, never host order), the ISO-8859 / windows-125X single-byte encodings plus cp866 /
# cp874 / mac_roman / mac_cyrillic / koi8-r, and EUC-KR (cp949 / UHC). An exhaustive byte differential vs the
# WHATWG index files confirmed none of these decodes any byte to a DIFFERENT character than a browser (the
# false-verdict direction). Two honesty caveats, BOTH in the safe (under-claim) direction, never a decode
# disagreement: (a) WHATWG maps several unassigned bytes in the windows/cp single-byte encodings (windows-1250
# /1251/1252/1253/1254/1255/1257/1258 and windows-874) to C1 controls (U+008x/U+009x) — and windows-1255 0xCA
# -> U+05BA; CPython strict-refuses those bytes, so such a page is reported INCONCLUSIVE rather than
# mis-decoded. (b) GBK/gb18030 and koi8-u are NOT
# byte-faithful — CPython ships GB18030-2000 (browsers use -2005; ~20 two-byte points differ) and CPython
# koi8-u differs from the WHATWG index at 0xAE/0xBE — so they are REFUSED (see _WHATWG_REFUSED), not
# resolved. Security-relevant remaps baked into the label lists: iso-8859-1/latin1/ascii/us-ascii -> cp1252;
# iso-8859-9 -> cp1254; iso-8859-11 -> cp874; euc-kr -> cp949; the `utf-16` label -> utf-16-le.
_LABEL_TO_CODEC: "dict[str, str]" = {}


def _reg_labels(codec: str, labels: str) -> None:
    for label in labels.split():
        _LABEL_TO_CODEC[label] = codec


_reg_labels("utf-8", "unicode-1-1-utf-8 unicode11utf8 unicode20utf8 utf-8 utf8 x-unicode20utf8")
_reg_labels("cp866", "866 cp866 csibm866 ibm866")
_reg_labels("iso8859-2", "csisolatin2 iso-8859-2 iso-ir-101 iso8859-2 iso88592 iso_8859-2 iso_8859-2:1987 l2 latin2")
_reg_labels("iso8859-3", "csisolatin3 iso-8859-3 iso-ir-109 iso8859-3 iso88593 iso_8859-3 iso_8859-3:1988 l3 latin3")
_reg_labels("iso8859-4", "csisolatin4 iso-8859-4 iso-ir-110 iso8859-4 iso88594 iso_8859-4 iso_8859-4:1988 l4 latin4")
_reg_labels("iso8859-5", "csisolatincyrillic cyrillic iso-8859-5 iso-ir-144 iso8859-5 iso88595 iso_8859-5 iso_8859-5:1988")
_reg_labels("iso8859-6", "arabic asmo-708 csiso88596e csiso88596i csisolatinarabic ecma-114 iso-8859-6 "
            "iso-8859-6-e iso-8859-6-i iso-ir-127 iso8859-6 iso88596 iso_8859-6 iso_8859-6:1987")
_reg_labels("iso8859-7", "csisolatingreek ecma-118 elot_928 greek greek8 iso-8859-7 iso-ir-126 iso8859-7 "
            "iso88597 iso_8859-7 iso_8859-7:1987 sun_eu_greek")
_reg_labels("iso8859-8", "csiso88598e csisolatinhebrew hebrew iso-8859-8 iso-8859-8-e iso-ir-138 iso8859-8 "
            "iso88598 iso_8859-8 iso_8859-8:1988 visual csiso88598i iso-8859-8-i logical")
_reg_labels("iso8859-10", "csisolatin6 iso-8859-10 iso-ir-157 iso8859-10 iso885910 l6 latin6")
_reg_labels("iso8859-13", "iso-8859-13 iso8859-13 iso885913")
_reg_labels("iso8859-14", "iso-8859-14 iso8859-14 iso885914")
_reg_labels("iso8859-15", "csisolatin9 iso-8859-15 iso8859-15 iso885915 iso_8859-15 l9")
_reg_labels("iso8859-16", "iso-8859-16")
_reg_labels("koi8-r", "cskoi8r koi koi8 koi8-r koi8_r")
_reg_labels("mac_roman", "csmacintosh mac macintosh x-mac-roman")
_reg_labels("cp874", "dos-874 iso-8859-11 iso8859-11 iso885911 tis-620 windows-874")
_reg_labels("cp1250", "cp1250 windows-1250 x-cp1250")
_reg_labels("cp1251", "cp1251 windows-1251 x-cp1251")
_reg_labels("cp1252", "ansi_x3.4-1968 ascii cp1252 cp819 csisolatin1 ibm819 iso-8859-1 iso-ir-100 iso8859-1 "
            "iso88591 iso_8859-1 iso_8859-1:1987 l1 latin1 us-ascii windows-1252 x-cp1252")
_reg_labels("cp1253", "cp1253 windows-1253 x-cp1253")
_reg_labels("cp1254", "cp1254 csisolatin5 iso-8859-9 iso-ir-148 iso8859-9 iso88599 iso_8859-9 "
            "iso_8859-9:1989 l5 latin5 windows-1254 x-cp1254")
_reg_labels("cp1255", "cp1255 windows-1255 x-cp1255")
_reg_labels("cp1256", "cp1256 windows-1256 x-cp1256")
_reg_labels("cp1257", "cp1257 windows-1257 x-cp1257")
_reg_labels("cp1258", "cp1258 windows-1258 x-cp1258")
_reg_labels("mac_cyrillic", "x-mac-cyrillic x-mac-ukrainian")
_reg_labels("cp949", "cseuckr csksc56011987 euc-kr iso-ir-149 korean ks_c_5601-1987 ks_c_5601-1989 ksc5601 "
            "ksc_5601 windows-949")
_reg_labels("utf-16-be", "unicodefffe utf-16be")
_reg_labels("utf-16-le", "csunicode iso-10646-ucs-2 ucs-2 unicode unicodefeff utf-16 utf-16le")

# WHATWG-recognized labels we deliberately do NOT decode: the "replacement" encoding (WHATWG maps these
# smuggling-prone labels to a single U+FFFD — a browser reads NO document from them, so neither may VIGIL),
# x-user-defined (a private-use remap with no faithful stdlib codec), and the CJK encodings whose WHATWG
# index is not byte-identical to any stdlib codec (Big5, Shift_JIS, EUC-JP, ISO-2022-JP). Recognized, but
# INCONCLUSIVE rather than decoded into text a browser would not produce. Upgrade path: vendored WHATWG codecs.
_WHATWG_REFUSED = set(
    "csiso2022kr hz-gb-2312 iso-2022-cn iso-2022-cn-ext iso-2022-kr replacement "
    "x-user-defined "
    "big5 big5-hkscs cn-big5 csbig5 x-x-big5 "
    "cseucpkdfmtjapanese euc-jp x-euc-jp "
    "csiso2022jp iso-2022-jp "
    "csshiftjis ms932 ms_kanji shift-jis shift_jis sjis windows-31j x-sjis "
    # A ground-truth differential vs the WHATWG index files showed CPython's tables DIVERGE from WHATWG for
    # these (not just refuse-undefined-bytes, but decode to the WRONG character): GBK/gb18030 — CPython ships
    # GB18030-2000, browsers use GB18030-2005 (~20 two-byte points differ, e.g. A3A0 -> U+E5E5 PUA vs
    # U+3000); koi8-u — bytes 0xAE/0xBE decode to box-drawing in CPython vs Cyrillic short-u in WHATWG. Refuse
    # them (safe under-claim) rather than assert availability over text a browser would not produce.
    "chinese csgb2312 csiso58gb231280 gb2312 gb_2312 gb_2312-80 gbk iso-ir-58 x-gbk gb18030 "
    "koi8-ru koi8-u".split())


def _whatwg_codec(label: str) -> "tuple[str | None, str]":
    """Resolve a Content-Type charset LABEL to a Python codec the WHATWG way.

    Returns ``(codec, status)``: ``status`` is ``"ok"`` (a byte-faithful codec), ``"unsupported"`` (a
    recognized WHATWG label we do not decode faithfully offline), or ``"unknown"`` (not a WHATWG label at
    all — a browser ignores such a header). Both non-ok cases resolve to unavailable, with distinct reasons."""
    norm = label.strip(" \t\n\f\r").lower()
    if norm in _LABEL_TO_CODEC:
        return _LABEL_TO_CODEC[norm], "ok"
    if norm in _WHATWG_REFUSED:
        return None, "unsupported"
    return None, "unknown"


@dataclass
class DecodedBody:
    """The result of turning response bytes into text, with the provenance to justify trusting it."""

    text: str = ""
    raw_len: int = 0
    raw_sha256: str = ""
    content_encoding: str = ""
    charset: str = ""
    charset_source: str = ""           # "bom" | "header" | "json-default" | "undeclared" — how it was decided
    decoded: bool = False              # bytes were completely decompressed AND strictly decoded to text
    truncated: bool = False            # the response was longer than the read bound — we hold a PREFIX
    reason: str = ""                   # why the body is unusable, when it is
    notes: list[str] = field(default_factory=list)

    @property
    def body_semantically_available(self) -> bool:
        """Whether a body-dependent predicate may be adjudicated over ``text``.

        False whenever we hold something other than the complete document the target served under a
        deterministically-determined encoding: an unsupported/host-dependent Content-Encoding, a truncated or
        concatenated compressed stream, an over-expanding payload, an undeclared charset, or a strict-decode
        failure. The runner MUST map False to INCONCLUSIVE for body-dependent checks — header-derived evidence
        in the same response is unaffected and stays adjudicable."""
        return self.decoded and not self.truncated


def decode_body(raw: bytes, headers: "list[tuple[str, str]]", *, truncated: bool = False) -> DecodedBody:
    """Decode ``raw`` using the response's own ``Content-Encoding`` and a deterministically-determined charset.

    Refuses rather than guesses: an encoding we cannot reverse on every host, an incomplete/concatenated or
    over-expanding compressed stream, an undeclared charset, or bytes that will not decode all leave
    ``body_semantically_available`` False, so the runner reports INCONCLUSIVE for body-dependent evidence
    instead of a CLEAN over bytes it never understood. ``truncated`` is honoured from the caller (which reads
    ``MAX_RAW_BYTES + 1`` to detect it) AND re-derived here from the raw length, so the module bounds its own
    input rather than trusting the caller to have done so."""
    raw_headers = headers or []
    lowered = {k.lower(): v for k, v in raw_headers}
    # RFC 7230 §3.2.2: repeated field lines with the same name are equivalent to ONE line whose value is the
    # fields joined by commas. Content-Encoding is a comma-list (1#content-coding), so two
    # `Content-Encoding: gzip` headers mean gzip applied TWICE — byte-identical to `Content-Encoding:
    # gzip, gzip`. Join the occurrences BEFORE parsing so both spellings are treated identically: a
    # multi-layer chain we do not implement falls to the unsupported path and is refused, instead of
    # last-wins silently decompressing a single layer and marking a double-encoded body available.
    encoding = ", ".join(v.strip() for k, v in raw_headers
                         if k.lower() == "content-encoding" and v.strip()).lower()
    content_type = lowered.get("content-type", "")
    charset = _charset_of(content_type)
    truncated = truncated or len(raw) > MAX_RAW_BYTES
    out = DecodedBody(raw_len=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
                      content_encoding=encoding, charset=charset, truncated=truncated)
    if len(raw) > MAX_RAW_BYTES:
        out.notes.append(f"raw body exceeds the {MAX_RAW_BYTES}-byte read bound; only a prefix is held")
    if truncated:
        out.notes.append("response exceeded the read bound; only a prefix was captured")

    # Content-Type is NOT a comma-list, so repeated Content-Type lines are a genuine ambiguity (which charset
    # applies?) rather than an RFC-combinable value. Conflicting duplicates are refused; identical repeats
    # collapse to one and are harmless. (Content-Encoding is a comma-list and was already RFC-combined above,
    # so a repeated/multi-layer encoding reaches the unsupported path and is refused there.)
    if len({v.strip().lower() for k, v in raw_headers if k.lower() == "content-type"}) > 1:
        out.reason = "ambiguous response: conflicting Content-Type headers"
        return out

    payload = raw
    if encoding not in _IDENTITY:
        if truncated:
            out.reason = f"cannot decompress a truncated {encoding} stream"
            return out
        if encoding not in ("gzip", "deflate"):
            # br/zstd/compress/chained encodings: reversing them soundly needs a vendored, version-pinned,
            # bounded streaming decoder (so adjudication is host-independent and offline-replayable). Until
            # that exists, they are UNSUPPORTED — INCONCLUSIVE, never an empty-body CLEAN.
            out.reason = f"unsupported Content-Encoding {encoding!r} (no host-independent decoder available)"
            return out
        try:
            payload = _decompress(raw, encoding)
        except _UnusableStream as exc:                      # bomb / truncated / concatenated — a real answer
            out.reason = str(exc)
            return out
        except Exception:                                   # noqa: BLE001 — zlib.error: wrong/absent wrapper
            if encoding == "deflate":                       # some servers send RAW deflate (no zlib header)
                try:
                    payload = _bounded_inflate(raw, zlib.decompressobj(-zlib.MAX_WBITS), "raw deflate")
                except _UnusableStream as exc:
                    out.reason = str(exc)
                    return out
                except Exception:                           # noqa: BLE001
                    out.reason = "malformed deflate body"
                    return out
            else:
                out.reason = f"malformed {encoding} body"
                return out

    return _finish(out, payload, content_type)


def _finish(out: DecodedBody, payload: bytes, content_type: str) -> DecodedBody:
    """Determine the charset the WHATWG way and decode strictly, or refuse.

    Precedence follows the leading steps of the WHATWG encoding-determination algorithm: a BOM is definitive;
    otherwise the TRANSPORT's Content-Type charset LABEL, resolved through the WHATWG "get an encoding" map
    (:func:`_whatwg_codec`) — not through Python's codec registry, which accepts labels a browser rejects and
    remaps others differently. Transport outranks the in-document ``<meta>`` prescan (the reverse let an
    attacker-controlled ``<meta charset>`` override the header). RFC 8259 makes ``application/json`` UTF-8 by
    default, a specification not a guess. Everything else is UNDECLARED — the remaining steps (the ``<meta>``
    prescan and a locale-dependent fallback) are a specified algorithm we do not reproduce soundly, so the
    body is INCONCLUSIVE."""
    bom = _bom_charset(payload)
    if bom:
        chosen, source, label = bom, "bom", bom          # BOM already names a faithful Python codec
    elif out.charset:
        codec, status = _whatwg_codec(out.charset)
        if codec is None:
            out.charset_source = "header"
            if status == "unsupported":
                out.reason = (f"Content-Type charset {out.charset!r} is a WHATWG encoding VIGIL does not "
                              f"decode faithfully offline — INCONCLUSIVE, not an empty-body CLEAN")
            else:
                out.reason = (f"Content-Type charset {out.charset!r} is not a recognized WHATWG encoding "
                              f"label; a browser ignores it, so VIGIL cannot claim to have read the document")
            return out
        chosen, source, label = codec, "header", out.charset
    elif _media_type(content_type) == "application/json" or _media_type(content_type).endswith("+json"):
        chosen, source, label = "utf-8", "json-default", "utf-8"     # RFC 8259 §8.1: JSON text is UTF-8
    else:
        out.charset_source = "undeclared"
        hint = _undeclared_hint(payload)
        if hint:
            out.notes.append(f"undeclared charset; non-authoritative hint: {hint}")
        out.reason = ("charset is undeclared (no BOM, no transport charset); a sound body-dependent verdict "
                      "needs a spec-compliant HTML encoding determination, which is not yet available")
        return out

    out.charset, out.charset_source = chosen, source
    if source == "header" and label.strip(" \t\n\f\r").lower() != chosen:
        out.notes.append(f"charset label {label!r} resolved to {chosen} per the WHATWG encoding map")
    try:
        codecs.lookup(chosen)                              # pragma: no cover - map holds only real codecs
    except LookupError:
        out.reason = f"resolved codec {chosen!r} is unavailable on this host"
        return out
    try:
        out.text = payload.decode(chosen)                  # strict: no replacement characters
    except (UnicodeDecodeError, ValueError):
        out.reason = f"body is not valid {chosen} (declared via {source} as {label!r})"
        return out
    if "\x00" in out.text:
        # A NUL surviving a STRICT decode under a DECLARED encoding means the declaration is wrong or the
        # bytes are not really text. Recovering the true encoding by heuristics (scoring candidate
        # endiannesses on printable ASCII) is a diagnostic LEAD, not proof of what a browser would select, so
        # it must not establish availability. Refuse; record the hint.
        hint = _undeclared_hint(payload)
        if hint:
            out.notes.append(f"declared {chosen} decoded with residual NUL; {hint} (diagnostic only)")
        out.text = ""
        out.reason = f"decoded {chosen} text contains NUL — the declared encoding does not hold"
        return out
    out.decoded = True
    return out
