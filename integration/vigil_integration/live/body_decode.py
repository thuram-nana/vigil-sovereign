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
  * the charset was determined DETERMINISTICALLY the way the HTML standard's leading steps do — a byte-order
    mark, or the transport's ``Content-Type`` charset (transport outranks the in-document ``<meta>`` prescan
    per WHATWG); AND
  * the bytes decode STRICTLY under that charset (no replacement characters, no residual NUL).

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
    lowered = {k.lower(): v for k, v in (headers or [])}
    encoding = (lowered.get("content-encoding") or "").strip().lower()
    content_type = lowered.get("content-type", "")
    charset = _charset_of(content_type)
    truncated = truncated or len(raw) > MAX_RAW_BYTES
    out = DecodedBody(raw_len=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
                      content_encoding=encoding, charset=charset, truncated=truncated)
    if len(raw) > MAX_RAW_BYTES:
        out.notes.append(f"raw body exceeds the {MAX_RAW_BYTES}-byte read bound; only a prefix is held")
    if truncated:
        out.notes.append("response exceeded the read bound; only a prefix was captured")

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
    """Determine the charset deterministically and decode strictly, or refuse.

    Precedence follows the leading, unambiguous steps of the WHATWG encoding-determination algorithm: a BOM
    is definitive; otherwise the TRANSPORT's Content-Type charset (transport outranks the in-document
    ``<meta>`` prescan — the previous order let an attacker-controlled ``<meta charset>`` override the header
    and make VIGIL reason over different text than a browser would). RFC 8259 makes ``application/json``
    UTF-8 by default, which is a specification, not a guess — so a JSON body with no charset is decodable.
    Everything else is UNDECLARED: the remaining steps (the ``<meta>`` prescan and a locale-dependent
    fallback) are a specified algorithm we do not reproduce soundly, so the body is INCONCLUSIVE."""
    bom = _bom_charset(payload)
    if bom:
        chosen, source = bom, "bom"
    elif out.charset:
        chosen, source = out.charset, "header"
    elif _media_type(content_type) == "application/json" or _media_type(content_type).endswith("+json"):
        chosen, source = "utf-8", "json-default"     # RFC 8259 §8.1: JSON text is UTF-8
    else:
        out.charset_source = "undeclared"
        hint = _undeclared_hint(payload)
        if hint:
            out.notes.append(f"undeclared charset; non-authoritative hint: {hint}")
        out.reason = ("charset is undeclared (no BOM, no transport charset); a sound body-dependent verdict "
                      "needs a spec-compliant HTML encoding determination, which is not yet available")
        return out

    out.charset, out.charset_source = chosen, source
    try:
        codecs.lookup(chosen)
    except LookupError:
        out.reason = f"unknown charset {chosen!r}"
        return out
    try:
        out.text = payload.decode(chosen)                  # strict: no replacement characters
    except (UnicodeDecodeError, ValueError):
        out.reason = f"body is not valid {chosen} (declared via {source})"
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
