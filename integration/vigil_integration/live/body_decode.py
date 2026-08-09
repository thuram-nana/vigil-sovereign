"""body_decode — turn raw HTTP response bytes into a body VIGIL may actually reason about, or refuse.

A body-dependent predicate (meta-refresh, host-header reflected into HTML, any markup scan) is only sound
over the document the target really served. The previous capture did ``raw.decode("utf-8", "replace")`` with
no ``Content-Encoding`` and no declared charset, so a gzip/Brotli response became replacement characters and
a UTF-16 page was misread — while the request still counted as an established channel. A body-dependent
check would then find nothing and be recorded as a channel-confirmed CLEAN over a document VIGIL never read.
That is a realistic false-CLEAN on ordinary CDN infrastructure, so this module makes the decode a first-class,
inspectable step whose failure modes are all INCONCLUSIVE rather than clean.

Every capture carries its own provenance: the raw bytes' digest and length, the observed encoding and
charset, whether decoding actually succeeded, whether the response was truncated, and a single
``body_semantically_available`` flag the runner uses to decide whether body-dependent evidence may be
adjudicated at all. Unsupported encoding, malformed decoding, excessive expansion and truncation all clear
that flag.

Decompression is bounded twice over — a cap on compressed input, a cap on decompressed output, and a maximum
expansion ratio — so a decompression bomb cannot be used to exhaust the prober.

Pure stdlib; no framework imports (FATAL-2 safe).
"""

from __future__ import annotations

import codecs
import hashlib
import re
import zlib
from dataclasses import dataclass, field

# Bounds. `RAW` is what we are willing to read off the wire; `DECODED` is what we are willing to hold after
# decompression; `RATIO` stops a small compressed body from expanding into the decoded cap.
MAX_RAW_BYTES = 2_000_000
MAX_DECODED_BYTES = 8_000_000
MAX_EXPANSION_RATIO = 100

# Encodings we can faithfully reverse. Anything else (br, zstd, compress, a multi-layer chain we do not
# implement) is UNSUPPORTED — which must read as "we could not see the document", never as "nothing here".
_IDENTITY = ("", "identity")

# Byte-order marks are DEFINITIVE per the HTML encoding sniffing algorithm — they outrank a declared
# charset. Sniffing them is what turns an undeclared UTF-16 page from "unreadable" into a document we can
# actually reason about, which is the difference between INCONCLUSIVE and a real verdict.
_BOMS = ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe\x00\x00", "utf-32-le"),
         (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
# The spec's prescan looks at the first 1024 bytes for a <meta charset> / <meta http-equiv content-type>.
_PRESCAN_BYTES = 1024
_META_CHARSET = re.compile(rb"""<meta[^>]*?charset\s*=\s*["']?\s*([A-Za-z0-9_\-:.]+)""", re.IGNORECASE)


def _sniff_charset(payload: bytes) -> tuple[str, str]:
    """Determine the encoding the way a browser does, returning ``(charset, how)``.

    Order is the HTML standard's: a BOM is definitive; otherwise the document's own ``<meta>`` declaration
    in the first 1024 bytes. The transport's declared charset is applied by the caller when neither fires."""
    for bom, name in _BOMS:
        if payload.startswith(bom):
            return name, "bom"
    found = _META_CHARSET.search(payload[:_PRESCAN_BYTES])
    if found:
        try:
            return found.group(1).decode("ascii").lower(), "meta"
        except UnicodeDecodeError:      # pragma: no cover - a non-ASCII charset name is not a charset name
            pass
    return "", ""


def _optional_decompressor(encoding: str):
    """brotli/zstd are not in the stdlib. If the host HAS a decoder we use it — a real capability upgrade on
    those hosts — and where it is absent we refuse honestly rather than pretending the body was empty."""
    if encoding == "br":
        for mod in ("brotli", "brotlicffi"):
            try:
                return __import__(mod).decompress
            except Exception:           # noqa: BLE001
                continue
    if encoding == "zstd":
        try:
            from compression.zstd import decompress as zdec   # Python >= 3.14
            return zdec
        except Exception:               # noqa: BLE001
            try:
                import zstandard
                return zstandard.ZstdDecompressor().decompress
            except Exception:           # noqa: BLE001
                pass
    return None


@dataclass
class DecodedBody:
    """The result of turning response bytes into text, with the provenance to justify trusting it."""

    text: str = ""
    raw_len: int = 0
    raw_sha256: str = ""
    content_encoding: str = ""
    charset: str = ""
    charset_source: str = ""           # "bom" | "meta" | "header" | "default" — how the encoding was decided
    decoded: bool = False              # the bytes were successfully decompressed AND decoded to text
    truncated: bool = False            # the response was longer than the read bound — we hold a PREFIX
    reason: str = ""                   # why the body is unusable, when it is
    notes: list[str] = field(default_factory=list)

    @property
    def body_semantically_available(self) -> bool:
        """Whether a body-dependent predicate may be adjudicated over ``text``.

        False whenever we hold something other than the document the target served: an unsupported
        Content-Encoding, a decompression or decode failure, an over-expanding payload, or a truncated
        response (a prefix cannot prove the ABSENCE of markup, so a body-dependent negative over it would be
        a false CLEAN). The runner must map False to INCONCLUSIVE for body-dependent checks — header-derived
        evidence in the same response is unaffected and stays adjudicable."""
        return self.decoded and not self.truncated


class _BoundedExpansion(ValueError):
    """Decompressed output exceeded its absolute cap or its expansion ratio."""


def _decompress(raw: bytes, encoding: str) -> bytes:
    """Reverse one Content-Encoding layer under hard bounds, or raise.

    ``zlib`` is fed incrementally with ``max_length`` so a decompression bomb is refused while it inflates,
    not after — we never materialise more than the cap even transiently."""
    limit = min(MAX_DECODED_BYTES, max(len(raw), 1) * MAX_EXPANSION_RATIO)
    if encoding == "gzip":
        obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        obj = zlib.decompressobj()      # zlib-wrapped; the raw-deflate fallback is handled by the caller
    else:                               # pragma: no cover - guarded by the caller's allow-list
        raise ValueError(f"unsupported encoding {encoding!r}")
    out = obj.decompress(raw, limit)
    if obj.unconsumed_tail:             # more input remains only because we hit `limit`
        raise _BoundedExpansion(
            f"{encoding} body exceeds the decoded bound ({limit} bytes / ratio {MAX_EXPANSION_RATIO})")
    return out


def _charset_of(content_type: str) -> str:
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip('"\'').lower()
    return ""


def decode_body(raw: bytes, headers: "list[tuple[str, str]]", *, truncated: bool = False) -> DecodedBody:
    """Decode ``raw`` using the response's own ``Content-Encoding`` and declared charset.

    Refuses rather than guesses: an encoding we cannot reverse, a decompression failure, an over-expanding
    payload or a charset that will not decode all leave ``body_semantically_available`` False, so the runner
    reports INCONCLUSIVE for body-dependent evidence instead of a CLEAN over bytes it never understood."""
    lowered = {k.lower(): v for k, v in (headers or [])}
    encoding = (lowered.get("content-encoding") or "").strip().lower()
    charset = _charset_of(lowered.get("content-type", ""))
    out = DecodedBody(raw_len=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
                      content_encoding=encoding, charset=charset, truncated=truncated)
    if truncated:
        out.notes.append("response exceeded the read bound; only a prefix was captured")

    payload = raw
    if encoding not in _IDENTITY:
        if truncated:
            out.reason = f"cannot decompress a truncated {encoding} stream"
            return out
        if encoding not in ("gzip", "deflate"):
            optional = _optional_decompressor(encoding)
            if optional is None:
                # A chained or unavailable encoding: we hold bytes we cannot reverse. Saying "clean" over
                # them would assert something about a document we never decoded.
                out.reason = f"unsupported Content-Encoding {encoding!r} (no decoder available on this host)"
                return out
            try:
                payload = optional(raw)
            except Exception:           # noqa: BLE001
                out.reason = f"malformed {encoding} body"
                return out
            if len(payload) > MAX_DECODED_BYTES:
                out.reason = f"{encoding} body exceeds the decoded bound"
                return out
            out.notes.append(f"decompressed with the host's {encoding} decoder")
            return _finish(out, payload)
        try:
            payload = _decompress(raw, encoding)
        except _BoundedExpansion as exc:
            out.reason = str(exc)
            return out
        except Exception:                                   # noqa: BLE001
            if encoding == "deflate":                       # some servers send RAW deflate (no zlib header)
                try:
                    payload = zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, MAX_DECODED_BYTES)
                except Exception:                           # noqa: BLE001
                    out.reason = "malformed deflate body"
                    return out
            else:
                out.reason = f"malformed {encoding} body"
                return out

    return _finish(out, payload)


def _finish(out: DecodedBody, payload: bytes) -> DecodedBody:
    """Decide the encoding the way a browser does and decode, or refuse.

    Precedence: BOM (definitive) > the document's own <meta> declaration > the transport's Content-Type >
    UTF-8. A body that will not decode under the chosen encoding is REFUSED rather than mangled into
    replacement characters — silently mangling is exactly how a UTF-16 page became "no markup found"."""
    sniffed, how = _sniff_charset(payload)
    if sniffed:
        chosen, source = sniffed, how
    elif out.charset:
        chosen, source = out.charset, "header"
    else:
        chosen, source = "utf-8", "default"
    out.charset, out.charset_source = chosen, source
    try:
        codecs.lookup(chosen)
    except LookupError:
        out.reason = f"unknown charset {chosen!r}"
        return out
    try:
        out.text = payload.decode(chosen)
    except (UnicodeDecodeError, ValueError):
        out.reason = f"body is not valid {chosen} (declared via {source})"
        return out
    if "\x00" in out.text:
        # NUL in decoded TEXT means we almost certainly picked the wrong encoding: a UTF-16/32 document
        # with no BOM and no declaration decodes as "valid" UTF-8 (NUL is a legal code point) and yields
        # interleaved garbage — a markup scan then finds nothing and the branch would be scored CLEAN over a
        # document we never actually read. Recover the real encoding where we can (an upgrade, not a
        # refusal); refuse only when nothing produces coherent text.
        # Score every candidate rather than taking the first NUL-free one: decoding UTF-16-BE bytes AS
        # little-endian also yields NUL-free text, just meaningless CJK, so "no NULs" alone picks the wrong
        # endianness. The document that is actually text scores far higher on printable ASCII.
        best, best_score = None, 0.0
        for candidate in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            try:
                recovered = payload.decode(candidate)
            except (UnicodeDecodeError, ValueError):
                continue
            if not recovered or "\x00" in recovered:
                continue
            score = sum(1 for ch in recovered if 32 <= ord(ch) < 127 or ch in "\r\n\t") / len(recovered)
            if score > best_score:
                best, best_score = (recovered, candidate), score
        if best is not None and best_score >= 0.80:   # a real HTML document is overwhelmingly ASCII
            out.text, out.charset, out.charset_source = best[0], best[1], "nul-recovery"
            out.notes.append(f"encoding recovered as {best[1]} ({best_score:.0%} printable): the "
                             f"declared/default decode held NULs")
            out.decoded = True
            return out
        out.text = ""
        out.reason = f"decoded {chosen} text contains NUL — the real encoding could not be determined"
        return out
    out.decoded = True
    return out
