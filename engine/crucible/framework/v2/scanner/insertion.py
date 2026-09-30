"""
scanner.insertion — the insertion-point engine.

Every active web check is an (insertion-point × payload × analyzer) triple.
Burp's coverage comes from firing N checks across M insertion points; CRUCIBLE
today substitutes one hardcoded parameter. This module closes that gap with a
complete, deterministic engine that:

  * parses a raw HTTP request into every markable insertion point Burp knows —
    URL path segments, query values, query *names*, urlencoded-body values and
    names, cookie values and *names*, request header values and *names*, nested
    JSON values and *keys*, multipart/form-data part bodies and field *names*,
    XML element text nodes and attribute values, and values nested inside an
    encoded blob (a JWT or base64'd JSON) decoded → fuzzed → re-encoded; and
  * renders a payload into exactly one point, rebuilding the request with
    correct percent-encoding, a corrected Content-Length, and everything else
    byte-preserved.

It is pure: no network, no clock, no randomness — the same request always yields
the same ordered insertion points, and the same (point, payload) always renders
the same bytes. It sends nothing; the audit engine issues rendered requests
through the existing ``agents.http_executor`` safety stack.
"""

from __future__ import annotations

import base64
import binascii
import enum
import json
import re
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

# Headers whose value the framework owns and must not fuzz (rendering recomputes
# Content-Length; fuzzing it would only produce malformed requests).
_MANAGED_HEADERS = frozenset({"content-length"})


class InsertionKind(str, enum.Enum):
    """Where a payload can be placed. The set spans every position Burp marks,
    so a check can target the exact surface a bug lives in."""

    URL_PATH_SEG = "url_path_seg"     # one '/'-delimited path segment value
    QUERY_VALUE = "query_value"       # a query-string parameter value
    QUERY_NAME = "query_name"         # a query-string parameter name
    BODY_FORM_VALUE = "body_form_value"  # urlencoded body parameter value
    BODY_FORM_NAME = "body_form_name"    # urlencoded body parameter name
    COOKIE_VALUE = "cookie_value"     # a Cookie header sub-value
    COOKIE_NAME = "cookie_name"       # a Cookie header sub-name
    HEADER_VALUE = "header_value"     # a request header value
    HEADER_NAME = "header_name"       # a request header name
    JSON_VALUE = "json_value"         # a JSON leaf value at a json-pointer
    JSON_KEY = "json_key"             # a JSON object key at a json-pointer
    MULTIPART_VALUE = "multipart_value"  # a multipart/form-data part's body
    MULTIPART_NAME = "multipart_name"    # a multipart/form-data part's field name
    XML_TEXT = "xml_text"             # an XML element text node
    XML_ATTR = "xml_attr"             # an XML attribute value
    NESTED_BLOB = "nested_blob"       # a value inside a base64/JWT-encoded blob
    BODY_WHOLE = "body_whole"         # the entire request body (opaque bodies)


class HttpRequest(BaseModel):
    """A raw HTTP request, decomposed but faithful. ``headers`` is an ordered
    list of (name, value) pairs — order and duplicates are preserved, because
    they matter to servers and to header-based attacks."""

    model_config = ConfigDict(extra="forbid")

    method: str = "GET"
    url: str = Field(min_length=1)
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body: str | None = None

    def header(self, name: str) -> str | None:
        """First value of ``name`` (case-insensitive), or None."""
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def content_type(self) -> str:
        ct = self.header("content-type") or ""
        return ct.split(";", 1)[0].strip().lower()


class InsertionPoint(BaseModel):
    """One markable position in a request. ``locator`` uniquely identifies the
    occurrence (a list index, or a json-pointer) so rendering targets exactly
    this position even when a name repeats. ``base_value`` is what is there now
    — a check diffs its payload response against the base."""

    model_config = ConfigDict(extra="forbid")

    kind: InsertionKind
    name: str = Field(description="Human label: param/header/cookie name, path index, or json-pointer.")
    locator: str = Field(description="Exact-occurrence locator interpreted by RequestTemplate.render.")
    base_value: str = ""

    @property
    def id(self) -> str:
        return f"{self.kind.value}:{self.locator}"


# ---------------------------------------------------------------------------
# tiny, dependency-free HTTP-component codecs
# ---------------------------------------------------------------------------

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _pct_encode(s: str, *, safe: str = "") -> str:
    """Percent-encode `s` for use in a URL component. `safe` names extra chars
    to leave literal (e.g. '/' inside a path). Deterministic, RFC-3986."""
    safe_set = _UNRESERVED | set(safe)
    out: list[str] = []
    for b in s.encode("utf-8"):
        c = chr(b)
        out.append(c if c in safe_set else f"%{b:02X}")
    return "".join(out)


def _split_url(url: str) -> tuple[str, str, str, str]:
    """(scheme_authority, path, query, fragment) with the path kept raw so path
    segments round-trip exactly. Avoids urllib's re-encoding surprises."""
    frag = ""
    if "#" in url:
        url, frag = url.split("#", 1)
    query = ""
    if "?" in url:
        url, query = url.split("?", 1)
    # scheme://authority ends at the first '/' after '://'
    if "://" in url:
        scheme, rest = url.split("://", 1)
        slash = rest.find("/")
        if slash == -1:
            return f"{scheme}://{rest}", "", query, frag
        return f"{scheme}://{rest[:slash]}", rest[slash:], query, frag
    # scheme-relative or path-only
    return "", url, query, frag


def _join_url(authority: str, path: str, query: str, frag: str) -> str:
    out = authority + path
    if query:
        out += "?" + query
    if frag:
        out += "#" + frag
    return out


def _parse_pairs(blob: str) -> list[tuple[str, str]]:
    """Parse `a=1&b=2` (query or urlencoded body) into ordered (name, value)
    pairs, decoding percent- and plus-encoding, keeping blanks and duplicates."""
    pairs: list[tuple[str, str]] = []
    if not blob:
        return pairs
    for chunk in blob.split("&"):
        if chunk == "":
            continue
        name, sep, value = chunk.partition("=")
        pairs.append((_pct_decode(name), _pct_decode(value) if sep else ""))
    return pairs


def _pct_decode(s: str) -> str:
    s = s.replace("+", " ")
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%" and i + 2 < len(s) + 1 and _is_hex(s[i + 1: i + 3]):
            out.append(int(s[i + 1: i + 3], 16))
            i += 3
        else:
            out.extend(c.encode("utf-8"))
            i += 1
    return out.decode("utf-8", errors="replace")


def _is_hex(h: str) -> bool:
    return len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h)


def _encode_pairs(pairs: Iterable[tuple[str, str]]) -> str:
    return "&".join(
        f"{_pct_encode(k, safe='')}={_pct_encode(v, safe='')}" for k, v in pairs
    )


def _parse_cookies(header_value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        out.append((name.strip(), value.strip() if sep else ""))
    return out


def _encode_cookies(pairs: Iterable[tuple[str, str]]) -> str:
    return "; ".join(f"{k}={v}" for k, v in pairs)


# JSON-pointer (RFC 6901) walk over already-parsed JSON.
def _json_leaves(node: Any, pointer: str) -> Iterable[tuple[str, str, Any]]:
    """Yield (pointer, kind, value) for every leaf value and every object key.
    kind is 'value' for scalar leaves, 'key' for object member names."""
    if isinstance(node, dict):
        for key, child in node.items():
            child_ptr = f"{pointer}/{_ptr_escape(key)}"
            yield (child_ptr, "key", key)
            yield from _json_leaves(child, child_ptr)
    elif isinstance(node, list):
        for i, child in enumerate(node):
            yield from _json_leaves(child, f"{pointer}/{i}")
    else:
        yield (pointer, "value", node)


def _ptr_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _ptr_unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _json_set(root: Any, pointer: str, *, value: Any = None, rename_to: str | None = None) -> Any:
    """Return a deep-updated copy of `root` where the node at `pointer` has its
    value replaced (value=) or, for an object member, its key renamed
    (rename_to=). Never mutates the input."""
    if pointer == "":
        return value
    tokens = [_ptr_unescape(t) for t in pointer.lstrip("/").split("/")]
    return _json_set_tokens(root, tokens, value=value, rename_to=rename_to)


def _json_set_tokens(node: Any, tokens: list[str], *, value: Any, rename_to: str | None) -> Any:
    token = tokens[0]
    last = len(tokens) == 1
    if isinstance(node, dict):
        out = dict(node)
        if last:
            if rename_to is not None:
                # rebuild preserving order, swapping just this key's name
                rebuilt = {}
                for k, v in node.items():
                    if k == token:
                        rebuilt[rename_to] = v
                    else:
                        rebuilt[k] = v
                return rebuilt
            out[token] = value
            return out
        out[token] = _json_set_tokens(node[token], tokens[1:], value=value, rename_to=rename_to)
        return out
    if isinstance(node, list):
        idx = int(token)
        out = list(node)
        if last:
            out[idx] = value
        else:
            out[idx] = _json_set_tokens(node[idx], tokens[1:], value=value, rename_to=rename_to)
        return out
    raise InsertionError(f"json-pointer {'/'.join(tokens)!r} does not resolve to a container")


class InsertionError(ValueError):
    """A malformed request or an insertion point that cannot be rendered."""


def _strip_crlf(s: str) -> str:
    """Drop CR/LF. Names (header/cookie/field) render through this so a payload can
    never inject a new header line or split the request framing — a NAME insertion
    is never a request-smuggling primitive (value-position header injection is a
    separate, deliberate surface)."""
    return s.replace("\r", "").replace("\n", "")


# ---------------------------------------------------------------------------
# multipart/form-data codec
# ---------------------------------------------------------------------------
#
# A multipart body is `--BOUNDARY`-delimited body-parts, each `<headers>CRLFCRLF<body>`.
# We keep the split raw so unmodified parts round-trip byte-for-byte
# (``("--"+boundary).join(segments) == body``) and only re-serialise the one part a
# payload targets. Rendering never touches the boundary or the Content-Type, so the
# emitted request stays valid multipart FOR ANY PAYLOAD THAT DOES NOT ITSELF CONTAIN THE
# DELIMITER ``--``+boundary. That residual is irreducible in RFC-2046 (multipart has no
# in-body boundary-escaping mechanism); the only defense is a unique boundary, which we
# preserve verbatim from the original request, and probe payloads never contain the
# request-derived (typically random) boundary token — so a real probe cannot split framing.

_MPART_NAME_RE = re.compile(r'name\s*=\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)


def _ct_params(header_value: str | None) -> dict[str, str]:
    """Parse a Content-Type header's parameters into a lower-cased name->value map,
    unquoting quoted values. Empty/None yields ``{}``."""
    out: dict[str, str] = {}
    if not header_value:
        return out
    for part in header_value.split(";")[1:]:
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        out[name] = value
    return out


def _mpart_unquote(s: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _mpart_quote(s: str) -> str:
    # RFC 2183 quoted-string: backslash-escape '\' and '"'; strip CR/LF so a field
    # name can never break out of its header line.
    return _strip_crlf(s).replace("\\", "\\\\").replace('"', '\\"')


def _parse_mpart_segment(seg: str) -> tuple[str, str, str, str] | None:
    """Split one `--boundary`-delimited segment into
    (leading transport-padding+CRLF, header-block, part-body, trailing CRLF), or
    None if it is not a well-formed body-part."""
    i = 0
    while i < len(seg) and seg[i] in " \t":
        i += 1
    if seg[i:i + 2] != "\r\n":
        return None
    leading = seg[:i + 2]
    rest = seg[i + 2:]
    if not rest.endswith("\r\n"):
        return None
    inner = rest[:-2]
    sep = inner.find("\r\n\r\n")
    if sep == -1:
        return None
    return leading, inner[:sep], inner[sep + 4:], "\r\n"


def _mpart_field_name(header_block: str) -> str:
    for line in header_block.split("\r\n"):
        if line.split(":", 1)[0].strip().lower() == "content-disposition":
            m = _MPART_NAME_RE.search(line)
            if m:
                return _mpart_unquote(m.group(1))
    return ""


def _mpart_set_name(header_block: str, new_name: str) -> str:
    quoted = _mpart_quote(new_name)
    lines = header_block.split("\r\n")
    for idx, line in enumerate(lines):
        if line.split(":", 1)[0].strip().lower() == "content-disposition":
            # function replacement: not subject to backslash/group interpretation.
            lines[idx] = _MPART_NAME_RE.sub(lambda _m: f'name="{quoted}"', line, count=1)
            break
    return "\r\n".join(lines)


def _split_multipart(body: str, boundary: str) -> tuple[list[str], list[dict]] | None:
    """Split ``body`` into its raw `--boundary` segments and a parsed view of its
    body-parts. Returns (segments, parts) or None when the body is not well-formed
    multipart (caller then falls back to a whole-body point). ``segments`` is exactly
    ``body.split("--"+boundary)`` so the join reproduces ``body`` byte-for-byte."""
    delim = "--" + boundary
    segments = body.split(delim)
    if len(segments) < 3 or not segments[-1].startswith("--"):
        return None
    parts: list[dict] = []
    for idx in range(1, len(segments) - 1):
        parsed = _parse_mpart_segment(segments[idx])
        if parsed is None:
            return None
        _leading, header_block, part_body, _trailing = parsed
        parts.append({"seg": idx, "name": _mpart_field_name(header_block), "body": part_body})
    return segments, parts


# ---------------------------------------------------------------------------
# XML codec — a deterministic lexer over the raw document
# ---------------------------------------------------------------------------
#
# ElementTree would re-serialise the whole document (dropping the declaration,
# normalising quoting/self-closing tags). We instead lex the RAW string and record
# the exact character spans of element text nodes and attribute values, so rendering
# replaces exactly one span and preserves every other byte. Comments, CDATA, PIs and
# the DOCTYPE are skipped (not fuzzed).


def _xml_escape_text(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xml_escape_attr(s: str) -> str:
    return _xml_escape_text(s).replace('"', "&quot;").replace("'", "&apos;")


def _xml_spans(body: str) -> list[dict]:
    """Yield, in document order, every fuzzable span: element text nodes and quoted
    attribute values. Each is ``{kind, label, value, start, end}`` where [start:end)
    is the raw region to replace. Deterministic; on anything it cannot parse it simply
    stops emitting (never raises for well-formed-enough input)."""
    spans: list[dict] = []
    n = len(body)
    i = 0
    stack: list[str] = []
    while i < n:
        c = body[i]
        if c == "<":
            if body.startswith("<!--", i):
                end = body.find("-->", i + 4)
                i = (end + 3) if end != -1 else n
                continue
            if body.startswith("<![CDATA[", i):
                end = body.find("]]>", i + 9)
                i = (end + 3) if end != -1 else n
                continue
            if body.startswith("<?", i):
                end = body.find("?>", i + 2)
                i = (end + 2) if end != -1 else n
                continue
            if body.startswith("<!", i):
                end = body.find(">", i + 2)
                i = (end + 1) if end != -1 else n
                continue
            if body.startswith("</", i):
                end = body.find(">", i + 2)
                if end == -1:
                    break
                if stack:
                    stack.pop()
                i = end + 1
                continue
            # start tag
            j = i + 1
            k = j
            while k < n and body[k] not in " \t\r\n/>":
                k += 1
            elem = body[j:k]
            p = k
            while p < n and body[p] != ">":
                if body[p] in " \t\r\n/":
                    p += 1
                    continue
                a = p
                while p < n and body[p] not in "=/> \t\r\n":
                    p += 1
                attr = body[a:p]
                while p < n and body[p] in " \t\r\n":
                    p += 1
                if p < n and body[p] == "=":
                    p += 1
                    while p < n and body[p] in " \t\r\n":
                        p += 1
                    if p < n and body[p] in "\"'":
                        quote = body[p]
                        p += 1
                        vstart = p
                        while p < n and body[p] != quote:
                            p += 1
                        spans.append({"kind": "attr", "label": f"{elem}@{attr}",
                                      "value": body[vstart:p], "start": vstart, "end": p})
                        if p < n:
                            p += 1  # closing quote
            if p >= n:
                break
            self_closing = body[p - 1] == "/"
            if not self_closing:
                stack.append(elem)
            i = p + 1
            continue
        # text node up to the next '<'
        tstart = i
        while i < n and body[i] != "<":
            i += 1
        text = body[tstart:i]
        if text.strip():
            spans.append({"kind": "text", "label": (stack[-1] if stack else "#text"),
                          "value": text, "start": tstart, "end": i})
    return spans


# ---------------------------------------------------------------------------
# nested-blob codec — base64(JSON) and JWT decode -> fuzz -> re-encode
# ---------------------------------------------------------------------------
#
# A value may itself carry a structured document (a session JWT, a base64'd JSON
# state blob). We decode it, expose its inner leaves as insertion points, and on
# render re-encode with exactly one leaf fuzzed. Reversibility is GUARANTEED by
# construction: ``_decode_blob`` returns a blob ONLY when the value re-encodes to
# itself byte-for-byte (the exactness gate in ``_b64_exact``/``_b64url_exact``), and
# a render whose payload equals the leaf's current value returns the original value
# unchanged. So the un-fuzzed round-trip reproduces the original envelope exactly.

_B64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
)


def _is_b64ish(v: str) -> bool:
    return bool(v) and all(c in _B64_CHARS for c in v)


def _b64_encode(raw: bytes, altchars: bytes | None, pad: bool) -> str:
    enc = (base64.b64encode(raw, altchars=altchars) if altchars
           else base64.b64encode(raw)).decode("ascii")
    return enc if pad else enc.rstrip("=")


def _b64_exact(v: str, altchars: bytes | None, pad: bool) -> bytes | None:
    """Decode ``v`` as base64 (std, or url when altchars=b'-_'), but ONLY if
    re-encoding the result reproduces ``v`` byte-for-byte under the same alphabet and
    padding. That exactness is what makes the codec reversible: a value that does not
    re-encode to itself is not a blob."""
    s = v if pad else v + "=" * (-len(v) % 4)
    try:
        raw = base64.b64decode(s, altchars=altchars, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if _b64_encode(raw, altchars, pad) == v else None


def _b64url_exact(seg: str) -> bytes | None:
    for pad in (False, True):
        raw = _b64_exact(seg, b"-_", pad)
        if raw is not None:
            return raw
    return None


def _load_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _dumps_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_get(root: Any, pointer: str) -> Any:
    if pointer == "":
        return root
    node = root
    for tok in pointer.lstrip("/").split("/"):
        tok = _ptr_unescape(tok)
        if isinstance(node, dict):
            node = node[tok]
        elif isinstance(node, list):
            node = node[int(tok)]
        else:
            raise KeyError(pointer)
    return node


def _decode_blob(value: str) -> dict | None:
    """Detect a JWT or a base64(JSON object/array). Returns a blob descriptor or None.
    Only returns a blob whose codec round-trips exactly (see module note)."""
    if not isinstance(value, str) or len(value) < 8:
        return None
    # JWT: header.payload.signature — header & payload are base64url JSON objects.
    if value.count(".") == 2:
        h, p, s = value.split(".")
        if h and p:
            hr, pr = _b64url_exact(h), _b64url_exact(p)
            if hr is not None and pr is not None:
                ho, po = _load_json(hr), _load_json(pr)
                if isinstance(ho, dict) and isinstance(po, dict):
                    return {"codec": "jwt", "segments": [h, p, s], "objs": {"h": ho, "p": po}}
    # base64(JSON object/array), std or url alphabet, padded or not.
    if len(value) >= 16 and _is_b64ish(value):
        for altchars, pad in ((None, True), (b"-_", True), (None, False), (b"-_", False)):
            raw = _b64_exact(value, altchars, pad)
            if raw is None:
                continue
            obj = _load_json(raw)
            if isinstance(obj, (dict, list)):
                return {"codec": "b64json", "alt": altchars, "pad": pad, "obj": obj}
    return None


def _blob_leaves(blob: dict) -> Iterable[tuple[str, Any]]:
    """Yield (json-pointer, value) for every scalar leaf inside the blob. JWT leaves
    are namespaced under ``/h`` (header) and ``/p`` (payload)."""
    root = {"h": blob["objs"]["h"], "p": blob["objs"]["p"]} if blob["codec"] == "jwt" else blob["obj"]
    for pointer, leaf_kind, val in _json_leaves(root, ""):
        if leaf_kind == "value":
            yield pointer, val


def _reencode_blob(original_value: str, prefix: str, payload: str, pointer: str) -> str:
    """Re-derive the blob from ``original_value``, set the leaf at ``pointer`` to
    ``payload``, and re-encode. ``prefix`` (e.g. ``"Bearer "``) is preserved verbatim.
    A no-op payload (equal to the current leaf) returns the original envelope
    unchanged — the reversibility guarantee."""
    blob = _decode_blob(original_value)
    if blob is None:
        raise InsertionError("nested blob no longer decodes")
    if blob["codec"] == "jwt":
        combined = {"h": blob["objs"]["h"], "p": blob["objs"]["p"]}
        if _json_get(combined, pointer) == payload:
            return prefix + original_value
        h_seg, p_seg, s_seg = blob["segments"]
        toks = pointer.lstrip("/").split("/", 1)
        top, sub = toks[0], ("/" + toks[1] if len(toks) > 1 else "")
        if top == "h":
            h_seg = _b64_encode(_dumps_bytes(_json_set(blob["objs"]["h"], sub, value=payload)), b"-_", pad=False)
        elif top == "p":
            p_seg = _b64_encode(_dumps_bytes(_json_set(blob["objs"]["p"], sub, value=payload)), b"-_", pad=False)
        else:
            raise InsertionError(f"nested blob pointer {pointer!r} not in header/payload")
        return prefix + ".".join([h_seg, p_seg, s_seg])
    # b64json
    if _json_get(blob["obj"], pointer) == payload:
        return prefix + original_value
    new_obj = _json_set(blob["obj"], pointer, value=payload)
    return prefix + _b64_encode(_dumps_bytes(new_obj), blob["alt"], blob["pad"])


# ---------------------------------------------------------------------------
# RequestTemplate
# ---------------------------------------------------------------------------


class RequestTemplate:
    """Parses one :class:`HttpRequest` into its insertion points and renders a
    payload into any of them. Construct once per request; call
    :meth:`insertion_points` to enumerate and :meth:`render` to place a payload.

    Deterministic and side-effect-free: it never mutates the original request
    and never touches the network."""

    def __init__(self, request: HttpRequest) -> None:
        self.request = request

    # -- enumerate ---------------------------------------------------------

    def insertion_points(
        self, *, kinds: Iterable[InsertionKind] | None = None
    ) -> list[InsertionPoint]:
        """Every insertion point in the request, in a stable order (path →
        query → cookies → headers → body). Restrict with ``kinds``."""
        want = set(kinds) if kinds is not None else None
        points: list[InsertionPoint] = []
        points.extend(self._path_points())
        points.extend(self._query_points())
        points.extend(self._cookie_points())
        points.extend(self._header_points())
        points.extend(self._body_points())
        # Nested blobs are derived from the string-carrying points already found, so
        # a JWT in a cookie, an Authorization header, a form field or a JSON value all
        # get their inner claims exposed through one uniform pass.
        points.extend(self._nested_blob_points(points))
        if want is not None:
            points = [p for p in points if p.kind in want]
        return points

    def _path_points(self) -> list[InsertionPoint]:
        _, path, _, _ = _split_url(self.request.url)
        segs = path.split("/")
        out: list[InsertionPoint] = []
        for i, seg in enumerate(segs):
            if seg == "":
                continue  # leading '/', empty segments carry nothing to fuzz
            out.append(InsertionPoint(
                kind=InsertionKind.URL_PATH_SEG, name=str(i), locator=str(i),
                base_value=_pct_decode(seg),
            ))
        return out

    def _query_points(self) -> list[InsertionPoint]:
        _, _, query, _ = _split_url(self.request.url)
        out: list[InsertionPoint] = []
        for i, (k, v) in enumerate(_parse_pairs(query)):
            out.append(InsertionPoint(
                kind=InsertionKind.QUERY_VALUE, name=k, locator=str(i), base_value=v,
            ))
            out.append(InsertionPoint(
                kind=InsertionKind.QUERY_NAME, name=k, locator=str(i), base_value=k,
            ))
        return out

    def _cookie_points(self) -> list[InsertionPoint]:
        out: list[InsertionPoint] = []
        cookie_hdr_index = -1
        for i, (k, _) in enumerate(self.request.headers):
            if k.lower() == "cookie":
                cookie_hdr_index = i
                break
        if cookie_hdr_index == -1:
            return out
        cookies = _parse_cookies(self.request.headers[cookie_hdr_index][1])
        for j, (ck, cv) in enumerate(cookies):
            out.append(InsertionPoint(
                kind=InsertionKind.COOKIE_VALUE, name=ck,
                locator=f"{cookie_hdr_index}:{j}", base_value=cv,
            ))
            out.append(InsertionPoint(
                kind=InsertionKind.COOKIE_NAME, name=ck,
                locator=f"{cookie_hdr_index}:{j}", base_value=ck,
            ))
        return out

    def _header_points(self) -> list[InsertionPoint]:
        out: list[InsertionPoint] = []
        for i, (k, v) in enumerate(self.request.headers):
            low = k.lower()
            if low in _MANAGED_HEADERS or low == "cookie":
                continue  # Content-Length is recomputed; Cookie is fuzzed per-value
            out.append(InsertionPoint(
                kind=InsertionKind.HEADER_VALUE, name=k, locator=str(i), base_value=v,
            ))
            out.append(InsertionPoint(
                kind=InsertionKind.HEADER_NAME, name=k, locator=str(i), base_value=k,
            ))
        return out

    def _body_points(self) -> list[InsertionPoint]:
        body = self.request.body
        if body is None or body == "":
            return []
        ct = self.request.content_type()
        if ct == "application/x-www-form-urlencoded":
            out: list[InsertionPoint] = []
            for i, (k, v) in enumerate(_parse_pairs(body)):
                out.append(InsertionPoint(
                    kind=InsertionKind.BODY_FORM_VALUE, name=k, locator=str(i), base_value=v))
                out.append(InsertionPoint(
                    kind=InsertionKind.BODY_FORM_NAME, name=k, locator=str(i), base_value=k))
            return out
        if ct == "application/json":
            try:
                parsed = json.loads(body)
            except (ValueError, TypeError):
                return [self._whole_body_point(body)]
            out2: list[InsertionPoint] = []
            for pointer, leaf_kind, val in _json_leaves(parsed, ""):
                if leaf_kind == "key":
                    out2.append(InsertionPoint(
                        kind=InsertionKind.JSON_KEY, name=pointer or "/",
                        locator=pointer, base_value=str(val)))
                else:
                    out2.append(InsertionPoint(
                        kind=InsertionKind.JSON_VALUE, name=pointer or "/",
                        locator=pointer, base_value="" if val is None else str(val)))
            return out2
        if ct == "multipart/form-data":
            return self._multipart_points(body)
        if ct in ("application/xml", "text/xml") or ct.endswith("+xml"):
            return self._xml_points(body)
        # opaque body (raw, unknown): the whole body is one point
        return [self._whole_body_point(body)]

    def _multipart_points(self, body: str) -> list[InsertionPoint]:
        boundary = _ct_params(self.request.header("content-type")).get("boundary")
        if not boundary:
            return [self._whole_body_point(body)]
        split = _split_multipart(body, boundary)
        if split is None:
            return [self._whole_body_point(body)]
        _segments, parts = split
        out: list[InsertionPoint] = []
        for part in parts:
            out.append(InsertionPoint(
                kind=InsertionKind.MULTIPART_VALUE, name=part["name"],
                locator=str(part["seg"]), base_value=part["body"]))
            out.append(InsertionPoint(
                kind=InsertionKind.MULTIPART_NAME, name=part["name"],
                locator=str(part["seg"]), base_value=part["name"]))
        # Retain the whole-body point (pre-existing surface): a check may still replace
        # the entire body — the parts are additive, not a replacement.
        out.append(self._whole_body_point(body))
        return out

    def _xml_points(self, body: str) -> list[InsertionPoint]:
        try:
            spans = _xml_spans(body)
        except Exception:
            spans = []
        out: list[InsertionPoint] = []
        for sp in spans:
            kind = InsertionKind.XML_ATTR if sp["kind"] == "attr" else InsertionKind.XML_TEXT
            out.append(InsertionPoint(
                kind=kind, name=sp["label"],
                locator=f'{sp["start"]}:{sp["end"]}', base_value=sp["value"]))
        # The whole-body point is REQUIRED for XML: an XXE payload injects a DOCTYPE into
        # the document prolog, which is a whole-document rewrite, not an element-node edit.
        out.append(self._whole_body_point(body))
        return out

    # kinds whose base_value is a free string that might itself carry a nested blob.
    _BLOB_CARRIER_KINDS = frozenset({
        InsertionKind.QUERY_VALUE, InsertionKind.COOKIE_VALUE, InsertionKind.HEADER_VALUE,
        InsertionKind.BODY_FORM_VALUE, InsertionKind.JSON_VALUE, InsertionKind.MULTIPART_VALUE,
    })

    def _nested_blob_points(self, existing: list[InsertionPoint]) -> list[InsertionPoint]:
        """For every string-carrying point whose value decodes to a JWT or base64(JSON),
        emit a NESTED_BLOB point per inner scalar leaf. Rendering re-encodes the blob and
        places it back through the CARRIER point's own render path, so the emitted request
        is valid and gated exactly like any other."""
        out: list[InsertionPoint] = []
        for p in existing:
            if p.kind not in self._BLOB_CARRIER_KINDS:
                continue
            carried, prefix = p.base_value, ""
            blob = _decode_blob(carried)
            if blob is None and " " in p.base_value:
                # scheme-prefixed carriers, e.g. `Authorization: Bearer <jwt>`.
                scheme, _, rest = p.base_value.partition(" ")
                alt = _decode_blob(rest)
                if alt is not None:
                    blob, carried, prefix = alt, rest, scheme + " "
            if blob is None:
                continue
            for pointer, leafval in _blob_leaves(blob):
                spec = {"o": p.kind.value, "l": p.locator, "p": prefix, "ptr": pointer, "b": carried}
                out.append(InsertionPoint(
                    kind=InsertionKind.NESTED_BLOB, name=f"{p.name}{pointer}",
                    locator=json.dumps(spec, sort_keys=True, separators=(",", ":")),
                    base_value="" if leafval is None else str(leafval)))
        return out

    @staticmethod
    def _whole_body_point(body: str) -> InsertionPoint:
        return InsertionPoint(
            kind=InsertionKind.BODY_WHOLE, name="body", locator="whole", base_value=body)

    # -- render ------------------------------------------------------------

    def render(self, point: InsertionPoint, payload: str) -> HttpRequest:
        """Return a new :class:`HttpRequest` with ``payload`` placed at
        ``point`` and everything else preserved; Content-Length is corrected
        whenever the body changes."""
        r = self.request
        method, url, headers, body = r.method, r.url, list(r.headers), r.body

        k = point.kind
        if k is InsertionKind.URL_PATH_SEG:
            url = self._render_path(url, int(point.locator), payload)
        elif k in (InsertionKind.QUERY_VALUE, InsertionKind.QUERY_NAME):
            url = self._render_query(url, int(point.locator), payload, rename=(k is InsertionKind.QUERY_NAME))
        elif k in (InsertionKind.COOKIE_VALUE, InsertionKind.COOKIE_NAME):
            hidx, cidx = (int(x) for x in point.locator.split(":"))
            headers = self._render_cookie(headers, hidx, cidx, payload,
                                          rename=(k is InsertionKind.COOKIE_NAME))
        elif k is InsertionKind.HEADER_VALUE:
            idx = int(point.locator)
            headers = list(headers)
            headers[idx] = (headers[idx][0], payload)
        elif k is InsertionKind.HEADER_NAME:
            idx = int(point.locator)
            headers = list(headers)
            headers[idx] = (_strip_crlf(payload), headers[idx][1])
        elif k in (InsertionKind.BODY_FORM_VALUE, InsertionKind.BODY_FORM_NAME):
            body = self._render_form_body(body or "", int(point.locator), payload,
                                          rename=(k is InsertionKind.BODY_FORM_NAME))
        elif k in (InsertionKind.JSON_VALUE, InsertionKind.JSON_KEY):
            body = self._render_json_body(body or "", point, payload)
        elif k in (InsertionKind.MULTIPART_VALUE, InsertionKind.MULTIPART_NAME):
            body = self._render_multipart(body or "", int(point.locator), payload,
                                          rename=(k is InsertionKind.MULTIPART_NAME))
        elif k in (InsertionKind.XML_TEXT, InsertionKind.XML_ATTR):
            start, end = (int(x) for x in point.locator.split(":"))
            body = self._render_xml(body or "", start, end, payload,
                                    is_attr=(k is InsertionKind.XML_ATTR))
        elif k is InsertionKind.NESTED_BLOB:
            return self._render_nested_blob(point, payload)
        elif k is InsertionKind.BODY_WHOLE:
            body = payload
        else:  # pragma: no cover - exhaustive above
            raise InsertionError(f"unhandled insertion kind {k!r}")

        if body != r.body:
            headers = self._fix_content_length(headers, body)
        return HttpRequest(method=method, url=url, headers=headers, body=body)

    # -- render helpers ----------------------------------------------------

    @staticmethod
    def _render_path(url: str, seg_index: int, payload: str) -> str:
        auth, path, query, frag = _split_url(url)
        segs = path.split("/")
        if not (0 <= seg_index < len(segs)):
            raise InsertionError(f"path segment {seg_index} out of range")
        segs[seg_index] = _pct_encode(payload, safe="")
        return _join_url(auth, "/".join(segs), query, frag)

    @staticmethod
    def _render_query(url: str, index: int, payload: str, *, rename: bool) -> str:
        auth, path, query, frag = _split_url(url)
        pairs = _parse_pairs(query)
        if not (0 <= index < len(pairs)):
            raise InsertionError(f"query param {index} out of range")
        k, v = pairs[index]
        pairs[index] = (payload, v) if rename else (k, payload)
        return _join_url(auth, path, _encode_pairs(pairs), frag)

    @staticmethod
    def _render_cookie(headers: list[tuple[str, str]], hidx: int, cidx: int, payload: str,
                       *, rename: bool = False) -> list[tuple[str, str]]:
        headers = list(headers)
        cookies = _parse_cookies(headers[hidx][1])
        if not (0 <= cidx < len(cookies)):
            raise InsertionError(f"cookie {cidx} out of range")
        ck, cv = cookies[cidx]
        cookies[cidx] = (_strip_crlf(payload), cv) if rename else (ck, payload)
        headers[hidx] = (headers[hidx][0], _encode_cookies(cookies))
        return headers

    def _render_multipart(self, body: str, seg_index: int, payload: str, *, rename: bool) -> str:
        boundary = _ct_params(self.request.header("content-type")).get("boundary")
        if not boundary:
            raise InsertionError("multipart body without a boundary")
        split = _split_multipart(body, boundary)
        if split is None:
            raise InsertionError("body is not well-formed multipart")
        segments, _parts = split
        if not (0 < seg_index < len(segments) - 1):
            raise InsertionError(f"multipart segment {seg_index} out of range")
        parsed = _parse_mpart_segment(segments[seg_index])
        if parsed is None:  # pragma: no cover - _split_multipart already validated it
            raise InsertionError("multipart segment is not a body-part")
        leading, header_block, part_body, trailing = parsed
        if rename:
            header_block = _mpart_set_name(header_block, payload)
        else:
            part_body = payload
        segments[seg_index] = leading + header_block + "\r\n\r\n" + part_body + trailing
        return ("--" + boundary).join(segments)

    @staticmethod
    def _render_xml(body: str, start: int, end: int, payload: str, *, is_attr: bool) -> str:
        if not (0 <= start <= end <= len(body)):
            raise InsertionError("xml span out of range")
        escaped = _xml_escape_attr(payload) if is_attr else _xml_escape_text(payload)
        return body[:start] + escaped + body[end:]

    def _render_nested_blob(self, point: InsertionPoint, payload: str) -> HttpRequest:
        try:
            spec = json.loads(point.locator)
        except ValueError as e:  # pragma: no cover - locator is engine-produced
            raise InsertionError(f"malformed nested-blob locator: {e}") from e
        reencoded = _reencode_blob(spec["b"], spec["p"], payload, spec["ptr"])
        outer = InsertionPoint(
            kind=InsertionKind(spec["o"]), name="(blob-carrier)",
            locator=spec["l"], base_value="")
        # Reuse the carrier's own render path — the emitted request is valid and gated
        # exactly as if the re-encoded blob had been the payload for that carrier.
        return self.render(outer, reencoded)

    @staticmethod
    def _render_form_body(body: str, index: int, payload: str, *, rename: bool) -> str:
        pairs = _parse_pairs(body)
        if not (0 <= index < len(pairs)):
            raise InsertionError(f"form param {index} out of range")
        k, v = pairs[index]
        pairs[index] = (payload, v) if rename else (k, payload)
        return _encode_pairs(pairs)

    @staticmethod
    def _render_json_body(body: str, point: InsertionPoint, payload: str) -> str:
        try:
            root = json.loads(body)
        except (ValueError, TypeError) as e:
            raise InsertionError(f"body is not JSON: {e}") from e
        if point.kind is InsertionKind.JSON_KEY:
            updated = _json_set(root, point.locator, rename_to=payload)
        else:
            updated = _json_set(root, point.locator, value=payload)
        # compact, stable serialization (sort_keys off to preserve author order)
        return json.dumps(updated, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _fix_content_length(headers: list[tuple[str, str]], body: str | None) -> list[tuple[str, str]]:
        n = len((body or "").encode("utf-8"))
        out: list[tuple[str, str]] = []
        found = False
        for k, v in headers:
            if k.lower() == "content-length":
                out.append((k, str(n)))
                found = True
            else:
                out.append((k, v))
        if not found and body:
            out.append(("Content-Length", str(n)))
        return out
