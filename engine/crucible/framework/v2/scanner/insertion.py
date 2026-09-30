"""
scanner.insertion — the insertion-point engine.

Every active web check is an (insertion-point × payload × analyzer) triple.
Burp's coverage comes from firing N checks across M insertion points; CRUCIBLE
today substitutes one hardcoded parameter. This module closes that gap with a
complete, deterministic engine that:

  * parses a raw HTTP request into every markable insertion point Burp knows —
    URL path segments, query values, query *names*, urlencoded-body values and
    names, cookies, request headers, and nested JSON values and *keys*; and
  * renders a payload into exactly one point, rebuilding the request with
    correct percent-encoding, a corrected Content-Length, and everything else
    byte-preserved.

It is pure: no network, no clock, no randomness — the same request always yields
the same ordered insertion points, and the same (point, payload) always renders
the same bytes. It sends nothing; the audit engine issues rendered requests
through the existing ``agents.http_executor`` safety stack.
"""

from __future__ import annotations

import enum
import json
import re
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urljoin

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # annotation only — importing discovery at runtime would cycle
    from .discovery import ApiOperation

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
    HEADER_VALUE = "header_value"     # a request header value
    JSON_VALUE = "json_value"         # a JSON leaf value at a json-pointer
    JSON_KEY = "json_key"             # a JSON object key at a json-pointer
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
        # opaque body (XML, raw, unknown): the whole body is one point
        return [self._whole_body_point(body)]

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
        elif k is InsertionKind.COOKIE_VALUE:
            hidx, cidx = (int(x) for x in point.locator.split(":"))
            headers = self._render_cookie(headers, hidx, cidx, payload)
        elif k is InsertionKind.HEADER_VALUE:
            idx = int(point.locator)
            headers = list(headers)
            headers[idx] = (headers[idx][0], payload)
        elif k in (InsertionKind.BODY_FORM_VALUE, InsertionKind.BODY_FORM_NAME):
            body = self._render_form_body(body or "", int(point.locator), payload,
                                          rename=(k is InsertionKind.BODY_FORM_NAME))
        elif k in (InsertionKind.JSON_VALUE, InsertionKind.JSON_KEY):
            body = self._render_json_body(body or "", point, payload)
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
    def _render_cookie(headers: list[tuple[str, str]], hidx: int, cidx: int, payload: str) -> list[tuple[str, str]]:
        headers = list(headers)
        cookies = _parse_cookies(headers[hidx][1])
        if not (0 <= cidx < len(cookies)):
            raise InsertionError(f"cookie {cidx} out of range")
        ck, _ = cookies[cidx]
        cookies[cidx] = (ck, payload)
        headers[hidx] = (headers[hidx][0], _encode_cookies(cookies))
        return headers

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


# ---------------------------------------------------------------------------
# API-operation -> request bridge
# ---------------------------------------------------------------------------
#
# The discovery layer (scanner.discovery.parse_openapi) lifts an OpenAPI/Swagger
# document into a flat list of ``ApiOperation``s (method + path + declared param
# names). This is the structural link that turns one such operation into a concrete
# ``HttpRequest`` the audit engine can then decompose into insertion points and
# fuzz — exactly like a crawled request. It SHAPES a request only: it sends
# nothing, so the operation reaches the target solely through the engine's gated
# executor, and it is audit SURFACE, never a finding on its own.

# Methods that carry a request body by convention. For these, declared params are
# placed in the body (in ``body_media_type``); for every other method they go in
# the query string. ``ApiOperation`` does not retain OpenAPI's per-parameter
# ``in:`` location, so this method convention is the deterministic mapping.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

# OpenAPI path templating: ``/users/{id}`` — a braced token is a PATH parameter,
# filled inline with a benign placeholder so the rendered path is concrete (and the
# templated name is not ALSO emitted as a query/body param).
_PATH_TEMPLATE = re.compile(r"\{[^{}/]+\}")


def request_from_api_operation(
    operation: "ApiOperation",
    base_url: str,
    *,
    body_media_type: str = "application/json",
    fill: str = "1",
) -> HttpRequest:
    """Bridge one discovered OpenAPI/Swagger operation into a concrete, fuzzable
    :class:`HttpRequest` — the structural link from ``scanner.discovery.parse_openapi``
    to the insertion-point engine, so a documented-but-unlinked API route becomes
    audit surface.

    The operation's ``method`` and ``path`` set the request line: the path is
    resolved against ``base_url`` and any ``{template}`` segment is filled by
    ``fill`` so it is concrete. Declared parameters become a benign, well-formed
    baseline the audit engine then mutates one point at a time:

      * a body method (POST/PUT/PATCH) renders them into the body in
        ``body_media_type`` — a JSON object (``application/json``, the default) or a
        urlencoded form — with a matching Content-Type and a correct Content-Length;
      * every other method renders them as query-string values.

    Path-template names are consumed by the path and never duplicated into the
    query/body. An operation with no free params yields a bare request (its path +
    method are still surface). Pure and deterministic (no network, no clock): the
    same operation always yields the same request bytes. Like every crawl seed it
    only SHAPES a request — the oracle still has to fire over the gated response for
    anything to be confirmed."""
    method = (operation.method or "GET").upper()
    raw_path = operation.path or "/"
    templated_names = {tok[1:-1] for tok in _PATH_TEMPLATE.findall(raw_path)}
    concrete_path = _PATH_TEMPLATE.sub(fill, raw_path)
    url = urljoin(base_url, concrete_path)

    free: list[str] = []
    seen: set[str] = set()
    for p in operation.params:
        if not p or p in templated_names or p in seen:
            continue
        seen.add(p)
        free.append(p)

    if not free:
        return HttpRequest(method=method, url=url)

    if method in _BODY_METHODS:
        media = body_media_type.split(";", 1)[0].strip().lower()
        if media == "application/json":
            body = json.dumps({name: fill for name in free},
                              separators=(",", ":"), ensure_ascii=False)
        else:
            body = _encode_pairs([(name, fill) for name in free])
        headers = [("Content-Type", body_media_type),
                   ("Content-Length", str(len(body.encode("utf-8"))))]
        return HttpRequest(method=method, url=url, headers=headers, body=body)

    query = _encode_pairs([(name, fill) for name in free])
    sep = "&" if "?" in url else "?"
    return HttpRequest(method=method, url=url + sep + query)
