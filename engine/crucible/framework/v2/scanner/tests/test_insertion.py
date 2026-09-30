"""
Insertion-point engine — real parse/render behavior across every point type.

These tests exercise the actual codecs (no fixtures shaped to pass): they parse
concrete requests, assert the enumerated points, render a payload into each, and
verify the rendered request places the payload correctly, encodes it, corrects
Content-Length, and preserves everything else byte-for-byte.
"""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET

from framework.v2.scanner.checks import REFLECTED_XSS
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import (
    HttpRequest,
    InsertionKind,
    RequestTemplate,
    _decode_blob,
    _reencode_blob,
)

_PAYLOAD = "' OR 1=1-- x"
_MARK = "MARK<script>"


def _jwt(header: dict, payload: dict, sig: str = "SIG") -> str:
    def _seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
    return f"{_seg(header)}.{_seg(payload)}.{sig}"


def _jwt_claim(token: str, claim: str) -> object:
    seg = token.split(".")[1]
    obj = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return obj.get(claim)


def _mp_fields(req: HttpRequest) -> dict[str, str]:
    """Independent multipart parser (does NOT use the engine's own codec) so a
    passing test proves the emitted body is parseable by a second implementation."""
    ct = req.header("content-type") or ""
    boundary = ""
    for part in ct.split(";")[1:]:
        k, _, v = part.partition("=")
        if k.strip().lower() == "boundary":
            boundary = v.strip().strip('"')
    out: dict[str, str] = {}
    for seg in (req.body or "").split("--" + boundary)[1:-1]:
        seg = seg[2:] if seg.startswith("\r\n") else seg
        head, _, rest = seg.partition("\r\n\r\n")
        value = rest[:-2] if rest.endswith("\r\n") else rest
        m = re.search(r'name="((?:[^"\\]|\\.)*)"', head)
        name = re.sub(r"\\(.)", r"\1", m.group(1)) if m else ""
        out[name] = value
    return out


def _reflect(value: str) -> dict:
    """A vulnerable sink: reflect a value verbatim into an HTML document. The
    REFLECTED_XSS canary (``"'><x{marker}>``) becomes a live <x…> tag, which the
    reflection-context oracle confirms."""
    return {"status": 200, "body": f"<html><body>result: {value}</body></html>"}


def _no_reflect() -> dict:
    return {"status": 200, "body": "<html><body>static, nothing echoed</body></html>"}


def _pairs(query: str) -> dict[str, str]:
    from framework.v2.scanner.insertion import _parse_pairs
    return dict(_parse_pairs(query))


def test_query_value_and_name_points() -> None:
    req = HttpRequest(method="GET", url="https://t/app?id=7&role=user")
    t = RequestTemplate(req)
    pts = t.insertion_points(kinds=[InsertionKind.QUERY_VALUE, InsertionKind.QUERY_NAME])
    names = {(p.kind, p.name, p.base_value) for p in pts}
    assert (InsertionKind.QUERY_VALUE, "id", "7") in names
    assert (InsertionKind.QUERY_NAME, "role", "role") in names

    # render into the `id` value: payload placed + percent-encoded, other param intact
    idv = next(p for p in pts if p.kind is InsertionKind.QUERY_VALUE and p.name == "id")
    out = t.render(idv, _PAYLOAD)
    q = out.url.split("?", 1)[1]
    parsed = _pairs(q)
    assert parsed["id"] == _PAYLOAD and parsed["role"] == "user"
    assert "%20" in q or "%27" in q, "payload must be percent-encoded in the query"

    # render a param NAME: the name becomes the payload, value preserved
    rolen = next(p for p in pts if p.kind is InsertionKind.QUERY_NAME and p.name == "role")
    out2 = t.render(rolen, "injected")
    assert _pairs(out2.url.split("?", 1)[1]) == {"id": "7", "injected": "user"}


def test_url_path_segment_point() -> None:
    req = HttpRequest(method="GET", url="https://t/api/users/42/profile?x=1")
    t = RequestTemplate(req)
    segs = [p for p in t.insertion_points() if p.kind is InsertionKind.URL_PATH_SEG]
    assert {p.base_value for p in segs} == {"api", "users", "42", "profile"}
    idseg = next(p for p in segs if p.base_value == "42")
    out = t.render(idseg, "1337")
    assert "/api/users/1337/profile" in out.url
    assert out.url.endswith("?x=1"), "query preserved when fuzzing the path"


def test_cookie_value_point() -> None:
    req = HttpRequest(url="https://t/", headers=[("Cookie", "session=abc; theme=dark")])
    t = RequestTemplate(req)
    cookies = [p for p in t.insertion_points() if p.kind is InsertionKind.COOKIE_VALUE]
    assert {(p.name, p.base_value) for p in cookies} == {("session", "abc"), ("theme", "dark")}
    sess = next(p for p in cookies if p.name == "session")
    out = t.render(sess, _PAYLOAD)
    assert out.header("Cookie") == f"session={_PAYLOAD}; theme=dark"


def test_header_value_point_excludes_managed() -> None:
    req = HttpRequest(
        url="https://t/",
        headers=[("Host", "t"), ("User-Agent", "ua"), ("Content-Length", "0"), ("Cookie", "a=b")],
    )
    t = RequestTemplate(req)
    hdrs = [p for p in t.insertion_points() if p.kind is InsertionKind.HEADER_VALUE]
    got = {p.name for p in hdrs}
    assert "Host" in got and "User-Agent" in got  # Host IS fuzzable (host-header attacks)
    assert "Content-Length" not in got, "managed header must not be an insertion point"
    assert "Cookie" not in got, "Cookie is fuzzed per-value, not as a header"

    host = next(p for p in hdrs if p.name == "Host")
    out = t.render(host, "evil.example")
    assert out.header("Host") == "evil.example"
    assert out.header("User-Agent") == "ua", "other headers preserved"


def test_urlencoded_body_value_and_name_with_content_length() -> None:
    body = "user=alice&role=user"
    req = HttpRequest(
        method="POST", url="https://t/login",
        headers=[("Content-Type", "application/x-www-form-urlencoded"), ("Content-Length", str(len(body)))],
        body=body,
    )
    t = RequestTemplate(req)
    vals = [p for p in t.insertion_points() if p.kind is InsertionKind.BODY_FORM_VALUE]
    assert {(p.name, p.base_value) for p in vals} == {("user", "alice"), ("role", "user")}

    role = next(p for p in vals if p.name == "role")
    out = t.render(role, "admin")
    assert _pairs(out.body) == {"user": "alice", "role": "admin"}
    assert out.header("Content-Length") == str(len(out.body)), "Content-Length recomputed"


def test_json_nested_value_and_key_points() -> None:
    payload_obj = {"user": {"id": 5, "name": "bob"}, "roles": ["a", "b"]}
    body = json.dumps(payload_obj)
    req = HttpRequest(
        method="POST", url="https://t/api",
        headers=[("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        body=body,
    )
    t = RequestTemplate(req)
    jvals = [p for p in t.insertion_points() if p.kind is InsertionKind.JSON_VALUE]
    jkeys = [p for p in t.insertion_points() if p.kind is InsertionKind.JSON_KEY]
    ptrs = {p.locator for p in jvals}
    assert "/user/id" in ptrs and "/user/name" in ptrs and "/roles/0" in ptrs and "/roles/1" in ptrs
    assert any(p.locator == "/user/name" for p in jkeys)  # object keys are points too

    # render a nested value: payload set at the pointer, structure preserved
    name = next(p for p in jvals if p.locator == "/user/name")
    out = t.render(name, _MARK)
    got = json.loads(out.body)
    assert got["user"]["name"] == _MARK and got["user"]["id"] == 5 and got["roles"] == ["a", "b"]
    assert out.header("Content-Length") == str(len(out.body.encode("utf-8")))

    # render a KEY rename: the member name changes, its value kept, order preserved
    keyp = next(p for p in jkeys if p.locator == "/user/id")
    out2 = t.render(keyp, "identifier")
    got2 = json.loads(out2.body)
    assert got2["user"]["identifier"] == 5 and "id" not in got2["user"]
    assert list(got2["user"].keys()) == ["identifier", "name"], "member order preserved on rename"


def test_opaque_body_is_one_whole_point() -> None:
    # A content-type the engine has no structured decoder for stays a single opaque
    # point (XML and multipart, formerly opaque, are now structured — see below).
    body = "\x00\x01rawbinaryblob\x02"
    req = HttpRequest(
        method="POST", url="https://t/upload",
        headers=[("Content-Type", "application/octet-stream"), ("Content-Length", str(len(body)))],
        body=body,
    )
    t = RequestTemplate(req)
    pts = [p for p in t.insertion_points() if p.kind is InsertionKind.BODY_WHOLE]
    assert len(pts) == 1 and pts[0].base_value == body
    out = t.render(pts[0], "REPLACED")
    assert out.body == "REPLACED" and out.header("Content-Length") == "8"


def test_render_is_pure_and_targets_exact_occurrence() -> None:
    # duplicate param names must be individually addressable, and the original
    # request must be untouched by render (purity).
    req = HttpRequest(url="https://t/s?x=1&x=2&x=3")
    t = RequestTemplate(req)
    xs = [p for p in t.insertion_points() if p.kind is InsertionKind.QUERY_VALUE]
    assert [p.base_value for p in xs] == ["1", "2", "3"]
    out = t.render(xs[1], "HIT")  # only the middle occurrence
    from framework.v2.scanner.insertion import _parse_pairs
    assert [v for _, v in _parse_pairs(out.url.split("?", 1)[1])] == ["1", "HIT", "3"]
    assert req.url == "https://t/s?x=1&x=2&x=3", "original request must be unchanged"


def test_enumeration_is_deterministic() -> None:
    req = HttpRequest(
        method="POST", url="https://t/a/b?q=1",
        headers=[("Cookie", "s=1"), ("X-Test", "v"), ("Content-Type", "application/x-www-form-urlencoded")],
        body="f=2",
    )
    a = [p.id for p in RequestTemplate(req).insertion_points()]
    b = [p.id for p in RequestTemplate(req).insertion_points()]
    assert a == b and len(a) == len(set(a)), "stable, unique insertion-point ids"


# ===========================================================================
# C3 — widened insertion model: cookie/header NAMES, multipart, XML, nested blob
# ===========================================================================


def _confirm_xss(req: HttpRequest, send, kinds) -> list:
    """Sweep REFLECTED_XSS over `kinds` against `send` and return oracle-confirmed
    XSS findings — the same gated audit pipeline every insertion point flows through."""
    findings = AuditEngine(send).audit(req, checks=(REFLECTED_XSS,), insertion_kinds=tuple(kinds))
    return [f for f in findings if f.bug_class == "xss"]


# --- cookie NAME -----------------------------------------------------------


def test_cookie_name_point_and_render() -> None:
    req = HttpRequest(url="https://t/", headers=[("Cookie", "session=abc; theme=dark")])
    t = RequestTemplate(req)
    names = [p for p in t.insertion_points() if p.kind is InsertionKind.COOKIE_NAME]
    assert {(p.name, p.base_value) for p in names} == {("session", "session"), ("theme", "theme")}
    sess = next(p for p in names if p.name == "session")
    out = t.render(sess, "renamed")
    assert out.header("Cookie") == "renamed=abc; theme=dark", "cookie key renamed, value kept"


def test_cookie_name_reaches_oracle_only_via_cookie_name() -> None:
    # sink reflects the set of COOKIE NAMES; the value is never echoed.
    def send(req: HttpRequest) -> dict:
        cookie = req.header("Cookie") or ""
        names = [c.split("=", 1)[0].strip() for c in cookie.split(";") if c.strip()]
        return _reflect(" ".join(names))
    req = HttpRequest(url="https://t/", headers=[("Cookie", "sid=xyz")])
    # value sweep cannot reach a name-only sink; name sweep confirms it.
    assert _confirm_xss(req, send, [InsertionKind.COOKIE_VALUE]) == []
    hits = _confirm_xss(req, send, [InsertionKind.COOKIE_NAME])
    assert hits and hits[0].insertion_point.startswith("cookie_name:")
    assert hits[0].confirmed_by == "reflection_context"


# --- header NAME -----------------------------------------------------------


def test_header_name_point_and_render() -> None:
    req = HttpRequest(url="https://t/", headers=[("X-Api", "v1"), ("Content-Length", "0")])
    t = RequestTemplate(req)
    names = {p.name for p in t.insertion_points() if p.kind is InsertionKind.HEADER_NAME}
    assert "X-Api" in names and "Content-Length" not in names, "managed header name not fuzzed"
    p = next(p for p in t.insertion_points() if p.kind is InsertionKind.HEADER_NAME)
    out = t.render(p, "X-Injected")
    assert out.header("X-Injected") == "v1" and out.header("X-Api") is None


def test_header_name_render_strips_crlf() -> None:
    req = HttpRequest(url="https://t/", headers=[("X-Api", "v1")])
    t = RequestTemplate(req)
    p = next(p for p in t.insertion_points() if p.kind is InsertionKind.HEADER_NAME)
    out = t.render(p, "Evil\r\nX-Smuggled: 1")
    assert all("\r" not in k and "\n" not in k for k, _ in out.headers), "no CRLF in a rendered header name"


def test_header_name_reaches_oracle_only_via_header_name() -> None:
    def send(req: HttpRequest) -> dict:
        return _reflect(" ".join(k for k, _ in req.headers))  # reflects header NAMES
    req = HttpRequest(url="https://t/", headers=[("X-Trace", "t1")])
    assert _confirm_xss(req, send, [InsertionKind.HEADER_VALUE]) == []
    hits = _confirm_xss(req, send, [InsertionKind.HEADER_NAME])
    assert hits and hits[0].insertion_point.startswith("header_name:")


# --- multipart/form-data ---------------------------------------------------


_BOUNDARY = "----crucibleBoundary42"


def _multipart_req() -> HttpRequest:
    body = (
        f"--{_BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="comment"\r\n\r\n'
        "hello\r\n"
        f"--{_BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="upload"; filename="a.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "FILE-CONTENT\r\n"
        f"--{_BOUNDARY}--\r\n"
    )
    return HttpRequest(
        method="POST", url="https://t/submit",
        headers=[("Content-Type", f"multipart/form-data; boundary={_BOUNDARY}"),
                 ("Content-Length", str(len(body)))],
        body=body,
    )


def test_multipart_value_and_name_points_and_render() -> None:
    t = RequestTemplate(_multipart_req())
    vals = [p for p in t.insertion_points() if p.kind is InsertionKind.MULTIPART_VALUE]
    names = [p for p in t.insertion_points() if p.kind is InsertionKind.MULTIPART_NAME]
    assert {(p.name, p.base_value) for p in vals} == {("comment", "hello"), ("upload", "FILE-CONTENT")}
    assert {p.base_value for p in names} == {"comment", "upload"}

    comment = next(p for p in vals if p.name == "comment")
    out = t.render(comment, "PWNED")
    fields = _mp_fields(out)  # parseable by an INDEPENDENT multipart parser
    assert fields == {"comment": "PWNED", "upload": "FILE-CONTENT"}, "one part changed, others intact"
    assert out.header("Content-Length") == str(len(out.body.encode("utf-8")))
    assert out.content_type() == "multipart/form-data", "Content-Type (with boundary) preserved"

    # rename a field; the multipart stays valid and only that field's name changes.
    out2 = t.render(names[0], "attacker")
    assert set(_mp_fields(out2)) == {"attacker", "upload"}


def test_multipart_value_reaches_oracle_only_via_that_part() -> None:
    def send(req: HttpRequest) -> dict:
        return _reflect(_mp_fields(req).get("comment", ""))  # only the comment part is a sink
    req = _multipart_req()
    hits = _confirm_xss(req, send, [InsertionKind.MULTIPART_VALUE])
    assert hits, "payload in the comment part was not confirmed"
    assert all(h.param == "comment" for h in hits), "only the reflected part fired"
    assert hits[0].insertion_point.startswith("multipart_value:")


# --- XML -------------------------------------------------------------------


def _xml_req() -> HttpRequest:
    body = '<order id="7"><comment>hi</comment><qty>1</qty></order>'
    return HttpRequest(
        method="POST", url="https://t/api",
        headers=[("Content-Type", "application/xml"), ("Content-Length", str(len(body)))],
        body=body,
    )


def test_xml_text_and_attr_points_and_escaped_render() -> None:
    t = RequestTemplate(_xml_req())
    texts = [p for p in t.insertion_points() if p.kind is InsertionKind.XML_TEXT]
    attrs = [p for p in t.insertion_points() if p.kind is InsertionKind.XML_ATTR]
    assert {(p.name, p.base_value) for p in texts} == {("comment", "hi"), ("qty", "1")}
    assert {(p.name, p.base_value) for p in attrs} == {("order@id", "7")}

    comment = next(p for p in texts if p.name == "comment")
    out = t.render(comment, "<script>&")
    # placed as WELL-FORMED xml (escaped); the rest of the document is byte-preserved.
    assert "<comment>&lt;script&gt;&amp;</comment>" in out.body
    assert ET.fromstring(out.body).find("comment").text == "<script>&", "server parses back the raw payload"
    assert '<qty>1</qty>' in out.body and 'id="7"' in out.body

    attr = attrs[0]
    outa = t.render(attr, 'x"y')
    assert 'id="x&quot;y"' in outa.body
    assert ET.fromstring(outa.body).get("id") == 'x"y'


def test_xml_text_reaches_oracle_only_via_xml_node() -> None:
    # sink parses the XML and reflects the <comment> text (entity-decoded) into HTML.
    def send(req: HttpRequest) -> dict:
        try:
            text = ET.fromstring(req.body).find("comment").text or ""
        except Exception:
            text = ""
        return _reflect(text)
    req = _xml_req()
    hits = _confirm_xss(req, send, [InsertionKind.XML_TEXT])
    assert hits, "XML-borne payload not confirmed"
    assert any(h.param == "comment" for h in hits)
    assert hits[0].insertion_point.startswith("xml_text:")


# --- nested blob (JWT / base64-JSON) --------------------------------------


def test_nested_blob_jwt_points_and_fuzz() -> None:
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "role": "user"})
    req = HttpRequest(url="https://t/", headers=[("Cookie", f"session={token}")])
    t = RequestTemplate(req)
    blobs = [p for p in t.insertion_points() if p.kind is InsertionKind.NESTED_BLOB]
    ptrs = {p.name: p for p in blobs}
    assert "session/p/role" in ptrs and "session/p/sub" in ptrs and "session/h/alg" in ptrs

    out = t.render(ptrs["session/p/role"], "admin")
    new_token = (out.header("Cookie")).split("=", 1)[1]
    h, p, s = new_token.split(".")
    assert s == "SIG", "signature segment byte-preserved"
    assert h == token.split(".")[0], "untouched header segment byte-preserved"
    assert _jwt_claim(new_token, "role") == "admin" and _jwt_claim(new_token, "sub") == "alice"


def test_nested_blob_roundtrip_is_faithful() -> None:
    # base64(JSON): an un-fuzzed re-encode returns the ORIGINAL envelope byte-for-byte —
    # even from non-compact source JSON, because the codec preserves the exact bytes and
    # a no-op payload returns the original value untouched. Both alphabets, padded or not.
    for raw_json in ('{"user": "alice", "admin": false}',   # spaced
                     '{"user":"alice","admin":false}'):     # compact
        for enc in (base64.b64encode(raw_json.encode()).decode(),
                    base64.urlsafe_b64encode(raw_json.encode()).rstrip(b"=").decode()):
            blob = _decode_blob(enc)
            assert blob is not None, f"should decode: {enc!r}"
            assert _reencode_blob(enc, "", "alice", "/user") == enc, "un-fuzzed round-trip is byte-exact"
            # a real fuzz changes the claim and the blob stays decodable / other claims intact.
            got = _decode_blob(_reencode_blob(enc, "", "PWN", "/user"))
            assert got is not None and got["obj"]["user"] == "PWN" and got["obj"]["admin"] is False

    # JWT: un-fuzzed re-encode reproduces the whole token; a fuzz touches only its segment.
    token = _jwt({"alg": "HS256"}, {"sub": "alice", "n": 5}, sig="ZZZ")
    assert _reencode_blob(token, "", "alice", "/p/sub") == token, "un-fuzzed JWT round-trip is byte-exact"
    fuzzed = _reencode_blob(token, "", "attacker", "/p/sub")
    assert fuzzed.split(".")[0] == token.split(".")[0] and fuzzed.split(".")[2] == "ZZZ", \
        "header + signature segments byte-preserved across a payload fuzz"
    assert _jwt_claim(fuzzed, "sub") == "attacker" and _jwt_claim(fuzzed, "n") == 5


def test_nested_blob_bearer_prefix_and_no_false_positive() -> None:
    token = _jwt({"alg": "none"}, {"sub": "u1"}, sig="")
    req = HttpRequest(url="https://t/", headers=[("Authorization", f"Bearer {token}")])
    t = RequestTemplate(req)
    blobs = [p for p in t.insertion_points() if p.kind is InsertionKind.NESTED_BLOB]
    sub = next(p for p in blobs if p.name.endswith("/p/sub"))
    out = t.render(sub, "attacker")
    auth = out.header("Authorization")
    assert auth.startswith("Bearer "), "the `Bearer ` prefix is preserved"
    assert _jwt_claim(auth.split(" ", 1)[1], "sub") == "attacker"

    # a plain value must never be mistaken for a blob.
    plain = RequestTemplate(HttpRequest(url="https://t/s?q=hello&id=42&t=plainstringvalue00"))
    assert [p for p in plain.insertion_points() if p.kind is InsertionKind.NESTED_BLOB] == []


def test_nested_blob_reaches_oracle_only_via_decoded_claim() -> None:
    # sink decodes the JWT cookie and reflects the `note` claim into HTML. The payload
    # only reaches the sink if the engine decoded → fuzzed → re-encoded the claim.
    token = _jwt({"alg": "HS256"}, {"note": "welcome", "role": "user"})
    req = HttpRequest(url="https://t/", headers=[("Cookie", f"session={token}")])

    def send(r: HttpRequest) -> dict:
        cookie = r.header("Cookie") or ""
        tok = cookie.split("session=", 1)[1].split(";", 1)[0] if "session=" in cookie else ""
        try:
            return _reflect(str(_jwt_claim(tok, "note")))
        except Exception:
            return _no_reflect()

    # the opaque cookie VALUE sweep cannot reach an inner claim; the nested-blob sweep can.
    assert _confirm_xss(req, send, [InsertionKind.COOKIE_VALUE]) == []
    hits = _confirm_xss(req, send, [InsertionKind.NESTED_BLOB])
    assert hits, "nested-claim payload was not confirmed by the oracle"
    assert hits[0].insertion_point.startswith("nested_blob:")
    assert any("note" in h.param for h in hits)
