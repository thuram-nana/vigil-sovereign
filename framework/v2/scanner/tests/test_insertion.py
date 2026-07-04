"""
Insertion-point engine — real parse/render behavior across every point type.

These tests exercise the actual codecs (no fixtures shaped to pass): they parse
concrete requests, assert the enumerated points, render a payload into each, and
verify the rendered request places the payload correctly, encodes it, corrects
Content-Length, and preserves everything else byte-for-byte.
"""

from __future__ import annotations

import json

from framework.v2.scanner.insertion import (
    HttpRequest,
    InsertionKind,
    RequestTemplate,
)

_PAYLOAD = "' OR 1=1-- x"
_MARK = "MARK<script>"


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
    body = "<xml><a>1</a></xml>"
    req = HttpRequest(
        method="POST", url="https://t/soap",
        headers=[("Content-Type", "application/xml"), ("Content-Length", str(len(body)))],
        body=body,
    )
    t = RequestTemplate(req)
    pts = [p for p in t.insertion_points() if p.kind is InsertionKind.BODY_WHOLE]
    assert len(pts) == 1 and pts[0].base_value == body
    out = t.render(pts[0], "<xxe/>")
    assert out.body == "<xxe/>" and out.header("Content-Length") == "6"


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
