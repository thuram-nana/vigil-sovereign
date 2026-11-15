"""Fresh browsers on the two keyless edges — the public site (pubui) and the customer app (custui).

Each edge reads its tree once at startup (ui/static_site.py) and:
  * names every asset in its pages as `<asset>?v=<sha256[:12] of its bytes>`;
  * serves `?v=<current digest>` as immutable for a year, ANY other `v` as 404 + no-store (a page of another build
    asking for its own bytes never gets today's bytes under that name), and the bare URL with revalidation;
  * serves pages with revalidation (customer: no-cache; public: max-age=0, s-maxage=60) and an ETag, and answers
    a matching If-None-Match with 304 and no body;
  * answers `GET /version.json` without authentication, no-store, and sends `X-Vigil-Build` on every response;
  * keeps serving the build it started with when the files change under it; a new edge over the new files
    reports a new build, and the old build's URLs are 404 there.
"""
from __future__ import annotations

import http.client
import json
import re
import socket
import threading
from pathlib import Path

import pytest

from sigil.ui import custui
from sigil.ui.custui import build_customer_server
from sigil.ui.pubui import build_public_server
from sigil.ui.static_site import IMMUTABLE, SiteSnapshot

_PAGE = """<!doctype html><html><head>
<link rel="stylesheet" href="/assets/site.css">
<link rel="icon" href="assets/logo.svg" type="image/svg+xml">
<link rel="manifest" href="manifest.webmanifest">
<link rel="stylesheet" href="https://cdn.example/x.css">
</head><body data-build="__VIGIL_BUILD__"><a href="/about">About</a><script src="app.js"></script></body></html>
"""


def _tree(root: Path, css: str = "body{color:red}") -> Path:
    (root / "assets").mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(_PAGE, encoding="utf-8")
    (root / "about.html").write_text("<p>about</p>", encoding="utf-8")
    (root / "404.html").write_text("<h1>gone</h1>", encoding="utf-8")
    (root / "assets" / "site.css").write_text(css, encoding="utf-8")
    (root / "assets" / "logo.svg").write_text("<svg/>", encoding="utf-8")
    (root / "app.js").write_text("var x = 1;", encoding="utf-8")
    (root / "manifest.webmanifest").write_text('{"name":"x"}', encoding="utf-8")
    return root


class _Edge:
    def __init__(self, srv):
        self.srv = srv
        self.port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def get(self, path, headers=None, method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, headers={"Host": f"127.0.0.1:{self.port}", **(headers or {})})
        r = c.getresponse()
        body = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def _public(root: Path) -> _Edge:
    return _Edge(build_public_server(host="127.0.0.1", port=0, root=str(root)))


def _customer(root: Path, tmp: Path, monkeypatch) -> _Edge:
    monkeypatch.setattr(custui, "_APP_ROOT", root)
    return _Edge(build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                       sessions_dir=str(tmp / "sessions")))


_PAGE_POLICY = {"public": "public, max-age=0, s-maxage=60", "customer": "no-cache"}


@pytest.fixture(params=["public", "customer"])
def edge(request, tmp_path, monkeypatch):
    root = _tree(tmp_path / "site")
    e = _public(root) if request.param == "public" else _customer(root, tmp_path, monkeypatch)
    e.kind = request.param
    e.root = root
    yield e
    e.close()


def _refs(page: bytes) -> dict:
    return dict(re.findall(r'(?:href|src)="([^"?]+)\?v=([0-9a-f]{12})"', page.decode()))


def test_the_page_names_each_asset_by_its_digest_and_leaves_everything_else(edge):
    status, h, page = edge.get("/")
    assert status == 200
    refs = _refs(page)
    snap = SiteSnapshot(edge.root, {}, max_file=1 << 20)
    assert refs == {"/assets/site.css": snap.get("assets/site.css").digest,
                    "assets/logo.svg": snap.get("assets/logo.svg").digest,
                    "app.js": snap.get("app.js").digest}
    text = page.decode()
    assert 'href="manifest.webmanifest"' in text                     # stable URL: never versioned
    assert 'href="https://cdn.example/x.css"' in text and 'href="/about"' in text   # external + page links untouched
    assert f'data-build="{h["x-vigil-build"]}"' in text and "__VIGIL_BUILD__" not in text


def test_a_current_versioned_url_is_immutable(edge):
    _s, _h, page = edge.get("/")
    for url, digest in _refs(page).items():
        path = url if url.startswith("/") else "/" + url
        status, h, body = edge.get(f"{path}?v={digest}")
        assert status == 200 and h["cache-control"] == IMMUTABLE and h["etag"], (url, h)
        assert body == (edge.root / path.lstrip("/")).read_bytes()


@pytest.mark.parametrize("query", ["v=000000000000", "v=", "v={d}&x=1", "v={d}&v={d}", "V={d}x"])
def test_any_other_version_is_404_and_no_store(edge, query):
    snap = SiteSnapshot(edge.root, {}, max_file=1 << 20)
    q = query.format(d=snap.get("assets/site.css").digest)
    status, h, body = edge.get(f"/assets/site.css?{q}")
    if query.startswith("V="):                                    # not a `v` parameter at all: a plain request
        assert status == 200 and h["cache-control"] == _PAGE_POLICY[edge.kind]
        return
    assert status == 404 and h["cache-control"] == "no-store", (q, status, h)
    assert b"color:red" not in body


def test_a_bare_asset_url_is_revalidated_never_immutable(edge):
    status, h, body = edge.get("/assets/site.css")
    assert status == 200 and h["cache-control"] == _PAGE_POLICY[edge.kind] and h["etag"]
    assert body == b"body{color:red}"


def test_the_page_is_revalidated_and_a_matching_etag_is_304(edge):
    status, h, _ = edge.get("/")
    assert status == 200 and h["cache-control"] == _PAGE_POLICY[edge.kind] and h["etag"]
    status2, h2, body2 = edge.get("/", headers={"If-None-Match": h["etag"]})
    assert status2 == 304 and body2 == b"" and h2["etag"] == h["etag"]
    status3, _h3, body3 = edge.get("/", headers={"If-None-Match": '"something-else"'})
    assert status3 == 200 and body3


@pytest.mark.parametrize("path", ["/", "/app.js", "/manifest.webmanifest"])
def test_a_304_sends_no_body_on_the_wire(edge, path):
    # http.client never reads a body after a 304, so read the raw bytes: the edge closes the connection after each
    # response, and nothing may follow the 304's header block
    _s, h, _b = edge.get(path)
    s = socket.create_connection(("127.0.0.1", edge.port), timeout=5)
    s.sendall(f"GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{edge.port}\r\nIf-None-Match: {h['etag']}\r\n\r\n".encode())
    raw = b""
    while chunk := s.recv(65536):
        raw += chunk
    s.close()
    head, sep, rest = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.0 304 ") and sep and rest == b"", raw[:120]


def test_version_json_is_unauthenticated_no_store_and_names_the_build(edge):
    status, h, body = edge.get("/version.json")
    assert status == 200 and h["cache-control"] == "no-store"
    assert h["content-type"].startswith("application/json") and "set-cookie" not in h
    build = json.loads(body)["build"]
    assert re.fullmatch(r"[0-9a-f]{12}", build) and h["x-vigil-build"] == build
    # the customer edge also writes a per-deployment value (the iOS install flag) into its page: part of the build
    expected = (SiteSnapshot(edge.root, {}, max_file=1 << 20) if edge.kind == "public"
                else custui.build_app_snapshot(edge.root)).build
    assert build == expected


@pytest.mark.parametrize("path", ["/", "/assets/site.css", "/healthz", "/readyz", "/nope", "/version.json"])
def test_every_response_names_the_build(edge, path):
    _s, h, _b = edge.get(path)
    assert re.fullmatch(r"[0-9a-f]{12}", h.get("x-vigil-build", "")), (path, h)


def test_a_404_is_never_cached(edge):
    status, h, _ = edge.get("/nope.css")
    assert status == 404 and h["cache-control"] == "no-store"


def test_a_running_edge_keeps_its_build_when_the_files_change(edge, tmp_path, monkeypatch):
    _s, h0, page0 = edge.get("/")
    old_css = _refs(page0)["/assets/site.css"]
    (edge.root / "assets" / "site.css").write_text("body{color:blue}", encoding="utf-8")   # a checkout under it
    status, h, body = edge.get(f"/assets/site.css?v={old_css}")
    assert status == 200 and body == b"body{color:red}" and h["x-vigil-build"] == h0["x-vigil-build"]
    # the replacement edge (the swap) reads the new files: a new build, a new digest, and the old URL is 404
    new = _public(edge.root) if edge.kind == "public" else _customer(edge.root, tmp_path / "n", monkeypatch)
    try:
        _s, h1, page1 = new.get("/")
        assert h1["x-vigil-build"] != h0["x-vigil-build"]
        assert _refs(page1)["/assets/site.css"] != old_css
        status, h, _ = new.get(f"/assets/site.css?v={old_css}")
        assert status == 404 and h["cache-control"] == "no-store"
    finally:
        new.close()


def test_the_build_is_deterministic_and_covers_every_file(tmp_path):
    a = SiteSnapshot(_tree(tmp_path / "a"), {}, max_file=1 << 20)
    b = SiteSnapshot(_tree(tmp_path / "b"), {}, max_file=1 << 20)
    assert a.build == b.build                                     # same files, same build
    (tmp_path / "b" / "about.html").write_text("<p>changed</p>", encoding="utf-8")
    assert SiteSnapshot(tmp_path / "b", {}, max_file=1 << 20).build != a.build
    # a per-deployment value written into the pages is part of the build
    c = SiteSnapshot(tmp_path / "a", {}, max_file=1 << 20, html_values={"__X__": "1"})
    assert c.build != a.build


def test_a_symlink_out_of_the_root_and_an_oversize_file_are_never_served(tmp_path):
    root = _tree(tmp_path / "site")
    (tmp_path / "secret.txt").write_text("TOP SECRET", encoding="utf-8")
    (root / "leak.txt").symlink_to(tmp_path / "secret.txt")
    (root / "big.js").write_bytes(b"x" * 2048)
    snap = SiteSnapshot(root, {}, max_file=1024)
    assert snap.get("leak.txt") is None and snap.get("big.js") is None and "big.js" in snap.too_large
    e = _public(root)
    try:
        assert e.get("/leak.txt")[0] == 404
        assert e.get("/%2e%2e/secret.txt")[0] == 404
    finally:
        e.close()


def test_the_shipped_customer_app_and_public_site_are_versioned(tmp_path):
    # the real trees: the customer shell and the public landing name their css/js by digest
    e = _Edge(build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                    sessions_dir=str(tmp_path / "s")))
    p = _public(Path(custui.__file__).resolve().parent / "public_site")
    try:
        for edge, needed in ((e, ("tokens.css", "components.css", "app.css", "ui.js", "app.js")),
                             (p, ("/assets/tokens.css", "/assets/site.css"))):
            _s, h, page = edge.get("/")
            refs = _refs(page)
            for n in needed:
                assert n in refs, (n, sorted(refs))
                status, h2, _ = edge.get((n if n.startswith("/") else "/" + n) + f"?v={refs[n]}")
                assert status == 200 and h2["cache-control"] == IMMUTABLE
    finally:
        e.close()
        p.close()
