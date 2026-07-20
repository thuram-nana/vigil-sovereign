"""intel.expand — in-loop crawl/mine surface expansion (Phase-1 Slice 2).

Pins that a bounded, scope-bound crawl of a seed endpoint (over the injected gated send) returns the
discovered in-scope, param-bearing URLs — reusing the existing Crawler + Scope, no new crawl logic.
"""

from __future__ import annotations

from framework.v2.intel.expand import expand_endpoint


def _linking_send():
    """A fake gated send: the root returns HTML linking to a param-bearing page and an off-host page;
    the child pages return trivial HTML. Records nothing — a pure crawl fixture (no network)."""
    def send(req):
        url = getattr(req, "url", "")
        if url.rstrip("/").endswith(":80") or url.endswith("/") or url.endswith("/index"):
            body = ('<html><body>'
                    '<a href="/search?q=hello">search</a>'
                    '<a href="/page?id=1">page</a>'
                    '<a href="/about">about (no param)</a>'
                    '<a href="http://evil.test/x?q=1">off-host</a>'
                    '</body></html>')
            return {"status": 200, "body": body, "headers": [("Content-Type", "text/html")]}
        return {"status": 200, "body": "<html><body>leaf</body></html>",
                "headers": [("Content-Type", "text/html")]}
    return send


def test_expand_returns_in_scope_param_bearing_urls():
    urls = expand_endpoint(_linking_send(), "http://host.example/", max_pages=10, max_depth=2)
    # the two same-host param-bearing links are discovered; the paramless /about and the off-host link
    # (Scope.in_scope refuses a different host) are NOT returned.
    assert "http://host.example/search?q=hello" in urls
    assert "http://host.example/page?id=1" in urls
    assert all("evil.test" not in u for u in urls)          # off-host refused by Scope
    assert all("/about" not in u for u in urls)             # paramless → not a new injectable surface
    assert urls == sorted(urls)                             # deterministic order


def test_expand_is_deterministic():
    a = expand_endpoint(_linking_send(), "http://host.example/")
    b = expand_endpoint(_linking_send(), "http://host.example/")
    assert a == b


def test_expand_bad_seed_returns_empty():
    assert expand_endpoint(_linking_send(), "ftp://host/") == []
    assert expand_endpoint(_linking_send(), "") == []


def test_expand_crawl_error_returns_empty():
    def boom(_req):
        raise RuntimeError("send failed")
    # a send that always errors → the crawler yields nothing → [] (best-effort, never raises)
    assert expand_endpoint(boom, "http://host.example/") == []


def _downgrade_and_escape_send():
    """Root (https) links to: a cleartext http downgrade, a '..' path-escape above the seed prefix, and
    a legitimate same-scheme same-subtree param page. Only the last must be minted."""
    def send(req):
        url = getattr(req, "url", "")
        if url.endswith("/app/") or url.rstrip("/").endswith("/app"):
            body = ('<html><body>'
                    '<a href="http://host.example/app/cleartext?d=1">downgrade</a>'
                    '<a href="https://host.example/app/../secret/admin?t=1">escape</a>'
                    '<a href="https://host.example/app/search?q=1">ok</a>'
                    '</body></html>')
            return {"status": 200, "body": body, "headers": [("Content-Type", "text/html")]}
        return {"status": 200, "body": "<html><body>leaf</body></html>",
                "headers": [("Content-Type", "text/html")]}
    return send


def test_expand_pins_scheme_and_path_prefix():
    """Review wcqss59lb LOWs: expand must not downgrade https→http, and a '..' must not escape the seed's
    path-prefix subtree. Only the same-scheme, in-subtree param page is minted."""
    urls = expand_endpoint(_downgrade_and_escape_send(), "https://host.example/app/",
                           max_pages=10, max_depth=2)
    assert urls == ["https://host.example/app/search?q=1"]
    assert all(u.startswith("https://") for u in urls)          # no http downgrade minted
    assert all("/secret/" not in u for u in urls)               # no '..' path-prefix escape minted
