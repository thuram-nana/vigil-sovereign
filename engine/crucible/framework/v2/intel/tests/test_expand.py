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


# ---------------------------------------------------------------------------
# #799 — expand also mines /sitemap.xml + /openapi.json (surfaces the HTML crawler is blind to)
# ---------------------------------------------------------------------------


def _surface_map_send(*, host="host.example", scheme="http"):
    """A gated send whose root HTML links nothing, but which serves a sitemap.xml and an openapi.json
    naming in-scope endpoints (plus an off-host sitemap loc and a templated openapi path that must be
    filtered out). Lets a test assert the machine-readable maps are mined and containment is applied."""
    origin = f"{scheme}://{host}"

    def send(req):
        url = getattr(req, "url", "")
        if url == f"{origin}/sitemap.xml":
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f'<url><loc>{origin}/records/search?q=1</loc></url>'
                f'<url><loc>{origin}/permits/list</loc></url>'
                '<url><loc>http://evil.test/x?q=1</loc></url>'   # off-host → filtered by containment
                '</urlset>')
            return {"status": 200, "body": body, "headers": [("Content-Type", "application/xml")]}
        if url == f"{origin}/openapi.json":
            body = (
                '{"openapi":"3.0.0","paths":{'
                '"/api/status":{"get":{}},'
                '"/api/users/{id}":{"get":{}},'   # templated → not a concrete fetchable URL → filtered
                '"/api/orders?type=x":{"get":{}}'
                '}}')
            return {"status": 200, "body": body, "headers": [("Content-Type", "application/json")]}
        # root + everything else: HTML with no links (so all discoveries come from the maps)
        return {"status": 200, "body": "<html><body>root</body></html>",
                "headers": [("Content-Type", "text/html")]}
    return send


def test_expand_mines_sitemap_and_openapi_surfaces():
    urls = expand_endpoint(_surface_map_send(), "http://host.example/", max_pages=5, max_depth=2)
    # sitemap <loc> entries (in-scope) are folded in — including a paramless one the HTML crawler would
    # never see because it is not linked from any page.
    assert "http://host.example/records/search?q=1" in urls
    assert "http://host.example/permits/list" in urls
    # openapi concrete paths are folded in; templated ({id}) paths are not (not a fetchable URL).
    assert "http://host.example/api/status" in urls
    assert all("{id}" not in u and "/api/users/" not in u for u in urls)
    # containment holds: the off-host sitemap loc is refused.
    assert all("evil.test" not in u for u in urls)
    assert urls == sorted(urls)


def test_expand_mines_sitemap_with_root_relative_locs():
    """#799: a spec-compliant sitemap uses ABSOLUTE URLs, but many real apps (e.g. the MERIDIAN range)
    emit ROOT-RELATIVE ``<loc>`` entries. Those must be resolved against the seed ORIGIN and folded in,
    still under the scheme+host+prefix containment filter (a ``//evil`` protocol-relative or off-subtree
    loc is dropped) — otherwise sitemap mining silently discovers nothing on a relative-sitemap target."""
    def send(req):
        url = getattr(req, "url", "")
        if url == "http://host.example/sitemap.xml":
            return {"status": 200,
                    "body": ('<?xml version="1.0" encoding="UTF-8"?>'
                             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                             '<url><loc>/records/search?q=1</loc></url>'      # root-relative, in-scope
                             '<url><loc>/documents</loc></url>'               # root-relative, paramless
                             '<url><loc>//evil.test/x?q=1</loc></url>'        # protocol-relative → off-host
                             '</urlset>'),
                    "headers": [("Content-Type", "application/xml")]}
        if url == "http://host.example/openapi.json":
            return {"status": 404, "body": "", "headers": []}
        return {"status": 200, "body": "<html><body>root</body></html>",
                "headers": [("Content-Type", "text/html")]}
    urls = expand_endpoint(send, "http://host.example/", max_pages=5, max_depth=2)
    assert "http://host.example/records/search?q=1" in urls   # relative loc resolved against the seed origin
    assert "http://host.example/documents" in urls
    assert all("evil.test" not in u for u in urls)            # protocol-relative off-host loc is dropped
    assert all(u.startswith("http://host.example/") for u in urls)


def test_expand_sitemap_no_scheme_downgrade():
    """A hostile/misconfigured sitemap on an https seed that lists http:// (cleartext) locs must NOT be
    minted — the same no-downgrade containment the crawler path enforces applies to mined surfaces."""
    def send(req):
        url = getattr(req, "url", "")
        if url == "https://host.example/sitemap.xml":
            return {"status": 200,
                    "body": ('<urlset><url><loc>http://host.example/leak?x=1</loc></url>'
                             '<url><loc>https://host.example/ok?y=1</loc></url></urlset>'),
                    "headers": [("Content-Type", "application/xml")]}
        if url == "https://host.example/openapi.json":
            return {"status": 404, "body": "", "headers": []}
        return {"status": 200, "body": "<html></html>", "headers": [("Content-Type", "text/html")]}
    urls = expand_endpoint(send, "https://host.example/", max_pages=5, max_depth=2)
    assert "https://host.example/ok?y=1" in urls
    assert all(u.startswith("https://") for u in urls)          # the http:// loc is dropped
    assert all("/leak" not in u for u in urls)


def test_expand_sitemap_is_xxe_proof_regex_not_parser():
    """The sitemap is parsed by a plain <loc> regex, NOT an XML parser — a DOCTYPE/ENTITY payload is
    inert (no external-entity fetch, no expansion). We assert the entity is NOT resolved into a URL."""
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE urlset [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<urlset><url><loc>http://host.example/real?a=1</loc></url>'
        '<url><loc>&xxe;</loc></url></urlset>')

    def send(req):
        url = getattr(req, "url", "")
        if url == "http://host.example/sitemap.xml":
            return {"status": 200, "body": payload, "headers": [("Content-Type", "application/xml")]}
        if url == "http://host.example/openapi.json":
            return {"status": 404, "body": "", "headers": []}
        return {"status": 200, "body": "<html></html>", "headers": [("Content-Type", "text/html")]}
    urls = expand_endpoint(send, "http://host.example/")
    assert "http://host.example/real?a=1" in urls
    assert all("passwd" not in u for u in urls)                 # the entity was never resolved
