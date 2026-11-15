"""VIGIL PUBLIC site server (`pubui`) — the deliberately-dumbest, keyless, cookieless, offense-free plane.

This serves VIGIL's PUBLIC marketing / tools / trust / blog surface. By construction it:
  * serves ONLY static files from a fixed, packaged content root (`public_site/`);
  * holds NO owner key, mints NO cookie / session / token, exposes NO API, GET/HEAD only;
  * makes NO outbound request — so there is nothing to leak and nothing to scrub.
It binds a `bind_ok` address (loopback/private) behind the external reverse proxy on a SEPARATE marketing
vhost — never the authenticated operator-console origin, never the cookie-bearing `custui` edge origin.

FATAL-2: sovereign-side (`assert_no_offense` at import); stdlib + the sovereign `bind_ok` only — imports NO
framework/strix/vigil_integration. A static file server that co-loads no offense code keeps the two-plane
boundary by construction. Path traversal is refused (`resolve()` + `is_relative_to(root)`); every response
carries a strict CSP + `nosniff` + `no-referrer` + `DENY` framing, set as HEADERS (never a <meta>).
"""
from __future__ import annotations

import ipaddress
import json
import posixpath
import re
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..reuse import assert_no_offense

assert_no_offense()

from ..bridge.daemon import bind_ok  # noqa: E402  (the ONE loopback/private bind invariant — reused, not re-authored)
from .graceful import GracefulMixin, serve_until_signal  # noqa: E402  (stdlib-only graceful stop)
from .static_site import IMMUTABLE, SiteSnapshot, normalize_rel, not_modified  # noqa: E402  (stdlib-only)

# The packaged content tree (ships with the sigil package, so it deploys wherever sigil does).
_PUBLIC_ROOT = Path(__file__).resolve().parent / "public_site"

# Strict CSP for a static, script-light marketing site: self only, no inline handlers, data: images (inline
# SVG / data-URI icons), no framing, no off-site form submission. Set as a RESPONSE HEADER, never a <meta>.
_CSP = ("default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
        "object-src 'none'; img-src 'self' data:")

_CTYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".webp": "image/webp", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8", ".webmanifest": "application/manifest+json",
    ".woff2": "font/woff2", ".map": "application/json",
}
_MAX_BYTES = 8 * 1024 * 1024   # a static asset over 8 MiB on a marketing site is a mistake — refuse

# Cache policy (the site is read once at startup into a content-hashed snapshot — ui/static_site.py):
#   * pages and any asset requested WITHOUT ?v=: a browser revalidates every time (ETag -> 304) and a CDN may
#     keep a copy for 60 s, so a release reaches every visitor within about a minute;
#   * an asset requested with ?v=<its current digest>: immutable for a year (the bytes behind that URL never
#     change); with any other v: 404 + no-store (see static_site.SiteSnapshot.version_state);
#   * /version.json, the probes, every 404: no-store.
_PAGE_CACHE = "public, max-age=0, s-maxage=60"

# A number in a query string: ASCII digits only and at most 9 of them. str.isdigit() also accepts '²' and other
# digits int() refuses, and int() refuses a string of more than 4300 digits; either used to end the request
# with no answer at all.
_NUMBER = re.compile(r"[0-9]{1,9}")


def _number(raw: str, default: "int | None") -> "int | None":
    return int(raw) if _NUMBER.fullmatch(raw) else default


class PublicServer(GracefulMixin, ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, root=None, catalog_path=None):
        host = addr[0]
        if not bind_ok(host):
            raise ValueError(
                f"refusing to bind {host!r}: the public site binds loopback or a PRIVATE (WireGuard/"
                f"Tailscale) address only — never 0.0.0.0 / unspecified / public. Front it with a reverse "
                f"proxy on the marketing vhost (apps/sigil/deploy/reverse-proxy).")
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            self.address_family = socket.AF_INET6
        # Bind now, LISTEN LAST (server_activate below): until the site is read, a connection to this port is
        # refused — nginx then sends it to the other port — so a startup that fails never drops a request.
        super().__init__(addr, handler, bind_and_activate=False)
        try:
            self.server_bind()
            self.root = (Path(root) if root is not None else _PUBLIC_ROOT).resolve()
            # the whole site, read ONCE: what this process serves until it stops (one consistent build)
            self.site = SiteSnapshot(self.root, _CTYPES, max_file=_MAX_BYTES)
            # Optional READ-ONLY public CVE catalog (offense-free SQLite, populated by `sigil cve ingest`). When
            # the file is absent the /api/cve endpoints answer honestly empty — the marketing pages never need it.
            self.catalog_path = Path(catalog_path) if catalog_path else None
            self.server_activate()
        except BaseException:
            self.server_close()
            raise


class PublicHandler(BaseHTTPRequestHandler):
    server: PublicServer
    server_version = "vigil-pubui/1.0"
    timeout = 30

    def log_message(self, fmt, *args):  # noqa: A003 — never log
        pass

    def _send_headers(self, code: int, ctype: str, length: int, *, cache: "str | None" = "public, max-age=300",
                      etag: "str | None" = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Vigil-Build", self.server.site.build)
        if cache:
            self.send_header("Cache-Control", cache)
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()

    def _resolve(self, urlpath: str):
        """Map a URL path to an asset of the site snapshot, or None. Directory / extension-less routes resolve
        to `<path>.html` then `<path>/index.html`; "/" → index.html. Only files read into the snapshot at
        startup can ever be served, and a path is clamped inside the content root before it is looked up."""
        rel = normalize_rel(urlparse(urlpath).path)
        site = self.server.site
        if rel is None:
            return None
        if rel == "":
            cands = ["index.html"]
        else:
            cands = [rel]
            if not posixpath.splitext(rel)[1]:            # a pretty route: try <path>.html then <path>/index.html
                cands += [rel + ".html", rel + "/index.html"]
        for cand in cands:
            a = site.get(cand)
            if a is not None:
                return a
        return None

    # --- health / readiness (probe surface) ----------------------------------------------------------
    # The site is keyless + cookieless, so these need no auth to bypass — they are answered FIRST, ahead of
    # content routing, and carry NO filesystem path or secret (a boolean + the check name only). `/healthz`
    # is pure liveness (the process answers); `/readyz` checks the edge's REAL dependency — its packaged
    # content root — so an LB drains an edge whose site tree is missing/unreadable rather than serving 404s.
    def _probe_json(self, obj, code: int = 200):
        body = json.dumps(obj).encode("utf-8")
        # no-store: a readiness verdict must never be cached by an intermediary/orchestrator probe.
        self._send_headers(code, "application/json; charset=utf-8", len(body), cache="no-store")
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _readyz(self):
        # ready = the site shell this edge serves at "/" is in the snapshot it read at startup
        ready = "index.html" in self.server.site
        self._probe_json({"ok": ready, "checks": [{"name": "content_root", "ok": ready}]},
                         200 if ready else 503)

    def _version(self, head: bool = False):
        """GET /version.json — the build this edge serves (a content hash; no auth, no-store)."""
        body = json.dumps({"build": self.server.site.build}).encode("utf-8")
        self._send_headers(200, "application/json; charset=utf-8", len(body), cache="no-store")
        if not head:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _fault(self, head: bool) -> None:
        """One clean 500 (no internals, no-store) for a fault no route expected — never a connection closed with no
        answer, which nginx would count against this edge."""
        api = urlparse(self.path).path.startswith("/api/")
        body = b'{"error": "request failed"}' if api else b"VIGIL could not answer this request.\n"
        try:
            self._send_headers(500, "application/json; charset=utf-8" if api else "text/plain; charset=utf-8",
                               len(body), cache="no-store")
            if not head:
                self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self):
        try:
            return self._route_get()
        except Exception:  # noqa: BLE001 — never 500-leak internals
            return self._fault(head=False)

    def do_HEAD(self):
        try:
            if urlparse(self.path).path == "/version.json":
                return self._version(head=True)
            return self._serve(head=True)
        except Exception:  # noqa: BLE001 — never 500-leak internals
            return self._fault(head=True)

    def _route_get(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self._probe_json({"ok": True})
        if path == "/readyz":
            return self._readyz()
        if path == "/version.json":
            return self._version()
        if path == "/api/cve" or path.startswith("/api/cve/"):
            return self._cve_api(path)
        # pretty dynamic CVE routes map to a static shell that client-side JS then fills from /api/cve.
        if re.fullmatch(r"/cve/CVE-\d{4}-\d{4,}/?", path, re.IGNORECASE):
            return self._serve(head=False, override="cve/_detail.html")
        if re.fullmatch(r"/cve/year/\d{4}/?", path):
            return self._serve(head=False, override="cve/_year.html")
        return self._serve(head=False)

    # -- read-only public CVE API (offense-free; reads the local catalog; no egress at request time) ---
    def _json(self, obj, code: int = 200):
        body = json.dumps(obj).encode("utf-8")
        self._send_headers(code, "application/json; charset=utf-8", len(body), cache="public, max-age=300")
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _catalog(self):
        """Open the catalog READ-only if its file exists, else None. Never CREATES it from the public plane
        (ingest owns creation) and imports the offense-free store lazily so pubui needs neither to run."""
        cp = self.server.catalog_path
        if cp is None or not cp.exists():
            return None
        try:
            from ..cve.catalog import CveCatalogStore
            return CveCatalogStore(str(cp))
        except Exception:  # noqa: BLE001 — a broken catalog must not 500 the public plane
            return None

    def _cve_api(self, path: str):
        store = self._catalog()
        if store is None:
            # honest empty responses so the pages render a "catalog not yet populated" state, never an error
            if path in ("/api/cve", "/api/cve/"):
                return self._json({"items": [], "total": 0, "page": 1, "per_page": 50, "pages": 1,
                                   "populated": False})
            if path == "/api/cve/stats":
                return self._json({"total": 0, "kev": 0, "by_severity": {}, "vigil_proven": 0,
                                   "populated": False})
            if path == "/api/cve/years":
                return self._json({"years": [], "populated": False})
            return self._json({"error": "not found"}, 404)
        if path in ("/api/cve", "/api/cve/"):
            q = parse_qs(urlparse(self.path).query)
            one = lambda k: (q.get(k, [""])[0] or "").strip()  # noqa: E731
            kev = one("kev")
            res = store.query(
                page=_number(one("page"), 1) or 1,
                per_page=_number(one("per_page"), 50) or 50,
                severity=one("severity") or None, q=one("q") or None,
                year=_number(one("year"), None),
                kev=(True if kev in ("1", "true", "yes") else (False if kev in ("0", "false", "no") else None)),
                order=one("order") or "published_desc")
            res["populated"] = True
            return self._json(res)
        if path == "/api/cve/stats":
            return self._json({**store.stats(), "populated": True})
        if path == "/api/cve/years":
            return self._json({"years": store.years(), "populated": True})
        m = re.fullmatch(r"/api/cve/(CVE-\d{4}-\d{4,})", path, re.IGNORECASE)
        if m:
            rec = store.get(m.group(1))
            return self._json(rec) if rec is not None else self._json({"error": "not found"}, 404)
        return self._json({"error": "not found"}, 404)

    def _serve(self, head: bool, override: "str | None" = None):
        hit = self._resolve("/" + override) if override else self._resolve(self.path)
        if hit is None:
            rel = normalize_rel(urlparse(self.path).path)
            if rel is not None and rel in self.server.site.too_large:
                self._send_headers(413, "text/plain; charset=utf-8", 0, cache="no-store")
                return
            return self._not_found(head)
        state = self.server.site.version_state(hit, urlparse(self.path).query)
        if state == "mismatch":
            return self._not_found(head)          # another build's URL: never cache today's bytes under it
        cache = IMMUTABLE if state == "immutable" else _PAGE_CACHE
        if not_modified(self.headers.get("If-None-Match", ""), hit.etag):
            self._send_headers(304, hit.ctype, len(hit.body), cache=cache, etag=hit.etag)   # no body follows
            return
        self._send_headers(200, hit.ctype, len(hit.body), cache=cache, etag=hit.etag)
        if not head:
            try:
                self.wfile.write(hit.body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _not_found(self, head: bool):
        custom = self.server.site.get("404.html")
        body = (custom.body if custom is not None
                else b"<!doctype html><meta charset=utf-8><title>404</title><h1>404 Not Found</h1>")
        # no-store: a 404 kept by a cache would outlive the release that adds the page (or the build it names)
        self._send_headers(404, "text/html; charset=utf-8", len(body), cache="no-store")
        if not head:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass


def build_public_server(*, host: str = "127.0.0.1", port=None, root=None) -> PublicServer:
    """Wire the public static server. Port defaults to `config.PUBLIC_UI_PORT` (:8735); `root` defaults to
    the packaged `public_site/` tree. No key, no cookie, no API — a static file server behind the edge."""
    from .. import config
    return PublicServer((host, config.PUBLIC_UI_PORT if port is None else int(port)), PublicHandler,
                        root=root, catalog_path=config.CVE_CATALOG_PATH)


def serve_public(*, host: str = "127.0.0.1", port=None, root=None) -> None:
    srv = build_public_server(host=host, port=port, root=root)
    bound_port = srv.server_address[1]
    print(f"  vigil public site on http://{host}:{bound_port}  (static; keyless + cookieless; root={srv.root})")
    serve_until_signal(srv)          # SIGTERM/SIGINT: finish the requests in flight, then exit (ui/graceful)
