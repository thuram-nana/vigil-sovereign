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
import re
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ..reuse import assert_no_offense

assert_no_offense()

from ..bridge.daemon import bind_ok  # noqa: E402  (the ONE loopback/private bind invariant — reused, not re-authored)

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


class PublicServer(ThreadingHTTPServer):
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
        super().__init__(addr, handler)
        self.root = (Path(root) if root is not None else _PUBLIC_ROOT).resolve()
        # Optional READ-ONLY public CVE catalog (offense-free SQLite, populated by `sigil cve ingest`). When
        # the file is absent the /api/cve endpoints answer honestly empty — the marketing pages never need it.
        self.catalog_path = Path(catalog_path) if catalog_path else None


class PublicHandler(BaseHTTPRequestHandler):
    server: PublicServer
    server_version = "vigil-pubui/1.0"
    timeout = 30

    def log_message(self, fmt, *args):  # noqa: A003 — never log
        pass

    def _send_headers(self, code: int, ctype: str, length: int, *, cache: "str | None" = "public, max-age=300"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if cache:
            self.send_header("Cache-Control", cache)
        self.end_headers()

    def _resolve(self, urlpath: str):
        """Map a URL path to a safe file under root, or None. Directory / extension-less routes resolve to
        `<path>.html` then `<path>/index.html`; "/" → index.html. Path-traversal is refused: every candidate
        must `resolve()` to within the (resolved) root. Returns (abs_path, content_type) or None → 404."""
        rel = unquote(urlparse(urlpath).path).lstrip("/")
        root = self.server.root
        if rel in ("", "/"):
            cands = [root / "index.html"]
        else:
            base = root / rel
            cands = [base]
            if not base.suffix:                       # a pretty route: try <path>.html then <path>/index.html
                cands += [root / (rel + ".html"), base / "index.html"]
        for cand in cands:
            try:
                rp = cand.resolve()
            except (OSError, RuntimeError, ValueError):
                continue
            if rp != root and not rp.is_relative_to(root):
                continue                              # traversal guard — must stay within the content root
            if rp.is_file():
                return rp, _CTYPES.get(rp.suffix.lower(), "application/octet-stream")
        return None

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/cve" or path.startswith("/api/cve/"):
            return self._cve_api(path)
        # pretty dynamic CVE routes map to a static shell that client-side JS then fills from /api/cve.
        if re.fullmatch(r"/cve/CVE-\d{4}-\d{4,}/?", path, re.IGNORECASE):
            return self._serve(head=False, override="cve/_detail.html")
        if re.fullmatch(r"/cve/year/\d{4}/?", path):
            return self._serve(head=False, override="cve/_year.html")
        self._serve(head=False)

    def do_HEAD(self):
        self._serve(head=True)

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
                page=int(one("page") or 1) if one("page").isdigit() else 1,
                per_page=int(one("per_page") or 50) if one("per_page").isdigit() else 50,
                severity=one("severity") or None, q=one("q") or None,
                year=int(one("year")) if one("year").isdigit() else None,
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
            return self._not_found(head)
        rp, ctype = hit
        try:
            data = rp.read_bytes()
        except OSError:
            return self._not_found(head)
        if len(data) > _MAX_BYTES:
            self._send_headers(413, "text/plain; charset=utf-8", 0, cache=None)
            return
        self._send_headers(200, ctype, len(data))
        if not head:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _not_found(self, head: bool):
        custom = self.server.root / "404.html"
        body = (custom.read_bytes() if custom.is_file()
                else b"<!doctype html><meta charset=utf-8><title>404</title><h1>404 Not Found</h1>")
        self._send_headers(404, "text/html; charset=utf-8", len(body), cache=None)
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
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
