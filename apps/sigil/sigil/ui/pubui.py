"""VIGIL PUBLIC site server (`pubui`) — the deliberately-dumbest, keyless, cookieless, offense-free plane.

This serves VIGIL's PUBLIC marketing / tools / trust / blog surface. By construction it:
  * serves static files from a fixed, packaged content root (`public_site/`);
  * holds NO owner key, mints NO cookie / session / token (keyless and cookieless on every response);
  * makes NO outbound request — so there is nothing to leak and nothing to scrub.
It answers GET/HEAD for content, a read-only JSON CVE API (`/api/cve*`, reads a local catalog), and ONE
same-origin POST, `/api/trust/access-request`, the Security & Trust Center's "request security documentation"
drop. That POST is origin/Host gated (a cookieless plane has no session to ride, so classic CSRF does not apply;
the gate keeps it same-origin so a cross-site page cannot script it), per-source rate-limited, validates every
field, and QUEUES the unsigned request to a 0600 file (`ui/trust_access_requests_store.py`): it mints nothing,
grants no access, delivers no document, holds no key, makes no outbound call, and sets no cookie. The visitor's
fields are never logged (this handler never logs). It binds a `bind_ok` address (loopback/private) behind the
external reverse proxy on a SEPARATE marketing vhost, never the authenticated operator-console origin, never the
cookie-bearing `custui` edge origin.

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
from . import input_safety  # noqa: E402  (the ONE central request-boundary sanitizer, applied in _parse_access_fields)
from .graceful import GracefulMixin, serve_until_signal  # noqa: E402  (stdlib-only graceful stop)
from .static_site import IMMUTABLE, Asset, SiteSnapshot, normalize_rel, not_modified  # noqa: E402  (stdlib-only)

# The packaged content tree (ships with the sigil package, so it deploys wherever sigil does).
_PUBLIC_ROOT = Path(__file__).resolve().parent / "public_site"
# PR-I — the public "Verify a VIGIL finding" explainer (/verify) and the shipped standalone verifier it hands out
# (/verify/verify_pcf.py). Its OWN content root, outside public_site/, so the site snapshot and its build id are
# byte-identical whether or not this feature exists; served only while VIGIL_CUSTOMER_PROOF_BADGE is on (read per
# request). The verifier path is the one ui/proof_export.py ships in every proof bundle (a test pins the two equal).
_PROOF_ROOT = Path(__file__).resolve().parent / "proof_site"
_VERIFIER_PATH = Path(__file__).resolve().parents[4] / "docs" / "proof-carrying-finding" / "verify_pcf.py"
_VERIFIER_REL = "verify/verify_pcf.py"

# Strict CSP for a static, script-light marketing site: self only, no inline handlers, data: images (inline
# SVG / data-URI icons), no framing. `form-action 'self'` lets the Trust Center's access-request form submit to
# the same-origin endpoint (and nowhere else: a cross-origin target is refused); no inline/remote script runs.
# Set as a RESPONSE HEADER, never a <meta>.
_CSP = ("default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
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

# The Security & Trust Center access-request endpoint (the ONE same-origin POST this plane answers).
_ACCESS_REQUEST_PATH = "/api/trust/access-request"
_MAX_POST_BYTES = 16 * 1024    # an access request body over 16 KiB is refused (the five fields are small)
# Central input sanitization for the one public POST (defense-in-depth ON TOP of trust_access_requests_store.validate,
# which still does the authoritative length / format / control-char validation — the two compose, never conflict).
# The access-request fields (full_name / organisation / email / job_title / reason) are all plain text, so NOTHING is
# passed through byte-exact; the structure guard still rejects a JSON-bomb before the fields are read.
_PUB_PASSTHROUGH: "frozenset[str]" = frozenset()
_PUB_FIELD_MAX = _MAX_POST_BYTES         # never truncates (the whole body is already capped below this); strips only
_PUB_MAX_DEPTH = 6
_PUB_MAX_NODES = 256
# The neutral acknowledgement: it promises ONLY that the request was received and queued for review. It never
# states that access was granted or that any document was sent (the public plane grants nothing and sends nothing).
_ACCESS_ACK = ("Thank you. Your request has been received and queued for review. If it is approved, a member of the "
               "team will contact you at the professional email you provided. No access has been granted and no "
               "document has been sent.")
# Per-source submission limiter defaults (ui/login_ratelimit.LoginRateLimiter, guard-and-count via `admit`): at most
# this many submissions per window from one source, then a cooling lockout. Fail-closed on a storage fault.
_ACCESS_MAX_SUBMISSIONS = 8
_ACCESS_WINDOW_S = 600.0
_ACCESS_BASE_LOCK_S = 120.0
_ACCESS_MAX_LOCK_S = 3600.0

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


def _is_loopback_ip(addr: str) -> bool:
    """True iff `addr` is a loopback IP (the trusted same-host reverse-proxy hop). Fail-closed on junk."""
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _parse_access_fields(body: bytes, content_type: str) -> "dict[str, str] | None":
    """The access-request fields from the POST body: a JSON object (the fetch path) or a urlencoded form (a no-JS
    submit). Returns a flat ``{field: str}`` map, or None when the body is not one of those shapes. Only string
    values are kept (a nested/array value is dropped, so validation then reports the field missing)."""
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if ctype == "application/json" or (not ctype and text.lstrip()[:1] == "{"):
        try:
            obj = json.loads(text)
        except ValueError:
            return None
        if not isinstance(obj, dict):
            return None
        # central sanitization pass (defense-in-depth): strip dangerous characters from every string value and
        # reject a JSON-bomb (too deep / too many nodes) before the fields are read — a clean None here is answered
        # as a 400 "malformed" by the caller.
        try:
            obj = input_safety.sanitize_body(obj, passthrough=_PUB_PASSTHROUGH, max_chars=_PUB_FIELD_MAX,
                                             max_depth=_PUB_MAX_DEPTH, max_nodes=_PUB_MAX_NODES)
        except ValueError:
            return None
        return {k: v for k, v in obj.items() if isinstance(k, str) and isinstance(v, str)}
    if ctype in ("application/x-www-form-urlencoded", ""):
        try:
            parsed = parse_qs(text, keep_blank_values=True, strict_parsing=False)
        except ValueError:
            return None
        flat = {k: (v[0] if v else "") for k, v in parsed.items()}
        try:
            return input_safety.sanitize_body(flat, passthrough=_PUB_PASSTHROUGH, max_chars=_PUB_FIELD_MAX,
                                              max_depth=_PUB_MAX_DEPTH, max_nodes=_PUB_MAX_NODES)
        except ValueError:
            return None
    return None


def _proof_on() -> bool:
    from .. import config
    return config.customer_proof_badge_enabled()


def _proof_site() -> "dict[str, Asset]":
    """PR-I — the explainer page + the verifier, read ONCE at startup (like the site): ``{"verify": page,
    "verify/verify_pcf.py": verifier}``, or ``{}`` when either cannot be read (the routes then 404 — fail-closed, and
    the rest of the site is untouched). The page carries the verifier's sha256 and the governance fingerprint(s) VIGIL
    publishes (``config.proof_published_fingerprints`` — each already validated as ``sha256:<64 hex>``, so nothing
    from the environment reaches the page unvalidated)."""
    import hashlib
    from .. import config
    try:
        if not _VERIFIER_PATH.is_file() or _VERIFIER_PATH.stat().st_size > _MAX_BYTES:
            return {}
        data = _VERIFIER_PATH.read_bytes()
    except OSError:
        return {}
    sha = hashlib.sha256(data).hexdigest()
    fps = config.proof_published_fingerprints()
    published = ("<ul>" + "".join(f"<li><code>{fp}</code></li>" for fp in fps) + "</ul>") if fps else (
        '<p class="muted">VIGIL has not published a governance fingerprint on this site yet. Ask your VIGIL contact '
        "for it through a channel you trust that is independent of the bundle you were given.</p>")
    try:
        snap = SiteSnapshot(_PROOF_ROOT, _CTYPES, max_file=_MAX_BYTES,
                            html_values={"__VIGIL_VERIFIER_SHA256__": sha, "__VIGIL_PROOF_PUBLISHED__": published})
    except (OSError, ValueError):
        return {}
    page = snap.get("verify.html")
    if page is None:
        return {}
    verifier = Asset(rel=_VERIFIER_REL, body=data, ctype="text/plain; charset=utf-8", etag='"' + sha[:32] + '"',
                     digest=sha[:12], versioned=False)
    return {"verify": page, _VERIFIER_REL: verifier}


class PublicServer(GracefulMixin, ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, root=None, catalog_path=None, access_requests_dir=None,
                 access_limiter=None):
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
            # PR-I: the /verify explainer + verifier, read once like the site; a separate snapshot, so the site and its
            # build id are untouched; served only while the proof badge is on (checked per request)
            self.proof = _proof_site()
            # Optional READ-ONLY public CVE catalog (offense-free SQLite, populated by `sigil cve ingest`). When
            # the file is absent the /api/cve endpoints answer honestly empty — the marketing pages never need it.
            self.catalog_path = Path(catalog_path) if catalog_path else None
            # The Security & Trust Center access-request queue dir + its per-source submission limiter. Both default
            # to the configured SIGIL_HOME paths; a test passes its own tmp dir / a tuned limiter. Nothing is written
            # until a validated request arrives (the dir is created lazily by the store).
            from .. import config
            self.access_requests_dir = Path(access_requests_dir) if access_requests_dir is not None \
                else Path(config.TRUST_ACCESS_REQUESTS_DIR)
            if access_limiter is not None:
                self.access_limiter = access_limiter
            else:
                from .login_ratelimit import LoginRateLimiter
                self.access_limiter = LoginRateLimiter(
                    config.TRUST_ACCESS_RATELIMIT_DIR, max_fails=_ACCESS_MAX_SUBMISSIONS,
                    window_s=_ACCESS_WINDOW_S, base_lock_s=_ACCESS_BASE_LOCK_S, max_lock_s=_ACCESS_MAX_LOCK_S)
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
            if self._is_proof_route():
                return self._serve_proof(head=True)
            return self._serve(head=True)
        except Exception:  # noqa: BLE001 — never 500-leak internals
            return self._fault(head=True)

    def do_POST(self):
        # The ONE write path on this plane: the Trust Center access-request drop. Everything else POSTed is a 404
        # (the public plane answers no other write). A fault answers one clean JSON 500, never a dropped connection.
        try:
            if urlparse(self.path).path == _ACCESS_REQUEST_PATH:
                return self._access_request()
            return self._not_found(head=False)
        except Exception:  # noqa: BLE001 - never 500-leak internals
            return self._fault(head=False)

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
        if self._is_proof_route():
            return self._serve_proof(head=False)
        return self._serve(head=False)

    # -- PR-I: the public "Verify a VIGIL finding" explainer (flag-gated per request) ------------------------------
    def _is_proof_route(self) -> bool:
        """True for /verify, /verify/ and anything under /verify/ while VIGIL_CUSTOMER_PROOF_BADGE is on. Off, these
        paths fall through to the site exactly as before (which has no such page: the same 404)."""
        rel = normalize_rel(urlparse(self.path).path)
        return rel is not None and (rel == "verify" or rel.startswith("verify/")) and _proof_on()

    def _serve_proof(self, head: bool):
        rel = normalize_rel(urlparse(self.path).path)
        hit = (getattr(self.server, "proof", None) or {}).get(rel or "")
        if hit is None:
            return self._not_found(head)
        if not_modified(self.headers.get("If-None-Match", ""), hit.etag):
            self._send_headers(304, hit.ctype, len(hit.body), cache=_PAGE_CACHE, etag=hit.etag)
            return
        self._send_headers(200, hit.ctype, len(hit.body), cache=_PAGE_CACHE, etag=hit.etag)
        if not head:
            try:
                self.wfile.write(hit.body)
            except (BrokenPipeError, ConnectionResetError):
                pass

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

    # -- Security & Trust Center: the same-origin access-request drop (the one write path) ------------------------
    def _ip(self) -> str:
        """The client IP for the per-source submission limiter. This plane binds loopback/private (bind_ok) behind a
        reverse proxy, so the raw TCP peer is the PROXY. When the immediate peer is loopback (the trusted same-host
        proxy hop) take the real client IP from `X-Real-IP`, which the shipped proxies overwrite with the address they
        accepted the connection from (so a client cannot choose it); otherwise key on the peer. The client-chosen
        `X-Forwarded-For` is NEVER trusted (it would let an attacker key on a victim's address)."""
        peer = self.client_address[0] if self.client_address else ""
        if peer and _is_loopback_ip(peer):
            xr = (self.headers.get("X-Real-IP", "") or "").strip()
            if xr:
                return xr
        return peer or "unknown"

    def _same_origin_ok(self) -> bool:
        """Same-origin gate for the POST. The plane is cookieless, so there is no ambient session for classic CSRF to
        ride; this keeps the write SAME-ORIGIN so a cross-site page cannot script it (and defends DNS-rebinding). The
        Origin (or, absent it, the Referer) host MUST equal the request Host, a present `Sec-Fetch-Site` must be
        `same-origin`/`none`, and a request carrying neither Origin nor Referer is refused (fail-closed: a real
        same-origin browser submit always sends at least one)."""
        host = (self.headers.get("Host", "") or "").strip().lower()
        if not host:
            return False
        sfs = (self.headers.get("Sec-Fetch-Site", "") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            return False
        origin = (self.headers.get("Origin", "") or "").strip()
        if origin:
            return urlparse(origin).netloc.lower() == host
        ref = (self.headers.get("Referer", "") or "").strip()
        if ref:
            return urlparse(ref).netloc.lower() == host
        return False

    def _read_post_body(self) -> "bytes | None":
        """The POST body, bounded to `_MAX_POST_BYTES`. None when there is no declared length, it is malformed, over
        the bound, or cannot be read in full (the caller answers a clean 400/413, never a hang)."""
        raw_len = self.headers.get("Content-Length", "")
        if not raw_len or not raw_len.strip().isdigit():
            return None
        length = int(raw_len.strip())
        if length <= 0 or length > _MAX_POST_BYTES:
            return None
        try:
            data, remaining = b"", length
            while remaining > 0:
                chunk = self.rfile.read(remaining)
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
        except (OSError, ValueError):
            return None
        return data if len(data) == length else None

    def _wants_html(self) -> bool:
        """True for a plain browser navigation (a no-JS form submit): prefers HTML and did not ask for JSON. The
        JS path sends `Accept: application/json`, so it gets JSON; a no-JS form POST gets a small HTML page."""
        accept = (self.headers.get("Accept", "") or "").lower()
        mode = (self.headers.get("Sec-Fetch-Mode", "") or "").lower()
        if "application/json" in accept:
            return False
        return "text/html" in accept or mode == "navigate"

    def _access_reply(self, code: int, payload: dict, *, html_title: str, html_body: str,
                      retry_after: "str | None" = None):
        """Answer the access-request POST as JSON (the fetch path) or a minimal CSP-clean HTML page (a no-JS form
        navigation). Both carry the strict public headers and no-store; neither sets a cookie."""
        if self._wants_html():
            doc = (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                   f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                   f"<title>{html_title} - VIGIL</title><link rel=\"stylesheet\" href=\"/assets/tokens.css\">"
                   f"<link rel=\"stylesheet\" href=\"/assets/site.css\"></head><body>"
                   f"<main class=\"wrap section\"><h1>{html_title}</h1>{html_body}"
                   f"<p><a class=\"btn btn--ghost\" href=\"/trust\">Back to the Trust Center</a></p>"
                   f"</main></body></html>")
            body = doc.encode("utf-8")
            ctype = "text/html; charset=utf-8"
        else:
            body = json.dumps(payload).encode("utf-8")
            ctype = "application/json; charset=utf-8"
        if retry_after:
            # Retry-After is advisory; set it before the standard header block.
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Vigil-Build", self.server.site.build)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Retry-After", retry_after)
            self.end_headers()
        else:
            self._send_headers(code, ctype, len(body), cache="no-store")
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _access_request(self):
        # 1) same-origin gate (a cross-site page cannot forge a matching Origin against our Host)
        if not self._same_origin_ok():
            return self._access_reply(403, {"ok": False, "error": "origin"},
                                      html_title="Request not accepted",
                                      html_body="<p>This form must be submitted from the VIGIL site.</p>")
        # 2) per-source rate limit (guard-and-count; fail-closed on a storage fault)
        locked = self.server.access_limiter.admit(f"trust-access:{self._ip()}")
        if locked is not None:
            retry = str(max(1, int(locked)))
            return self._access_reply(429, {"ok": False, "error": "rate_limited",
                                            "message": "Too many requests. Please try again later."},
                                      html_title="Too many requests",
                                      html_body="<p>Too many requests from your network. Please try again later, "
                                                "or email <a href=\"mailto:info@sigilsovereign.com\">"
                                                "info@sigilsovereign.com</a>.</p>", retry_after=retry)
        # 3) read + parse the body (JSON from fetch, or urlencoded from a no-JS form submit)
        body = self._read_post_body()
        if body is None:
            return self._access_reply(413, {"ok": False, "error": "body"},
                                      html_title="Request not accepted",
                                      html_body="<p>The submission was empty or too large.</p>")
        fields = _parse_access_fields(body, self.headers.get("Content-Type", ""))
        if fields is None:
            return self._access_reply(400, {"ok": False, "error": "malformed"},
                                      html_title="Request not accepted",
                                      html_body="<p>The submission could not be read.</p>")
        # 4) validate every field (the store is the authority; it echoes no submitted value back)
        from .trust_access_requests_store import QueueFull, record_request, validate
        clean, errors = validate(fields)
        if errors:
            return self._access_reply(400, {"ok": False, "error": "invalid", "fields": errors},
                                      html_title="Please check the form",
                                      html_body="<p>Some fields need attention. Please go back and complete every "
                                                "required field with valid details.</p>")
        # 5) record it (fail-closed: NEVER acknowledge a request we did not store)
        try:
            record_request(clean, requests_dir=self.server.access_requests_dir)
        except (QueueFull, OSError, ValueError):
            return self._access_reply(503, {"ok": False, "error": "unavailable",
                                            "message": "We could not record your request right now. Please email "
                                                       "info@sigilsovereign.com."},
                                      html_title="Please try again",
                                      html_body="<p>We could not record your request right now. Please try again "
                                                "later, or email <a href=\"mailto:info@sigilsovereign.com\">"
                                                "info@sigilsovereign.com</a>.</p>")
        # 6) neutral acknowledgement: received + queued, never "granted" or "delivered"
        return self._access_reply(200, {"ok": True, "message": _ACCESS_ACK},
                                  html_title="Request received",
                                  html_body=f"<p>{_ACCESS_ACK}</p>")

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


def build_public_server(*, host: str = "127.0.0.1", port=None, root=None, access_requests_dir=None,
                        access_limiter=None) -> PublicServer:
    """Wire the public static server. Port defaults to `config.PUBLIC_UI_PORT` (:8735); `root` defaults to
    the packaged `public_site/` tree. Keyless + cookieless; GET/HEAD content, a read-only CVE API, and the one
    same-origin access-request POST. `access_requests_dir` / `access_limiter` default to the configured paths
    (a test passes its own)."""
    from .. import config
    return PublicServer((host, config.PUBLIC_UI_PORT if port is None else int(port)), PublicHandler,
                        root=root, catalog_path=config.CVE_CATALOG_PATH,
                        access_requests_dir=access_requests_dir, access_limiter=access_limiter)


def serve_public(*, host: str = "127.0.0.1", port=None, root=None) -> None:
    srv = build_public_server(host=host, port=port, root=root)
    bound_port = srv.server_address[1]
    print(f"  vigil public site on http://{host}:{bound_port}  (static; keyless + cookieless; root={srv.root})")
    serve_until_signal(srv)          # SIGTERM/SIGINT: finish the requests in flight, then exit (ui/graceful)
