"""Slice E1 — the keyless CUSTOMER edge (`custui`, default :8734). FATAL-2 sovereign-side; holds NO owner key.

This is the internet-facing customer plane, isolated from the operator cockpit. It AUTHENTICATES the
customer session itself (the `vigil_customer_session` cookie + a server-side `SessionLedger`) and reaches the
owner-signed provisioner ONLY over loopback + `VIGIL_PROVISION_HOP_KEY` (the sovereign `/api/provision/*`
routes). It mints no grant and loads no owner key — the one process that holds the key is the sovereign
provisioner, never this edge (the principal's R2 / the design-pass dedicated-provisioner correction).

Isolation (the design-pass isolation critic's bar — a false-green here is the sharpest break):
  * its session cookie is `vigil_customer_session` with its OWN `SessionLedger` (a dir distinct from the
    operator `sigil_session` ledger), so an operator cookie presented here resolves to NOTHING and a customer
    cookie presented to the cockpit resolves to NOTHING — different name AND different ledger;
  * member management takes the acting REQUESTER and the active ORG from the SERVER-side session, NEVER the
    request body — so a customer can only manage their own active org's team, as themselves (Finding D +
    tenant isolation, enforced at the edge before the hop even fires);
  * every POST is CSRF/anti-rebind gated (exact Origin/Host allowlist) and the cookie is SameSite=Strict +
    HttpOnly (+ Secure in production); a password reset severs the account's existing sessions.

Stdlib + sovereign `reuse`/`config`/`sessions` + `vigil_core` only — no framework/strix (guarded by
`assert_no_offense` at import), so the keyless edge can never pull an offense dependency across FATAL-2.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.hopauth import body_binding, stamp_hop_assertion  # noqa: E402
from vigil_core.posture import is_production_posture  # noqa: E402

from ..bridge.daemon import bind_ok  # noqa: E402
from .sessions import DEFAULT_ABSOLUTE_TTL_SECONDS, SessionLedger  # noqa: E402

CUSTOMER_COOKIE = "vigil_customer_session"       # DISTINCT from the operator `sigil_session` (no cross-bleed)
# E2b — the SHORT-LIVED Google-OIDC browser-binding cookie: HttpOnly, SameSite=Lax (must ride the IdP's
# top-level GET redirect back to us), Path-scoped to /api/customer/oidc, Max-Age 600s. Its sha256 is bound to
# the single-use `state` at login and re-checked at the callback (anti login-CSRF). DISTINCT from the session
# cookie AND from the operator plane's `sigil_oidc_sid`.
_OIDC_SID_COOKIE = "vigil_customer_oidc_sid"
# Strict CSP for the self-contained customer SPA — the SAME shape as the operator bundle (_BUNDLE_CSP) and the
# public site: self-only scripts/styles (the shared kit uses addEventListener + CSSOM, never inline handlers
# or inline <style>), data: images for inline icons, no framing, no off-site form posts. Set as a RESPONSE
# HEADER (never a <meta>), uniformly on JSON and SPA responses alike.
_CSP = ("default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
        "object-src 'none'; img-src 'self' data:")
_MAX_BODY = 65536

# How long the edge waits on its loopback hop to the cockpit. A hop that gives up BEFORE the cockpit finishes is
# worse than a slow page: the cockpit completes the action anyway (a hosted checkout is created, an email sent,
# a single-use OIDC code consumed) while the customer is told it failed — so they retry into a duplicate, or are
# locked out of a login. So the wait is PER ACTION and always exceeds that action's own outbound worst case
# (each figure below is pinned against the downstream timeout constants by test_custui_hop_budget.py); purely
# local actions keep the short default so a wedged cockpit still fails fast.
_HOP_TIMEOUT_S = 10.0
_SLOW_HOP_TIMEOUTS_S = {
    # Flutterwave hosted-checkout POST: 15 s per blocking socket op (connect, then read) -> 30 s + margin.
    "billing_checkout": 45.0,
    # OIDC: token exchange POST + JWKS GET, 10 s per blocking op each -> 40 s + margin.
    "oidc_finish": 45.0,
    # domain-ownership fetch: a 10 s ABSOLUTE wall-clock budget for the whole fetch -> + margin.
    "target_verify": 20.0,
    # verification / reset email sent INLINE over SMTP: connect, EHLO, STARTTLS, AUTH, DATA at 10 s each.
    "signup_request": 60.0,
    "recover_request": 60.0,
}


def _hop_timeout(action: str) -> float:
    """The edge→cockpit wait for ``action`` (read at call time so the table is the one source of truth)."""
    return _SLOW_HOP_TIMEOUTS_S.get(action, _HOP_TIMEOUT_S)
# The packaged customer SPA tree this keyless edge serves itself (Slice I). The app is HASH-routed, so only
# the mount root ("/" -> index.html) and its static assets are ever requested — there are no deep server
# routes and no SPA history fallback (an unknown path 404s). A per-asset size cap guards against a mistake.
_APP_ROOT = Path(__file__).resolve().parent / "customer_app"
_MAX_APP_BYTES = 4 * 1024 * 1024
_APP_CTYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
    ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8", ".map": "application/json",
    ".wav": "audio/wav",   # the notification chime (same-origin media; strict CSP's default-src 'self' covers it)
}
# The customer session's non-authoritative plane label. It is NEVER a `vigil_core.rbac` role, so
# `role_can(_CUSTOMER_SESSION_ROLE, …)` is False for every permission — the edge stores NO authoritative role
# in the session (the design-pass correction); the per-org role is resolved LIVE by the sovereign
# `admit_customer` on every member op, so a revoked membership dies on the very next request, not at TTL.
_CUSTOMER_SESSION_ROLE = "customer"


def _is_loopback(addr: str) -> bool:
    """True iff `addr` is a loopback IP (the trusted same-host reverse-proxy hop). Fail-closed on junk."""
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _listening(host: str, port: int) -> bool:
    """True if something is LISTENING on (host, port) right now. A short-timeout connect, nothing sent:
    this REPORTS liveness, it never provisions or mutates anything on the provisioner."""
    try:
        with socket.create_connection((host, int(port)), timeout=0.35):
            return True
    except (OSError, ValueError, OverflowError):
        return False


def _provision_addr(provision_base: str) -> "tuple[str, int] | None":
    """The (host, port) of the provisioner the edge federates to, parsed from its base URL. Returns None
    when the base is unset/unparseable (→ the edge cannot be ready). Never surfaced to the caller — only a
    boolean readiness verdict is — so no address ever leaves on the probe body."""
    try:
        u = urlparse(provision_base or "")
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)   # u.port validates the range HERE, inside the guard
    except ValueError:                                           # bad port (:99999 / :bad) OR malformed IPv6 literal
        return None
    if not host:
        return None
    return host, int(port)


# `/readyz` is UNAUTHENTICATED, so an untrusted caller could hammer it. The check does a live TCP connect to
# the provisioner backend; without a bound, a probe flood would AMPLIFY into a matching flood of provisioner
# connects. Debounce it: a result is cached for a short TTL and shared across the ThreadingHTTPServer's
# request threads, so no matter the incoming /readyz rate the edge opens at most ~1 provisioner connect per
# TTL per address. The window is tiny, so readiness still reflects reality for an orchestrator's probe.
# (Mirrors `uiproxy._sovereign_ready_debounced`.)
_READYZ_TTL = 1.0
_readyz_lock = threading.Lock()
_readyz_cache: dict = {}


def _provisioner_ready_debounced(host: str, port: int) -> bool:
    """`_listening(host, port)` behind a short-TTL, thread-safe cache, so an unauthenticated /readyz flood
    cannot amplify into a flood of provisioner connects. Returns the cached result within the TTL, else does
    one live connect and caches it."""
    key = (host, int(port))
    now = time.monotonic()
    with _readyz_lock:
        hit = _readyz_cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1]
    ok = _listening(host, port)          # the single live connect, done OUTSIDE the lock
    with _readyz_lock:
        _readyz_cache[key] = (now + _READYZ_TTL, ok)
    return ok



# The customer-plane READ routes relayed to the provisioner (module scope so a test can census every route that
# can carry finding detail and run the preview leak scan over each). Flag-gated reads are routed separately.
_READS = {"/api/customer/billing": "billing_overview", "/api/customer/invoices": "billing_invoices",
          "/api/customer/assessments": "assessment_summary",
          "/api/customer/assessments/findings": "assessment_findings",
          "/api/customer/assets": "assets_overview",
          "/api/customer/notifications": "notifications"}

class CustomerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, hop_key: str, provision_base: str, sessions_dir,
                 extra_hosts=(), extra_origins=()):
        host = addr[0]
        if not bind_ok(host):
            raise ValueError(
                f"refusing to bind {host!r}: the customer edge binds loopback or a PRIVATE (WireGuard/"
                f"Tailscale) address only — never 0.0.0.0 / unspecified / public. Serve a real customer "
                f"domain via a reverse proxy in front (see deploy/REMOTE-HOSTING.md).")
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            self.address_family = socket.AF_INET6
        super().__init__(addr, handler)
        self.hop_key = str(hop_key or "")
        self.provision_base = str(provision_base).rstrip("/")
        self.sessions = SessionLedger(sessions_dir)
        # E2b — the edge's OWN single-use OIDC state ledger (state↔nonce↔PKCE verifier↔sid_hash), a SIBLING
        # dir of the session ledger (its own dir, so a test's temp sessions dir gets an isolated ledger). The
        # edge holds the PKCE verifier + nonce here (non-secret, browser-binding/anti-replay material); the
        # client secret + the egress stay in the provisioner.
        self.oidc_state_dir = Path(str(sessions_dir)).parent / "customer-oidc-state"
        # E3b-2 — the edge's single-use WebAuthn challenge ledger (passkey enroll + login), a SIBLING dir.
        self.passkey_challenge_dir = Path(str(sessions_dir)).parent / "customer-passkey-challenges"
        port = self.server_address[1]

        def _hp(h: str) -> str:
            return f"[{h}]:{port}" if ":" in h else f"{h}:{port}"

        hosts = {_hp(host)}
        origins = {f"http://{_hp(host)}"}
        if ip.is_loopback:
            lit = "::1" if ip.version == 6 else "127.0.0.1"
            hosts |= {_hp(lit), f"localhost:{port}"}
            origins |= {f"http://{_hp(lit)}", f"http://localhost:{port}"}
        hosts |= {h.strip() for h in extra_hosts if h and h.strip()}
        origins |= {o.strip().rstrip("/") for o in extra_origins if o and o.strip()}
        self.allowed_hosts = frozenset(hosts)
        self.allowed_origins = frozenset(origins)


class CustomerHandler(BaseHTTPRequestHandler):
    server: CustomerServer
    server_version = "vigil-custui/1.0"
    timeout = 30

    def log_message(self, fmt, *args):  # noqa: A003 — never log (a token can ride a query on other planes)
        pass

    # --- response + session helpers ----------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        sc = getattr(self, "_pending_set_cookie", None)
        if sc:
            self.send_header("Set-Cookie", sc)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _deny(self, code=403, msg="forbidden"):
        self._json({"error": msg}, code)

    def _origin_host_ok(self) -> bool:
        """The anti-CSRF / anti-DNS-rebinding gate (Host + EXACT Origin/Referer), identical in shape to the
        cockpit action plane. A cross-origin page cannot forge an allowed Origin, and SameSite=Strict keeps
        the cookie off cross-site requests — together they make the keyless cookie plane CSRF-proof."""
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            return False
        o = self.headers.get("Origin") or ""
        ref = self.headers.get("Referer") or ""
        if o and o not in self.server.allowed_origins:
            return False
        if ref and not any(ref.startswith(a + "/") or ref == a for a in self.server.allowed_origins):
            return False
        return True

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            from http.cookies import SimpleCookie
            jar = SimpleCookie()
            jar.load(raw)
            m = jar.get(CUSTOMER_COOKIE)
            return m.value if m else ""
        except Exception:  # noqa: BLE001 — a malformed Cookie header is "no session", never a crash
            return ""

    def _session(self):
        sid = self._cookie()
        return self.server.sessions.resolve(sid) if sid else None

    def _set_cookie(self, sid: str) -> None:
        parts = [f"{CUSTOMER_COOKIE}={sid}", "Path=/", "HttpOnly", "SameSite=Strict",
                 f"Max-Age={int(DEFAULT_ABSOLUTE_TTL_SECONDS)}"]
        if is_production_posture():                   # a Secure cookie needs TLS; dev loopback omits it
            parts.append("Secure")
        self._pending_set_cookie = "; ".join(parts)

    def _clear_cookie(self) -> None:
        self._pending_set_cookie = f"{CUSTOMER_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

    def _ip(self) -> str:
        """The client IP for the BEST-EFFORT per-IP rate-limit leg. The edge binds loopback/private (bind_ok)
        and sits behind a reverse proxy, so the raw TCP peer is the PROXY — keying on it would collapse every
        customer onto ONE rate-limit key, letting a single attacker lock out the entire customer auth surface
        (the red-pen's CO5). When the immediate peer is loopback (the trusted same-host proxy hop), take the
        real client IP from `X-Real-IP` / the first `X-Forwarded-For` entry instead. This value feeds ONLY the
        best-effort per-IP leg (the per-account/email leg is the reliable one), NEVER authz — so a spoofed
        header lets an attacker evade only their OWN throttle, never impersonate or lock out another."""
        peer = self.client_address[0] if self.client_address else ""
        if peer and _is_loopback(peer):
            xr = (self.headers.get("X-Real-IP", "") or "").strip()
            if xr:
                return xr
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
        return peer

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > _MAX_BODY:
            raise ValueError("body too large")
        body = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("body must be an object")
        return body

    def _provision(self, action: str, principal: str, body: dict):
        """Call the sovereign provisioner route over loopback, stamping the hop assertion the same way the
        sovereign verifies it (role == action; principal + method + path + ts inside the HMAC). The hop key
        is this edge's ONLY credential — it holds no owner key. A dead provisioner, or a reply that cannot be read
        (truncated, not JSON), is a 502, never a crash."""
        if not self.server.hop_key:
            # No hop key: nothing this edge could stamp would verify (and `body_binding` raises on a blank key —
            # a POST surfaced that as a 400, a GET dropped the connection). Refuse before any hop, with the same
            # 403 the cockpit gives an unkeyed hop, so every verb gets one clean, fail-closed answer.
            return 403, {"error": "provision denied (hop)"}
        path = f"/api/provision/{action}"
        ts = str(int(time.time()))
        data = json.dumps(body).encode("utf-8")
        # NH-1: bind the EXACT body bytes into the hop (role == "<action>:<body_binding(body)>"), matching the
        # cockpit's recomputation over the bytes it receives — a captured assertion cannot be replayed with a
        # swapped body to mint an attacker-chosen grant. The body can carry a password, so the binding is a
        # KEYED, SLOW password-grade KDF (vigil_core.hopauth.body_binding), never a fast hash.
        bound_role = f"{action}:{body_binding(self.server.hop_key, data)}"
        sig = stamp_hop_assertion(self.server.hop_key, principal, bound_role, "POST", path, ts)
        req = urllib.request.Request(
            self.server.provision_base + path, data=data, method="POST",
            headers={"Content-Type": "application/json", "X-VIGIL-Provision-Principal": principal,
                     "X-VIGIL-Provision-Ts": ts, "X-VIGIL-Provision-Sig": sig})
        try:
            with urllib.request.urlopen(req, timeout=_hop_timeout(action)) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode())
            except (ValueError, http.client.HTTPException, OSError):   # an unreadable error body keeps its status
                return e.code, {"error": "provision error"}
        except (urllib.error.URLError, OSError):
            return 502, {"error": "provisioner unreachable"}
        except (ValueError, http.client.HTTPException):
            # a 2xx whose body is truncated (IncompleteRead) or not JSON — e.g. the cockpit restarted mid-reply, or
            # provision_base names the wrong service: one clean 502 on every verb (a GET used to drop the connection)
            return 502, {"error": "provisioner reply unreadable"}

    def _mint(self, username: str, org_id, *, mfa_at=None, mfa_method=None) -> None:
        # E3c — `mfa_at`/`mfa_method` stamp a FRESH step-up at mint: a passkey LOGIN is itself a fresh second
        # factor, so it mints an already-stepped-up session; password/signup/OIDC mint with None (no factor).
        sid = self.server.sessions.create(str(username), _CUSTOMER_SESSION_ROLE, org_id=org_id,
                                          mfa_at=mfa_at, mfa_method=mfa_method)
        if sid:
            self._set_cookie(sid)

    # --- health / readiness (probe surface) --------------------------------------------------------
    def _readyz(self):
        """Readiness — a LIVE, DEBOUNCED port probe of the edge's one real dependency: the sovereign
        provisioner. Returns 503 when it is not listening (the edge can still serve its static shell, but
        no customer read/action can complete), so an LB drains this edge instead of serving 502s. ALSO 503
        when the edge holds no hop key: every provisioner hop then fails closed, so no customer read/action
        can complete regardless of the port being up — a local, no-network check that honours the same
        contract. The body is a boolean + the check name ONLY — never the provisioner address, so the
        unauthenticated probe leaks nothing. Side-effect-free: it opens one TCP connection and sends no bytes."""
        addr = _provision_addr(self.server.provision_base)
        # an edge with NO hop key cannot authenticate a single provisioner hop (serve_customer boots that
        # degraded mode with a banner), so it is not ready even if the provisioner port is reachable.
        ok = bool(self.server.hop_key) and bool(addr) and _provisioner_ready_debounced(*addr)
        self._json({"ok": ok, "checks": [{"name": "provisioner", "ok": ok}]}, 200 if ok else 503)

    # --- routing -----------------------------------------------------------------------------------
    def do_GET(self):
        # the same catch-all do_POST has: an unexpected fault answers one clean JSON 500 (no internals), never a
        # dropped connection with a handler traceback
        try:
            return self._route_get()
        except Exception:  # noqa: BLE001 — never 500-leak internals
            return self._deny(500, "request failed")

    def _route_get(self):
        path = urlparse(self.path).path
        # Probe surface (UNAUTHENTICATED, no cookie, no secret) — placed FIRST, ahead of the session/relay
        # plane, so a k8s/LB liveness+readiness probe (which can present no customer cookie) is answered
        # without touching any privileged state. `/healthz` is pure liveness (the process answers);
        # `/readyz` checks the edge's REAL dependency — the sovereign provisioner it federates every
        # customer read/action to — and returns 503 when it is unreachable, so an orchestrator drains an
        # edge whose provisioner is down rather than serving 502s from it.
        if path == "/healthz":
            return self._json({"ok": True})
        if path == "/readyz":
            return self._readyz()
        if path == "/api/customer/whoami":
            rec = self._session()
            if rec is None:
                return self._json({"authenticated": False})
            # role is the non-authoritative session label; the live per-org role is resolved server-side.
            return self._json({"authenticated": True, "username": rec.get("username"),
                               "org_id": rec.get("org_id")})
        # customer-plane READS (the Slice-I backend): billing overview / invoices / assessment summary +
        # findings. org comes from the SERVER-side session, never the query; the provisioner admit_customer-
        # gates it. SameSite=Strict keeps the session cookie off cross-site GETs, so a cross-site read carries
        # no session -> 401 (no cross-origin data leak); same-origin reads (the customer SPA) carry the cookie.
        if path in _READS:
            return self._customer_read_relay(_READS[path])
        if path == "/api/customer/billing/offers" and _checkout_on():   # CHK-2 (flag OFF -> unknown-route 404)
            return self._customer_read_relay("billing_offers")
        if path == "/api/customer/monitoring" and _monitoring_on():     # AE-1 (flag OFF -> unknown-route 404)
            return self._customer_read_relay("monitor_list")
        if path == "/api/customer/monitoring/events" and _monitoring_on():
            return self._customer_read_relay("monitor_events")
        # E2b — Google OIDC (GET: the SPA links to /login as a top-level nav; the IdP redirects to /callback).
        # Both are served ONLY when customer_oidc_enabled() — otherwise the routes are absent (404), so the
        # edge is byte-identical to a build without customer OIDC (mirrors the operator route-gating).
        if path in ("/api/customer/oidc/login", "/api/customer/oidc/callback"):
            from .. import config as _config
            if not _config.customer_oidc_enabled():
                return self._deny(404, "not found")
            return self._oidc_login() if path.endswith("/login") else self._oidc_callback()
        if path.startswith("/api/"):           # an unknown API route 404s — NEVER fall through to the SPA shell
            return self._deny(404, "not found")
        return self._serve_app(path)           # else the keyless edge serves its own hash-routed static SPA

    def _resolve_app(self, urlpath: str):
        """Map a URL path to a safe file under `_APP_ROOT`, or None. "/" -> index.html; any other path is an
        EXACT static asset (the SPA is hash-routed, so there are no deep routes and NO index.html fallback —
        an unknown path returns None -> 404, never a masked shell). Path-traversal is refused: the candidate
        must `resolve()` to within the resolved root. Returns (abs_path, content_type) or None."""
        rel = unquote(urlparse(urlpath).path).lstrip("/")
        root = _APP_ROOT
        cand = (root / "index.html") if rel in ("", "/") else (root / rel)
        try:
            rp = cand.resolve()
        except (OSError, RuntimeError, ValueError):
            return None
        if rp != root and not rp.is_relative_to(root):
            return None                        # traversal guard — must stay within the content root
        if rp.is_file():
            return rp, _APP_CTYPES.get(rp.suffix.lower(), "application/octet-stream")
        return None

    def _serve_app(self, path: str):
        """Serve the self-contained customer SPA (static, traversal-safe, strict-CSP, size-capped). The edge
        holds no key and the SPA carries no token — it authenticates by the `vigil_customer_session` cookie."""
        hit = self._resolve_app(path)
        if hit is None:
            return self._deny(404, "not found")
        rp, ctype = hit
        try:
            data = rp.read_bytes()
        except OSError:
            return self._deny(404, "not found")
        if len(data) > _MAX_APP_BYTES:
            return self._deny(413, "asset too large")
        self._send(200, data, ctype)           # same strict CSP / nosniff / no-referrer headers as every response

    def _customer_read_relay(self, action: str):
        """Relay a customer-plane READ to the provisioner over the hop, carrying the SESSION org (never a
        query/body field). A caller with no customer session (or no bound org) is refused before the hop."""
        rec = self._session()
        if rec is None or not rec.get("org_id"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        c, r = self._provision(action, requester, {"org_id": str(rec.get("org_id") or ""), "ip": self._ip()})
        return self._json(r, c)

    # --- Google OIDC (E2b): the keyless edge drives the browser-facing half; the secret stays provisioner-side
    def _oidc_state_store(self):
        """The edge's single-use OIDC state ledger (state↔nonce↔PKCE verifier↔sid_hash), rooted at the
        server's `oidc_state_dir`. Reuses the sovereign `ui.oidc.OidcStateStore` (stdlib-only; FATAL-2 clean)."""
        from .oidc import OidcStateStore
        return OidcStateStore(self.server.oidc_state_dir)

    def _oidc_sid_cookie(self) -> str:
        """The value of the short-lived OIDC browser-binding cookie on THIS request (or "" — fail-closed)."""
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            from http.cookies import SimpleCookie
            jar = SimpleCookie()
            jar.load(raw)
            m = jar.get(_OIDC_SID_COOKIE)
            return m.value if m else ""
        except Exception:  # noqa: BLE001 — a malformed Cookie header is "no binding", never a crash
            return ""

    def _oidc_login(self):
        """GET /api/customer/oidc/login — 302 to Google's authorize endpoint with a fresh single-use
        state+nonce+PKCE-S256 challenge, setting the HttpOnly SameSite=Lax sid cookie whose hash binds the
        state to THIS browser. Built from the NON-SECRET public config only (the client secret never reaches
        this keyless edge). Same-origin/Host gated like every edge route; a misconfigured OIDC fails LOUD (500)."""
        if not self._origin_host_ok():
            return self._deny(403, "denied (origin / host)")
        from .. import config as _config
        from . import oidc as _oidc
        try:
            cfg = _oidc.OidcConfig.from_settings(_config.customer_oidc_public_settings())
        except _oidc.OidcError:
            return self._deny(500, "customer google sign-in is enabled but misconfigured")
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = _oidc.generate_pkce_verifier()
        challenge = _oidc.pkce_challenge_s256(verifier)
        sid = secrets.token_urlsafe(32)
        sid_hash = hashlib.sha256(sid.encode("utf-8")).hexdigest()
        try:
            self._oidc_state_store().issue(state, nonce, verifier=verifier, sid_hash=sid_hash)
        except Exception:  # noqa: BLE001 — a ledger I/O error must not leak internals; refuse the mint
            return self._deny(500, "could not mint an oidc login state")
        location = _oidc.build_authorize_url(cfg, state, nonce, code_challenge=challenge)
        cookie = (f"{_OIDC_SID_COOKIE}={sid}; Path=/api/customer/oidc; Max-Age=600; HttpOnly; SameSite=Lax"
                  + ("; Secure" if is_production_posture() else ""))
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("Referrer-Policy", "no-referrer")       # the state/nonce never leak via Referer
        self.end_headers()

    def _oidc_callback(self):
        """GET /api/customer/oidc/callback?code&state — Google redirects here. HOST-gated only (NOT
        Origin/Referer-gated: an IdP top-level redirect legitimately carries a foreign Referer and no Origin;
        the anti-CSRF binding is the single-use state + the HttpOnly sid-cookie hash, which an attacker cannot
        forge). Steps, each fail-closed:
          1. CONSUME the single-use state → bound (nonce, PKCE verifier, sid_hash); replay/unknown → refuse.
          2. SESSION-BIND: the presenting browser's sid cookie must hash to the bound sid_hash (anti login-CSRF).
          3. HOP {code, code_verifier, nonce} to the provisioner's secret-bearing oidc_finish → {username, orgs}.
          4. On success MINT a CUSTOMER session cookie (never an operator bearer) and 302 into the SPA."""
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            return self._deny(403, "denied (host)")
        q = parse_qs(urlparse(self.path).query)
        err = (q.get("error", [""])[0] or "")
        if err:
            return self._json({"authenticated": False, "error": f"idp returned an error: {str(err)[:120]}"}, 401)
        code = q.get("code", [""])[0] or ""
        state = q.get("state", [""])[0] or ""
        rec = self._oidc_state_store().consume(state)
        if rec is None:
            return self._json({"authenticated": False,
                               "error": "unknown, expired, or already-used oidc state"}, 401)
        presented = self._oidc_sid_cookie()
        if not rec.sid_hash or not presented or not hmac.compare_digest(
                hashlib.sha256(presented.encode("utf-8")).hexdigest(), rec.sid_hash):
            return self._json({"authenticated": False,
                               "error": "oidc state is not bound to this browser session"}, 401)
        # HOP the single-use grant to the provisioner (principal "" — this IS the login; the hop key alone
        # gates it). The provisioner does the secret-bearing exchange + verify + auto-provision/anti-takeover.
        c, r = self._provision("oidc_finish", "", {"code": code, "code_verifier": rec.verifier,
                                                   "nonce": rec.nonce, "ip": self._ip()})
        if c == 200 and isinstance(r, dict) and r.get("username"):
            orgs = r.get("orgs") or []
            active = orgs[0] if orgs else None               # server-bound active org (switch is a later slice)
            self._mint(r["username"], active)                # sets the CUSTOMER session cookie (never operator)
            return self._redirect_to_app()                   # 302 into the hash-routed SPA, carrying the session
        return self._redirect_to_app(ok=False)               # a refusal lands the browser back on the app

    def _redirect_to_app(self, *, ok: bool = True):
        """End the top-level OIDC flow with a 302 into the SPA root. On success the `_mint`-set session cookie
        rides along (so the SPA is immediately authenticated); on failure no cookie is set and the SPA shows
        the signed-out state. A terse `#oidc=err` fragment on failure lets the SPA surface a generic message
        without leaking why (and without a raw JSON page in the user's browser)."""
        self.send_response(302)
        self.send_header("Location", "/" if ok else "/#oidc=err")
        self.send_header("Content-Length", "0")
        sc = getattr(self, "_pending_set_cookie", None)
        if ok and sc:
            self.send_header("Set-Cookie", sc)
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/customer/"):
            return self._deny(404, "not found")
        if not self._origin_host_ok():                # CSRF/anti-rebind on EVERY customer mutation
            return self._deny(403, "denied (origin / host)")
        action = path[len("/api/customer/"):]
        try:
            body = self._read_body()
        except (ValueError, OSError) as e:
            return self._deny(400, f"bad request: {str(e)[:200]}")
        try:
            return self._dispatch(action, body)
        except Exception as e:  # noqa: BLE001 — never 500-leak internals
            return self._deny(400, f"request failed: {str(e)[:200]}")

    def _dispatch(self, action: str, body: dict):
        if action == "signup/request":
            c, r = self._provision("signup_request", "", {"email": body.get("email", ""), "ip": self._ip()})
            return self._json(r, c)
        if action == "signup/confirm":
            c, r = self._provision("signup_confirm", "", {"token": body.get("token", ""),
                    "password": body.get("password", ""), "org_name": body.get("org_name", ""),
                    "ip": self._ip()})
            if c == 200 and isinstance(r, dict) and r.get("username"):
                self._mint(r["username"], r.get("org_id"))     # the new org_admin's session, bound to their org
            return self._json(r, c)
        if action == "login":
            c, r = self._provision("login", "", {"email": body.get("email", ""),
                    "password": body.get("password", ""), "ip": self._ip()})
            if c == 200 and isinstance(r, dict) and r.get("username"):
                orgs = r.get("orgs") or []
                active = orgs[0] if orgs else None             # server-bound active org (switch is a later slice)
                self._mint(r["username"], active)
                r = {**r, "active_org": active}
            return self._json(r, c)
        if action == "recover/request":
            c, r = self._provision("recover_request", "", {"email": body.get("email", ""), "ip": self._ip()})
            return self._json(r, c)
        if action == "recover/confirm":
            c, r = self._provision("recover_confirm", "", {"token": body.get("token", ""),
                    "new_password": body.get("new_password", "")})
            if c == 200 and isinstance(r, dict) and r.get("username"):
                # SEVER every existing session for the account (the edge half of the session-reset seam).
                self.server.sessions.revoke_all_for_user(str(r["username"]))
            return self._json(r, c)
        if action == "logout":
            sid = self._cookie()
            if sid:
                self.server.sessions.revoke(sid)
            self._clear_cookie()
            return self._json({"ok": True})
        if action in ("member/grant", "member/revoke"):
            return self._member(action, body)
        if action in ("target/challenge", "target/verify"):
            return self._target(action, body)
        if action in ("launch/reserve", "launch/cancel", "launch/start"):
            return self._launch(action, body)
        if action in ("launch/pause", "launch/resume") and _pause_resume_on():  # PR-4b (flag OFF -> unknown-action 404)
            return self._launch(action, body)
        if action in ("monitoring/authorize", "monitoring/revoke") and _monitoring_on():
            return self._monitoring(action, body)
        if action == "billing/checkout" and _checkout_on():          # CHK-1 (flag OFF -> unknown-action 404)
            return self._checkout(body)
        if action in ("mfa/totp/enroll", "mfa/verify"):
            return self._mfa(action, body)
        if action in ("passkey/enroll/challenge", "passkey/enroll/verify",
                      "passkey/login/challenge", "passkey/login/verify"):
            return self._passkey(action, body)
        return self._deny(404, "unknown action")

    def _member(self, action: str, body: dict):
        """Member management: the acting REQUESTER and the active ORG are taken from the SERVER-side session
        — NEVER the request body (Finding D + tenant isolation at the edge). A body `org_id`/`requester` is
        ignored. A caller with no customer session (or no bound org) is refused before the hop fires."""
        rec = self._session()
        if rec is None or not rec.get("org_id"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        payload = {"org_id": str(rec.get("org_id") or ""),      # the session's bound org, never body-supplied
                   "member_username": body.get("member_username", ""), "ip": self._ip(),
                   "mfa_at": rec.get("mfa_at")}                 # E3c step-up stamp from the SESSION, never body
        if action == "member/grant":
            payload["role"] = body.get("role", "")
            c, r = self._provision("member_grant", requester, payload)
        else:
            c, r = self._provision("member_revoke", requester, payload)
        return self._json(r, c)

    def _target(self, action: str, body: dict):
        """Asset-ownership target registration (Slice G0). Like `_member`, the acting REQUESTER and the active
        ORG are taken from the SERVER-side session — NEVER the body (tenant isolation at the edge): a customer
        proves ownership of a host for THEIR bound org only, and cannot name another org. The `host` (and, on
        verify, the `method`) are the customer's chosen target, carried in the body; the sovereign provisioner
        gates on admit_customer(run_engagement) and mints only on a current ownership proof."""
        rec = self._session()
        if rec is None or not rec.get("org_id"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        payload = {"org_id": str(rec.get("org_id") or ""),      # the session's bound org, never body-supplied
                   "host": body.get("host", ""), "ip": self._ip(),
                   "mfa_at": rec.get("mfa_at")}                 # E3c step-up stamp from the SESSION, never body
        if action == "target/challenge":
            c, r = self._provision("target_challenge", requester, payload)
        else:
            payload["method"] = body.get("method", "")
            # The customer's inline "I am authorized to test this asset" affirmation. Unlike requester/org (which
            # are session-bound, never body), this is the customer's OWN statement, so it legitimately rides the
            # body; the provisioner requires it fail-closed before it will mint the target authority.
            payload["authorized"] = bool(body.get("authorized"))
            c, r = self._provision("target_verify", requester, payload)
        return self._json(r, c)

    def _launch(self, action: str, body: dict):
        """Offense-launch credit reservation (Slice G). Like `_target`, the acting REQUESTER and the active
        ORG are taken from the SERVER-side session — NEVER the body (tenant isolation at the edge): a customer
        reserves credits + mints a launch lease for THEIR bound org only, and cannot name another tenant. On
        reserve, the `host` (the customer's already-ownership-proven, owner-authorized target) rides the body;
        the credit `units` are SERVER-decided (``config.LAUNCH_UNITS`` at the provisioner), NEVER customer-
        supplied (money doctrine). On cancel, the signed `lease` to release rides the body and the sovereign
        binds it to the session org (``expect_org_id``) — so a customer can never settle/cancel another
        tenant's reservation even by presenting that tenant's (owner-signed) lease."""
        rec = self._session()
        if rec is None or not rec.get("org_id"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        # dict[str, object]: the lease (cancel) is a nested object, not a str — so the payload is not str-valued
        payload: dict[str, object] = {"org_id": str(rec.get("org_id") or ""), "ip": self._ip(),
                                      "mfa_at": rec.get("mfa_at")}   # E3c step-up stamp from the SESSION, never body
        if action == "launch/reserve":
            payload["host"] = body.get("host", "")              # session org, never body-supplied
            payload["product_id"] = body.get("product_id", "")  # EC-7b: tier product choice (catalog id, not an amount)
            c, r = self._provision("launch_reserve", requester, payload)
        elif action in ("launch/start", "launch/cancel", "launch/pause", "launch/resume"):
            # all carry the signed lease; the sovereign re-verifies it owner-pinned + tenant-binds to the session
            # org. launch/pause|resume (PR-4b) are flag-gated at the route, so the hop 404s when the flag is off.
            payload["lease"] = body.get("lease")
            c, r = self._provision(action.replace("/", "_", 1), requester, payload)  # launch_start|cancel|pause|resume
        else:
            return self._deny(404, "unknown launch action")
        return self._json(r, c)

    def _checkout(self, body: dict):
        """Front B CHK-1 — open a hosted checkout. REQUESTER + ORG from the SERVER-side session, never the body (a
        body org_id is ignored): a customer can only ever fund THEIR bound org. The body carries ONLY the catalog
        ``price_id``; the amount is the owner catalog's (sovereign side). Returns the processor's hosted link."""
        rec = self._session()
        if rec is None or not rec.get("org_id"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        payload: dict[str, object] = {"org_id": str(rec.get("org_id") or ""), "price_id": body.get("price_id", ""),
                                      "ip": self._ip(), "mfa_at": rec.get("mfa_at")}
        c, r = self._provision("billing_checkout", requester, payload)
        return self._json(r, c)

    def _monitoring(self, action: str, body: dict):
        """AEGIS-SaaS AE-1 — DEFENSIVE monitoring authority. REQUESTER + ORG from the SERVER-side session, never
        the body (a body org_id is ignored); host / mode / window_s are the customer's request (the window is
        server-capped). The sovereign provisioner admits, steps up, mints + publishes."""
        rec = self._session()
        if rec is None or not rec.get("org_id"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        payload: dict[str, object] = {"org_id": str(rec.get("org_id") or ""), "host": body.get("host", ""),
                                      "ip": self._ip(), "mfa_at": rec.get("mfa_at")}
        if action == "monitoring/authorize":
            payload["mode"] = body.get("mode", "observe")
            if body.get("window_s") is not None:
                payload["window_s"] = body.get("window_s")
            c, r = self._provision("monitor_authorize", requester, payload)
        else:
            c, r = self._provision("monitor_revoke", requester, payload)
        return self._json(r, c)

    def _mfa(self, action: str, body: dict):
        """Customer MFA (E3b TOTP): the acting REQUESTER is taken from the SERVER-side session — NEVER the
        body. MFA is ACCOUNT-level (a customer enrolls/verifies their OWN factor, not an org's), so the gate
        is simply an authenticated session. `mfa/totp/enroll` returns the otpauth:// URI + the one-time secret
        for the customer to add to their authenticator app (shown once, never persisted plaintext);
        `mfa/verify` proves a fresh TOTP code (the step-up / second-factor primitive E3c consumes)."""
        rec = self._session()
        if rec is None or not rec.get("username"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        if action == "mfa/totp/enroll":
            c, r = self._provision("mfa_enroll_totp", requester, {"ip": self._ip()})
        else:
            c, r = self._provision("mfa_verify", requester, {"code": body.get("code", ""), "ip": self._ip()})
            # E3c step-up: a verified TOTP stamps mfa_at onto the LIVE session (the edge half — mfa_at is
            # SERVER-set from `now`, never a client field), so the sensitive ops see a fresh second factor.
            if c == 200 and isinstance(r, dict) and r.get("ok"):
                sid = self._cookie()
                if sid:
                    self.server.sessions.stamp_mfa(sid, mfa_at=time.time(), mfa_method="totp")
        return self._json(r, c)

    def _passkey_challenge_store(self):
        """The edge's single-use WebAuthn challenge ledger (reuses the stdlib ChallengeLedger)."""
        from .login_challenges import ChallengeLedger
        return ChallengeLedger(self.server.passkey_challenge_dir)

    def _passkey(self, action: str, body: dict):
        """Customer passkey (E3b-2 WebAuthn). ENROLL is session-gated (the requester is the session username,
        account-level — never a body field). LOGIN is a public bootstrap (no session): the credential_id
        resolves the customer at the provisioner, and a successful assertion MINTS a customer session (never
        an operator bearer). Every challenge is single-use (minted here, CONSUMED before the hop — the replay
        guard); every POST is already CSRF/Origin-gated by do_POST. Routes absent when passkey is disabled."""
        from .. import config as _config
        if not _config.customer_passkey_enabled():
            return self._deny(404, "not found")
        store = self._passkey_challenge_store()
        # --- LOGIN (no session) ---
        if action == "passkey/login/challenge":
            ch = secrets.token_urlsafe(32)
            try:
                store.issue(ch)
            except Exception:  # noqa: BLE001 — a ledger I/O / capacity error must not leak internals
                return self._deny(500, "could not mint a passkey challenge")
            return self._json({"challenge": ch})
        if action == "passkey/login/verify":
            ch = str(body.get("challenge", ""))
            if not ch or not store.consume(ch):
                return self._deny(401, "unknown, expired, or already-used passkey challenge")
            c, r = self._provision("passkey_login", "", {
                "credential_id": body.get("credential_id", ""),
                "authenticator_data": body.get("authenticator_data", ""),
                "client_data_json": body.get("client_data_json", ""),
                "signature": body.get("signature", ""), "challenge": ch, "ip": self._ip()})
            if c == 200 and isinstance(r, dict) and r.get("username"):
                orgs = r.get("orgs") or []
                active = orgs[0] if orgs else None             # server-bound active org (switch is a later slice)
                # a fresh passkey LOGIN is itself a fresh second factor → mint an already-stepped-up session (E3c)
                self._mint(r["username"], active, mfa_at=time.time(), mfa_method="passkey")
                r = {**r, "active_org": active}
            return self._json(r, c)
        # --- ENROLL (session required; account-level) ---
        rec = self._session()
        if rec is None or not rec.get("username"):
            return self._deny(401, "login required")
        requester = str(rec.get("username") or "")
        if action == "passkey/enroll/challenge":
            ch = secrets.token_urlsafe(32)
            try:
                store.issue(ch)
            except Exception:  # noqa: BLE001
                return self._deny(500, "could not mint a passkey challenge")
            return self._json({"challenge": ch})
        # passkey/enroll/verify
        ch = str(body.get("challenge", ""))
        if not ch or not store.consume(ch):
            return self._deny(401, "unknown, expired, or already-used passkey challenge")
        c, r = self._provision("passkey_enroll", requester, {
            "credential_id": body.get("credential_id", ""),
            "public_key_spki_b64": body.get("public_key_spki_b64", ""),
            "cose_alg": body.get("cose_alg"), "uv": bool(body.get("uv")),
            "client_data_json": body.get("client_data_json", ""), "challenge": ch, "ip": self._ip()})
        return self._json(r, c)


def _monitoring_on() -> bool:
    from .. import config as _config
    return _config.customer_monitoring_enabled()


def _checkout_on() -> bool:
    from .. import config as _config
    return _config.customer_checkout_enabled()


def _pause_resume_on() -> bool:
    from .. import config as _config
    return _config.customer_pause_resume_enabled()


def build_customer_server(*, host: str = "127.0.0.1", port=None, hop_key=None, provision_base=None,
                          sessions_dir=None, extra_hosts=(), extra_origins=()) -> CustomerServer:
    """Wire the keyless customer edge from config: the customer port (:8734), the edge→provisioner hop key,
    the sovereign provision base URL (loopback), and the customer session ledger dir (under SIGIL_HOME). No
    owner key is ever loaded — only the hop secret. Tests inject explicit values (two in-process servers)."""
    from .. import config
    return CustomerServer(
        (host, config.CUSTOMER_UI_PORT if port is None else int(port)), CustomerHandler,
        hop_key=config.provision_hop_key() if hop_key is None else hop_key,
        provision_base=config.sovereign_provision_base() if provision_base is None else provision_base,
        sessions_dir=config.CUSTOMER_SESSIONS_DIR if sessions_dir is None else sessions_dir,
        extra_hosts=extra_hosts, extra_origins=extra_origins)


def serve_customer(*, host: str = "127.0.0.1", port=None, hop_key=None, provision_base=None,
                   sessions_dir=None, extra_hosts=(), extra_origins=()) -> None:
    """Build the keyless customer edge from config and serve it (blocking). Mirrors `pubui.serve_public`.
    The edge holds NO owner key — only the edge→provisioner HMAC hop; an EMPTY hop key means every
    provisioning route fails CLOSED (login still works for already-provisioned sessions, but no signup /
    member grant can mint), so the banner says so plainly rather than pretending it is ready."""
    srv = build_customer_server(host=host, port=port, hop_key=hop_key, provision_base=provision_base,
                                sessions_dir=sessions_dir, extra_hosts=extra_hosts, extra_origins=extra_origins)
    bound_port = srv.server_address[1]
    keyed = ("hop key SET" if srv.hop_key
             else "hop key UNSET → provisioning FAILS CLOSED (set VIGIL_PROVISION_HOP_KEY)")
    print(f"  vigil customer edge on http://{host}:{bound_port}  (keyless; cookie=vigil_customer_session; "
          f"provisioner={srv.provision_base}; {keyed})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
