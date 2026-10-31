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
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.hopauth import stamp_hop_assertion  # noqa: E402
from vigil_core.posture import is_production_posture  # noqa: E402

from ..bridge.daemon import bind_ok  # noqa: E402
from .sessions import DEFAULT_ABSOLUTE_TTL_SECONDS, SessionLedger  # noqa: E402

CUSTOMER_COOKIE = "vigil_customer_session"       # DISTINCT from the operator `sigil_session` (no cross-bleed)
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
_MAX_BODY = 65536
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
        is this edge's ONLY credential — it holds no owner key. A dead provisioner is a 502, never a crash."""
        path = f"/api/provision/{action}"
        ts = str(int(time.time()))
        data = json.dumps(body).encode("utf-8")
        # NH-1: bind the EXACT body bytes into the hop (role == "<action>:<sha256(body)>"), matching the
        # cockpit's recomputation over the bytes it receives — a captured assertion cannot be replayed with a
        # swapped body to mint an attacker-chosen grant.
        bound_role = f"{action}:{hashlib.sha256(data).hexdigest()}"
        sig = stamp_hop_assertion(self.server.hop_key, principal, bound_role, "POST", path, ts)
        req = urllib.request.Request(
            self.server.provision_base + path, data=data, method="POST",
            headers={"Content-Type": "application/json", "X-VIGIL-Provision-Principal": principal,
                     "X-VIGIL-Provision-Ts": ts, "X-VIGIL-Provision-Sig": sig})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode())
            except ValueError:
                return e.code, {"error": "provision error"}
        except (urllib.error.URLError, OSError):
            return 502, {"error": "provisioner unreachable"}

    def _mint(self, username: str, org_id) -> None:
        sid = self.server.sessions.create(str(username), _CUSTOMER_SESSION_ROLE, org_id=org_id)
        if sid:
            self._set_cookie(sid)

    # --- routing -----------------------------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self._json({"ok": True})
        if path == "/api/customer/whoami":
            rec = self._session()
            if rec is None:
                return self._json({"authenticated": False})
            # role is the non-authoritative session label; the live per-org role is resolved server-side.
            return self._json({"authenticated": True, "username": rec.get("username"),
                               "org_id": rec.get("org_id")})
        return self._deny(404, "not found")

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
                   "member_username": body.get("member_username", ""), "ip": self._ip()}
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
                   "host": body.get("host", ""), "ip": self._ip()}
        if action == "target/challenge":
            c, r = self._provision("target_challenge", requester, payload)
        else:
            payload["method"] = body.get("method", "")
            c, r = self._provision("target_verify", requester, payload)
        return self._json(r, c)


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
