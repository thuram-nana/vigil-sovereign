"""The SIGIL glass-cockpit server (Phase 7, WS-C) — a NON-PUBLIC, two-plane HTTP server (stdlib
only, minimal auditable surface). Mirrors the MCP server's posture: read-only over the spine +
provenance on every atom, plus a CSRF-proof owner-signed action plane.

Security model (the red-pen keystone):
  • binds a `bind_ok` address ONLY — loopback (default) or a PRIVATE (WireGuard/Tailscale) address.
    NEVER 0.0.0.0 / an unspecified / a public address (the constructor raises otherwise). To reach the
    cockpit by a real domain, put a reverse proxy in front that terminates TLS and forwards to this
    private bind — the tunnel/proxy is the network boundary, not a public listener (see
    apps/sigil/deploy/REMOTE-HOSTING.md).
  • a session TOKEN is minted at startup and PRINTED TO THE TERMINAL (so only someone at the machine
    can drive it, and no web page can read it). The served page embeds it; a cross-origin page cannot.
  • READ plane (GET /api/*): requires the token (header `X-SIGIL-Token`, or `?token=` for SSE which
    can't set headers). Read/query only — EXCEPT `/api/ask`, which DISPATCHES a WARDEN-gated KERNEL
    query (a subprocess), so it carries the FULL action gate (token + Origin + Host), not just token.
  • ACTION plane (POST /api/action): requires the token AND an EXACT-MATCH `Origin`/`Referer` in the
    allowlist AND a `Host` in the allowlist (defeats DNS-rebinding). The allowlist is derived from the
    REAL bound address (plus the loopback pair when bound to loopback) UNIONED with the operator's
    explicitly-configured domain Host/Origin (`allowed_hosts`/`allowed_origins`) — so a reverse proxy
    forwarding `Host: cockpit.example.com` + `Origin: https://cockpit.example.com` is accepted while
    every other cross-origin request is still refused. Routes ONLY the closed owner-signed action set.
    The private key never touches the browser — the server signs (see `ui.actions`).
  • Static assets + the index bootstrap are token-free (they carry no secret; the token is injected
    into the page as a data attribute, unreadable cross-origin). A strict CSP + external `self` JS/CSS
    keeps the page functional AND locked down."""
from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import secrets
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from vigil_core.spine_domains import DOMAIN_TAGS

from ..bridge.daemon import bind_ok
from ..config import SPINE_PATH, oidc_enabled
from ..reuse import verify_one
from ..spine.store import SpineStore
from ..spine.tail import SpineTailer
from ..spine.verify import verify_record
from . import actions as _actions

_STATIC = Path(__file__).parent / "static"
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

# S3 proof-of-possession login: the domain-separated message a user signs is DOMAIN_TAG + the raw challenge
# bytes. The tag (a versioned, NUL-terminated label) namespaces the signature so a login proof can never be
# a valid signature for any OTHER protocol that reuses the same user key, and vice-versa. Sourced from the
# ONE registry of VIGIL's signed spine/log domains (`vigil_core.spine_domains`) rather than a local literal,
# so the registry stays complete and the two can never drift.
_LOGIN_POP_DOMAIN_TAG = DOMAIN_TAGS["login-pop"]


class UIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, token: str, spine_path: Path,
                 extra_hosts=(), extra_origins=(), oidc_http_post=None, oidc_jwks_fetcher=None):
        host = addr[0]
        if not bind_ok(host):
            raise ValueError(
                f"refusing to bind {host!r}: the cockpit binds loopback or a PRIVATE (WireGuard/"
                f"Tailscale) address only — never 0.0.0.0 / an unspecified / a public address. To serve "
                f"a real domain, run a reverse proxy in front (see deploy/REMOTE-HOSTING.md).")
        ip = ipaddress.ip_address(host)             # bind_ok already proved this parses
        if ip.version == 6:                         # bind an IPv6 tunnel (WireGuard/Tailscale) address
            self.address_family = socket.AF_INET6   # (instance attr read by TCPServer.__init__ below)
        super().__init__(addr, handler)
        self.token = token
        self.spine_path = spine_path
        port = self.server_address[1]              # the ACTUAL bound port (correct even for port 0)
        # Anti-DNS-rebinding allowlist: the REAL bound address, plus the loopback pair only when bound to
        # loopback (dev convenience — never added for a private/WG bind), UNIONED with the operator's
        # explicitly-configured reverse-proxy domain Host/Origin. Empty/blank extras are dropped. IPv6
        # literals are bracketed to match the Host-header/Origin form a browser sends (`[::1]:port`).
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
        # OIDC (S5): injectable network hooks so a test can drive the callback against an in-process mock
        # IdP with NO real network. Both default to None → the real urllib egress (used only when OIDC is
        # enabled AND a callback is actually processed). Never touched when OIDC is off.
        self.oidc_http_post = oidc_http_post           # (url, form) -> dict  (token exchange)
        self.oidc_jwks_fetcher = oidc_jwks_fetcher     # (url) -> dict        (JWKS fetch)

    def store(self) -> SpineStore:
        return SpineStore(self.spine_path)         # fresh read each request (cheap, current)


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server: UIServer                    # set by the socketserver machinery to our concrete server
    server_version = "sigil-ui/1.0"
    timeout = 30                        # per-connection socket timeout (BLOCK-4: no hung reader)
    _MAX_BODY = 65536                   # action bodies are tiny; cap to avoid a Content-Length hang
    _STATIC_OK = frozenset({"app.js", "style.css"})

    # never log the token (it can ride in ?token= for SSE)
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    # --- auth -------------------------------------------------------------------------------------
    def _query(self) -> dict:
        return parse_qs(urlparse(self.path).query)

    def _token_ok(self) -> bool:
        q = self._query()
        tok = self.headers.get("X-SIGIL-Token") or (q.get("token", [""])[0])
        return bool(tok) and hmac.compare_digest(tok, self.server.token)

    def _principal_for_token(self, tok: str):
        """Map a presented token to its `accounts.Principal`, or None (fail-closed). FAIL-OPEN is restricted
        to the EXACT legacy shared owner token → OWNER_PRINCIPAL: the owner is physically at the host and
        must never be locked out. Any OTHER token is resolved through the owner-signed account fold; an
        unknown/blank/wrong token → None (unchanged 401 semantics). This is the ONLY fail-open path."""
        from ..governor.accounts import OWNER_PRINCIPAL, AccountsRegistry
        if not tok:
            return None
        if hmac.compare_digest(tok, self.server.token):
            return OWNER_PRINCIPAL
        try:
            return AccountsRegistry(self.server.store()).resolve(tok)
        except Exception:  # noqa: BLE001 — a hostile/corrupt spine must never crash auth → fail-closed None
            return None

    def _principal(self):
        """The authenticated principal for THIS request (header `X-SIGIL-Token`, or `?token=` for SSE/
        downloads), or None. The same carrier now bears either the legacy owner token or a per-user bearer
        — zero change to the ~100 existing call sites."""
        q = self._query()
        tok = self.headers.get("X-SIGIL-Token") or (q.get("token", [""])[0])
        return self._principal_for_token(tok or "")

    def _origin_host_ok(self) -> bool:
        """The anti-CSRF / anti-DNS-rebinding half of the action gate (Host + exact Origin/Referer), with no
        token/principal check — the caller adds that."""
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            return False                                       # anti DNS-rebinding
        o = self.headers.get("Origin") or ""
        ref = self.headers.get("Referer") or ""
        # EXACT-match the Origin (a `startswith` lets `http://127.0.0.1:80.evil.com` slip); a Referer,
        # if present, must sit under an allowed origin. A cross-origin Origin → refuse.
        if o and o not in self.server.allowed_origins:
            return False
        if ref and not any(ref.startswith(a + "/") or ref == a for a in self.server.allowed_origins):
            return False
        return True

    def _action_ok(self) -> bool:
        # /api/ask keeps the OWNER-token action gate (it dispatches a KERNEL subprocess): Host+Origin+the
        # exact owner shared token. Per-user access to /api/ask is intentionally NOT granted in this slice.
        return self._origin_host_ok() and self._token_ok()

    # --- response helpers -------------------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, _json_bytes(obj))

    def _deny(self, code=403, msg="forbidden"):
        self._json({"error": msg}, code)

    # --- GET (read plane) -------------------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path.startswith("/static/"):
            return self._serve_static(path.rsplit("/", 1)[-1])   # token-free bootstrap assets (no secret)
        if not path.startswith("/api/"):
            return self._deny(404, "not found")
        # /api/whoami is TOKEN-OPTIONAL: the SPA calls it on boot to decide whether to show the login gate,
        # so it must report {authenticated:false} rather than 401 for an anonymous caller.
        if path == "/api/whoami":
            return self._whoami()
        # OIDC (S5) — token-OPTIONAL, and REGISTERED ONLY when SIGIL_OIDC_ENABLED is on. When off these
        # paths are unknown → the fall-through 404 (byte-identical to a build without OIDC; no egress). The
        # login redirect and the callback both bootstrap a session for a caller that has no token yet, so
        # they must sit BEFORE the principal/401 gate below.
        if oidc_enabled() and path == "/api/oidc/login":
            return self._oidc_login()
        if oidc_enabled() and path == "/api/oidc/callback":
            return self._oidc_callback()
        # Every other read requires an authenticated principal (viewer+). The legacy owner token resolves to
        # OWNER_PRINCIPAL; a valid per-user bearer resolves to its principal; anything else → 401.
        principal = self._principal()
        if principal is None:
            return self._deny(401, "missing/invalid token")
        if path == "/api/accounts":
            # Users & Roles list — OWNER-ONLY (manage_users). cred_hash/salt are NEVER surfaced.
            from ..governor.accounts import role_can
            if not role_can(principal.role, "manage_users"):
                return self._deny(403, "owner only")
            return self._accounts()
        if path == "/api/ask":
            # /api/ask DISPATCHES a KERNEL subprocess → it gets the FULL action gate, not just token.
            return self._ask(self._query().get("q", [""])[0]) if self._action_ok() else self._deny(403, "denied")
        if path == "/api/snapshot":
            from ..dashboard import snapshot
            return self._json(snapshot(self.server.store()))
        if path == "/api/settings":
            from . import settings as _settings
            return self._json(_settings.settings_status())     # REDACTED — never a secret value
        if path.startswith("/api/record/"):
            return self._record(path.rsplit("/", 1)[-1])
        if path == "/api/stream":
            return self._sse()
        if path == "/api/sigil/hud":
            return self._hud()
        if path == "/api/graph":
            return self._graph()
        if path == "/api/graph/entity":
            return self._graph_entity(self._query().get("name", [""])[0])
        if path == "/api/classify":
            return self._classify(self._query().get("tool", [""])[0])
        return self._deny(404, "unknown endpoint")

    def _serve_static(self, name):
        if name not in self._STATIC_OK:
            return self._deny(404, "not found")
        try:
            data = (_STATIC / name).read_bytes()
        except OSError:
            return self._deny(404, "not found")
        ctype = "application/javascript" if name.endswith(".js") else "text/css"
        self._send(200, data, ctype=f"{ctype}; charset=utf-8")

    def _serve_index(self):
        try:
            html = (_STATIC / "index.html").read_text(encoding="utf-8")
        except OSError:
            return self._deny(500, "ui missing")
        html = html.replace("__SIGIL_TOKEN__", self.server.token)   # embed token for the same-origin page
        self._send(200, html.encode("utf-8"), ctype="text/html; charset=utf-8")

    def _record(self, raw):
        try:
            seq = int(raw)
        except ValueError:
            return self._deny(400, "bad seq")
        rec = self.server.store().get(seq)
        if rec is None:
            return self._json({"error": "no such record", "seq": seq, "note": "no grounded record — not fabricated"}, 404)
        ok, reason = verify_record(rec)                          # re-verify the atom LIVE (prove-don't-guess)
        self._json({"seq": rec.seq, "kind": rec.kind, "source": rec.source, "actor": rec.actor,
                    "ts": rec.ts, "entry_hash": rec.entry_hash, "prev_hash": rec.prev_hash,
                    "payload": rec.payload, "integrity_ok": ok, "integrity_reason": reason})

    def _graph(self):
        try:
            from ..graph import health
            self._json({"health": health()})
        except Exception as e:  # noqa: BLE001 — graph may not be built yet
            self._json({"error": "graph unavailable", "note": str(e)[:200]})

    def _graph_entity(self, name):
        try:
            from ..graph import entity
            self._json(entity(name))
        except Exception as e:  # noqa: BLE001
            self._json({"error": "graph unavailable", "note": str(e)[:200]})

    def _classify(self, tool):
        from ..agents.kernel_classify import KernelClassifier
        self._json({"tool": tool, "tier": KernelClassifier().classify(tool).label()})

    def _ask(self, q):
        from ..voice.dispatch import KernelDispatch
        self._json({"q": q, "answer": KernelDispatch().send(q)})

    # --- Claim 6 RBAC surface (whoami / accounts / login) -----------------------------------------
    def _principal_json(self, principal) -> dict:
        from ..governor.accounts import PERMISSIONS
        return {"authenticated": True, "username": principal.username, "role": principal.role,
                "permissions": sorted(PERMISSIONS.get(principal.role, frozenset()))}

    def _whoami(self):
        """The current principal from the presented token (token-optional). {authenticated:false} for an
        anonymous/invalid caller so the SPA can render its login gate without a 401 round-trip."""
        p = self._principal()
        self._json(self._principal_json(p) if p is not None else {"authenticated": False})

    def _accounts(self):
        """The owner's Users & Roles list — username/role/state/issued_at only. cred_hash/salt never leave
        the server (they are not even placed in the response)."""
        from ..governor.accounts import AccountsRegistry
        accts = AccountsRegistry(self.server.store()).accounts()
        self._json({"accounts": [{"username": a.username, "role": a.role, "state": a.state,
                                  "issued_at": a.issued_at} for a in accts]})

    def _challenge_ledger(self):
        """The single-use login-challenge ledger, rooted next to the spine file (one dir per spine, so a
        test's temp spine gets its own isolated ledger)."""
        from .login_challenges import ChallengeLedger
        base = Path(self.server.spine_path)
        return ChallengeLedger(base.parent / (base.name + ".login-challenges"))

    def _login_challenge(self):
        """POST /api/login/challenge — mint a fresh, unpredictable, SINGLE-USE server nonce for the S3
        challenge/response login. Same-origin gated (Host+Origin) like `_login`, but requires NO
        pre-existing token (the whole point is to bootstrap a login for a caller that holds only its private
        key). The challenge is recorded OUTSTANDING; `_login`'s PoP branch consumes it exactly once."""
        if not self._origin_host_ok():
            return self._deny(403, "denied (origin / host)")
        challenge = secrets.token_urlsafe(32)          # 256 bits of CSPRNG entropy — unpredictable
        try:
            self._challenge_ledger().issue(challenge)
        except Exception:  # noqa: BLE001 — a ledger I/O error must not leak internals; refuse the mint
            return self._deny(500, "could not mint a challenge")
        self._json({"ok": True, "challenge": challenge})

    def _login(self):
        """Verify a login presented in the POST body and return its principal + permission set. Same-origin
        gated (Host+Origin), but requires NO pre-existing token — verifying the credential you supply is the
        whole point. TWO methods, both ending at the SAME X-SIGIL-Token bearer carrier:
          * PoP (S3, stronger): body {username, challenge, signature} and no token → verify the owner-bound
            Ed25519 key against a consumed single-use challenge, then mint a fresh session bearer.
          * bearer (legacy): body {token} → resolve the per-user bearer (or the legacy owner token).
          * password (S4, OPTIONAL/weaker): body {username, password} and no token → verify the salted
            scrypt hash, then mint a fresh session bearer. Keypairs (PoP) are the stronger path.
        A second factor rides on top of any method: if the resolved account has TOTP enrolled, a valid
        current {totp} code is ALSO required before {ok:true}.
        Fail-closed 401 for any invalid credential."""
        if not self._origin_host_ok():
            return self._deny(403, "denied (origin / host)")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > self._MAX_BODY:
                return self._deny(413, "body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, KeyError):
            return self._deny(400, "bad request")
        body = body or {}
        username = str(body.get("username", "") or "")
        challenge = str(body.get("challenge", "") or "")
        signature = str(body.get("signature", "") or "")
        password = str(body.get("password", "") or "")
        # PoP branch: a {username, challenge, signature} triple with NO bearer. (A body that also carries a
        # token falls through to the legacy bearer branch — PoP never rides alongside a bearer.)
        if username and challenge and signature and not body.get("token"):
            return self._login_pop(username, challenge, signature, body)
        # password branch: {username, password} with NO bearer / no PoP triple (S4, the weaker path).
        if username and password and not body.get("token"):
            return self._login_password(username, password, body)
        tok = str(body.get("token", "") or "")
        p = self._principal_for_token(tok)
        if p is None:
            return self._json({"ok": False, "authenticated": False, "error": "invalid token"}, 401)
        # S4 second factor: if this account has TOTP enrolled, a valid current code is required even for a
        # bearer login. The X-SIGIL-Token carrier and every downstream call site are UNCHANGED — the gate
        # lives only here at /api/login (fail-closed).
        terr = self._check_totp(p.username, body)
        if terr is not None:
            return self._json({"ok": False, "authenticated": False, "error": terr}, 401)
        self._json({"ok": True, **self._principal_json(p)})

    def _login_pop(self, username: str, challenge: str, signature: str, body: dict):
        """The S3 proof-of-possession login. Fail-closed 401 unless: the account exists AND has an
        owner-bound `user_pubkey`; the challenge is a known, unexpired, not-yet-consumed server nonce (spent
        atomically here so a replay of the same triple is refused); and the signature verifies as this
        account's key over `DOMAIN_TAG + challenge`. If the account also has TOTP enrolled, a valid current
        code is required too (S4) BEFORE a bearer is issued. On success mint a fresh owner-signed session
        bearer (the plaintext bearer is never stored, so PoP hands back a rotated one through the SAME
        carrier)."""
        from ..governor.accounts import AccountsRegistry, Principal
        from ..governor.identity import ensure_owner_keypair
        store = self.server.store()
        try:
            acct = AccountsRegistry(store).account(username)
        except Exception:  # noqa: BLE001 — a hostile/corrupt spine must never crash auth → fail-closed
            acct = None
        if acct is None or not acct.user_pubkey:
            # No cryptographic identity bound for this account → refuse (fail-closed, never fall back to a
            # weaker check). Same 401 shape whether the account is unknown, revoked, or bearer-only.
            return self._json({"ok": False, "authenticated": False,
                               "error": "no cryptographic identity bound for this account"}, 401)
        # Consume the challenge FIRST (single-use + TTL). A replay of a captured triple finds it already
        # spent → refused here, before any signature work.
        if not self._challenge_ledger().consume(challenge):
            return self._json({"ok": False, "authenticated": False,
                               "error": "unknown, expired, or already-used challenge"}, 401)
        message = _LOGIN_POP_DOMAIN_TAG + challenge.encode("utf-8")
        try:
            sig_ok = verify_one(acct.user_pubkey, message, signature)
        except Exception:  # noqa: BLE001 — malformed sig/key material is a fail-closed refusal, not a crash
            sig_ok = False
        if not sig_ok:
            return self._json({"ok": False, "authenticated": False,
                               "error": "proof-of-possession signature invalid"}, 401)
        # S4 second factor (if enrolled) — required BEFORE a bearer is minted, so no session token is ever
        # handed out on the first factor alone.
        terr = self._check_totp(username, body)
        if terr is not None:
            return self._json({"ok": False, "authenticated": False, "error": terr}, 401)
        # Proven. Mint a fresh owner-signed session bearer for this account (owner is the sole signer; the
        # user proved possession, the server re-binds). Returned through the same X-SIGIL-Token carrier.
        reg = AccountsRegistry(store, owner_key=ensure_owner_keypair())
        bearer, _seq = reg.mint_session_bearer(username, issued_at=time.time())
        p = Principal(username=acct.username, role=acct.role)
        self._json({"ok": True, **self._principal_json(p), "bearer": bearer})

    def _login_password(self, username: str, password: str, body: dict):
        """The S4 OPTIONAL password login (the weaker convenience path — per-user KEYPAIRS via S3 PoP are
        stronger and preferred). Fail-closed 401 unless the account exists, has a `password_hash`, and the
        salted-scrypt verify passes (unknown-user and wrong-password return the SAME 401 message). If the
        account also has TOTP enrolled, a valid current code is required too. On success mint a fresh
        owner-signed session bearer through the SAME X-SIGIL-Token carrier as PoP."""
        from ..governor.accounts import (
            DECOY_PASSWORD_HASH,
            AccountsRegistry,
            Principal,
            verify_password,
        )
        from ..governor.identity import ensure_owner_keypair
        store = self.server.store()
        try:
            acct = AccountsRegistry(store).account(username)
        except Exception:  # noqa: BLE001 — hostile/corrupt spine must never crash auth → fail-closed
            acct = None
        # ALWAYS run exactly ONE scrypt of equal cost — against the real hash when present, else a DECOY —
        # so the endpoint's TIMING never reveals whether the username exists or has a password enrolled (the
        # user-enumeration oracle a short-circuit would open). The 401 message stays constant; the auth
        # decision still requires a real account WITH a password AND a matching verify.
        stored = acct.password_hash if (acct is not None and acct.password_hash) else DECOY_PASSWORD_HASH
        password_ok = verify_password(password, stored)
        if acct is None or not acct.password_hash or not password_ok:
            return self._json({"ok": False, "authenticated": False,
                               "error": "invalid username or password"}, 401)
        terr = self._check_totp(username, body)
        if terr is not None:
            return self._json({"ok": False, "authenticated": False, "error": terr}, 401)
        reg = AccountsRegistry(store, owner_key=ensure_owner_keypair())
        bearer, _seq = reg.mint_session_bearer(username, issued_at=time.time())
        p = Principal(username=acct.username, role=acct.role)
        self._json({"ok": True, **self._principal_json(p), "bearer": bearer})

    # --- OIDC Relying Party (S5, SHIPPED OFF BY DEFAULT) ------------------------------------------
    def _oidc_state_store(self):
        """The single-use OIDC state→nonce ledger, rooted next to the spine file (one dir per spine, so a
        test's temp spine gets its own isolated ledger — mirrors the S3 challenge ledger)."""
        from .oidc import OidcStateStore
        base = Path(self.server.spine_path)
        return OidcStateStore(base.parent / (base.name + ".oidc-state"))

    def _oidc_login(self):
        """POST/GET /api/oidc/login — 302 redirect to the IdP authorize endpoint with a fresh, unguessable,
        SINGLE-USE `state` + `nonce` (bound together and recorded OUTSTANDING). Same-origin/Host gated (anti
        DNS-rebinding) like `_login`, but token-free: the point is to bootstrap a session for a caller that
        holds no bearer yet. A misconfigured OIDC (missing SIGIL_OIDC_* settings) fails LOUD (500), never a
        silent half-login. Reached ONLY when SIGIL_OIDC_ENABLED is on (the route is otherwise unregistered)."""
        if not self._origin_host_ok():
            return self._deny(403, "denied (origin / host)")
        from . import oidc as _oidc
        try:
            config = _oidc.load_config()
        except _oidc.OidcError as e:
            return self._deny(500, f"oidc is enabled but misconfigured: {str(e)[:200]}")
        state = secrets.token_urlsafe(32)              # 256-bit CSPRNG — unguessable, single-use
        nonce = secrets.token_urlsafe(32)              # bound to `state`; echoed back inside the id_token
        try:
            self._oidc_state_store().issue(state, nonce)
        except Exception:  # noqa: BLE001 — a ledger I/O error must not leak internals; refuse the mint
            return self._deny(500, "could not mint an oidc login state")
        location = _oidc.build_authorize_url(config, state, nonce)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("Referrer-Policy", "no-referrer")     # the state/nonce never leak via Referer
        self.end_headers()

    def _oidc_callback(self):
        """GET /api/oidc/callback?code&state — the IdP redirects here after the user authenticates. Steps,
        each fail-closed to 401 with NO bearer:
          1. Host/Origin gate (anti-rebind).
          2. CONSUME the single-use `state` → recover the `nonce` bound to it (CSRF + replay + a state/nonce
             mix-and-match all fail here; a replayed callback finds its state already spent).
          3. Exchange `code` at the token endpoint; VERIFY the id_token (RS256/ES256 against the IdP JWKS,
             rejecting alg:none/symmetric/wrong-kid/bad-sig/bad-iss/bad-aud/expired, and requiring the
             nonce to equal the one minted at login).
          4. Map the VERIFIED identity claim to an owner-signed `governor.account`. The ROLE comes from that
             grant — NEVER from an OIDC claim. NO owner-signed active account ⇒ REFUSE. A TOTP-enrolled
             account still needs its second factor (unsatisfiable by the redirect alone ⇒ refused here).
          5. Mint a fresh owner-signed session bearer for the mapped principal's role.
        Reached ONLY when SIGIL_OIDC_ENABLED is on."""
        if not self._origin_host_ok():
            return self._deny(403, "denied (origin / host)")
        from . import oidc as _oidc
        q = self._query()
        err = q.get("error", [""])[0]
        if err:
            return self._json({"ok": False, "authenticated": False,
                               "error": f"idp returned an error: {str(err)[:120]}"}, 401)
        code = q.get("code", [""])[0]
        state = q.get("state", [""])[0]
        # (2) single-use state → bound nonce. Unknown / expired / already-used → refuse before any token work.
        nonce = self._oidc_state_store().consume(state)
        if not nonce:
            return self._json({"ok": False, "authenticated": False,
                               "error": "unknown, expired, or already-used oidc state"}, 401)
        try:
            config = _oidc.load_config()
            token_resp = _oidc.exchange_code(config, code, http_post=self.server.oidc_http_post)
            provider = _oidc.JwksProvider(config.jwks_uri, fetcher=self.server.oidc_jwks_fetcher)
            claims = _oidc.verify_id_token(
                token_resp["id_token"], jwks_keys=provider.keys(), issuer=config.issuer,
                client_id=config.client_id, expected_nonce=nonce, allowed_algs=config.signing_algs,
                now=time.time(), skew=config.clock_skew_seconds)
            username = _oidc.identity_from_claims(claims, config.username_claim)
        except _oidc.OidcError as e:
            return self._json({"ok": False, "authenticated": False,
                               "error": f"oidc verification failed: {str(e)[:160]}"}, 401)
        except Exception:  # noqa: BLE001 — an IdP/network fault is a fail-closed refusal, not a 500 leak
            return self._json({"ok": False, "authenticated": False,
                               "error": "oidc token exchange or verification failed"}, 401)
        # (4) ROLE FROM AN OWNER-SIGNED GRANT, NEVER FROM A CLAIM. `account()` returns only ACTIVE accounts
        # (a revoked/unknown username is absent), so an OIDC identity with no owner-signed active account is
        # REFUSED — the verified token alone never mints access or a role.
        from ..governor.accounts import AccountsRegistry, Principal
        from ..governor.identity import ensure_owner_keypair
        store = self.server.store()
        try:
            acct = AccountsRegistry(store).account(username)
        except Exception:  # noqa: BLE001 — hostile/corrupt spine must never crash auth → fail-closed
            acct = None
        if acct is None:
            return self._json({"ok": False, "authenticated": False,
                               "error": "no owner-signed account for this verified OIDC identity"}, 401)
        # S4 second factor still applies. The redirect flow carries no place to submit a TOTP code, so a
        # TOTP-enrolled account is refused here (OIDC establishes the first factor only) — `_check_totp`
        # returns None for a non-enrolled account (proceed) and an error string for an enrolled one.
        terr = self._check_totp(username, {})
        if terr is not None:
            return self._json({"ok": False, "authenticated": False, "error": terr,
                               "second_factor_required": True}, 401)
        reg = AccountsRegistry(store, owner_key=ensure_owner_keypair())
        bearer, _seq = reg.mint_session_bearer(username, issued_at=time.time())
        p = Principal(username=acct.username, role=acct.role)   # role FROM the owner-signed account
        self._json({"ok": True, **self._principal_json(p), "bearer": bearer})

    def _totp_replay_ledger(self):
        """The per-account TOTP replay ledger, rooted next to the spine file (its own dir per spine, so a
        test's temp spine gets an isolated ledger)."""
        from .totp_replay import TotpReplayLedger
        base = Path(self.server.spine_path)
        return TotpReplayLedger(base.parent / (base.name + ".totp-replay"))

    def _check_totp(self, username: str, body: dict):
        """S4 second-factor gate. Returns None when the account has NO TOTP enrolled (nothing to enforce —
        backward-compat) OR a valid, non-replayed current code is supplied; otherwise returns an error
        STRING (the caller 401s). Fail-closed: any lookup/unseal fault REFUSES rather than bypasses, and a
        replayed code (already spent for its step) is refused."""
        from ..governor.accounts import AccountsRegistry
        store = self.server.store()
        try:
            acct = AccountsRegistry(store).account(username)
        except Exception:  # noqa: BLE001 — corrupt spine → fail-closed refusal
            return "second-factor check is unavailable"
        if acct is None or not acct.totp_secret:
            return None                                     # no TOTP bound → nothing to enforce
        code = str(body.get("totp", "") or "")
        if not code:
            return "a TOTP second-factor code is required for this account"
        from ..governor import totp as _totp
        from ..governor.accounts import TOTP_SEAL_CONTEXT
        from ..platform.vault import owner_vault
        try:
            secret = owner_vault().unseal_secret(base64.b64decode(acct.totp_secret),
                                                 context=TOTP_SEAL_CONTEXT).decode("utf-8")
        except Exception:  # noqa: BLE001 — sealed secret unreadable (vault locked / tamper) → fail-closed
            return "second-factor verification is unavailable (sealed secret could not be opened)"
        step = _totp.verify(secret, code, at=time.time(), window=1)
        if step is None:
            return "invalid or expired TOTP code"
        # Replay guard: a TOTP code is valid for its whole step, so refuse a code already spent for this
        # (username, step). Consume AFTER a successful verify so an invalid code never touches the ledger.
        if not self._totp_replay_ledger().consume(username, step):
            return "this TOTP code was already used"
        return None

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        try:
            since = int(self._query().get("since", ["-1"])[0])
        except (ValueError, TypeError):
            since = -1                                          # any malformed cursor → from genesis
        tailer = SpineTailer(self.server.store(), since_seq=since)
        try:
            while True:
                sent = False
                for ev in tailer.poll():
                    self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
                    sent = True
                self.wfile.write(b": hb\n\n")                    # heartbeat / flush
                self.wfile.flush()
                if not sent:
                    time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return                                               # client closed — end the stream

    def _hud(self):
        """S2/S4 — the SIGIL on-screen HUD channel (SSE, token-gated in do_GET). Tails the owner-signed
        spine for ``sigil.nav`` SIGNALS and emits ``{"t":"nav","screen_id":…}`` so the browser switches to
        the commanded screen (voice/gesture). It DISPATCHES nothing (read-only signal fan-out; the token
        gate suffices — no action gate needed). A nav payload is fully plaintext (no CONTENT_FIELDS), so no
        vault is touched. S4 will add ``state``/``feedback`` events from the ephemeral status file."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        try:
            since = int(self._query().get("since", ["-1"])[0])
        except (ValueError, TypeError):
            since = -1
        store = self.server.store()
        cursor = since
        if since < 0:
            # default to the CURRENT tip: the HUD drives live navigation, so it must NOT replay historical
            # sigil.nav records on connect (that would bounce a freshly-loaded page to the last-voiced
            # screen). One scan at connect to find the tip; then only navs appended AFTER connect stream.
            for r in store.iter_records(since_seq=-1):
                cursor = r.seq
        from ..voice.hud_status import read_status
        last_state = None
        try:
            while True:
                sent = False
                # S4: fan out the voice FSM state (idle/listening/thinking/speaking) from the EPHEMERAL 0600
                # status file — deduped (emit only on change). It is read-only telemetry, never the spine.
                st = read_status()
                if isinstance(st, dict) and st != last_state:
                    last_state = st
                    ev = {"t": "state", "state": str(st.get("state", "idle")),
                          "transcript": str(st.get("transcript", "")), "feedback": str(st.get("feedback", ""))}
                    self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
                    sent = True
                for r in store.iter_records(since_seq=cursor):
                    cursor = r.seq
                    pay = getattr(store.decrypted_or_raw(r), "payload", None) or {}
                    if isinstance(pay, dict) and pay.get("signal") == "sigil.nav":
                        sid = str(pay.get("screen_id") or "")
                        direction = str(pay.get("nav") or "")
                        if sid:                                   # voice / pinch: an absolute screen id
                            ev = {"t": "nav", "screen_id": sid, "seq": r.seq}
                        elif direction in ("next", "prev"):        # gesture swipe: a relative step
                            ev = {"t": "nav", "direction": direction, "seq": r.seq}
                        else:
                            continue
                        self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
                        sent = True
                self.wfile.write(b": hb\n\n")
                self.wfile.flush()
                if not sent:
                    time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    # --- POST (action plane) ----------------------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/login/challenge":
            return self._login_challenge()
        if path == "/api/login":
            return self._login()
        # OIDC login initiation also accepts POST (a form/fetch), gated ON only when enabled (byte-identical
        # otherwise). GET is handled in do_GET for a plain top-level navigation.
        if oidc_enabled() and path == "/api/oidc/login":
            return self._oidc_login()
        if path != "/api/action":
            return self._deny(404, "not found")
        # Anti-CSRF/rebinding (Host+Origin) first, THEN the principal. A per-user bearer or the legacy owner
        # token both authenticate here; the per-action RBAC check lives inside do_action (before signing).
        if not self._origin_host_ok():
            return self._deny(403, "action denied (origin / host)")
        principal = self._principal()
        if principal is None:
            # Faithful to the pre-RBAC action-plane semantics: a missing/invalid credential on the action
            # plane is a 403 "action denied" (reads use 401). Either way the request is refused.
            return self._deny(403, "action denied (token / origin / host)")
        from ..governor.accounts import PermissionDenied
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > self._MAX_BODY:                         # BLOCK-4: cap the body (no CL hang / alloc)
                return self._deny(413, "body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            action = str(body.get("action", ""))
            result = _actions.do_action(action, body, store=self.server.store(), principal=principal)
            self._json(result)
        except PermissionDenied as e:                          # RBAC refusal → 403 (distinct from a bad request)
            self._deny(403, f"permission denied: {str(e)[:200]}")
        except (ValueError, KeyError) as e:
            self._deny(400, f"bad request: {e}")
        except Exception as e:  # noqa: BLE001 — ApprovalError etc. → 400, never 500-leak internals
            self._deny(400, f"action failed: {str(e)[:200]}")


def build_server(*, token: str, host: str = "127.0.0.1", port: int = 8733, spine_path=None,
                 allowed_hosts=(), allowed_origins=(), oidc_http_post=None,
                 oidc_jwks_fetcher=None) -> UIServer:
    """Build (do not run) the cockpit bound to ``host:port`` (asserted ``bind_ok`` — never public).
    ``allowed_hosts``/``allowed_origins`` are the operator's reverse-proxy domain forms (e.g.
    ``cockpit.example.com`` / ``https://cockpit.example.com``) unioned into the anti-rebind allowlist.
    ``oidc_http_post``/``oidc_jwks_fetcher`` are OPTIONAL injection hooks (default None → real urllib
    egress) so a test can drive the OIDC callback against an in-process mock IdP with no network."""
    return UIServer((host, port), Handler, token=token,
                    spine_path=Path(spine_path) if spine_path else SPINE_PATH,
                    extra_hosts=allowed_hosts, extra_origins=allowed_origins,
                    oidc_http_post=oidc_http_post, oidc_jwks_fetcher=oidc_jwks_fetcher)


def serve(*, token: str, host: str = "127.0.0.1", port: int = 8733, spine_path=None,
          allowed_hosts=(), allowed_origins=()) -> None:
    srv = build_server(token=token, host=host, port=port, spine_path=spine_path,
                       allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)
    bound = srv.server_address
    bip = ipaddress.ip_address(bound[0])
    disp = f"[{bound[0]}]" if bip.version == 6 else bound[0]     # bracket IPv6 in the URL
    print(f"  SIGIL cockpit → http://{disp}:{bound[1]}/?token={token}")
    if bip.is_loopback:
        print("  (loopback only; the token gates every request — keep it to yourself)")
    else:
        print(f"  (private bind {bound[0]} — reach it via a reverse proxy / tunnel, never a public listener)")
    # the operator-configured reverse-proxy domains (printed from the inputs, not reverse-engineered)
    extras = ", ".join(sorted({h.strip() for h in allowed_hosts if h and h.strip()}))
    if extras:
        print(f"  (reverse-proxy Host allowlist: {extras})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
