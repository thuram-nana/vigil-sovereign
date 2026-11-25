"""Consumer PR-H (Area 7) — the KEYLESS customer-edge half of enterprise SSO + SCIM (mixed into `ui.custui`).

Every route here exists ONLY while `config.customer_sso_enabled()` (VIGIL_CUSTOMER_SSO) is on. With it off the
edge is byte-identical to a build without SSO: a GET/POST to any path below falls through to the edge's own
unknown-route 404, and PUT / PATCH / DELETE answer exactly what `BaseHTTPRequestHandler` answers for a method a
handler does not implement (501, "Unsupported method").

The edge holds NO key and reads NO spine. It drives the browser half of sign-in and relays everything that needs
authority to the sovereign provisioner over the hop key (`ui.sso_provision` does the verification and the
owner-signed, ceiling-capped minting):

  * `GET  /api/customer/sso/login?org=<org_id>` — SP-initiated sign-in. The provisioner returns the org's
    owner-signed IdP endpoint; the edge mints the single-use login state (SAML: an AuthnRequest ID + RelayState;
    OIDC: state + nonce + PKCE verifier), binds it to THIS browser with a short-lived HttpOnly SameSite=Lax cookie
    (only its sha256 is stored), and 302s to the IdP. HOST-gated only: unlike the in-app Google button, this link
    is MEANT to be followed cross-site (the IdP's app tile, a bookmark, an emailed link), and a top-level
    navigation from such a page carries the foreign page as its Referer. Nothing is granted here — the start
    mints only a browser-bound, single-use state and sends the browser to the org's owner-registered IdP, which
    must authenticate the person before the ACS / callback will mint anything.
  * `POST /api/customer/sso/saml/acs[/<org_id>]` — the IdP's HTTP-POST of the SAMLResponse. HOST-gated only (the
    IdP's page is a foreign origin; the anti-CSRF binding is the single-use RelayState + the browser cookie). The
    RelayState is CONSUMED (single use) and the org + AuthnRequest ID come from it — never from the request. The
    Response is relayed for verification BOUND to that AuthnRequest. A cross-site POST cannot carry the Lax
    browser cookie, so on success the edge parks a one-time finish ticket (~2 minutes) and 303s the browser to:
  * `GET  /api/customer/sso/finish?ticket=…` — a top-level GET that DOES carry the Lax cookie: the ticket is
    consumed, the cookie's hash must match the login's, and only then is a CUSTOMER session minted.
  * `GET  /api/customer/sso/oidc/callback?code&state` — enterprise OIDC: consume the state, check the browser
    binding, relay {code, PKCE verifier, nonce} for the token exchange + id_token verification, mint the session.
  * `GET|POST|PUT|PATCH|DELETE /scim/v2/<org_id>/(Users|Groups|ServiceProviderConfig|ResourceTypes|Schemas)…` —
    SCIM 2.0 for the org in the PATH, authenticated by that org's owner-signed, rotatable bearer AT THE
    PROVISIONER (the edge only relays the Authorization header; it never sees a fingerprint). No cookie is read or
    set; responses are `application/scim+json`, no-store. When the provisioner reports deactivated members, the
    edge severs their sessions at once (and every relayed request of theirs is refused anyway: the per-org role is
    resolved live by `admit_customer`).

Every refusal of a browser step lands on `/#sso=err` with no reason (no oracle for an attacker probing org ids,
states or tickets), and no step ever mints a session without a verified IdP proof AND the browser binding.

FATAL-2: SOVEREIGN-side, stdlib + `sigil.config` / `ui.saml` / `ui.oidc` only — imports NO `framework` / `strix`
(`assert_no_offense()` at import).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, urlparse

from ..reuse import assert_no_offense

assert_no_offense()

if TYPE_CHECKING:                                    # typing only: custui imports THIS module (no runtime cycle)
    from .custui import CustomerServer

SSO_SID_COOKIE = "vigil_customer_sso_sid"          # DISTINCT from the session + the Google-OIDC binding cookies
SSO_COOKIE_PATH = "/api/customer/sso"
LOGIN_PATH = "/api/customer/sso/login"
ACS_PATH = "/api/customer/sso/saml/acs"
FINISH_PATH = "/api/customer/sso/finish"
OIDC_CALLBACK_PATH = "/api/customer/sso/oidc/callback"
SCIM_PREFIX = "/scim/v2/"
FAIL_LOCATION = "/#sso=err"
LOGIN_TTL_S = 600.0                                 # the round trip through the IdP (interactive sign-in)
FINISH_TTL_S = 120.0                                # the ACS → finish bounce (one redirect)
_MAX_ACS_BODY = 768 * 1024                          # the IdP's form POST (a signed Response is tens of KiB)
MAX_SCIM_BODY = 1024 * 1024                         # one SCIM request body (a group PUT naming many members)
# org_id == tenant_id; mirrors governor.orgs._TENANT_RE (a lockstep test keeps them equal)
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


def _sso_on() -> bool:
    from .. import config as _config
    return _config.customer_sso_enabled()


def parse_scim_path(path: str) -> "Optional[tuple[str, str]]":
    """(`org_id`, the resource path under it — e.g. `/Users/<id>`) for `/scim/v2/<org_id>/...`, else None. The org
    segment must be a valid tenant id (no traversal, no separators)."""
    p = str(path or "")
    if not p.startswith(SCIM_PREFIX):
        return None
    org, _sep, tail = p[len(SCIM_PREFIX):].partition("/")
    if not _TENANT_RE.fullmatch(org):
        return None
    return org, "/" + tail


def scim_error(status: int, detail: str) -> dict:
    return {"schemas": [_SCIM_ERROR], "status": str(int(status)), "detail": str(detail)}


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def public_urls(public_base: str, org_id: str) -> "dict[str, str]":
    """The public URLs an org's IdP is registered with, derived from the customer app's public ORIGIN (https; plain
    http only for a loopback dev edge) — what the owner hands the customer's IT admin and signs into the config:
    the SAML ACS + this org's SP entity id (== the audience, so it is per-org), the enterprise-OIDC redirect URI,
    the SCIM base URL and the SP-initiated sign-in link (an IdP tile / bookmark)."""
    from urllib.parse import urlparse as _urlparse
    base = str(public_base or "").strip().rstrip("/")
    u = _urlparse(base)
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not host or u.path or u.query or u.fragment or u.params \
            or (u.scheme == "http" and host not in _LOOPBACK_HOSTS):
        raise ValueError("the public base must be the customer app's https origin, e.g. https://app.example.com")
    oid = str(org_id or "").strip()
    if not _TENANT_RE.fullmatch(oid):
        raise ValueError("org_id must be a valid tenant id")
    return {"login_url": f"{base}{LOGIN_PATH}?org={oid}",
            "saml_acs_url": f"{base}{ACS_PATH}",
            "saml_sp_entity_id": f"{base}/api/customer/sso/saml/{oid}",
            "oidc_redirect_uri": f"{base}{OIDC_CALLBACK_PATH}",
            "scim_base_url": f"{base}{SCIM_PREFIX}{oid}"}


class SsoStateLedger:
    """The edge's durable, single-use ledger for SSO login state and finish tickets. One 0600 marker per key named
    `sha256(key)` (no traversal / injection; the raw state never touches disk as a name), created O_EXCL; CONSUMED
    by an atomic unlink (of N concurrent consumers exactly one wins — the replay guard); every record carries its
    `kind` and expiry, and `consume` refuses a record of another kind (a finish ticket is never a login state). A
    per-issue sweep + a hard cap bound the directory. Holds only non-secret, browser-binding material (the
    sid cookie's HASH, a PKCE verifier, an AuthnRequest ID) — the hop key and every owner key live elsewhere."""

    _MAX_OUTSTANDING = 8192

    def __init__(self, path) -> None:
        self.dir = Path(path)

    def _marker(self, key: str) -> Path:
        return self.dir / hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _sweep(self, now: float) -> int:
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for e in entries:
            try:
                rec = json.loads(Path(e.path).read_text(encoding="utf-8"))
                exp = float(rec["exp"])
            except (OSError, ValueError, KeyError, TypeError):
                _unlink(e.path)
                continue
            if now > exp:
                _unlink(e.path)
            else:
                live += 1
        return live

    def issue(self, key: str, record: dict, *, ttl_s: float, now: Optional[float] = None) -> None:
        """Record `record` (must carry a `kind`) under the fresh single-use `key`, expiring after `ttl_s`. Raises on
        a blank key, a full ledger or an I/O error (the caller then mints nothing)."""
        k = str(key or "")
        if not k or not str(record.get("kind") or ""):
            raise ValueError("refusing to issue SSO state without a key and a kind")
        t = time.time() if now is None else float(now)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._sweep(t) >= self._MAX_OUTSTANDING:
            raise RuntimeError("SSO state ledger at capacity; retry shortly")
        data = json.dumps({**record, "exp": t + float(ttl_s)}, ensure_ascii=False).encode("utf-8")
        fd = os.open(str(self._marker(k)), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def consume(self, key: str, *, kind: str, now: Optional[float] = None) -> Optional[dict]:
        """ATOMICALLY spend an unexpired record of `kind` under `key` → the record, else None (unknown, expired,
        already spent, or another kind). Never raises."""
        k = str(key or "")
        if not k or len(k) > 512:
            return None
        marker = self._marker(k)
        try:
            rec = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        try:
            os.unlink(str(marker))                       # the serialization point: one winner
        except OSError:
            return None
        t = time.time() if now is None else float(now)
        if not isinstance(rec, dict) or rec.get("kind") != kind:
            return None
        exp = rec.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or t > float(exp):
            return None                                  # malformed or expired
        return rec


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


def _one(q: dict, name: str, cap: int = 4096) -> str:
    v = q.get(name, [])
    return v[0] if len(v) == 1 and len(v[0]) <= cap else ""


class SsoEdgeMixin(BaseHTTPRequestHandler):
    """The SSO / SCIM routes of the keyless customer edge. Mixed into `custui.CustomerHandler` (which supplies the
    hop relay `_provision`, `_mint`, `_ip`, `_deny` and the server's session ledger — declared below for the type
    checker only, so the handler's own implementations are the ones that run)."""

    server: "CustomerServer"

    if TYPE_CHECKING:
        def _provision(self, action: str, principal: str, body: dict) -> "tuple[int, Any]": ...

        def _mint(self, username: str, org_id: Any, *, mfa_at: Any = None, mfa_method: Any = None) -> None: ...

        def _ip(self) -> str: ...

        def _deny(self, code: int = 403, msg: str = "forbidden") -> None: ...

    # -- routing (each answers False while the flag is off, so the edge's own fallbacks answer unchanged) ---
    def _sso_handles_get(self, path: str) -> bool:
        return (path in (LOGIN_PATH, FINISH_PATH, OIDC_CALLBACK_PATH) or path.startswith(SCIM_PREFIX)) \
            and _sso_on()

    def _sso_get(self, path: str):
        if path.startswith(SCIM_PREFIX):
            return self._scim()
        if path == LOGIN_PATH:
            return self._sso_login()
        if path == FINISH_PATH:
            return self._sso_finish()
        return self._sso_oidc_callback()

    def _sso_handles_post(self, path: str) -> bool:
        return (path == ACS_PATH or path.startswith(ACS_PATH + "/") or path.startswith(SCIM_PREFIX)) and _sso_on()

    def _sso_post(self, path: str):
        if path.startswith(SCIM_PREFIX):
            return self._scim()
        return self._sso_saml_acs(path)

    def _scim_or_unsupported(self):
        """PUT / PATCH / DELETE: SCIM while the flag is on, else EXACTLY the stdlib's answer for a method the handler
        does not implement (byte-identical to a build without these methods)."""
        path = urlparse(self.path).path
        if path.startswith(SCIM_PREFIX) and _sso_on():
            try:
                return self._scim()
            except Exception:  # noqa: BLE001 — never 500-leak internals, never drop the connection
                return self._scim_send(500, scim_error(500, "SCIM request failed"))
        self.send_error(HTTPStatus.NOT_IMPLEMENTED, "Unsupported method (%r)" % self.command)

    def do_PUT(self):
        return self._scim_or_unsupported()

    def do_PATCH(self):
        return self._scim_or_unsupported()

    def do_DELETE(self):
        return self._scim_or_unsupported()

    # -- shared helpers --------------------------------------------------------------------------------------
    def _sso_ledger(self) -> SsoStateLedger:
        return SsoStateLedger(self.server.sso_state_dir)

    def _sso_sid_cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            from http.cookies import SimpleCookie
            jar = SimpleCookie()
            jar.load(raw)
            m = jar.get(SSO_SID_COOKIE)
            return m.value if m else ""
        except Exception:  # noqa: BLE001 — a malformed Cookie header is "no binding", never a crash
            return ""

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _sso_redirect(self, location: str, *, status: int = 302, cookies=()) -> None:
        """End a top-level SSO step with a redirect: no-store, strict CSP, no Referer (a state / ticket in the URL
        never leaks onward). `cookies` are extra Set-Cookie values; a minted session cookie (`_mint`) rides along
        only on a success redirect (never on the `#sso=err` landing)."""
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        from .custui import _CSP
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Vigil-Build", self.server.app.build)
        session = getattr(self, "_pending_set_cookie", None)
        if session and location != FAIL_LOCATION:
            self.send_header("Set-Cookie", session)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()

    def _sso_fail(self, status: int = 302) -> None:
        return self._sso_redirect(FAIL_LOCATION, status=status)

    def _sid_cookie_value(self, sid: str) -> str:
        from vigil_core.posture import is_production_posture
        return (f"{SSO_SID_COOKIE}={sid}; Path={SSO_COOKIE_PATH}; Max-Age={int(LOGIN_TTL_S)}; HttpOnly; "
                f"SameSite=Lax" + ("; Secure" if is_production_posture() else ""))

    def _sid_cookie_clear(self) -> str:
        return f"{SSO_SID_COOKIE}=; Path={SSO_COOKIE_PATH}; Max-Age=0; HttpOnly; SameSite=Lax"

    def _browser_bound(self, sid_hash: object) -> bool:
        presented = self._sso_sid_cookie()
        return bool(isinstance(sid_hash, str) and sid_hash and presented
                    and hmac.compare_digest(_sid_hash(presented), sid_hash))

    # -- SP-initiated sign-in start --------------------------------------------------------------------------
    def _sso_login(self):
        if not self._host_ok():                              # Host-only: see the module note (an IdP tile is cross-site)
            return self._deny(403, "denied (host)")
        org = _one(parse_qs(urlparse(self.path).query, keep_blank_values=True), "org", 64).strip()
        if not _TENANT_RE.fullmatch(org):
            return self._sso_fail()
        c, r = self._provision("sso_login_start", "", {"org_id": org, "ip": self._ip()})
        if c != 200 or not isinstance(r, dict) or r.get("org_id") != org:
            return self._sso_fail()                          # no reason: not an oracle for which orgs use SSO
        sid = secrets.token_urlsafe(32)
        try:
            if r.get("protocol") == "saml":
                location = self._saml_start(org, r, _sid_hash(sid))
            elif r.get("protocol") == "oidc":
                location = self._oidc_start(org, r, _sid_hash(sid))
            else:
                return self._sso_fail()
        except Exception:  # noqa: BLE001 — a malformed IdP endpoint / a ledger fault: mint nothing, refuse
            return self._sso_fail()
        return self._sso_redirect(location, cookies=(self._sid_cookie_value(sid),))

    def _saml_start(self, org: str, info: dict, sid_hash: str) -> str:
        from . import saml as _saml
        request_id = _saml.new_request_id()
        relay = secrets.token_urlsafe(32)
        xml = _saml.build_authn_request(request_id, sp_entity_id=str(info.get("sp_entity_id") or ""),
                                        acs_url=str(info.get("acs_url") or ""),
                                        idp_sso_url=str(info.get("idp_sso_url") or ""), issue_instant=time.time())
        location = _saml.authn_request_redirect_url(str(info.get("idp_sso_url") or ""), xml, relay)
        self._sso_ledger().issue(relay, {"kind": "saml_login", "org_id": org, "request_id": request_id,
                                         "sid_hash": sid_hash}, ttl_s=LOGIN_TTL_S)
        return location

    def _oidc_start(self, org: str, info: dict, sid_hash: str) -> str:
        from . import oidc as _oidc
        endpoint = str(info.get("authorize_endpoint") or "")
        u = urlparse(endpoint)
        if u.scheme.lower() != "https" or not u.hostname:
            raise ValueError("the IdP authorize endpoint must be https")
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier = _oidc.generate_pkce_verifier()
        cfg = _oidc.OidcConfig(issuer="", client_id=str(info.get("client_id") or ""), client_secret="",
                               redirect_uri=str(info.get("redirect_uri") or ""), authorize_endpoint=endpoint,
                               token_endpoint="", jwks_uri="", scopes=str(info.get("scopes") or "openid"),
                               username_claim="sub")
        if not cfg.client_id or not cfg.redirect_uri:
            raise ValueError("incomplete enterprise-OIDC config")
        location = _oidc.build_authorize_url(cfg, state, nonce, code_challenge=_oidc.pkce_challenge_s256(verifier))
        self._sso_ledger().issue(state, {"kind": "oidc_login", "org_id": org, "nonce": nonce, "verifier": verifier,
                                         "sid_hash": sid_hash}, ttl_s=LOGIN_TTL_S)
        return location

    # -- SAML: the IdP's POST to the ACS, then the browser-bound finish --------------------------------------
    def _sso_saml_acs(self, path: str):
        if not self._host_ok():
            return self._deny(403, "denied (host)")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._sso_fail(303)
        if length <= 0 or length > _MAX_ACS_BODY:
            return self._sso_fail(303)
        try:
            form = parse_qs(self.rfile.read(length).decode("ascii"), keep_blank_values=True, strict_parsing=True)
        except (ValueError, UnicodeDecodeError, OSError):
            return self._sso_fail(303)
        saml_response, relay = _one(form, "SAMLResponse", _MAX_ACS_BODY), _one(form, "RelayState", 512)
        rec = self._sso_ledger().consume(relay, kind="saml_login") if relay and saml_response else None
        if rec is None:
            return self._sso_fail(303)                       # unknown / spent / expired RelayState: nothing relayed
        path_org = path[len(ACS_PATH):].strip("/")
        org = str(rec.get("org_id") or "")
        if path_org and path_org != org:
            return self._sso_fail(303)
        c, r = self._provision("sso_saml_acs", "", {"org_id": org, "saml_response": saml_response,
                                                    "request_id": str(rec.get("request_id") or ""),
                                                    "ip": self._ip()})
        if not (c == 200 and isinstance(r, dict) and r.get("username") and r.get("org_id") == org):
            return self._sso_fail(303)
        ticket = secrets.token_urlsafe(32)
        try:
            self._sso_ledger().issue(ticket, {"kind": "saml_finish", "username": str(r["username"]), "org_id": org,
                                              "sid_hash": str(rec.get("sid_hash") or "")}, ttl_s=FINISH_TTL_S)
        except Exception:  # noqa: BLE001
            return self._sso_fail(303)
        return self._sso_redirect(f"{FINISH_PATH}?ticket={ticket}", status=303)

    def _sso_finish(self):
        if not self._host_ok():
            return self._deny(403, "denied (host)")
        ticket = _one(parse_qs(urlparse(self.path).query, keep_blank_values=True), "ticket", 128)
        rec = self._sso_ledger().consume(ticket, kind="saml_finish") if ticket else None
        if rec is None or not self._browser_bound(rec.get("sid_hash")):
            return self._sso_fail()
        self._mint(str(rec.get("username") or ""), str(rec.get("org_id") or ""))
        if not getattr(self, "_pending_set_cookie", None):
            return self._sso_fail()                          # the session ledger refused the mint
        return self._sso_redirect("/", cookies=(self._sid_cookie_clear(),))

    # -- enterprise OIDC callback ----------------------------------------------------------------------------
    def _sso_oidc_callback(self):
        if not self._host_ok():
            return self._deny(403, "denied (host)")
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        state, code = _one(q, "state", 512), _one(q, "code", 4096)
        rec = self._sso_ledger().consume(state, kind="oidc_login") if state else None
        if rec is None or _one(q, "error") or not code or not self._browser_bound(rec.get("sid_hash")):
            return self._sso_fail()
        org = str(rec.get("org_id") or "")
        c, r = self._provision("sso_oidc_finish", "", {"org_id": org, "code": code,
                                                       "code_verifier": str(rec.get("verifier") or ""),
                                                       "nonce": str(rec.get("nonce") or ""), "ip": self._ip()})
        if not (c == 200 and isinstance(r, dict) and r.get("username") and r.get("org_id") == org):
            return self._sso_fail()
        self._mint(str(r["username"]), org)
        if not getattr(self, "_pending_set_cookie", None):
            return self._sso_fail()
        return self._sso_redirect("/", cookies=(self._sid_cookie_clear(),))

    # -- SCIM 2.0 ----------------------------------------------------------------------------------------------
    def _scim_send(self, status: int, body: Optional[dict]) -> None:
        data = b"" if status == 204 or body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        if data:
            self.send_header("Content-Type", "application/scim+json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        from .custui import _CSP
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        ra = getattr(self, "_pending_retry_after", None)
        if ra:
            self.send_header("Retry-After", ra)
        self.end_headers()
        if data:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _scim(self):
        """Relay one SCIM request for the org in the path. The edge never authenticates the bearer itself (it holds
        no fingerprint): the provisioner does, against that org's owner-signed config. The provisioner's answer is
        returned verbatim; every username it reports deactivated loses its sessions here and now."""
        method = str(self.command or "").upper()
        u = urlparse(self.path)
        if not self._host_ok():
            return self._scim_send(403, scim_error(403, "denied (host)"))
        parsed = parse_scim_path(u.path)
        if parsed is None:
            return self._scim_send(404, scim_error(404, "unknown SCIM endpoint"))
        org, rest = parsed
        body: object = None
        if method in ("POST", "PUT", "PATCH"):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._scim_send(400, scim_error(400, "bad Content-Length"))
            if length > MAX_SCIM_BODY:
                return self._scim_send(413, scim_error(413, "request body too large"))
            raw = self.rfile.read(length) if length > 0 else b""
            if raw:
                try:
                    body = json.loads(raw)
                except (ValueError, RecursionError):
                    return self._scim_send(400, {**scim_error(400, "the body is not valid JSON"),
                                                 "scimType": "invalidSyntax"})
        c, r = self._provision("scim_request", "", {"org_id": org, "method": method, "path": rest,
                                                    "query": u.query, "body": body,
                                                    "authorization": self.headers.get("Authorization", "") or "",
                                                    "ip": self._ip()})
        status = r.get("status") if isinstance(r, dict) else None
        if c == 200 and isinstance(status, int) and 200 <= status <= 599:
            for gone in r.get("deactivated") or ():
                if isinstance(gone, str) and gone:
                    self.server.sessions.revoke_all_for_user(gone)     # the deactivated member's sessions die now
            ra = r.get("retry_after")
            if isinstance(ra, int) and ra > 0:
                self._pending_retry_after = str(ra)
            body_out = r.get("body")
            return self._scim_send(status, body_out if isinstance(body_out, dict) else None)
        hop = c if c in (404, 413, 503) else 502             # the hop itself failed (never a 2xx without a verdict)
        detail = {404: "unknown SCIM endpoint", 413: "request body too large"}.get(hop, "SCIM is unavailable right now")
        return self._scim_send(hop, scim_error(hop, detail))
