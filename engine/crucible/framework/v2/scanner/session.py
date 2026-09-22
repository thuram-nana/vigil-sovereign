"""
scanner.session — authenticated scanning (cookie jar + login + re-auth).

Most of a real app's attack surface is behind a login. The crawler and audit
engine only take a ``send`` callable, so authentication is added *around* them:
:class:`AuthSession` wraps a raw ``send`` into an authenticated one that carries
a cookie jar, performs a login sequence, detects when the session has gone (a
401/403 or a logged-out marker), and re-authenticates before retrying — Burp's
session-handling in one composable object.

    auth = AuthSession(raw_send, LoginSequence(url=".../login", body="user=a&password=b"))
    Crawler(auth.send).crawl(base + "/account")          # crawls authenticated
    AuditEngine(auth.send).audit(request_behind_login)   # scans authenticated

Nothing here weakens the boundary: it sends only through the injected raw
``send`` (the scope/charter/kill-switch-gated executor in production), and the
credentials are operator-supplied for an authorized target. It just keeps a
valid session while the existing engines do the work.
"""

from __future__ import annotations

import re
import secrets

from pydantic import BaseModel, ConfigDict, Field

from ..verify.adapter import FindingContext
from .checks import Send
from .insertion import HttpRequest

_SET_COOKIE = re.compile(r"\s*([^=;]+)=([^;]*)")


class CookieJar:
    """A minimal cookie store: captures name=value from Set-Cookie and renders
    the Cookie request header. Attributes (Path/HttpOnly/…) are intentionally
    ignored — for staying logged in during a scan, the name/value pair is what
    matters, and a last-writer-wins jar mirrors browser behavior closely enough."""

    def __init__(self) -> None:
        self._cookies: dict[str, str] = {}

    def update_from_headers(self, headers: list[tuple[str, str]]) -> None:
        for k, v in headers:
            if k.lower() == "set-cookie":
                m = _SET_COOKIE.match(v)
                if m:
                    name, value = m.group(1).strip(), m.group(2).strip()
                    if value in ("deleted", "") and "max-age=0" in v.lower():
                        self._cookies.pop(name, None)  # server expiring the cookie
                    else:
                        self._cookies[name] = value

    def set(self, name: str, value: str) -> None:
        """Set a cookie name/value directly (a client-chosen cookie, e.g. a VIGIL-fixed session id)."""
        self._cookies[name] = value

    def get(self, name: str) -> str | None:
        return self._cookies.get(name)

    def header(self) -> str | None:
        if not self._cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def clear(self) -> None:
        self._cookies.clear()

    def __contains__(self, name: str) -> bool:
        return name in self._cookies

    def __len__(self) -> int:
        return len(self._cookies)


class LoginSequence(BaseModel):
    """How to authenticate: one request (usually a POST of credentials) plus an
    optional success marker. Success is inferred from a marker in the response
    or from a session cookie being set."""

    model_config = ConfigDict(extra="forbid")

    url: str
    method: str = "POST"
    body: str | None = "user=admin&password=admin"
    content_type: str = "application/x-www-form-urlencoded"
    success_marker: str | None = None
    logged_out_markers: tuple[str, ...] = Field(default_factory=tuple)
    logged_out_statuses: tuple[int, ...] = (401, 403)


class AuthSession:
    """Wraps a raw ``send`` into an authenticated one. Lazily logs in on the
    first request, keeps the cookie jar current, and on a logged-out response
    re-authenticates once and retries."""

    def __init__(self, send: Send, login: LoginSequence, *, max_relogins: int = 3) -> None:
        self._raw = send
        self.login = login
        self.jar = CookieJar()
        self.max_relogins = max_relogins
        self._authenticated = False
        self.relogins = 0

    # -- public send -------------------------------------------------------

    def send(self, req: HttpRequest) -> dict:
        """The authenticated ``send``: ensures a session, carries cookies, and
        re-authenticates + retries once if the response looks logged out."""
        if not self._authenticated:
            self.authenticate()
        resp = self._send_raw(req)
        if self._looks_logged_out(resp) and self.relogins < self.max_relogins:
            if self.authenticate():
                resp = self._send_raw(req)
        return resp

    def authenticate(self) -> bool:
        """Run the login sequence; capture the session cookie. Success = the
        login response set a cookie (a session was issued) or the success marker
        appeared — a value-agnostic test, so re-login works even when the new
        session cookie overwrites the old one (same count, new value)."""
        self.relogins += 1
        headers: list[tuple[str, str]] = []
        if self.login.body is not None:
            headers.append(("Content-Type", self.login.content_type))
        req = HttpRequest(method=self.login.method, url=self.login.url,
                          headers=headers, body=self.login.body)
        resp = self._send_raw(req)
        resp_headers = resp.get("headers", []) if isinstance(resp, dict) else []
        set_a_cookie = any(str(k).lower() == "set-cookie" for k, _ in resp_headers)
        status = int(resp.get("status", 0)) if isinstance(resp, dict) else 0
        ok = set_a_cookie
        if not ok and self.login.success_marker:
            ok = self.login.success_marker in _body(resp)
        if status in self.login.logged_out_statuses:
            ok = False  # an explicit 401/403 is a credential failure, not a session
        self._authenticated = ok
        return ok

    # -- internals ---------------------------------------------------------

    def _send_raw(self, req: HttpRequest) -> dict:
        resp = self._raw(self._apply_cookies(req))
        headers = resp.get("headers", []) if isinstance(resp, dict) else []
        self.jar.update_from_headers([(str(k), str(v)) for k, v in headers])
        return resp

    def _apply_cookies(self, req: HttpRequest) -> HttpRequest:
        cookie = self.jar.header()
        if cookie is None:
            return req
        headers = [(k, v) for k, v in req.headers if k.lower() != "cookie"]
        headers.append(("Cookie", cookie))
        return req.model_copy(update={"headers": headers})

    def _looks_logged_out(self, resp: dict) -> bool:
        status = int(resp.get("status", 0)) if isinstance(resp, dict) else 0
        if status in self.login.logged_out_statuses:
            return True
        body = _body(resp)
        return any(m in body for m in self.login.logged_out_markers)


def _body(resp: object) -> str:
    if isinstance(resp, dict):
        return str(resp.get("body", ""))
    return str(resp)


def authenticated_send(send: Send, login: LoginSequence, **kwargs: object) -> Send:
    """Convenience: return an authenticated ``send`` ready to hand to a Crawler,
    AuditEngine, or WebScanCampaign."""
    return AuthSession(send, login, **kwargs).send  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Session fixation (Wave-3.2, gated-workflow, opt-in) — CWE-384 ACHIEVED_STATE.
# ---------------------------------------------------------------------------


def mint_session_sentinel() -> str:
    """A UNIQUE, high-entropy session-fixation SENTINEL id VIGIL fixes BEFORE authenticating. The
    ``sfx_<hex>`` shape is the self-contained soundness marker the ``session_fixation_oracle`` requires: a
    server-issued session value can never carry it, so a confirmed FACT provably rests on an id VIGIL drove
    in — never a value the app minted itself."""
    return "sfx_" + secrets.token_hex(16)


def _is_authenticated(resp: object, login: "LoginSequence") -> bool | None:
    """A POSITIVE authenticated-state test over a protected-page response, reusing the operator's login spec.

    TRI-STATE — the distinction is load-bearing for soundness:

      * ``True``  — a positive authenticated-state discriminator confirmed a LIVE authenticated session: the
        ``success_marker`` is present, or (when only ``logged_out_markers`` were supplied) the response is a
        non-logged-out 2xx/3xx;
      * ``False`` — a discriminator was available and decisively says NOT authenticated (a logged-out
        status/marker, or the ``success_marker`` absent);
      * ``None``  — NO positive authenticated-state discriminator was supplied (NEITHER ``success_marker`` NOR
        ``logged_out_markers``). There is then nothing that distinguishes a live authenticated page from an
        unauthenticated login form served at HTTP 200, so we FAIL CLOSED to "unknown" rather than scoring a
        bare 2xx/3xx as authenticated. The caller must NOT mint a FACT off this (it degrades to INCONCLUSIVE).

    Failing closed here is the fix for the marker-absent degeneration: a bare 200 is not evidence of an
    authenticated session, and a session-fixation FACT must rest on positive proof the fixed id is LIVE."""
    # No positive authenticated-state discriminator at all ⇒ cannot decide ⇒ unknown (never True on a status).
    if login.success_marker is None and not login.logged_out_markers:
        return None
    if not isinstance(resp, dict):
        return None
    status = int(resp.get("status", 0))
    if status in login.logged_out_statuses:
        return False
    body = _body(resp)
    if any(m in body for m in login.logged_out_markers):
        return False
    if login.success_marker is not None:
        return login.success_marker in body
    # Only logged_out_markers were supplied (no success_marker): a non-logged-out 2xx/3xx is
    # positive-by-absence evidence the id reached an authenticated state.
    return 200 <= status < 400


def confirm_session_fixation(
    send: Send,
    *,
    login: LoginSequence,
    session_cookie: str,
    protected_url: str,
    sentinel_id: str | None = None,
) -> FindingContext | None:
    """Gated-workflow session-fixation probe (CWE-384), built on :class:`LoginSequence` + :class:`CookieJar`.

    VIGIL FIXES a unique high-entropy sentinel id S0 as the ``session_cookie`` value BEFORE authenticating,
    runs the operator's login sequence through the gated ``send`` carrying S0, then observes the session id in
    effect AFTER login (S1). Finally — the SOUND positive test — it re-presents the VIGIL-fixed id **S0**
    (not merely S1) to a protected page and tests whether S0 STILL reaches an authenticated state after login.
    ``authenticated_after_login`` records that S0 re-probe as a TRI-STATE (``True`` live / ``False`` dead /
    ``None`` undecidable). The returned :class:`FindingContext` routes to the deterministic
    ``session_fixation_oracle``, which fires ONLY when the VIGIL-fixed id survived unrotated (S1 == S0) AND
    S0 still authenticates — the achieved fixation state.

    Re-probing S0 directly (rather than trusting S1==S0 as a rotation proxy) is deliberate: an app can rotate
    the cookie VALUE at login yet leave the pre-auth-fixed id S0 still valid — a REAL fixation a value check
    would miss. Probing S0 yields ``False`` for a genuinely-defended rotate (S0 is dead → a channel-confirmed
    CLEAN) and ``True`` for a value-rotation-but-S0-valid app (the oracle refuses to CLEAN that — never a
    false clean). A positive authenticated-state discriminator (``success_marker`` or ``logged_out_markers``)
    is REQUIRED to mint: absent it the S0 probe is ``None`` and the oracle returns INCONCLUSIVE, never a FACT
    and never a CLEAN. Returns ``None`` only when no channel was established (a non-dict login response);
    every other outcome is adjudicated by the oracle. All traffic rides the injected ``send`` (the
    scope/charter/kill-switch-gated executor); nothing here weakens the boundary."""
    s0 = sentinel_id or mint_session_sentinel()

    # 1. VIGIL fixes the session id to S0 BEFORE auth, then runs the login sequence carrying it.
    login_headers: list[tuple[str, str]] = [("Cookie", f"{session_cookie}={s0}")]
    if login.body is not None:
        login_headers.append(("Content-Type", login.content_type))
    login_req = HttpRequest(method=login.method, url=login.url, headers=login_headers, body=login.body)
    login_resp = send(login_req)
    if not isinstance(login_resp, dict):
        return None   # no channel established — INCONCLUSIVE, never a CLEAN

    # 2. Post-auth session id S1: seed a jar with the fixed S0, then apply the login response's Set-Cookie.
    #    If login re-issued the session cookie (rotation), S1 is the NEW value; otherwise S0 survived.
    jar = CookieJar()
    jar.set(session_cookie, s0)
    login_headers_resp = login_resp.get("headers", []) if isinstance(login_resp, dict) else []
    jar.update_from_headers([(str(k), str(v)) for k, v in login_headers_resp])
    s1 = jar.get(session_cookie)

    # 3. SOUND fixation test: does the ORIGINAL VIGIL-fixed id S0 STILL authenticate a protected request
    #    AFTER login? This is the definition of the achieved fixation state — and, unlike an S1==S0 value
    #    check, it also exposes a value-rotating app that leaves S0 valid, and yields a genuine CLEAN
    #    (S0 dead) for a real rotate defense. Tri-state: True live / False dead / None undecidable.
    authenticated = _is_authenticated(
        send(HttpRequest(method="GET", url=protected_url,
                         headers=[("Cookie", f"{session_cookie}={s0}")], body=None)),
        login)

    return FindingContext.from_session_fixation(
        sentinel_id=s0, post_auth_id=s1, authenticated_after_login=authenticated,
        cookie_name=session_cookie)
