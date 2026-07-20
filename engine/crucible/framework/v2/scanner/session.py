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

from pydantic import BaseModel, ConfigDict, Field

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
