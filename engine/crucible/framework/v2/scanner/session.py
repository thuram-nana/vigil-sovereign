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


# ---------------------------------------------------------------------------
# SHARED GUARDS — Wave-3 vacuous-predicate-satisfaction fix (kept inline here; a later commit DRYs these
# into one helper module — names/semantics MUST stay identical across the Wave-3 slices).
# A contains / not-contains check is only meaningful when BOTH the discriminator and the body it is tested
# against are SUBSTANTIVE. An empty/whitespace/too-short marker is trivially "in" any body, and an
# empty/error/deny body neither proves a positive predicate nor serves as a negative control.
# ---------------------------------------------------------------------------

_MIN_SUBSTANTIVE_BODY = 16   # a real page body, not a stub/error token
_MIN_DISCRIMINATOR = 3       # a marker below this is trivially a substring of almost any body

# Bare error/deny signatures — strings that mark a body as a server-error or access-denied page rather than
# a substantive authenticated response. Deliberately specific (multi-word / status-line shaped) so a genuine
# authenticated page that merely mentions the word "error" in prose is NOT misclassified, and a normal
# logged-out page ("please log in", "you are logged out") is NOT treated as an error either.
_BARE_ERROR_SIGNATURES: tuple[str, ...] = (
    "internal server error", "500 internal server error",
    "service unavailable", "service temporarily unavailable", "temporarily unavailable",
    "bad gateway", "gateway timeout", "bad request",
    "not found", "page not found", "404 not found", "403 forbidden",
    "access denied", "access is denied", "access blocked", "request blocked",
    "an error occurred", "an error has occurred", "an unexpected error", "something went wrong",
)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# A start-anchored opener that marks the WHOLE body as an error/deny page (so prose that merely uses the
# word later is not caught): a leading error/forbidden/unauthorized/denied token, or an HTTP status line.
_ERROR_OPENER_RE = re.compile(r"^(errors?\b|forbidden\b|unauthori[sz]ed\b|denied\b|[45]\d\d\b)")


def _visible_text(body: str) -> str:
    """The body's visible text: HTML tags dropped, whitespace collapsed, lowercased — used ONLY for
    error-signature matching (the length guard uses the raw ``body.strip()`` per the shared contract)."""
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", body)).strip().lower()


def _is_bare_error_signature(body: str) -> bool:
    """True when ``body`` is essentially a server-error or access-denied page rather than a substantive
    authenticated response. Conservative by design: only a body that OPENS with an error/status token, or a
    short body dominated by a canonical error/deny phrase, counts — so a real authenticated page that
    happens to contain "error" in prose, and a normal logged-out page, are never misclassified."""
    text = _visible_text(body)
    if not text:
        return True   # nothing but markup/whitespace — not substantive
    if _ERROR_OPENER_RE.match(text):
        return True
    if len(text) <= 96 and any(sig in text for sig in _BARE_ERROR_SIGNATURES):
        return True
    return False


def is_substantive_success(status: int, body: str) -> bool:
    """SHARED GUARD: a response is a SUBSTANTIVE SUCCESS — one that may satisfy a positive fire-predicate OR
    serve as a negative control — ONLY when it is a real 2xx with a non-trivial body that is not itself an
    error/deny signature. A response that fails this proves NOTHING: it can neither be scored authenticated
    NOR clear a control, and the caller must FAIL CLOSED (never a FACT, never a false CLEAN).

        is_substantive_success(status, body) ⇔
            200 <= status < 300  AND  len(body.strip()) >= 16  AND  not a bare error/deny signature."""
    if not (200 <= int(status) < 300):
        return False
    text = body or ""
    if len(text.strip()) < _MIN_SUBSTANTIVE_BODY:
        return False
    return not _is_bare_error_signature(text)


def valid_discriminator(marker: str | None, *, nonce: str | None = None) -> bool:
    """SHARED GUARD: a discriminator is USABLE as a positive/absence marker ONLY when it is a real,
    non-trivial string — present, not pure whitespace, and at least ``_MIN_DISCRIMINATOR`` stripped
    characters. A vacuous marker (``''`` / ``'   '`` / a 1-2 char fragment) is trivially "in" almost any body
    and so discriminates NOTHING; it must never be allowed to satisfy a contains-predicate. Where a per-probe
    ``nonce`` exists, the marker must not be a mere substring of it (that would discriminate the nonce, not an
    authenticated state); session fixation carries no such nonce, so callers here pass none."""
    if marker is None:
        return False
    stripped = marker.strip()
    if len(stripped) < _MIN_DISCRIMINATOR:
        return False
    if nonce and stripped in nonce:
        return False
    return True


def _sfx_view(resp: object) -> dict:
    """The retained ``{status, body}`` of a protected-page response the oracle re-runs its differential over.
    A non-dict (no channel on that leg) becomes ``{status: None, body: ""}`` — a non-substantive view the
    oracle treats as undecidable (fails closed to a LEAD), never as a differential reference."""
    if isinstance(resp, dict):
        return {"status": resp.get("status"), "body": _body(resp)}
    return {"status": None, "body": _body(resp)}


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
    runs the operator's login sequence through the gated ``send`` carrying S0, observes the session id in
    effect AFTER login (S1), and then re-presents the VIGIL-fixed id **S0** to the protected page — CAPTURING
    THE RAW RESPONSE. It ALSO captures a LOGGED-OUT NEGATIVE REFERENCE: the SAME protected URL fetched with NO
    session cookie. The scanner makes NO authentication decision; it hands the RAW bytes (the fixed-session
    view, the logged-out reference, the operator success_marker + logged-out signals) to the deterministic
    ``session_fixation_oracle``, which RE-DERIVES — via a DIFFERENTIAL — whether S0 reached an authenticated
    state, and fires ONLY when the fixed id survived login UNROTATED (S1 == S0) AND the success_marker is
    PRESENT in S0's fixed-session view yet PROVABLY ABSENT from the SUBSTANTIVE logged-out reference (proving
    the marker is access-gated, not a common token / chrome / a benign soft-200 body both views share).

    Capturing S0's view directly (rather than trusting S1==S0 as a rotation proxy) is deliberate: an app can
    rotate the cookie VALUE at login yet leave the pre-auth-fixed id S0 still valid — a REAL fixation a value
    check would miss; the oracle's differential exposes it. Capturing a LOGGED-OUT REFERENCE (rather than
    scoring the fixed-session body alone) is the ROUND-4 soundness fix: a single body cannot be classified
    authenticated-vs-benign by content heuristics, so the marker is qualified ONLY by its ABSENCE from a
    same-URL logged-out view. If no substantive logged-out reference is available, the oracle FAILS CLOSED to
    a LEAD. Returns ``None`` only when no channel was established for the login leg (a non-dict login
    response); every other outcome is adjudicated by the oracle. All traffic rides the injected ``send`` (the
    scope/charter/kill-switch-gated executor); nothing here weakens the boundary."""
    s0 = sentinel_id or mint_session_sentinel()

    # 0. LOGGED-OUT NEGATIVE REFERENCE: fetch the protected URL with NO session cookie — the differential
    #    base. The oracle qualifies the operator success_marker as an authenticated-state discriminator ONLY
    #    if it is PROVABLY ABSENT from this SUBSTANTIVE logged-out view of the SAME url, so a common token /
    #    page chrome / a benign soft-200 body both views share can NEVER mint a spurious CWE-384 FACT.
    logged_out_resp = send(HttpRequest(method="GET", url=protected_url, headers=[], body=None))

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

    # 3. AUTHORIZED (fixed-session) VIEW: re-present the ORIGINAL VIGIL-fixed id S0 to the protected page
    #    AFTER login and CAPTURE THE RAW RESPONSE. The oracle re-derives — from these raw bytes vs the
    #    logged-out reference — whether S0 reached an authenticated state; the scanner scores nothing.
    authorized_resp = send(HttpRequest(method="GET", url=protected_url,
                                       headers=[("Cookie", f"{session_cookie}={s0}")], body=None))

    return FindingContext.from_session_fixation(
        sentinel_id=s0, post_auth_id=s1, cookie_name=session_cookie,
        success_marker=login.success_marker,
        logged_out_markers=login.logged_out_markers,
        logged_out_statuses=login.logged_out_statuses,
        authorized_view=_sfx_view(authorized_resp),
        logged_out_ref=_sfx_view(logged_out_resp))
