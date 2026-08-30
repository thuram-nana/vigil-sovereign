"""Authentication — login (weak, writes auth.log) + the open-redirect continue endpoint.

/login: plaintext credential check with NO rate limit (the weak-authn surface; every attempt is written to
auth.log, feeding the brute-force / password-spray detection demo).
/auth/continue?next=: a 302 to the attacker-controlled `next` (open redirect) in vuln mode; same-origin only
in hardened mode.
"""

from __future__ import annotations

import threading
import time

from .. import auth, db, logs, theme
from ..config import Config
from ..router import Ctx, Response, Router

# In-memory login-failure tracker — used ONLY in hardened mode (vuln mode has no rate limit, the weak-authn
# plant). Real wall-clock here is fine: this is the target app, not the engine's deterministic path.
_FAILS: dict[str, list[float]] = {}
_FAILS_LOCK = threading.Lock()
_FAIL_WINDOW = 300.0
_MAX_FAILS = 8


def _rate_limited(ip: str) -> bool:
    now = time.time()
    with _FAILS_LOCK:
        hist = [t for t in _FAILS.get(ip, []) if now - t < _FAIL_WINDOW]
        _FAILS[ip] = hist
        return len(hist) >= _MAX_FAILS


def _record_fail(ip: str) -> None:
    with _FAILS_LOCK:
        _FAILS.setdefault(ip, []).append(time.time())


def _safe_next(nxt: str, hardened: bool) -> tuple[bool, str]:
    """(ok, location). In hardened mode only a same-origin relative path is allowed."""
    if not hardened:
        return True, nxt or "/"
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return True, nxt
    return False, "/"


def _login_form(ctx: Ctx, error: str = "") -> Response:
    nxt = theme.esc(ctx.q1("next"))
    err = f'<div class="notice danger">{theme.esc(error)}</div>' if error else ""
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Staff</span>'
        '<h1>Sign in</h1><p class="sub">Clerks, inspectors, registrars and administrators.</p></div>'
        f'{err}<div class="card"><form method="post" action="/login">'
        f'<input type="hidden" name="next" value="{nxt}">'
        '<label class="field"><span>Username</span><input name="username" autofocus></label>'
        '<label class="field"><span>Password</span><input name="password" type="password"></label>'
        '<button class="btn primary" type="submit">Sign in</button></form>'
        '<p style="color:var(--text-2);margin-top:var(--sp-3)">Or '
        '<a href="/auth/continue?next=/">continue as a guest</a>.</p></div></main>'
    )
    return Response.html(theme.page("Sign in", body, active="signin", mode=ctx.mode))


def _login_submit(ctx: Ctx) -> Response:
    username = ctx.f1("username")
    password = ctx.f1("password")
    nxt = ctx.f1("next")
    auth_log = Config(base_dir=ctx.base_dir).auth_log

    if ctx.hardened and _rate_limited(ctx.client_ip):
        logs.write_auth(auth_log, ctx.client_ip, username or "-", "failure")
        return Response.text("Too many attempts. Try again later.", status=429)

    con = db.from_ctx(ctx)
    try:
        account = auth.authenticate(con, username, password)
        if account is None:
            logs.write_auth(auth_log, ctx.client_ip, username or "-", "failure")  # vuln: NO rate limit
            if ctx.hardened:
                _record_fail(ctx.client_ip)
            return _login_form(ctx, error="Invalid username or password.")
        logs.write_auth(auth_log, ctx.client_ip, username, "success")
        role = account["role"]
        kind = "citizen" if role == "citizen" else "staff"
        # a citizen session is keyed to its CITIZEN id (the object owner), a staff session to the account id
        subject = account["citizen_id"] if (role == "citizen" and account["citizen_id"] is not None) else account["id"]
        token = auth.create_session(con, kind=kind, subject_id=subject,
                                    username=account["username"], role=role)
    finally:
        con.close()
    ok, location = _safe_next(nxt, ctx.hardened)
    resp = Response.redirect(location if ok else "/", status=302)
    key, val = auth.set_cookie_header(token)
    resp.headers[key] = val
    return resp


def _continue(ctx: Ctx) -> Response:
    nxt = ctx.q1("next", "/")
    ok, location = _safe_next(nxt, ctx.hardened)
    if not ok:
        return Response.text("refused: only same-origin redirects are allowed", status=400)
    return Response.redirect(location, status=302)  # vuln mode: `next` honoured verbatim (open redirect)


def _logout(ctx: Ctx) -> Response:
    resp = Response.redirect("/", status=302)
    resp.headers["Set-Cookie"] = f"{auth.COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
    return resp


def register(r: Router) -> None:
    r.add("GET", "/login", _login_form)
    r.add("POST", "/login", _login_submit)
    r.add("GET", "/auth/continue", _continue)
    r.add("GET", "/logout", _logout)
