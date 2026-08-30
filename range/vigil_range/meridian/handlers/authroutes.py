"""Authentication — login (weak, writes auth.log) + the open-redirect continue endpoint.

/login: plaintext credential check with NO rate limit (the weak-authn surface; every attempt is written to
auth.log, feeding the brute-force / password-spray detection demo).
/auth/continue?next=: a 302 to the attacker-controlled `next` (open redirect) in vuln mode; same-origin only
in hardened mode.
"""

from __future__ import annotations

from .. import auth, db, logs, theme
from ..config import Config
from ..router import Ctx, Response, Router


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
    con = db.from_ctx(ctx)
    try:
        account = auth.authenticate(con, username, password)
        if account is None:
            logs.write_auth(auth_log, ctx.client_ip, username or "-", "failure")  # NO rate limit (weak authn)
            return _login_form(ctx, error="Invalid username or password.")
        logs.write_auth(auth_log, ctx.client_ip, username, "success")
        kind = "staff" if account["role"] != "citizen" else "citizen"
        token = auth.create_session(con, kind=kind, subject_id=account["id"],
                                    username=account["username"], role=account["role"])
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
