"""Staff back office + admin console — the broken-access-control / BFLA / privilege-escalation surface.

Vuln mode performs NO authorization checks: the review queue (with applicant PII + notes rendered
unescaped) is reachable by anyone; the approve action is a BFLA (any caller approves); the admin role-change
is a privilege escalation (any caller elevates any user, including themselves). Hardened mode enforces the
role ladder (queue = clerk+, approve = registrar+, admin console + role change = admin only).
"""

from __future__ import annotations

from .. import auth, db, theme
from ..router import Ctx, Response, Router


def _session(ctx: Ctx):
    con = db.from_ctx(ctx)
    try:
        return auth.session_from_cookies(con, ctx.header("cookie"))
    finally:
        con.close()


def _forbidden(ctx: Ctx, need: str) -> Response:
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">403</span>'
        f'<h1>Not authorized</h1><p class="sub">This area requires the <b>{theme.esc(need)}</b> role.</p>'
        '<p><a class="btn" href="/login?next=/staff">Sign in</a></p></div></main>'
    )
    return Response.html(theme.page("Forbidden", body, active="signin", mode=ctx.mode), status=403)


def _review_queue(ctx: Ctx) -> Response:
    if ctx.hardened:
        s = _session(ctx)
        if s is None or not auth.is_staff(s["role"]):
            return _forbidden(ctx, "clerk (or above)")
    con = db.from_ctx(ctx)
    try:
        rows = con.execute(
            "SELECT a.id, a.ref, a.permit_type, a.status, a.notes, c.name "
            "FROM applications a JOIN citizens c ON c.id = a.citizen_id ORDER BY a.id").fetchall()
    finally:
        con.close()
    trs = ""
    for r in rows:
        note = theme.esc(r["notes"]) if ctx.hardened else (r["notes"] or "")  # staff view: stored XSS in vuln mode
        trs += (
            f'<tr><td class="mono">{theme.esc(r["ref"])}</td><td>{theme.esc(r["name"])}</td>'
            f'<td>{theme.esc(r["permit_type"])}</td><td>{theme.esc(r["status"])}</td><td>{note}</td>'
            f'<td><form method="post" action="/staff/applications/{r["id"]}/approve" style="margin:0">'
            f'<button class="btn sm" type="submit">Approve</button></form></td></tr>'
        )
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Back office</span>'
        '<h1>Review queue</h1><p class="sub">Applications awaiting review.</p></div>'
        '<div class="card scroll-x"><table><thead><tr><th>Ref</th><th>Applicant</th><th>Type</th>'
        f'<th>Status</th><th>Notes</th><th></th></tr></thead><tbody>{trs}</tbody></table></div>'
        '<p style="margin-top:var(--sp-4)"><a href="/admin">Admin console →</a></p></main>'
    )
    return Response.html(theme.page("Review queue", body, active="signin", mode=ctx.mode))


def _approve(ctx: Ctx) -> Response:
    if ctx.hardened:
        s = _session(ctx)
        if s is None or not auth.at_least(s["role"], "registrar"):  # approval is a registrar+ function
            return Response.json({"error": "forbidden", "need": "registrar"}, status=403)
    try:
        app_id = int(ctx.params["id"])
    except (KeyError, ValueError):
        return Response.json({"error": "not found"}, status=404)
    con = db.from_ctx(ctx)
    try:
        con.execute("UPDATE applications SET status = 'approved' WHERE id = ?", (app_id,))
        con.commit()
    finally:
        con.close()
    return Response.redirect("/staff", status=302)


def _admin_console(ctx: Ctx) -> Response:
    if ctx.hardened:
        s = _session(ctx)
        if s is None or s["role"] != "admin":
            return _forbidden(ctx, "admin")
    con = db.from_ctx(ctx)
    try:
        rows = con.execute("SELECT id, username, role FROM accounts ORDER BY id").fetchall()
    finally:
        con.close()
    opts = "".join(f"<option>{r}</option>" for r in auth.ROLES)
    trs = "".join(
        f'<tr><td>{r["id"]}</td><td>{theme.esc(r["username"])}</td><td>{theme.esc(r["role"])}</td>'
        f'<td><form method="post" action="/admin/users/{r["id"]}/role" style="margin:0;display:flex;gap:8px">'
        f'<select name="role">{opts}</select><button class="btn sm" type="submit">Set</button></form></td></tr>'
        for r in rows
    )
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Administration</span>'
        '<h1>Admin console</h1><p class="sub">Manage staff accounts and roles.</p></div>'
        '<div class="card scroll-x"><table><thead><tr><th>ID</th><th>Username</th><th>Role</th>'
        f'<th>Change role</th></tr></thead><tbody>{trs}</tbody></table></div></main>'
    )
    return Response.html(theme.page("Admin", body, active="signin", mode=ctx.mode))


def _set_role(ctx: Ctx) -> Response:
    if ctx.hardened:
        s = _session(ctx)
        if s is None or s["role"] != "admin":  # only an admin may change roles (no self-elevation path)
            return Response.json({"error": "forbidden", "need": "admin"}, status=403)
    try:
        uid = int(ctx.params["id"])
    except (KeyError, ValueError):
        return Response.json({"error": "not found"}, status=404)
    new_role = ctx.f1("role")
    if new_role not in auth.ROLES:
        return Response.json({"error": "invalid role"}, status=400)
    con = db.from_ctx(ctx)
    try:
        con.execute("UPDATE accounts SET role = ? WHERE id = ?", (new_role, uid))
        con.commit()
    finally:
        con.close()
    return Response.redirect("/admin", status=302)


def register(r: Router) -> None:
    r.add("GET", "/staff", _review_queue)
    r.add("POST", "/staff/applications/<id>/approve", _approve)
    r.add("GET", "/admin", _admin_console)
    r.add("POST", "/admin/users/<id>/role", _set_role)
