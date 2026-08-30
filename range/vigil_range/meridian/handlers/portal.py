"""Citizen portal — apply for a permit, then track it.

The `notes` field submitted at /apply is stored VERBATIM and rendered UNESCAPED on /track (stored XSS); the
`ref` value is echoed unescaped in the not-found message (reflected XSS). Hardened mode escapes both. The
apply flow also seeds the record an IDOR/BOLA finding (S2) reaches.
"""

from __future__ import annotations

import datetime
import secrets

from .. import db, theme
from ..router import Ctx, Response, Router

_PERMIT_TYPES = ["Business Licence", "Building Permit", "Vehicle Licence", "Professional Licence"]
_FEE_CENTS = {"Business Licence": 12000, "Building Permit": 34000, "Vehicle Licence": 8000,
              "Professional Licence": 15000}


def _apply_form(ctx: Ctx) -> Response:
    opts = "".join(f'<option>{theme.esc(t)}</option>' for t in _PERMIT_TYPES)
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Apply</span>'
        '<h1>Apply for a permit</h1><p class="sub">Submit an application and receive a tracking reference.</p></div>'
        '<div class="card"><form method="post" action="/apply">'
        '<label class="field"><span>Full name</span><input name="name" required></label>'
        f'<label class="field"><span>Permit type</span><select name="permit_type">{opts}</select></label>'
        '<label class="field"><span>Notes</span><textarea name="notes" '
        'placeholder="Anything the reviewer should know"></textarea></label>'
        '<button class="btn primary" type="submit">Submit application</button></form></div></main>'
    )
    return Response.html(theme.page("Apply", body, active="apply", mode=ctx.mode))


def _apply_submit(ctx: Ctx) -> Response:
    name = ctx.f1("name") or "Anonymous Applicant"
    permit_type = ctx.f1("permit_type") or _PERMIT_TYPES[0]
    notes = ctx.f1("notes")
    ref = f"APP-LAB-{secrets.token_hex(3).upper()}"
    created = datetime.date.today().isoformat()
    con = db.from_ctx(ctx)
    try:
        con.execute(
            "INSERT INTO applications (ref, citizen_id, permit_type, status, notes, fee_cents, created) "
            "VALUES (?,?,?,?,?,?,?)",
            (ref, 1, permit_type, "submitted", notes, _FEE_CENTS.get(permit_type, 10000), created),
        )
        con.commit()
    finally:
        con.close()
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Submitted</span>'
        '<h1>Application received</h1></div>'
        f'<div class="card"><p>Thank you, {theme.esc(name)}. Your application for a '
        f'<b>{theme.esc(permit_type)}</b> has been received.</p>'
        f'<p>Your tracking reference is <b class="mono">{theme.esc(ref)}</b>.</p>'
        f'<p><a class="btn" href="/track?ref={theme.esc(ref)}">Track this application</a></p></div></main>'
    )
    return Response.html(theme.page("Submitted", body, active="apply", mode=ctx.mode))


def _track(ctx: Ctx) -> Response:
    ref = ctx.q1("ref")
    con = db.from_ctx(ctx)
    try:
        row = con.execute("SELECT ref, permit_type, status, notes FROM applications WHERE ref = ?",
                          (ref,)).fetchone()
    finally:
        con.close()

    if row is None:
        # reflected XSS: the ref is echoed unescaped in vuln mode
        shown_ref = theme.esc(ref) if ctx.hardened else ref
        body = (
            '<main class="wrap"><div class="screen-head"><span class="label">Track</span>'
            '<h1>Track an application</h1></div>'
            f'<div class="notice warn">No application matches reference: {shown_ref}</div>'
            '<div class="card" style="margin-top:var(--sp-4)"><form method="get" action="/track">'
            '<label class="field"><span>Reference</span><input name="ref" placeholder="APP-LAB-…"></label>'
            '<button class="btn" type="submit">Track</button></form></div></main>'
        )
        return Response.html(theme.page("Track", body, active="track", mode=ctx.mode))

    # stored XSS: the notes field is rendered unescaped in vuln mode
    notes = theme.esc(row["notes"]) if ctx.hardened else (row["notes"] or "")
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Track</span>'
        f'<h1>Application {theme.esc(row["ref"])}</h1></div>'
        '<div class="card"><table>'
        f'<tr><th>Permit type</th><td>{theme.esc(row["permit_type"])}</td></tr>'
        f'<tr><th>Status</th><td>{theme.esc(row["status"])}</td></tr>'
        f'<tr><th>Notes</th><td>{notes}</td></tr>'
        '</table></div></main>'
    )
    return Response.html(theme.page("Track", body, active="track", mode=ctx.mode))


def register(r: Router) -> None:
    r.add("GET", "/apply", _apply_form)
    r.add("POST", "/apply", _apply_submit)
    r.add("GET", "/track", _track)
