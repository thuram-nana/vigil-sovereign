"""My profile / account settings — the IDOR/BOLA, mass-assignment priv-esc, and reflected-XSS surface.

Three sinks live here. Each is genuinely vulnerable in vuln mode and genuinely safe in hardened mode on the
SAME route + SAME param, so VIGIL's oracle fires in vuln and goes silent (a sound CLEAN) in hardened:

  (a) IDOR / BOLA (CWE-639) — GET /profile?id=<n> returns ANY account's full PII (display name, national id,
      email, role) with no ownership check in vuln mode. Hardened serves ONLY the id that equals the
      server-side session principal; any other id is refused 403, while the owner's own id still answers
      (the channel stays live → the negative is CLOSED, not merely unproven).

  (b) Mass-assignment privilege escalation (CWE-915 / CWE-269) — POST /profile/update in vuln mode binds
      EVERY submitted field that is an account attribute, INCLUDING 'role', so a caller can POST role=admin
      and elevate themselves. Hardened binds only an allowlist (display_name, email) and never trusts role.

  (c) Reflected XSS (CWE-79) — the updated display_name is echoed back into the update response unescaped in
      vuln mode and HTML-escaped in hardened mode.

Self-contained by design: a MODULE-LEVEL synthetic dataset of CLEARLY-FAKE accounts (national ids carry a
`LAB-NID-` marker, emails use the reserved `.example` TLD). No shared db.py / seed.py is touched.

Two deliberate soundness choices:
  * The session principal is a FIXED server-side constant, never derived from a client cookie/param — so the
    hardened ownership check cannot be defeated by forging the identity it compares against (that would make
    the hardened negative unsound).
  * /profile/update applies the submitted fields to a per-request COPY of the account and does not persist,
    so every request is deterministic regardless of order in a shared-process test harness. The CWE-915
    property — unfiltered binding of a client 'role' — is genuinely present either way; the unfiltered bind
    is the flaw, not whether the row is written back.
"""

from __future__ import annotations

from .. import theme
from ..router import Ctx, Response, Router

# --- module-level synthetic dataset — CLEARLY FAKE, lab only (no real people) ----------------------
_USERS: dict[int, dict[str, str]] = {
    1: {"id": "1", "display_name": "Robin Meadowlark", "national_id": "LAB-NID-1001",
        "email": "robin.meadowlark@citizens.meridian.example", "phone": "+1-555-0101", "role": "citizen"},
    2: {"id": "2", "display_name": "Jules Harbor", "national_id": "LAB-NID-1002",
        "email": "jules.harbor@citizens.meridian.example", "phone": "+1-555-0102", "role": "citizen"},
    3: {"id": "3", "display_name": "Sam Underwood", "national_id": "LAB-NID-1003",
        "email": "sam.underwood@staff.meridian.example", "phone": "+1-555-0103", "role": "registrar"},
}

# The signed-in citizen for this loopback lab session. A FIXED server-side principal — deliberately NOT read
# from any client-controlled input, so the hardened ownership check is sound.
_SESSION_UID = 1

# Hardened mode binds ONLY these fields from the update form. 'role' is intentionally absent.
_ALLOWED_FIELDS = ("display_name", "email")


def _field_rows(user: dict[str, str], *, name_html: str) -> str:
    """The PII rows of the profile card. `name_html` is the already-rendered display name (escaped or not,
    per mode — that is the reflected-XSS sink); every other field is always escaped (none is the XSS sink)."""
    return (
        f"<tr><th>Display name</th><td>{name_html}</td></tr>"
        f'<tr><th>Account ID</th><td class="mono">{theme.esc(user["id"])}</td></tr>'
        f'<tr><th>National ID</th><td class="mono">{theme.esc(user["national_id"])}</td></tr>'
        f"<tr><th>Email</th><td>{theme.esc(user['email'])}</td></tr>"
        f"<tr><th>Phone</th><td>{theme.esc(user['phone'])}</td></tr>"
        f'<tr><th>Account role</th><td class="mono">{theme.esc(user["role"])}</td></tr>'
    )


def _card(user: dict[str, str], *, name_html: str) -> str:
    return (
        '<div class="card"><div class="card-h"><span class="label">Citizen account</span>'
        f"<h3>{name_html}</h3></div><table>{_field_rows(user, name_html=name_html)}</table></div>"
    )


def _edit_form(session_user: dict[str, str]) -> str:
    """The settings form — it edits the signed-in user's own profile (POST /profile/update)."""
    return (
        '<div class="card"><div class="card-h"><span class="label">Account settings</span>'
        "<h3>Edit your profile</h3></div><form method=\"post\" action=\"/profile/update\">"
        '<label class="field"><span>Display name</span>'
        f'<input name="display_name" value="{theme.esc(session_user["display_name"])}"></label>'
        '<label class="field"><span>Email</span>'
        f'<input name="email" value="{theme.esc(session_user["email"])}"></label>'
        '<button class="btn primary" type="submit">Save changes</button></form></div>'
    )


def _notice(ctx: Ctx, title: str, msg_html: str, *, status: int = 200) -> Response:
    body = (
        '<main class="wrap"><div class="screen-head">'
        f'<span class="label">{theme.esc(title)}</span><h1>{theme.esc(title)}</h1></div>'
        f'<div class="notice warn">{msg_html}</div>'
        '<p style="margin-top:var(--sp-4)"><a class="btn" href="/profile">Back to my profile</a></p></main>'
    )
    return Response.html(theme.page(title, body, active="profile", mode=ctx.mode), status=status)


def _profile(ctx: Ctx) -> Response:
    """GET /profile[?id=<n>] — the profile card + settings form.

    (a) IDOR/BOLA: vuln serves any requested id's PII; hardened serves only the session principal's.
    """
    raw = ctx.q1("id")
    uid = _SESSION_UID
    if raw:
        try:
            uid = int(raw)
        except ValueError:
            return _notice(ctx, "Not found", f"No account with id {theme.esc(raw)}.", status=404)

    user = _USERS.get(uid)
    if user is None:
        return _notice(ctx, "Not found", f"No account with id {theme.esc(str(uid))}.", status=404)

    if ctx.hardened and uid != _SESSION_UID:
        # ownership enforced: you may read only your own profile. Route stays live for your own id.
        return _notice(ctx, "Forbidden", "You may only view your own profile.", status=403)

    # GET read path: display name is static synthetic data, always escaped (this path is not the XSS sink).
    card = _card(user, name_html=theme.esc(user["display_name"]))
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">My account</span>'
        "<h1>My profile</h1><p class=\"sub\">View your account details and update your settings.</p></div>"
        f'<div class="grid cols-2">{card}{_edit_form(_USERS[_SESSION_UID])}</div></main>'
    )
    return Response.html(theme.page("My profile", body, active="profile", mode=ctx.mode))


def _update(ctx: Ctx) -> Response:
    """POST /profile/update — save the signed-in user's settings.

    (b) mass-assignment priv-esc + (c) reflected XSS, both on this route/param across modes.
    """
    form = ctx.form()
    user = dict(_USERS[_SESSION_UID])  # per-request copy, not persisted → deterministic across requests

    if ctx.hardened:
        # allowlist bind: only display_name + email; a submitted 'role' is ignored entirely.
        for field in _ALLOWED_FIELDS:
            if field in form and form[field]:
                user[field] = form[field][0]
    else:
        # INTENTIONAL (CWE-915): bind EVERY submitted field that is an account attribute — 'role' included,
        # so `role=admin` in the body elevates the caller. No allowlist.
        for field, vals in form.items():
            if field in user and vals:
                user[field] = vals[0]

    # (c) reflected XSS: echo the updated display name unescaped in vuln mode, escaped in hardened mode.
    name_html = theme.esc(user["display_name"]) if ctx.hardened else user["display_name"]

    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">My account</span>'
        "<h1>Profile updated</h1></div>"
        f'<div class="notice">Saved. Welcome back, {name_html}. '
        f'Your account role is now <b class="mono">{theme.esc(user["role"])}</b>.</div>'
        f'<div class="grid cols-2" style="margin-top:var(--sp-4)">'
        f"{_card(user, name_html=name_html)}{_edit_form(user)}</div></main>"
    )
    return Response.html(theme.page("Profile updated", body, active="profile", mode=ctx.mode))


def register(r: Router) -> None:
    r.add("GET", "/profile", _profile)
    r.add("POST", "/profile/update", _update)
