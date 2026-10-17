"""Secure messaging / inbox — the stored-XSS + IDOR surface.

A private message centre between a citizen and the agency. Two planted flaws, both on the SAME
`/messages/view?id=<n>` route and the SAME `id` param, so VIGIL's oracle fires in vuln mode and goes
silent (a sound CLEAN) in hardened mode:

  * Stored XSS (CWE-79): a message `body` submitted at POST /messages/send is stored VERBATIM and
    rendered UNESCAPED on the view page in vuln mode; `theme.esc(...)`-escaped in hardened mode.
  * IDOR / BOLA (CWE-639): GET /messages/view?id=<n> returns ANY message — including other users' —
    with no ownership check in vuln mode; hardened mode enforces `recipient == session` (403 otherwise).

Confirmable with no out-of-band infra: the XSS is reflection and the IDOR is a status + achieved-state
differential (reading another user's message exposes a distinctive lab secret such as OTP-LAB-7Q2X).

All data is module-level and clearly fake; this handler never touches the shared db.py / seed.py.
"""

from __future__ import annotations

import datetime
import threading

from .. import theme
from ..router import Ctx, Response, Router

# The lab fixes the "logged-in" user; a real app derives this from the authenticated session.
_SESSION_USER = 1
_USERS = {1: "Ada Lovelace", 2: "Grace Hopper", 3: "Katherine Johnson"}

# Module-level synthetic inbox — clearly-fake lab data. Messages to_id 2/3 belong to OTHER users and
# carry distinctive fake secrets, so a successful cross-user read (IDOR) is unambiguous achieved state.
_MESSAGES: list[dict] = [
    {"id": 1, "frm": "Permits Office", "to_id": 1, "subject": "Building permit BP-LAB-2231 in review",
     "body": "Hello Ada, your building permit application has moved to review. No action is needed.",
     "sent": "2026-09-02"},
    {"id": 2, "frm": "Billing Department", "to_id": 1, "subject": "Receipt for your licence fee",
     "body": "We received your licence fee. Reference RCPT-LAB-0098. Thank you.", "sent": "2026-09-05"},
    {"id": 3, "frm": "Records Office", "to_id": 2, "subject": "Re: identity verification",
     "body": "Grace, your one-time verification code is OTP-LAB-7Q2X. Do not share it with anyone.",
     "sent": "2026-09-06"},
    {"id": 4, "frm": "Human Resources", "to_id": 3, "subject": "Private: salary band review",
     "body": "Katherine, your confidential band-review note is BAND-LAB-55K. Treat as restricted.",
     "sent": "2026-09-09"},
]
_LOCK = threading.Lock()  # guards the id assignment + append when a message is sent


def _notice(ctx: Ctx, title: str, message: str, status: int, kind: str = "warn") -> Response:
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Secure messaging</span>'
        f'<h1>{theme.esc(title)}</h1></div>'
        f'<div class="notice {kind}">{theme.esc(message)}</div>'
        '<p style="margin-top:var(--sp-4)"><a class="btn" href="/messages">Back to inbox</a></p></main>'
    )
    return Response.html(theme.page(title, body, active="messages", mode=ctx.mode), status=status)


def _inbox(ctx: Ctx) -> Response:
    inbox = [m for m in _MESSAGES if m["to_id"] == _SESSION_USER]
    rows = "".join(
        f'<tr><td><a href="/messages/view?id={m["id"]}">{theme.esc(m["subject"])}</a></td>'
        f'<td>{theme.esc(m["frm"])}</td><td class="mono">{theme.esc(m["sent"])}</td></tr>'
        for m in inbox
    ) or '<tr><td colspan="3" style="color:var(--text-2)">Your inbox is empty.</td></tr>'
    opts = "".join(
        f'<option value="{uid}"{" selected" if uid == _SESSION_USER else ""}>'
        f'{theme.esc(name)}{" (you)" if uid == _SESSION_USER else ""}</option>'
        for uid, name in _USERS.items()
    )
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Secure messaging</span>'
        f'<h1>Inbox</h1><p class="sub">Signed in as {theme.esc(_USERS[_SESSION_USER])}. '
        'Private messages between you and the agency.</p></div>'
        '<div class="card scroll-x"><table><thead><tr><th>Subject</th><th>From</th><th>Received</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
        '<div class="card" style="margin-top:var(--sp-5)"><div class="card-h"><h3>Compose</h3></div>'
        '<form method="post" action="/messages/send">'
        f'<label class="field"><span>To</span><select name="to">{opts}</select></label>'
        '<label class="field"><span>Subject</span><input name="subject" placeholder="Subject"></label>'
        '<label class="field"><span>Message</span><textarea name="body" '
        'placeholder="Type your message"></textarea></label>'
        '<button class="btn primary" type="submit">Send message</button></form></div></main>'
    )
    return Response.html(theme.page("Inbox", body, active="messages", mode=ctx.mode))


def _send(ctx: Ctx) -> Response:
    try:
        to_id = int(ctx.f1("to", str(_SESSION_USER)))
    except ValueError:
        to_id = _SESSION_USER
    if to_id not in _USERS:
        to_id = _SESSION_USER
    subject = ctx.f1("subject") or "(no subject)"
    body = ctx.f1("body")  # stored VERBATIM — the stored-XSS sink is read back at /messages/view
    with _LOCK:
        mid = max((m["id"] for m in _MESSAGES), default=0) + 1
        _MESSAGES.append({"id": mid, "frm": _USERS[_SESSION_USER], "to_id": to_id,
                          "subject": subject, "body": body,
                          "sent": datetime.date.today().isoformat()})
    return Response.redirect(f"/messages/view?id={mid}")


def _view(ctx: Ctx) -> Response:
    raw = ctx.q1("id")
    try:
        mid = int(raw)
    except ValueError:
        return _notice(ctx, "Invalid message id", f"'{raw}' is not a valid message id.", 400)
    msg = next((m for m in _MESSAGES if m["id"] == mid), None)
    if msg is None:
        return _notice(ctx, "Message not found", f"No message with id {mid}.", 404)

    # IDOR / BOLA (CWE-639): hardened enforces recipient == session; vuln returns ANY message.
    if ctx.hardened and msg["to_id"] != _SESSION_USER:
        return _notice(ctx, "Forbidden", "You are not the recipient of this message.", 403, kind="danger")

    # Stored XSS (CWE-79): the body is rendered UNESCAPED in vuln mode, escaped in hardened mode.
    body_html = theme.esc(msg["body"]) if ctx.hardened else msg["body"]
    to_name = _USERS.get(msg["to_id"], "Unknown")
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Message</span>'
        f'<h1>{theme.esc(msg["subject"])}</h1>'
        f'<p class="sub">From {theme.esc(msg["frm"])} · to {theme.esc(to_name)} · '
        f'<span class="mono">{theme.esc(msg["sent"])}</span> · <a href="/messages">Back to inbox</a></p></div>'
        f'<div class="card"><div style="white-space:pre-wrap">{body_html}</div></div></main>'
    )
    return Response.html(theme.page("Message", body, active="messages", mode=ctx.mode))


def register(r: Router) -> None:
    r.add("GET", "/messages", _inbox)
    r.add("POST", "/messages/send", _send)
    r.add("GET", "/messages/view", _view)
