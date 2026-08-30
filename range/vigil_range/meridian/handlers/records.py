"""Public records search — the SQLi + reflected-XSS surface.

Vuln mode: the `q` value is string-concatenated into a real SQLite query (a broken quote surfaces a real
`sqlite3.OperationalError`; `' OR '1'='1` vs `' AND '1'='2` gives a boolean differential) AND echoed into
the HTML unescaped. Hardened mode: parameterized query, no error echo, escaped reflection — same route and
param, so the oracle runs and does not fire (a sound CLOSED negative).
"""

from __future__ import annotations

from .. import db, theme
from ..router import Ctx, Response, Router

_COLS = "permit_no, holder_name, permit_type, status"


def _records_home(ctx: Ctx) -> Response:
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Public register</span>'
        '<h1>Search public records</h1>'
        '<p class="sub">Search the public register of issued permits and licences by holder name.</p></div>'
        '<div class="card"><form method="get" action="/records/search">'
        '<label class="field"><span>Holder name</span>'
        '<input name="q" placeholder="e.g. Ada Turing" autofocus></label>'
        '<button class="btn primary" type="submit">Search the register</button></form>'
        '<p style="color:var(--text-2);margin-top:var(--sp-3)">Tip: try a full name such as '
        '<a href="/records/search?q=Ada%20Turing">Ada Turing</a>.</p></div></main>'
    )
    return Response.html(theme.page("Public records", body, active="records", mode=ctx.mode))


def _records_search(ctx: Ctx) -> Response:
    q = ctx.q1("q")
    con = db.from_ctx(ctx)
    rows, err = [], ""
    try:
        cur = con.cursor()
        if ctx.hardened:
            cur.execute(f"SELECT {_COLS} FROM permits WHERE holder_name = ?", (q,))  # parameterized: no SQLi
        else:
            # INTENTIONAL: user input concatenated straight into the SQL text.
            cur.execute(f"SELECT {_COLS} FROM permits WHERE holder_name = '" + q + "'")  # noqa: S608
        rows = cur.fetchall()
    except Exception as exc:  # a broken injection surfaces the real DB error (the error-based SQLi tell)
        err = f"SQL error: {exc}"
    finally:
        con.close()

    shown = theme.esc(q) if ctx.hardened else q  # vuln mode: reflected XSS (q echoed unescaped)
    if rows:
        body_rows = "".join(
            f"<tr><td class=\"mono\">{theme.esc(r['permit_no'])}</td><td>{theme.esc(r['holder_name'])}</td>"
            f"<td>{theme.esc(r['permit_type'])}</td><td>{theme.esc(r['status'])}</td></tr>"
            for r in rows
        )
    else:
        body_rows = '<tr><td colspan="4" style="color:var(--text-2)">No matching records.</td></tr>'
    table = (
        '<div class="card scroll-x"><table><thead><tr><th>Permit no.</th><th>Holder</th>'
        f'<th>Type</th><th>Status</th></tr></thead><tbody>{body_rows}</tbody></table></div>'
    )
    err_block = f'<div class="notice danger" style="margin-top:var(--sp-4)"><pre class="mono">{theme.esc(err)}</pre></div>' if err else ""
    body = (
        f'<main class="wrap"><div class="screen-head"><span class="label">Public register</span>'
        f'<h1>Results for: {shown}</h1>'
        f'<p class="sub"><a href="/records">New search</a></p></div>{table}{err_block}</main>'
    )
    return Response.html(theme.page("Search results", body, active="records", mode=ctx.mode))


def register(r: Router) -> None:
    r.add("GET", "/records", _records_home)
    r.add("GET", "/records/search", _records_search)
