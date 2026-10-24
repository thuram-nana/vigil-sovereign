"""Report builder — the SSTI + SQLi surface.

Vuln mode: the report `title` is run through a naive `{{ ... }}` expression evaluator, so a user-supplied
template expression is evaluated server-side (`{{7*7}}` -> `49`, `{{8*8}}` -> `64`) and written into the
page unescaped (server-side template injection); AND the `status` filter is string-concatenated into a real
SQLite query over a synthetic in-memory table (a broken quote surfaces a real `sqlite3.OperationalError`;
`' OR '1'='1` returns every row while `' AND '1'='2` returns none — a boolean differential). Hardened mode:
the title is treated as a literal and escaped (no evaluation), and the status filter is parameterized. SAME
routes, SAME params in both modes — so VIGIL's oracle fires in vuln and goes silent (a sound negative) in
hardened.

Stdlib only. A small MODULE-LEVEL dataset of CLEARLY-FAKE lab rows is loaded into a fresh `sqlite3`
`:memory:` database per request; nothing here touches the shared db.py / seed.py.
"""

from __future__ import annotations

import ast
import operator
import re
import sqlite3

from .. import theme
from ..router import Ctx, Response, Router

# --- synthetic, CLEARLY-FAKE lab data (never touches the shared DB) --------------------------------
_COLS = "report_no, title, owner, status, created"
_STATUSES = ("draft", "submitted", "approved", "rejected", "archived")
_REPORTS: list[tuple[str, str, str, str, str]] = [
    ("RPT-LAB-001", "Q1 Permit Volumes (SAMPLE)",   "Ada Example",     "approved",  "2025-01-14"),
    ("RPT-LAB-002", "Lab Fixture Backlog",          "Bob Sample",      "submitted", "2025-02-02"),
    ("RPT-LAB-003", "Fake Inspection Summary",       "Carol Testcase",  "draft",     "2025-02-19"),
    ("RPT-LAB-004", "Placeholder Revenue Review",    "Dave Mockdata",   "rejected",  "2025-03-05"),
    ("RPT-LAB-005", "Synthetic Licence Audit",       "Eve Fixture",     "approved",  "2025-03-22"),
    ("RPT-LAB-006", "Demo Archive Dump",             "Frank Dummy",     "archived",  "2025-04-01"),
]


def _build_db() -> sqlite3.Connection:
    """A fresh in-memory SQLite DB seeded from the synthetic rows (real SQL => a real, confirmable SQLi)."""
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE reports (report_no TEXT, title TEXT, owner TEXT, status TEXT, created TEXT)")
    con.executemany(f"INSERT INTO reports ({_COLS}) VALUES (?,?,?,?,?)", _REPORTS)
    con.commit()
    return con


# --- the naive report-title template evaluator (the SSTI sink) -------------------------------------
_TEMPLATE_RE = re.compile(r"\{\{(.*?)\}\}")
_BIN_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
            ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
            ast.Mod: operator.mod, ast.Pow: operator.pow}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval_expr(node: ast.AST) -> int | float:
    """Evaluate one arithmetic expression node (`7*7` -> 49). Anything non-arithmetic raises."""
    if isinstance(node, ast.Expression):
        return _eval_expr(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval_expr(node.operand))
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left, right = _eval_expr(node.left), _eval_expr(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 64:  # keep the lab honest: no CPU/memory DoS
            raise ValueError("exponent too large")
        return _BIN_OPS[type(node.op)](left, right)
    raise ValueError("unsupported expression")


def _render_title(title: str) -> str:
    """VULN render: substitute each `{{expr}}` with its evaluated value (server-side template injection)."""
    def repl(m: re.Match[str]) -> str:
        try:
            val = _eval_expr(ast.parse(m.group(1).strip(), mode="eval"))
        except Exception:  # noqa: BLE001 — not simple arithmetic: leave the literal token untouched
            return m.group(0)
        return str(int(val) if isinstance(val, float) and val.is_integer() else val)
    return _TEMPLATE_RE.sub(repl, title)


def _reports_home(ctx: Ctx) -> Response:
    opts = "".join(f'<option value="{theme.esc(s)}">' for s in _STATUSES)
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Reporting</span>'
        '<h1>Report builder</h1>'
        '<p class="sub">Compose a titled report over the permit register and filter it by status.</p></div>'
        '<div class="card"><form method="get" action="/reports/run">'
        '<label class="field"><span>Report title</span>'
        '<input name="title" placeholder="Permit report — {{7*7}} totals" autofocus></label>'
        '<label class="field"><span>Status filter</span>'
        '<input name="status" list="statuses" placeholder="e.g. approved"></label>'
        f'<datalist id="statuses">{opts}</datalist>'
        '<button class="btn primary" type="submit">Run report</button></form>'
        '<p style="color:var(--text-2);margin-top:var(--sp-3)">Leave the filter blank to list every report. '
        'Example: <a href="/reports/run?title=Totals%20{{7*7}}&status=approved">a quick report</a>.</p>'
        '</div></main>'
    )
    return Response.html(theme.page("Report builder", body, active="reports", mode=ctx.mode))


def _reports_run(ctx: Ctx) -> Response:
    title = ctx.q1("title")
    status = ctx.q1("status")

    con = _build_db()
    rows, err = [], ""
    try:
        cur = con.cursor()
        if not status:
            cur.execute(f"SELECT {_COLS} FROM reports ORDER BY report_no")
        elif ctx.hardened:
            cur.execute(f"SELECT {_COLS} FROM reports WHERE status = ?", (status,))  # parameterized: no SQLi
        else:
            # INTENTIONAL: the status filter is concatenated straight into the SQL text.
            cur.execute(f"SELECT {_COLS} FROM reports WHERE status = '" + status + "'")  # noqa: S608
        rows = cur.fetchall()
    except Exception as exc:  # a broken injection surfaces the real DB error (the error-based SQLi tell)
        err = f"SQL error: {exc}"
    finally:
        con.close()

    # SSTI sink: vuln renders the title template (unescaped); hardened keeps it a literal (escaped).
    if not title:
        shown_title = "Untitled report"
    else:
        shown_title = theme.esc(title) if ctx.hardened else _render_title(title)

    if rows:
        body_rows = "".join(
            f'<tr><td class="mono">{theme.esc(r["report_no"])}</td><td>{theme.esc(r["title"])}</td>'
            f'<td>{theme.esc(r["owner"])}</td><td>{theme.esc(r["status"])}</td>'
            f'<td class="mono">{theme.esc(r["created"])}</td></tr>'
            for r in rows
        )
    else:
        body_rows = '<tr><td colspan="5" style="color:var(--text-2)">No reports match this filter.</td></tr>'
    table = (
        '<div class="card scroll-x"><table><thead><tr><th>Report no.</th><th>Title</th><th>Owner</th>'
        f'<th>Status</th><th>Created</th></tr></thead><tbody>{body_rows}</tbody></table></div>'
    )
    err_block = (
        f'<div class="notice danger" style="margin-top:var(--sp-4)"><pre class="mono">{theme.esc(err)}</pre></div>'
        if err else ""
    )
    body = (
        f'<main class="wrap"><div class="screen-head"><span class="label">Reporting</span>'
        f'<h1>{shown_title}</h1>'
        f'<p class="sub">{len(rows)} report(s) match · <a href="/reports">New report</a></p></div>'
        f'{table}{err_block}</main>'
    )
    return Response.html(theme.page("Report results", body, active="reports", mode=ctx.mode))


def register(r: Router) -> None:
    r.add("GET", "/reports", _reports_home)
    r.add("GET", "/reports/run", _reports_run)
