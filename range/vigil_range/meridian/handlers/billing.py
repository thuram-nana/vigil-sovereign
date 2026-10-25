"""Invoices & payments — the IDOR (BOLA) + payment business-logic surface.

A citizen billing centre: list your invoices, open one, and pay it. Two planted flaws, each on one
route, each identical route + param across modes so VIGIL's oracle fires in vuln and goes silent (a
sound CLEAN) in hardened:

  * IDOR / BOLA (CWE-639): GET /billing/invoice?id=<n> returns ANY invoice — amount + payer PII (name,
    email, national id) — with NO ownership check in vuln mode; hardened returns it only when it belongs
    to the signed-in payer and answers 403 otherwise.
  * Business-logic (CWE-840): POST /billing/checkout trusts the client `discount` percent unbounded, so
    a discount of 100+ books a zero/negative total still marked PAID in vuln mode; hardened recomputes
    from the server-side price, rejects a discount outside [0, 50], and never books a non-positive total.

Confirmable with no out-of-band infra: the IDOR is a status + achieved-state differential (a cross-owner
read returns a distinctive fake id such as MER-FAKE-0002) and the business-logic flaw an achieved-state
differential (a PAID receipt whose total is <= 0). Data is module-level and clearly fake; never touches
the shared db.py / seed.py.
"""

from __future__ import annotations

from .. import theme
from ..router import Ctx, Response, Router

# The lab fixes the "signed-in" payer; a real app derives this from an opaque server-side session. It is
# NOT client-controlled, so the hardened ownership check below is genuinely safe.
_CURRENT_PAYER_ID = 1
_MAX_DISCOUNT_PCT = 50.0  # the largest promotion the hardened business rules permit

# Module-level synthetic data — all fictional, lab-only (no real people, no real data). Each payer carries
# a distinctive fake national id so a successful cross-owner read (IDOR) is unambiguous achieved state.
_PAYERS = {
    1: {"name": "Ada Lovelace",      "email": "ada.lovelace@citizen.meridia.example", "national_id": "MER-FAKE-0001"},
    2: {"name": "Grace Hopper",      "email": "grace.hopper@citizen.meridia.example", "national_id": "MER-FAKE-0002"},
    3: {"name": "Alan Turing",       "email": "alan.turing@citizen.meridia.example",  "national_id": "MER-FAKE-0003"},
    4: {"name": "Katherine Johnson", "email": "k.johnson@citizen.meridia.example",    "national_id": "MER-FAKE-0004"},
    5: {"name": "Edsger Dijkstra",   "email": "e.dijkstra@citizen.meridia.example",   "national_id": "MER-FAKE-0005"},
}
# invoice id -> record. `amount_cents` is the SERVER-SIDE price the hardened checkout recomputes against.
# Ids 4801/4804 belong to the signed-in payer (1); the rest belong to OTHER payers (the IDOR targets).
_INVOICES = {
    4801: {"payer_id": 1, "desc": "Business Licence — annual renewal", "amount_cents": 12000, "status": "DUE",  "issued": "2026-09-02", "due": "2026-10-02"},
    4802: {"payer_id": 2, "desc": "Building Permit — extension",       "amount_cents": 34000, "status": "PAID", "issued": "2026-08-14", "due": "2026-09-14"},
    4803: {"payer_id": 3, "desc": "Vehicle Licence — heavy goods",     "amount_cents": 8000,  "status": "DUE",  "issued": "2026-09-20", "due": "2026-10-20"},
    4804: {"payer_id": 1, "desc": "Professional Licence — surveyor",   "amount_cents": 15000, "status": "DUE",  "issued": "2026-09-28", "due": "2026-10-28"},
    4805: {"payer_id": 4, "desc": "Business Licence — new",            "amount_cents": 12000, "status": "PAID", "issued": "2026-07-11", "due": "2026-08-11"},
    4806: {"payer_id": 5, "desc": "Building Permit — demolition",      "amount_cents": 34000, "status": "DUE",  "issued": "2026-09-30", "due": "2026-10-30"},
}


def _money(cents: int) -> str:
    """Format integer cents as currency, keeping the sign so a non-positive total stays visible."""
    sign = "-" if cents < 0 else ""
    return f"{sign}${abs(cents) / 100:,.2f}"


def _notice(ctx: Ctx, title: str, message: str, status: int, kind: str = "warn") -> Response:
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Invoices &amp; payments</span>'
        f'<h1>{theme.esc(title)}</h1></div>'
        f'<div class="notice {kind}">{theme.esc(message)}</div>'
        '<p style="margin-top:var(--sp-4)"><a class="btn" href="/billing">Back to invoices</a></p></main>'
    )
    return Response.html(theme.page(title, body, active="billing", mode=ctx.mode), status=status)


def _billing_home(ctx: Ctx) -> Response:
    """The payer's own invoices — the legitimate view. Invoices are addressed by a sequential id, and the
    ownership check lives (or, in vuln mode, does not) on /billing/invoice."""
    mine = [(iid, inv) for iid, inv in sorted(_INVOICES.items()) if inv["payer_id"] == _CURRENT_PAYER_ID]
    rows = "".join(
        f'<tr><td class="mono">INV-{iid}</td><td>{theme.esc(inv["desc"])}</td>'
        f'<td class="mono">{theme.esc(inv["issued"])}</td><td class="mono">{theme.esc(inv["due"])}</td>'
        f'<td class="mono">{_money(inv["amount_cents"])}</td>'
        f'<td><span class="pill {"ok" if inv["status"] == "PAID" else "danger"}">'
        f'<span class="dot"></span>{inv["status"]}</span></td>'
        f'<td><a class="btn sm" href="/billing/invoice?id={iid}">View</a></td></tr>'
        for iid, inv in mine
    )
    due = sum(inv["amount_cents"] for _iid, inv in mine if inv["status"] != "PAID")
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Invoices &amp; payments</span>'
        '<h1>Invoices &amp; payments</h1>'
        f'<p class="sub">Signed in as <b>{theme.esc(_PAYERS[_CURRENT_PAYER_ID]["name"])}</b>. '
        'Review your invoices and settle any outstanding balance.</p></div>'
        '<div class="grid cols-3" style="margin-bottom:var(--sp-5)">'
        f'<div class="tile"><div class="k">Your invoices</div><div class="v tnum">{len(mine)}</div></div>'
        f'<div class="tile"><div class="k">Outstanding</div><div class="v tnum">{_money(due)}</div></div>'
        f'<div class="tile"><div class="k">Account</div><div class="v tnum">#{_CURRENT_PAYER_ID}</div></div></div>'
        '<div class="card scroll-x"><table><thead><tr><th>Invoice</th><th>Description</th><th>Issued</th>'
        '<th>Due</th><th>Amount</th><th>Status</th><th></th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
        '<p class="sub" style="margin-top:var(--sp-4)">Each invoice is addressed by its number, e.g. '
        '<a href="/billing/invoice?id=4801">/billing/invoice?id=4801</a>.</p></main>'
    )
    return Response.html(theme.page("Invoices", body, active="billing", mode=ctx.mode))


def _invoice_detail(ctx: Ctx) -> Response:
    """IDOR / BOLA (CWE-639): hardened enforces owner == signed-in payer; vuln returns ANY invoice + PII."""
    raw = ctx.q1("id")
    try:
        iid = int(raw)
    except ValueError:
        return _notice(ctx, "Invalid invoice id", f"'{raw}' is not a valid invoice id.", 400)
    inv = _INVOICES.get(iid)
    if inv is None:
        return _notice(ctx, "Invoice not found", f"No invoice with id {iid}.", 404)
    if ctx.hardened and inv["payer_id"] != _CURRENT_PAYER_ID:
        return _notice(ctx, "Forbidden", "This invoice belongs to another account.", 403, kind="danger")

    # vuln mode falls straight through: the payer's full PII is returned to any caller (BOLA/IDOR).
    p = _PAYERS[inv["payer_id"]]
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Invoices &amp; payments</span>'
        f'<h1>Invoice INV-{iid}</h1>'
        f'<p class="sub">Issued {theme.esc(inv["issued"])} · due {theme.esc(inv["due"])} · '
        '<a href="/billing">All invoices</a></p></div>'
        '<div class="grid cols-2">'
        '<div class="card"><div class="card-h"><span class="label">Invoice</span>'
        f'<h3>{theme.esc(inv["desc"])}</h3></div><table>'
        f'<tr><th>Amount</th><td class="mono">{_money(inv["amount_cents"])}</td></tr>'
        f'<tr><th>Status</th><td>{inv["status"]}</td></tr>'
        f'<tr><th>Account</th><td class="mono">#{inv["payer_id"]}</td></tr></table></div>'
        '<div class="card"><div class="card-h"><span class="label">Billed to</span>'
        '<h3>Payer details</h3></div><table>'
        f'<tr><th>Name</th><td>{theme.esc(p["name"])}</td></tr>'
        f'<tr><th>Email</th><td>{theme.esc(p["email"])}</td></tr>'
        f'<tr><th>National ID</th><td class="mono">{theme.esc(p["national_id"])}</td></tr></table></div></div>'
        '<div class="card" style="margin-top:var(--sp-4)"><div class="card-h">'
        '<span class="label">Checkout</span><h3>Pay this invoice</h3></div>'
        '<form method="post" action="/billing/checkout">'
        f'<input type="hidden" name="id" value="{iid}">'
        '<label class="field"><span>Promotional discount (%)</span>'
        '<input name="discount" value="0" inputmode="decimal"></label>'
        f'<p class="sub">Payable: <b class="mono">{_money(inv["amount_cents"])}</b> before any discount.</p>'
        '<button class="btn primary" type="submit">Pay invoice</button></form></div></main>'
    )
    return Response.html(theme.page("Invoice", body, active="billing", mode=ctx.mode))


def _receipt(ctx: Ctx, *, title: str, ok: bool, status: int, lines: list[tuple[str, str]]) -> Response:
    trs = "".join(f'<tr><th>{theme.esc(k)}</th><td class="mono">{theme.esc(v)}</td></tr>' for k, v in lines)
    pill = (f'<span class="pill {"ok" if ok else "danger"}"><span class="dot"></span>'
            f'{"PAID" if ok else "REJECTED"}</span>')
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Checkout</span>'
        f'<h1>{theme.esc(title)}</h1><p class="sub">{pill}</p></div>'
        f'<div class="card"><table>{trs}</table></div>'
        '<p class="sub" style="margin-top:var(--sp-4)"><a href="/billing">Back to invoices</a></p></main>'
    )
    return Response.html(theme.page("Checkout", body, active="billing", mode=ctx.mode), status=status)


def _checkout(ctx: Ctx) -> Response:
    """Business-logic flaw (CWE-840): vuln trusts the client `discount` percent unbounded, so a discount
    >= 100 books a zero/negative total still marked PAID. Hardened recomputes from the server price,
    rejects a discount outside [0, _MAX_DISCOUNT_PCT], and refuses a non-positive total."""
    try:
        iid = int(ctx.f1("id"))
    except ValueError:
        return _receipt(ctx, title="Payment failed", ok=False, status=400, lines=[("Error", "invalid invoice id")])
    inv = _INVOICES.get(iid)
    if inv is None:
        return _receipt(ctx, title="Payment failed", ok=False, status=404, lines=[("Error", "invoice not found")])
    base = inv["amount_cents"]
    try:
        discount = float(ctx.f1("discount", "0"))
    except ValueError:
        return _receipt(ctx, title="Payment failed", ok=False, status=400, lines=[("Error", "discount must be a number")])

    if ctx.hardened:
        # the recompute path refuses an out-of-range promotion BEFORE charging (the flaw is closed here).
        if not (0.0 <= discount <= _MAX_DISCOUNT_PCT):
            return _receipt(ctx, title="Payment rejected", ok=False, status=400, lines=[
                ("Invoice", f"INV-{iid}"),
                ("Reason", f"discount {discount:g}% is outside the permitted 0-{_MAX_DISCOUNT_PCT:g}%"),
                ("Amount due", _money(base))])
        total = round(base * (100.0 - discount) / 100.0)
        if total <= 0:  # a valid promo can never reach this, but refuse a non-positive total regardless
            return _receipt(ctx, title="Payment rejected", ok=False, status=400,
                            lines=[("Invoice", f"INV-{iid}"), ("Reason", "computed total is not positive")])
    else:
        # vuln: the client discount is trusted verbatim — 100%+ drives the total to zero/negative, and the
        # checkout is still accepted and marked PAID (no clamp, no server recompute, no rejection).
        total = round(base * (100.0 - discount) / 100.0)

    return _receipt(ctx, title="Payment confirmed", ok=True, status=200, lines=[
        ("Invoice", f"INV-{iid}"),
        ("List price", _money(base)),
        ("Discount applied", f"{discount:g}%"),
        ("Total charged", _money(total)),
        ("Status", "PAID")])


def register(r: Router) -> None:
    r.add("GET", "/billing", _billing_home)
    r.add("GET", "/billing/invoice", _invoice_detail)
    r.add("POST", "/billing/checkout", _checkout)
