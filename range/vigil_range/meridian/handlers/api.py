"""The REST API — the BOLA/IDOR, CORS, and host-header surface.

/api/applications/<id> returns an application together with the owner's PII. In vuln mode there is NO
ownership check (any caller — even unauthenticated — reads any citizen's record: BOLA/IDOR), the CORS
response reflects a hostile Origin with credentials, and the share link is built from the attacker-controlled
Host header. Hardened mode enforces ownership/staff, a strict CORS allowlist, and a canonical host.
"""

from __future__ import annotations

from .. import auth, db
from ..router import Ctx, Response, Router

_CANONICAL_HOST = "meridian.gov.example"


def _cors(ctx: Ctx) -> dict[str, str]:
    origin = ctx.header("origin")
    if not origin:
        return {}
    if ctx.hardened:
        # strict allowlist: reflect ONLY a known same-origin, never a hostile one, never with credentials
        return {}
    # vuln: reflect ANY origin and allow credentials (the CORS-misconfig the oracle confirms)
    return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}


def _applications_list(ctx: Ctx) -> Response:
    # a `?id=<n>` query is an alias for the detail endpoint — the named-param form the engine's
    # access-control mode targets with `--ac-ref idor:id:<victim>`.
    if ctx.q1("id"):
        return _detail_by_id(ctx, ctx.q1("id"))
    con = db.from_ctx(ctx)
    try:
        rows = con.execute("SELECT id, ref, permit_type, status FROM applications ORDER BY id").fetchall()
    finally:
        con.close()
    data = [{"id": r["id"], "ref": r["ref"], "permit_type": r["permit_type"], "status": r["status"]} for r in rows]
    return Response.json({"applications": data}, headers=_cors(ctx))


def _application_detail(ctx: Ctx) -> Response:
    return _detail_by_id(ctx, ctx.params.get("id", ""))


def _detail_by_id(ctx: Ctx, raw_id: str) -> Response:
    cors = _cors(ctx)
    try:
        app_id = int(raw_id)
    except (TypeError, ValueError):
        return Response.json({"error": "not found"}, status=404, headers=cors)

    con = db.from_ctx(ctx)
    try:
        session = auth.session_from_cookies(con, ctx.header("cookie"))
        row = con.execute(
            "SELECT a.id, a.ref, a.citizen_id, a.permit_type, a.status, a.notes, a.fee_cents, "
            "c.name, c.email, c.national_id, c.phone "
            "FROM applications a JOIN citizens c ON c.id = a.citizen_id WHERE a.id = ?",
            (app_id,),
        ).fetchone()
    finally:
        con.close()

    if row is None:
        return Response.json({"error": "not found"}, status=404, headers=cors)

    if ctx.hardened:
        if session is None:
            return Response.json({"error": "authentication required"}, status=401, headers=cors)
        owns = session["kind"] == "citizen" and session["subject_id"] == row["citizen_id"]
        if not (owns or auth.is_staff(session["role"])):
            return Response.json({"error": "forbidden"}, status=403, headers=cors)

    # vuln mode: no authorization check → the owner's full PII is returned to any caller (BOLA/IDOR)
    data = {
        "id": row["id"], "ref": row["ref"], "permit_type": row["permit_type"], "status": row["status"],
        "notes": row["notes"], "fee_cents": row["fee_cents"],
        "applicant": {"name": row["name"], "email": row["email"],
                      "national_id": row["national_id"], "phone": row["phone"]},
    }
    return Response.json(data, headers=cors)


def _application_share(ctx: Ctx) -> Response:
    """A share link for an application. Vuln: the absolute URL is built from the (attacker-controlled) Host
    header (host-header injection → the link points wherever the attacker set Host). Hardened: canonical host."""
    ref = ctx.params.get("ref", "")
    host = ctx.header("host", _CANONICAL_HOST) if not ctx.hardened else _CANONICAL_HOST
    link = f"http://{host}/track?ref={ref}"
    return Response.json({"ref": ref, "share_url": link}, headers=_cors(ctx))


def _pay(ctx: Ctx) -> Response:
    """Pay an application's fee. Vuln: the client-supplied `amount` is trusted, so any value — including 0 or
    a negative — marks the application PAID (business-logic flaw). Hardened: the server charges the real fee
    and rejects an underpayment."""
    try:
        app_id = int(ctx.params["id"])
    except (KeyError, ValueError):
        return Response.json({"error": "not found"}, status=404, headers=_cors(ctx))
    try:
        amount = int(ctx.f1("amount", "0"))
    except ValueError:
        return Response.json({"error": "invalid amount"}, status=400, headers=_cors(ctx))

    con = db.from_ctx(ctx)
    try:
        row = con.execute("SELECT id, fee_cents FROM applications WHERE id = ?", (app_id,)).fetchone()
        if row is None:
            return Response.json({"error": "not found"}, status=404, headers=_cors(ctx))
        fee = row["fee_cents"]
        if ctx.hardened and amount < fee:
            return Response.json({"error": "underpayment", "fee_cents": fee, "amount_cents": amount},
                                 status=402, headers=_cors(ctx))
        charged = fee if ctx.hardened else amount  # hardened charges the real fee; vuln trusts the client
        con.execute("UPDATE applications SET paid = 1, amount_paid_cents = ? WHERE id = ?", (charged, app_id))
        con.commit()
    finally:
        con.close()
    return Response.json({"id": app_id, "paid": True, "amount_paid_cents": charged, "fee_cents": fee},
                         headers=_cors(ctx))


def _openapi(_ctx: Ctx) -> Response:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "MERIDIAN Permits API", "version": "1.0"},
        "paths": {
            "/api/applications": {"get": {"summary": "List applications"}},
            "/api/applications/{id}": {"get": {"summary": "Get an application (with applicant PII)"}},
            "/api/applications/{ref}/share": {"get": {"summary": "Build a share link"}},
        },
    }
    return Response.json(spec)


def register(r: Router) -> None:
    r.add("GET", "/api/applications", _applications_list)
    r.add("GET", "/api/applications/<id>", _application_detail)
    r.add("POST", "/api/applications/<id>/pay", _pay)
    r.add("GET", "/api/applications/<ref>/share", _application_share)
    r.add("GET", "/openapi.json", _openapi)
