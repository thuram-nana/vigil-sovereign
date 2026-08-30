"""Base chrome: home, robots, sitemap, health, lab-manifest, and the themed 404.

The home page LINKS every service entry point so VIGIL's crawler discovers the whole surface from the seed
URL; robots.txt + sitemap.xml add discovery hints (and a `Disallow:` the recon oracle treats as a seed).
"""

from __future__ import annotations

from .. import theme
from ..config import READY_MARKER
from ..router import Ctx, Response, Router

# The public service tiles shown on the home page (id, href, title, blurb).
_SERVICES = [
    ("apply", "/apply", "Apply for a permit",
     "Business, building, vehicle and professional licences. Upload supporting documents and pay the fee."),
    ("track", "/track", "Track an application",
     "Check the status of a submitted application by its reference number."),
    ("records", "/records", "Search public records",
     "Search the public register of issued permits and licences."),
    ("documents", "/documents", "Documents",
     "Download issued permits and import a supporting document by URL or XML."),
    ("assistant", "/assistant", "Ask PermitBot",
     "The MERIDIAN assistant answers questions about permits and application status."),
    ("signin", "/login", "Staff sign in",
     "Clerks, inspectors, registrars and administrators sign in to the back office."),
]


def _home(ctx: Ctx) -> Response:
    tiles = "".join(
        f'<a class="card" href="{href}" style="text-decoration:none">'
        f'<div class="card-h"><span class="label">Service</span><h3>{theme.esc(title)}</h3></div>'
        f'<p style="color:var(--text-1)">{theme.esc(blurb)}</p></a>'
        for _sid, href, title, blurb in _SERVICES
    )
    body = (
        '<main class="wrap">'
        '<div class="screen-head">'
        '<span class="label">Government of Meridia · fictional</span>'
        # READY_MARKER lives verbatim in this heading (the range-registry readiness check asserts it).
        f'<h1>{theme.esc(READY_MARKER)} &amp; Licensing Authority</h1>'
        '<p class="sub">Apply for, track and verify national permits and licences. '
        'This portal is a fictional target for authorized security testing of VIGIL.</p>'
        '</div>'
        f'<div class="grid cols-3">{tiles}</div>'
        '<footer class="foot" style="border:0;margin-top:var(--sp-6)">'
        'Open data: <a href="/robots.txt">robots.txt</a> · <a href="/sitemap.xml">sitemap.xml</a> · '
        '<a href="/openapi.json">API schema</a> · <a href="/lab-manifest.json">lab manifest</a>'
        '</footer>'
        '</main>'
    )
    return Response.html(theme.page("Home", body, active="home", mode=ctx.mode))


def _robots(_ctx: Ctx) -> Response:
    return Response.text(
        "User-agent: *\nDisallow: /admin\nDisallow: /staff\nSitemap: /sitemap.xml\n",
        content_type="text/plain; charset=utf-8",
    )


def _sitemap(_ctx: Ctx) -> Response:
    urls = ["/", "/apply", "/track", "/records", "/records/search", "/documents",
            "/assistant", "/login", "/api/applications"]
    locs = "".join(f"<url><loc>{u}</loc></url>" for u in urls)
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{locs}</urlset>'
    return Response.text(xml, content_type="application/xml; charset=utf-8")


def _healthz(_ctx: Ctx) -> Response:
    return Response.json({"status": "ok", "app": "meridian", "lab": True})


def _lab_manifest(ctx: Ctx) -> Response:
    return Response.json({
        "lab": True,
        "intentionally_vulnerable": True,
        "no_real_data": True,
        "loopback_only": True,
        "name": "MERIDIAN",
        "mode": ctx.mode,
        "authorization": "targets/meridian/charter.md",
        "warning": "INTENTIONALLY VULNERABLE — LAB ONLY.",
    })


def not_found(ctx: Ctx) -> Response:
    body = (
        '<main class="wrap"><div class="screen-head">'
        '<span class="label">404</span><h1>Page not found</h1>'
        f'<p class="sub">No resource at <code>{theme.esc(ctx.path)}</code>.</p>'
        '<p><a class="btn" href="/">Return home</a></p></div></main>'
    )
    return Response.html(theme.page("Not found", body, active="home", mode=ctx.mode), status=404)


def register(r: Router) -> None:
    r.add("GET", "/", _home)
    r.add("GET", "/robots.txt", _robots)
    r.add("GET", "/sitemap.xml", _sitemap)
    r.add("GET", "/healthz", _healthz)
    r.add("GET", "/lab-manifest.json", _lab_manifest)
