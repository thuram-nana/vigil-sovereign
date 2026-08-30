"""Document download — the path-traversal surface (S1). SSRF fetch + XXE import are added in S3.

A traversal attempt (`../`, `%2e`, `/etc/`, `passwd`) returns a DECOY passwd string, so the traversal
signature fires for both the offensive and the detection oracle while NO real file is ever read. Hardened
mode refuses the escape with a 404.
"""

from __future__ import annotations

from .. import theme
from ..router import Ctx, Response, Router

# Returned on a traversal attempt — a fake /etc/passwd. It contains the `root:x:0:0:` signature the engine's
# side-effect oracle keys on, but leaks nothing real.
_DECOY_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "meridian:x:1000:1000:MERIDIA National Permits (LAB decoy):/home/meridian:/bin/false\n"
)

# The only genuinely-servable public documents (by logical name).
_PUBLIC_DOCS = {
    "readme": "MERIDIAN document service — public readme. This is a lab.\n",
    "permit-guide": "How to apply for a permit: submit at /apply, pay the fee, track at /track.\n",
}


def _documents_home(ctx: Ctx) -> Response:
    links = "".join(f'<li><a href="/documents/download?file={name}">{theme.esc(name)}</a></li>'
                    for name in _PUBLIC_DOCS)
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Documents</span>'
        '<h1>Document service</h1>'
        '<p class="sub">Download public guidance documents.</p></div>'
        f'<div class="card"><ul>{links}</ul>'
        '<form method="get" action="/documents/download" style="margin-top:var(--sp-4)">'
        '<label class="field"><span>Document name</span>'
        '<input name="file" placeholder="readme"></label>'
        '<button class="btn" type="submit">Download</button></form></div></main>'
    )
    return Response.html(theme.page("Documents", body, active="documents", mode=ctx.mode))


def _download(ctx: Ctx) -> Response:
    path = ctx.q1("file")
    low = path.lower()
    if ".." in low or "%2e" in low or low.startswith("/etc/") or "passwd" in low:
        if ctx.hardened:
            return Response.text("no such file", status=404)      # hardened: refuse the escape, leak nothing
        return Response.text(_DECOY_PASSWD, content_type="text/plain; charset=utf-8")  # decoy: proves traversal
    doc = _PUBLIC_DOCS.get(path.strip("/"))
    if doc is None:
        return Response.text("no such file", status=404)
    return Response.text(doc, content_type="text/plain; charset=utf-8")


def register(r: Router) -> None:
    r.add("GET", "/documents", _documents_home)
    r.add("GET", "/documents/download", _download)
