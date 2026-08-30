"""Document download — the path-traversal surface (S1). SSRF fetch + XXE import are added in S3.

A traversal attempt (`../`, `%2e`, `/etc/`, `passwd`) returns a DECOY passwd string, so the traversal
signature fires for both the offensive and the detection oracle while NO real file is ever read. Hardened
mode refuses the escape with a 404.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

from .. import theme
from ..router import Ctx, Response, Router

# Hardened mode only lets the document-fetch reach this allowlisted host (everything else — including any
# private/loopback address, which is where an SSRF/OOB callback lives — is refused).
_ALLOWED_FETCH_HOST = "docs.meridian.gov.example"
_FETCH_TIMEOUT = 3.0
_FETCH_CAP = 4096
# A SYSTEM external-entity declaration in an imported XML doc (the XXE vector).
_SYSTEM_ENTITY_RE = re.compile(r"""<!ENTITY\s+\w+\s+SYSTEM\s+["']([^"']+)["']""", re.IGNORECASE)

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
        '<button class="btn" type="submit">Download</button></form></div>'
        '<div class="card" style="margin-top:var(--sp-4)"><div class="card-h">'
        '<span class="label">Import</span><h3>Fetch a supporting document by URL</h3></div>'
        '<form method="get" action="/documents/fetch">'
        '<label class="field"><span>Document URL</span>'
        '<input name="url" placeholder="https://docs.meridian.gov.example/form.pdf"></label>'
        '<button class="btn" type="submit">Fetch</button></form>'
        '<p style="color:var(--text-2);margin-top:var(--sp-3)">You can also POST an XML manifest to '
        '<code>/documents/import</code>.</p></div></main>'
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


def _http_get(url: str) -> tuple[bool, str]:
    """Server-side fetch of an http(s) URL (bounded). Returns (ok, detail). file://, gopher:// etc. are
    refused even in vuln mode, so this is an SSRF surface but never a local-file-read (LFI) one."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"unsupported scheme: {parsed.scheme or '(none)'}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MERIDIAN-doc-fetch/1.0"})
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as r:  # noqa: S310 — intentional SSRF sink
            body = r.read(_FETCH_CAP)
        return True, f"fetched {len(body)} bytes (status {r.status}) from {url}"
    except urllib.error.HTTPError as e:
        return True, f"fetched (status {e.code}) from {url}"  # the request still egressed (OOB fired)
    except Exception as e:  # noqa: BLE001 — a target must not crash on a bad fetch
        return False, f"fetch error: {type(e).__name__}"


def _fetch(ctx: Ctx) -> Response:
    """SSRF: the server fetches an arbitrary user-supplied URL. When the engine injects its loopback OOB
    callback URL here, the outbound request lands on the receiver and the OOB oracle fires. Hardened mode
    only permits the allowlisted document host."""
    url = ctx.q1("url")
    if not url:
        return Response.text("provide a ?url=", status=400)
    if ctx.hardened:
        host = urllib.parse.urlsplit(url).hostname or ""
        if host != _ALLOWED_FETCH_HOST:
            return Response.text(f"refused: only {_ALLOWED_FETCH_HOST} may be fetched", status=400)
    ok, detail = _http_get(url)
    return Response.text(detail, status=200 if ok else 502)


def _import_xml(ctx: Ctx) -> Response:
    """XXE: an imported XML document's external SYSTEM entity is resolved (fetched). Hardened mode never
    resolves external entities. The observable effect — an outbound request to the entity's SYSTEM URL — is
    exactly the OOB signal the engine's oracle confirms."""
    xml_text = ctx.body.decode("utf-8", "replace")
    matches = _SYSTEM_ENTITY_RE.findall(xml_text)
    if ctx.hardened:
        # external entities are disabled: parse structurally, resolve NOTHING
        return Response.json({"imported": True, "external_entities_resolved": 0, "hardened": True})
    resolved = []
    for system_url in matches:
        ok, _ = _http_get(system_url)  # a vulnerable parser fetches the external entity
        resolved.append({"system": system_url, "fetched": ok})
    return Response.json({"imported": True, "external_entities_resolved": len(resolved), "entities": resolved})


def register(r: Router) -> None:
    r.add("GET", "/documents", _documents_home)
    r.add("GET", "/documents/download", _download)
    r.add("GET", "/documents/fetch", _fetch)
    r.add("POST", "/documents/import", _import_xml)
