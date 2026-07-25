"""
api.guard — the loopback + same-origin request guards, shared with the console posture.

The external API mirrors the Ops Console's on-host security model exactly (see
``console.server``): it binds LOOPBACK ONLY, and it accepts a state-changing POST only
when the request PROVES it is same-origin to the loopback API. The loopback-host
classifier is REUSED from ``console.server`` (one definition of "is this loopback"),
and the same-origin check is the console's guard, lifted into a free function so both
surfaces enforce it identically.

Why POSITIVE proof (a custom header a cross-site HTML ``<form>`` cannot set) rather than
mere absence of a cross-site signal: a cross-site form POST can omit BOTH ``Origin`` and
``Sec-Fetch-Site`` (Safari <16.4, in-app WebViews); a deny-by-absence guard would let it
through. Requiring a custom header forces a CORS preflight the API never answers, so a
cross-site page physically cannot drive an action. The ``Host`` check (mandatory, exact
loopback + exact port) then defeats a DNS-rebinding domain even if it forged the header.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# reuse the console's single definition of "is this a genuine loopback host".
from ..console.server import _is_loopback_host

# The custom request header the same-origin client sets and a cross-site HTML form cannot.
CSRF_HEADER = "X-Requested-With"

# loopback hosts the API is willing to BIND (the console uses the same set).
LOOPBACK_BIND_HOSTS = ("127.0.0.1", "localhost", "::1")


def check_same_origin(headers, server_port: int,
                      allowed_hosts=(), allowed_origins=()) -> tuple[bool, str]:
    """Return ``(ok, reason)``. ``ok`` is True only when the request proves same-origin
    to the loopback API on ``server_port`` — OR its Host/Origin is an exact operator-
    configured reverse-proxy domain in ``allowed_hosts``/``allowed_origins`` (both empty
    by default → loopback-only, byte-identical to before). The custom-header +
    Sec-Fetch-Site proofs still apply regardless. ``headers`` is a mapping with a
    case-insensitive ``.get`` (an ``http.client.HTTPMessage`` / dict). Fail-closed: any
    malformed/missing signal denies. Read-only GET is not routed here."""
    _allow_hosts = frozenset(h.strip() for h in allowed_hosts if h and h.strip())
    _allow_origins = frozenset(o.strip().rstrip("/") for o in allowed_origins if o and o.strip())
    # 1. POSITIVE proof: a custom header a cross-site <form> cannot set.
    if not headers.get(CSRF_HEADER):
        return False, f"missing {CSRF_HEADER} (cross-site form / non-API client)"

    # 2. fetch metadata: a cross-site / same-site Sec-Fetch-Site is refused (a modern
    #    browser stamps this on every cross-origin request).
    sfs = (headers.get("Sec-Fetch-Site", "") or "").strip().lower()
    if sfs and sfs not in ("same-origin", "none"):
        return False, f"Sec-Fetch-Site={sfs}"

    def _port_ok(parsed, scheme_default: int) -> bool:
        try:
            p = parsed.port
        except ValueError:
            return False
        return (p if p is not None else scheme_default) == server_port

    def _authority_ok(value: str, scheme_default: int) -> bool:
        try:
            u = urlsplit("//" + value if "//" not in value else value)
            return _is_loopback_host(u.hostname or "") and _port_ok(u, scheme_default)
        except ValueError:
            return False

    # 3. Host is mandatory (HTTP/1.1 always carries it) + strict (loopback + exact port):
    #    this refuses a DNS-rebinding domain even if it forged the custom header.
    host_hdr = (headers.get("Host", "") or "").strip()
    if not host_hdr:
        return False, "Host missing"
    if not (_authority_ok(host_hdr, 80) or host_hdr in _allow_hosts):
        return False, f"Host={host_hdr!r}"

    # 4. Origin, when present, must likewise be the loopback API with the exact port, OR an
    #    exact operator-allowlisted reverse-proxy origin.
    origin = (headers.get("Origin", "") or "").strip()
    if origin:
        scheme_default = 443 if origin.lower().startswith("https:") else 80
        if not (_authority_ok(origin, scheme_default) or origin.rstrip("/") in _allow_origins):
            return False, f"Origin={origin}"
    return True, ""
