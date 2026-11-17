"""The OUTBOUND GitHub App API egress (customer-facing Red-Pen App), SHIPPED OFF BY DEFAULT.

The GitHub twin of ``governor.stripe_egress``: the single hardened outbound call ``governor.github_app`` needs to
reach ``api.github.com`` — the App-JWT -> installation-token exchange, the installation's repository list, and the
check-run write (all SOVEREIGN-side per Red-Pen decision O-5). Built so ``github_app`` stays pure (the JWT math and
the credential reads live there; this module only moves bytes over a pinned socket), offline-testable by injecting a
transport.

Same hardening as the Stripe / Flutterwave egresses: stdlib ``urllib`` only (FATAL-2 clean, no vendor SDK); an
https-only + exact-host allowlist guard before any socket opens (``config.GITHUB_APP_EGRESS_ALLOWLIST``, no
API-base override); a redirect-BLOCKING opener so a 3xx can never relay the bearer credential; a bounded response
read; a JSON request body (GitHub's wire format). The bearer (the short-lived App JWT or installation token) rides
ONLY the ``Authorization`` header, so no URL, log line or exception message can contain it. A transport fault or an
HTTP 408/425/429/5xx raises a ``GitHubEgressError`` marked ``transient`` (a drain may retry it); everything else is
definitive. The App PRIVATE key never reaches this module — only a short-lived bearer it signed does.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from ..reuse import assert_no_offense

assert_no_offense()

_API_BASE = "https://api.github.com"            # no override: the egress can only ever reach this host
_API_VERSION = "2022-11-28"                      # the pinned GitHub REST API version (X-GitHub-Api-Version)
_ACCEPT = "application/vnd.github+json"
_USER_AGENT = "VIGIL-RedPen"                     # a generic, non-identifying client name (never a person/org)
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_DEFAULT_TIMEOUT_S = 15.0
_TRANSIENT_HTTP = frozenset({408, 425, 429})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a 3xx: urllib would copy the ``Authorization`` header (the live bearer) onto the redirect
    target, which the one-shot ``_guard`` never re-checks. Returning None makes the 3xx a non-2xx ``HTTPError``,
    i.e. a fail-closed ``GitHubEgressError``."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _do_open(req, timeout):
    """The single outbound open point (a redirect-blocking opener); also the test seam the egress tests patch to
    stand in a FAKE GitHub with NO network."""
    return _OPENER.open(req, timeout=timeout)   # noqa: S310 — https + host pinned by _guard; redirects blocked


class GitHubEgressError(RuntimeError):
    """A fail-closed GitHub egress refusal. Its message never contains the bearer. ``transient`` is True only on an
    instance raised for a failure a later retry may cure (a transport fault, HTTP 408/425/429/5xx). ``status`` is
    the HTTP code when one was received (0 otherwise), so a caller can distinguish a 404 (a missing object / a
    wrong installation) from a 401 (a bad or expired bearer) without parsing the message."""

    transient: bool = False
    status: int = 0


def _err(message: str, *, transient: bool = False, status: int = 0) -> GitHubEgressError:
    exc = GitHubEgressError(message)
    exc.transient = transient
    exc.status = status
    return exc


def _allowlist() -> frozenset:
    """The egress host allowlist, read from ``config`` at call time. Empty ⇒ every host refused."""
    from .. import config
    return frozenset(config.GITHUB_APP_EGRESS_ALLOWLIST)


def _guard(url: str) -> None:
    """Refuse a non-https scheme, embedded userinfo, an explicit port, or an off-allowlist host BEFORE the stdlib
    call. Exact, case-insensitive host match (mirrors ``stripe_egress._guard``)."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise _err(f"refusing a non-https GitHub egress (scheme {parts.scheme!r})")
    if "@" in (parts.netloc or ""):
        raise _err("refusing a GitHub egress URL carrying userinfo")
    try:
        port = parts.port
    except ValueError:
        raise _err("refusing a GitHub egress URL with a malformed port") from None
    if port not in (None, 443):
        raise _err("refusing a GitHub egress URL with a non-default port")
    host = (parts.hostname or "").lower()
    if host not in _allowlist():
        raise _err(f"refusing GitHub egress to non-allowlisted host {host!r}")


def api_url(path: str) -> str:
    """``https://api.github.com`` + an absolute ``path`` the caller has already built from validated components.
    The path must start with ``/`` and carry no scheme/host/userinfo/``..`` (the caller builds it from a validated
    repo ref / numeric installation id, so this is a defence-in-depth shape check, not the only one)."""
    p = str(path or "")
    if not p.startswith("/") or "://" in p or ".." in p or any(c.isspace() for c in p):
        raise _err("refusing a malformed GitHub API path")
    return _API_BASE + p


def request(method: str, path: str, *, bearer: str, scheme: str = "Bearer",
            json_body: "Optional[Mapping[str, Any]]" = None, timeout: float = _DEFAULT_TIMEOUT_S,
            transport=None) -> Any:
    """The ONE stdlib outbound call. Guard first, then a request carrying the bearer in ``Authorization`` only
    (``scheme`` is ``Bearer`` for an App JWT or an installation token; GitHub accepts ``token`` too), the pinned
    ``Accept`` + ``X-GitHub-Api-Version``, a JSON body for a write, and a bounded read + JSON parse. Every failure
    is a ``GitHubEgressError`` whose message carries no bearer. ``transport`` is an injectable ``(method, url, *,
    headers, body) -> parsed`` for offline tests (a FAKE GitHub); unset ⇒ the real pinned urllib call."""
    if not isinstance(bearer, str) or not bearer:
        raise _err("refusing a GitHub egress without a bearer credential")
    if scheme not in ("Bearer", "token"):
        raise _err("GitHub Authorization scheme must be 'Bearer' or 'token'")
    url = api_url(path)
    _guard(url)                                    # https + exact-host pin BEFORE any socket (or the fake transport)
    headers = {"Authorization": f"{scheme} {bearer}", "Accept": _ACCEPT,
               "X-GitHub-Api-Version": _API_VERSION, "User-Agent": _USER_AGENT}
    body = None
    if json_body is not None:
        body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if transport is not None:
        # The test seam: a FAKE GitHub still goes through the guard above (so the pin/allowlist is exercised),
        # then the injected transport answers with a parsed object (or raises GitHubEgressError).
        return transport(method, url, headers=headers, body=body)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _do_open(req, timeout) as r:
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
    except GitHubEgressError:
        raise
    except urllib.error.HTTPError as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        msg = f"GitHub {method} returned HTTP {code}"
        if code in _TRANSIENT_HTTP or 500 <= code <= 599:
            raise _err(msg, transient=True, status=code) from None
        raise _err(msg, status=code) from None
    except Exception as exc:  # noqa: BLE001 — timeout / TLS / reset / DNS → transient, fail-closed
        raise _err(f"GitHub {method} transport failure ({type(exc).__name__})", transient=True) from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise _err("GitHub response exceeded the response-size cap")
    if not raw:
        return {}                                   # a 204 (no content) — e.g. some check-run updates
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _err(f"GitHub response was not valid JSON ({type(exc).__name__})") from None
