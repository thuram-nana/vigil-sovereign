"""The OUTBOUND delivery egress for the customer DevSecOps INTEGRATIONS layer (Slack / Jira / Linear).

The generalised twin of ``governor.github_app_egress``: one hardened, stdlib-only outbound POST that the
``governor.customer_integrations`` adapters use to reach a provider API. It does NOT invent a new SSRF decision —
the ONE sovereign outbound gate is reused: every URL is admitted by :func:`notify_channels.guard_outbound_url`
(https-only, no embedded userinfo, default port, host on the OWNER-reviewed allowlist AND resolving ENTIRELY to
PUBLIC addresses — the loopback / RFC-1918 / link-local / cloud-metadata ``169.254.169.254`` / CGNAT / reserved
refusal) BEFORE any socket opens. A tenant supplies a Slack channel / Jira cloud id / Linear team id, never a
destination host it could steer at an internal target.

Same hardening as the Stripe / GitHub egresses on top of that gate:

  * a redirect-BLOCKING opener, so a 3xx can never relay the ``Authorization`` credential onto a target the
    one-shot guard never re-checked;
  * a bounded response read + JSON parse;
  * the per-provider credential rides ONLY the request header (the ``auth`` arg), so NO url, log line or exception
    message can contain it — and the request BODY never carries it either (the money-safe / no-plaintext-leak rule);
  * a transport fault or an HTTP 408/425/429/5xx raises an :class:`IntegrationEgressError` marked ``transient``
    (a drain may retry it); everything else is definitive.

``transport`` is an injectable ``(method, url, *, headers, body) -> IntegrationResponse`` for offline tests (a FAKE
provider, no network); it still passes through the reused guard, so the pin/allowlist/SSRF check is exercised.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); stdlib ``urllib`` + sovereign siblings
(``notify_channels`` for the guard) only. Never imports engine/crucible or ``strix``; no vendor SDK.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import notify_channels as _nc  # noqa: E402  (the ONE sovereign outbound SSRF/allowlist gate + resolver type)

_USER_AGENT = "VIGIL-Integrations"               # a generic, non-identifying client name (never a person/org)
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024
_DEFAULT_TIMEOUT_S = 15.0
_TRANSIENT_HTTP = frozenset({408, 425, 429})


class IntegrationEgressError(RuntimeError):
    """A fail-closed integration-egress refusal. Its message NEVER contains the delivery credential. ``transient``
    is True only for a failure a later retry may cure (a transport fault, HTTP 408/425/429/5xx). ``status`` is the
    HTTP code when one was received (0 otherwise)."""

    transient: bool = False
    status: int = 0


def _err(message: str, *, transient: bool = False, status: int = 0) -> IntegrationEgressError:
    exc = IntegrationEgressError(message)
    exc.transient = transient
    exc.status = status
    return exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a 3xx: urllib would copy the ``Authorization`` header (the live credential) onto the redirect
    target, which the one-shot guard never re-checked. Returning None makes the 3xx a fail-closed ``HTTPError``."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _do_open(req, timeout):
    """The single outbound open point (a redirect-blocking opener); https + host pinned by the guard that ran
    first. Also a seam the egress tests may patch."""
    return _OPENER.open(req, timeout=timeout)   # noqa: S310 — https + host pinned by guard_outbound_url; redirects blocked


@dataclass(frozen=True)
class IntegrationResponse:
    """The outcome of ONE delivery POST. ``status`` is the HTTP code; ``json`` the parsed body (``None`` when the
    body was empty or not JSON — a Slack webhook answers with the literal ``ok``); ``host`` the guard-validated
    host. Carries NO credential and no raw tenant content beyond what the provider echoes."""

    status: int
    json: Optional[Any]
    host: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def post_json(url: str, *, body: "Mapping[str, Any]", auth: "Optional[tuple[str, str]]",
              allow_hosts: "frozenset[str]", allow_suffixes: "frozenset[str]" = frozenset(),
              resolver=None, timeout: float = _DEFAULT_TIMEOUT_S,
              transport=None) -> IntegrationResponse:
    """POST ``body`` as JSON to ``url`` with the credential in the ``auth`` header ONLY, returning an
    :class:`IntegrationResponse`. The ONE sovereign SSRF/allowlist gate (:func:`notify_channels.guard_outbound_url`)
    admits the URL first (https + no userinfo + default port + ``allow_hosts``/``allow_suffixes`` + every resolved
    address PUBLIC) — so this never bypasses the egress gate. ``auth`` is ``(header_name, header_value)`` or ``None``
    (a Slack incoming-webhook authenticates by the URL path, not a header). Fail-closed: a guard refusal, a bad
    status, an oversize or non-JSON body each raise an :class:`IntegrationEgressError` whose message carries no
    credential."""
    # THE egress gate (reused, never bypassed): refuses a non-allowlisted / non-public / malformed target first.
    try:
        host = _nc.guard_outbound_url(url, allow_hosts=allow_hosts, allow_suffixes=allow_suffixes, resolver=resolver)
    except _nc.OutboundRefused as exc:
        raise _err(f"integration egress refused: {exc}", transient=getattr(exc, "transient", False)) from None
    headers: dict[str, str] = {"User-Agent": _USER_AGENT, "Content-Type": "application/json",
                               "Accept": "application/json"}
    if auth is not None:
        name, value = auth
        if not isinstance(name, str) or not name or not isinstance(value, str) or not value:
            raise _err("refusing a delivery with a malformed auth header")
        if any(c in name for c in "\r\n") or any(c in value for c in "\r\n"):
            raise _err("refusing a delivery whose credential header carries CR/LF (injection guard)")
        headers[name] = value
    data = json.dumps(dict(body), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if transport is not None:
        # The test seam: a FAKE provider still passed through the guard above (pin/allowlist/SSRF exercised),
        # then the injected transport answers with an IntegrationResponse (or raises IntegrationEgressError).
        res = transport("POST", url, headers=dict(headers), body=data)
        if not isinstance(res, IntegrationResponse):
            raise _err("injected integration transport returned a non-IntegrationResponse")
        return res
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with _do_open(req, timeout) as r:
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
            status = int(getattr(r, "status", 0) or 0)
    except IntegrationEgressError:
        raise
    except urllib.error.HTTPError as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        raise _err(f"integration POST returned HTTP {code}",
                   transient=(code in _TRANSIENT_HTTP or 500 <= code <= 599), status=code) from None
    except Exception as exc:  # noqa: BLE001 — timeout / TLS / reset / DNS → transient, fail-closed, credential-free
        raise _err(f"integration POST transport failure ({type(exc).__name__})", transient=True) from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise _err("integration response exceeded the response-size cap")
    parsed: Optional[Any] = None
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None                           # a non-JSON body (Slack webhook's "ok") — status is the signal
    return IntegrationResponse(status=status, json=parsed, host=host)
