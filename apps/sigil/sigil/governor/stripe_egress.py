"""The OUTBOUND Stripe API egress (owner-provisioned HTTPS), SHIPPED OFF BY DEFAULT.

The Stripe twin of ``governor.flutterwave_egress``: the outbound calls the Stripe adapter needs, built to be
INJECTED into ``StripeBillingProvider`` so ``billing.py`` stays pure (no network, offline-testable).

  * ``make_object_fetcher()`` -> ``fetch(kind, object_id)``: GET the authoritative Checkout Session / Invoice /
    Subscription named by a signed inbound event. The signer maps money from THIS object, never from the webhook
    body. A 404 is a hard refusal (not a no-op): a signed event naming an object our key cannot see means a key,
    account or test/live mismatch, which an operator must look at.
  * ``make_checkout_creator()`` -> ``create(params, *, idempotency_key)``: POST ``/v1/checkout/sessions`` with an
    ``Idempotency-Key`` header (a retried create can never open a second session). The params are built upstream
    from the OWNER CATALOG; this poster never edits money.

Every call reads the restricted API key from ``VIGIL_STRIPE_SECRET_KEY`` AT CALL TIME (never cached, never
persisted, never printed) and sends the API version from ``VIGIL_STRIPE_API_VERSION`` as ``Stripe-Version``. The
version is REQUIRED (no default): the owner pins the version the integration was tested against, so a dashboard
upgrade can never silently change the shape of the objects money is read from.

Same hardening as the Flutterwave egress: stdlib ``urllib`` only (FATAL-2 clean, no vendor SDK); an https-only +
exact-host allowlist guard before any socket opens (``config.STRIPE_EGRESS_ALLOWLIST``, no API-base override); a
redirect-BLOCKING opener so a 3xx can never relay the key; a bounded response read; request bodies form-encoded
(Stripe's wire format), never JSON. The key rides ONLY the ``Authorization`` header, so no URL, log line or
exception message (and so no quarantine ``.reason`` sidecar) can contain it. A transport fault or an HTTP
408/425/429/5xx raises a ``StripeEgressError`` marked ``transient`` (the drain may retry it); everything else is
definitive.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlencode, urlsplit

from ..reuse import assert_no_offense

assert_no_offense()

_API_BASE = "https://api.stripe.com"            # no override: the egress can only ever reach this host
_SECRET_ENV = "VIGIL_STRIPE_SECRET_KEY"
_VERSION_ENV = "VIGIL_STRIPE_API_VERSION"
# A Stripe API version: a date, optionally followed by a release name (e.g. "YYYY-MM-DD" or "YYYY-MM-DD.name").
_VERSION_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:\.[a-z]{1,32})?")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_DEFAULT_TIMEOUT_S = 15.0
_MAX_IDEMPOTENCY_KEY = 255
_FORM_KEY_RE = re.compile(r"[A-Za-z0-9_]{1,64}")

# kind -> (path prefix, the `object` value the response must carry, the anchored id shape). Only ASCII
# alphanumerics after the prefix, so `..`, `/`, `%`, whitespace and Unicode digits can never reach the path.
_OBJECTS: "Mapping[str, tuple[str, str, re.Pattern[str]]]" = {
    "checkout_session": ("/v1/checkout/sessions/", "checkout.session",
                         re.compile(r"cs_(?:test|live)_[A-Za-z0-9]{1,255}")),
    "invoice": ("/v1/invoices/", "invoice", re.compile(r"in_[A-Za-z0-9]{1,255}")),
    "subscription": ("/v1/subscriptions/", "subscription", re.compile(r"sub_[A-Za-z0-9]{1,255}")),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a 3xx: urllib would copy the ``Authorization`` header (the live API key) onto the redirect
    target, which the one-shot ``_guard`` never re-checks. Returning None makes the 3xx a non-2xx ``HTTPError``,
    i.e. a fail-closed ``StripeEgressError``."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _do_open(req, timeout):
    """The single outbound open point (a redirect-blocking opener); also the test seam the egress tests patch."""
    return _OPENER.open(req, timeout=timeout)   # noqa: S310 — https + host pinned by _guard; redirects blocked


class StripeEgressError(RuntimeError):
    """A fail-closed Stripe egress refusal. Its message never contains the key. ``transient`` is True only on an
    instance raised for a failure a later retry may cure (a transport fault, HTTP 408/425/429/5xx)."""

    transient: bool = False


_TRANSIENT_HTTP = frozenset({408, 425, 429})


def _transient(message: str) -> StripeEgressError:
    exc = StripeEgressError(message)
    exc.transient = True
    return exc


def _allowlist() -> frozenset:
    """The egress host allowlist, read from ``config`` at call time. Empty ⇒ every host refused."""
    from .. import config
    return frozenset(config.STRIPE_EGRESS_ALLOWLIST)


def _guard(url: str) -> None:
    """Refuse a non-https scheme, embedded userinfo, an explicit port, or an off-allowlist host BEFORE the stdlib
    call. Exact, case-insensitive host match."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise StripeEgressError(f"refusing a non-https Stripe egress (scheme {parts.scheme!r})")
    if "@" in (parts.netloc or ""):
        raise StripeEgressError("refusing a Stripe egress URL carrying userinfo")
    try:
        port = parts.port
    except ValueError:
        raise StripeEgressError("refusing a Stripe egress URL with a malformed port") from None
    if port not in (None, 443):
        raise StripeEgressError("refusing a Stripe egress URL with a non-default port")
    host = (parts.hostname or "").lower()
    if host not in _allowlist():
        raise StripeEgressError(f"refusing Stripe egress to non-allowlisted host {host!r}")


def encode_form(params: "Mapping[str, Any]") -> "list[tuple[str, str]]":
    """Flatten nested params into Stripe's bracket form keys (``metadata[price_id]``, ``line_items[0][quantity]``).
    Keys must be plain ``[A-Za-z0-9_]`` (a key can never smuggle a bracket or ``&``); values are str / int / bool
    (``true``/``false``). A float or any other type is refused: money is always integer minor units."""
    out: "list[tuple[str, str]]" = []

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, Mapping):
            for k, v in value.items():
                if not isinstance(k, str) or not _FORM_KEY_RE.fullmatch(k):
                    raise StripeEgressError("refusing a Stripe form key outside [A-Za-z0-9_]")
                walk(f"{prefix}[{k}]" if prefix else k, v)
        elif isinstance(value, (list, tuple)):
            if not prefix:
                raise StripeEgressError("refusing a top-level Stripe form list")
            for i, v in enumerate(value):
                walk(f"{prefix}[{i}]", v)
        elif isinstance(value, bool):
            out.append((prefix, "true" if value else "false"))
        elif isinstance(value, int):
            out.append((prefix, str(value)))
        elif isinstance(value, str):
            out.append((prefix, value))
        else:
            raise StripeEgressError(f"refusing a Stripe form value of type {type(value).__name__}")

    if not isinstance(params, Mapping):
        raise StripeEgressError("Stripe form params must be a mapping")
    walk("", params)
    return out


def _api_version() -> str:
    version = (os.environ.get(_VERSION_ENV) or "").strip()
    if not _VERSION_RE.fullmatch(version):
        raise StripeEgressError(f"{_VERSION_ENV} is unset or malformed — pin the Stripe API version the "
                                "integration was tested against (fail-closed)")
    return version


def _request(method: str, url: str, *, secret: str, form: "Optional[Mapping[str, Any]]" = None,
             idempotency_key: Optional[str] = None, timeout: float = _DEFAULT_TIMEOUT_S) -> Any:
    """The ONE stdlib outbound call. Guard first, then a request carrying the key in ``Authorization`` only, the
    pinned ``Stripe-Version``, a form-encoded body for a POST and an ``Idempotency-Key`` when given. Bounded read
    + JSON parse; every failure is a ``StripeEgressError`` whose message carries no key."""
    _guard(url)
    headers = {"Authorization": f"Bearer {secret}", "Accept": "application/json", "Stripe-Version": _api_version()}
    data = None
    if form is not None:
        data = urlencode(encode_form(form)).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _do_open(req, timeout) as r:
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
    except StripeEgressError:
        raise
    except urllib.error.HTTPError as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        msg = f"Stripe {method} returned HTTP {code}"
        if code in _TRANSIENT_HTTP or 500 <= code <= 599:
            raise _transient(msg) from None
        raise StripeEgressError(msg) from None
    except Exception as exc:  # noqa: BLE001 — timeout / TLS / reset / DNS → transient, fail-closed
        raise _transient(f"Stripe {method} transport failure ({type(exc).__name__})") from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise StripeEgressError("Stripe response exceeded the response-size cap")
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise StripeEgressError(f"Stripe response was not valid JSON ({type(exc).__name__})") from None


def stripe_secret_configured() -> bool:
    """True iff ``VIGIL_STRIPE_SECRET_KEY`` is set: the DEFAULT-OFF gate (unset ⇒ nothing is wired). A presence
    check only; the value is read afresh at each call."""
    return bool((os.environ.get(_SECRET_ENV) or "").strip())


def stripe_key_mode() -> Optional[str]:
    """``"live"`` / ``"test"`` from the configured key's prefix (secret ``sk_`` or restricted ``rk_``), or None
    when unset or unrecognised. Never returns or logs any part of the key itself."""
    key = (os.environ.get(_SECRET_ENV) or "").strip()
    for mode in ("live", "test"):
        if key.startswith((f"sk_{mode}_", f"rk_{mode}_")):
            return mode
    return None


def _require_secret() -> str:
    secret = (os.environ.get(_SECRET_ENV) or "").strip()
    if not secret:
        raise StripeEgressError(f"{_SECRET_ENV} is not set — refusing a Stripe egress (fail-closed)")
    return secret


ObjectFetcher = Callable[[str, str], Mapping[str, Any]]


def make_object_fetcher(*, transport=None) -> ObjectFetcher:
    """Build ``fetch(kind, object_id)``: ``kind`` is one of ``checkout_session`` / ``invoice`` / ``subscription``;
    the id must match that kind's anchored shape and is percent-encoded into one path segment. Returns the
    object, which must carry the expected ``object`` type and the requested ``id``. Any refusal raises (a 404, a
    4xx, a type or id mismatch: definitive; a transport fault or 408/425/429/5xx: transient). It never returns
    None: an event whose object cannot be read is never treated as a no-op."""
    send = transport or _request

    def fetch(kind: str, object_id: str) -> "Mapping[str, Any]":
        spec = _OBJECTS.get(kind) if isinstance(kind, str) else None
        if spec is None:
            raise StripeEgressError(f"refusing a Stripe fetch of an unsupported object kind {kind!r}")
        prefix, expected_type, shape = spec
        if not isinstance(object_id, str) or not shape.fullmatch(object_id):
            raise StripeEgressError(f"refusing a Stripe {kind} fetch for a malformed id")
        secret = _require_secret()
        obj = send("GET", f"{_API_BASE}{prefix}{quote(object_id, safe='')}", secret=secret)
        if not isinstance(obj, Mapping) or obj.get("object") != expected_type or obj.get("id") != object_id:
            raise StripeEgressError(f"Stripe {kind} fetch returned an unexpected object")
        return obj

    return fetch


def make_checkout_creator(*, transport=None):
    """Build ``create(params, *, idempotency_key)``: POST ``/v1/checkout/sessions`` form-encoded, with the
    ``Idempotency-Key`` header (required, printable ASCII, at most 255 chars). Returns the parsed session object
    for the adapter's link check (``billing._https_link_on`` with the ``checkout.stripe.com`` exact pin)."""
    send = transport or _request

    def create(params: "Mapping[str, Any]", *, idempotency_key: str) -> "Mapping[str, Any]":
        if (not isinstance(idempotency_key, str) or not idempotency_key
                or len(idempotency_key) > _MAX_IDEMPOTENCY_KEY
                or any(not (0x21 <= ord(c) <= 0x7e) for c in idempotency_key)):
            raise StripeEgressError("refusing a Stripe checkout create without a valid Idempotency-Key")
        secret = _require_secret()
        resp = send("POST", f"{_API_BASE}/v1/checkout/sessions", secret=secret, form=params,
                    idempotency_key=idempotency_key)
        if not isinstance(resp, Mapping) or resp.get("object") != "checkout.session":
            raise StripeEgressError("Stripe checkout create returned an unexpected object")
        return resp

    return create
