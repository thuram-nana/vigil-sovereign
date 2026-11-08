"""Slice A1 — the OUTBOUND Flutterwave v3 egress (owner-provisioned HTTPS), SHIPPED OFF BY DEFAULT.

This is the sovereign, offense-free I/O boundary the deterministic billing signer refuses to be: the two
outbound calls Flutterwave's API needs, built to be INJECTED into ``FlutterwaveBillingProvider`` so
``billing.py`` itself stays pure (no network, offline-testable). Both read the provider SECRET KEY from the
environment AT CALL TIME (``VIGIL_FLW_SECRET_KEY``) — never captured in a closure default, never persisted,
never printed — and mirror ``ui/oidc.py``'s gated egress exactly: stdlib ``urllib`` only (FATAL-2 clean — no
``framework`` / ``strix``, no vendor SDK), an https-ONLY + host-ALLOWLIST guard that runs BEFORE the socket
opens, and a bounded response read.

  * ``make_checkout_creator()`` -> ``CheckoutCreator``: POST the provider-built ``/v3/payments`` body (whose
    amount is the OWNER CATALOG's, set upstream — this poster NEVER edits money) and return the hosted-link
    response for ``billing._flw_checkout_link`` to sanitize.
  * ``make_transaction_verifier()`` -> ``TransactionVerifier``: GET ``/v3/transactions/{id}/verify`` and return
    the AUTHORITATIVE verified transaction object (the response's ``data``), or None on a definitive non-success
    lookup (the signer then mints nothing).

DEFAULT-OFF + FAIL-CLOSED: with ``VIGIL_FLW_SECRET_KEY`` unset the cli hooks wire NEITHER callable, so
``create_checkout`` keeps raising ``UnsupportedCapability`` and ``billing-drain`` keeps refusing — byte-identical
to before this slice (no egress, no new surface). A TRANSIENT transport failure RAISES (so the inbound drain
QUARANTINES + retries, per the verifier contract); a DEFINITIVE non-success lookup returns None (a no-op the
signer mints nothing on). The provider secret rides ONLY the ``Authorization: Bearer`` header — never the URL,
never a log, never an exception message — so a quarantine ``.reason`` sidecar cannot leak it.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Mapping, Optional
from urllib.parse import quote, urlsplit

from ..reuse import assert_no_offense

assert_no_offense()

# The Flutterwave v3 API host the egress is pinned to (the allowlist in ``config`` enforces it before any socket
# opens). Overridable ONLY for a sandbox via ``VIGIL_FLW_API_BASE``, which must STILL be https on an allowlisted
# host — a steered base cannot turn this into an SSRF proxy (the ``_guard`` re-checks the final URL every call).
_DEFAULT_API_BASE = "https://api.flutterwave.com"
_SECRET_ENV = "VIGIL_FLW_SECRET_KEY"

# A verify / create response is a few KiB; cap the read so a compromised / MITM'd provider cannot stream an
# unbounded body into the sovereign process (mirrors ``oidc._read_capped``).
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_DEFAULT_TIMEOUT_S = 15.0
_MAX_TXID_LEN = 32


class FlutterwaveEgressError(RuntimeError):
    """A fail-closed outbound-egress refusal (a non-https / off-allowlist URL, a transport failure, a malformed
    transaction id, an oversize or non-JSON response). Its message NEVER contains the secret (the secret rides
    only the ``Authorization`` header, never the URL or a message), so a quarantine ``.reason`` sidecar or a
    dropped-to-type refusal cannot leak it."""


def _api_base() -> str:
    base = (os.environ.get("VIGIL_FLW_API_BASE") or _DEFAULT_API_BASE).strip()
    return base[:-1] if base.endswith("/") else base


def _allowlist() -> frozenset:
    """The egress host allowlist, read from ``config`` AT CALL TIME (so an override is honoured and a test can
    monkeypatch it). Empty ⇒ fail-closed (every host refused)."""
    from .. import config
    return frozenset(config.FLUTTERWAVE_EGRESS_ALLOWLIST)


def _guard(url: str) -> None:
    """Refuse a non-https scheme, embedded userinfo, or an off-allowlist host BEFORE the real stdlib call — the
    SSRF / egress pin. Exact, case-insensitive host match. Mirrors ``oidc.host_allowlisted_transport``'s guard."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise FlutterwaveEgressError(f"refusing a non-https Flutterwave egress (scheme {parts.scheme!r})")
    if "@" in (parts.netloc or ""):
        raise FlutterwaveEgressError("refusing a Flutterwave egress URL carrying userinfo")
    host = (parts.hostname or "").lower()
    if host not in _allowlist():
        raise FlutterwaveEgressError(f"refusing Flutterwave egress to non-allowlisted host {host!r}")


def _request_json(method: str, url: str, *, secret: str, json_body: "Optional[Mapping[str, Any]]" = None,
                  timeout: float = _DEFAULT_TIMEOUT_S) -> Any:
    """The ONE stdlib outbound call (POST create / GET verify). The https + host-allowlist ``_guard`` runs FIRST,
    then a urllib request carrying ``Authorization: Bearer <secret>`` (the secret rides the header ONLY — never
    the URL, never a log). Bounded read + JSON parse. Any transport / scheme / size / parse failure is a
    fail-closed ``FlutterwaveEgressError`` whose message carries NO secret (only the method + an HTTP status or
    an exception TYPE name)."""
    _guard(url)
    headers = {"Authorization": f"Bearer {secret}", "Accept": "application/json"}
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — scheme + host guarded above
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
    except FlutterwaveEgressError:
        raise
    except urllib.error.HTTPError as exc:                        # a non-2xx — transient from our side, fail-closed
        raise FlutterwaveEgressError(f"Flutterwave {method} returned HTTP {exc.code}") from None
    except Exception as exc:  # noqa: BLE001 — timeout / TLS / connection-reset / DNS → transient, fail-closed
        raise FlutterwaveEgressError(f"Flutterwave {method} transport failure ({type(exc).__name__})") from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise FlutterwaveEgressError("Flutterwave response exceeded the response-size cap")
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise FlutterwaveEgressError(f"Flutterwave response was not valid JSON ({type(exc).__name__})") from None


def flutterwave_secret_configured() -> bool:
    """True iff the provider SECRET KEY is present in the environment — the DEFAULT-OFF gate the cli billing
    hooks consult: unset ⇒ NEITHER outbound callable is wired (checkout refuses, the drain refuses). A presence
    check ONLY; the VALUE is read afresh at each call, never cached here."""
    return bool((os.environ.get(_SECRET_ENV) or "").strip())


def _require_secret() -> str:
    secret = (os.environ.get(_SECRET_ENV) or "").strip()
    if not secret:
        raise FlutterwaveEgressError(f"{_SECRET_ENV} is not set — refusing a Flutterwave egress (fail-closed)")
    return secret


def make_checkout_creator(*, transport=None):
    """Build the ``CheckoutCreator`` injected at ``FlutterwaveBillingProvider(checkout_creator=…)``. The returned
    callable reads ``VIGIL_FLW_SECRET_KEY`` AT CALL TIME, POSTs the provider-built ``/v3/payments`` body (whose
    amount is the OWNER CATALOG's — this poster never edits money) and returns the parsed hosted-link response
    for ``billing._flw_checkout_link`` to sanitize. ``transport`` is an injectable ``(method, url, *, secret,
    json_body=…, timeout=…) -> Any`` so tests never touch the network."""
    send = transport or _request_json

    def create_checkout(payload: "Mapping[str, Any]") -> "Optional[Mapping[str, Any]]":
        secret = _require_secret()                              # read AT CALL TIME; drops out of scope after
        return send("POST", f"{_api_base()}/v3/payments", secret=secret, json_body=payload)

    return create_checkout


def make_transaction_verifier(*, transport=None):
    """Build the ``TransactionVerifier`` the billing drain injects. The returned callable reads
    ``VIGIL_FLW_SECRET_KEY`` AT CALL TIME and GETs ``/v3/transactions/{id}/verify``, returning the AUTHORITATIVE
    verified transaction object (the response ``data``) on a success envelope, or None on a definitive
    non-success lookup (the signer then mints nothing). A TRANSIENT transport failure RAISES (so the drain
    QUARANTINES + retries, per the verifier contract). ``txid`` is validated numeric and percent-encoded into a
    single path segment, so a hostile webhook ``id`` can never traverse the path or re-aim the egress.
    ``transport`` is injectable so tests never touch the network."""
    send = transport or _request_json

    def verify_transaction(txid: str) -> "Optional[Mapping[str, Any]]":
        tx = str(txid).strip()
        if not tx.isdigit() or len(tx) > _MAX_TXID_LEN:        # Flutterwave tx ids are positive integers
            raise FlutterwaveEgressError("refusing a Flutterwave verify for a non-numeric / oversize "
                                         "transaction id")
        secret = _require_secret()                              # read AT CALL TIME; drops out of scope after
        url = f"{_api_base()}/v3/transactions/{quote(tx, safe='')}/verify"
        resp = send("GET", url, secret=secret)
        if not isinstance(resp, Mapping) or resp.get("status") != "success":
            return None                                         # definitive non-success lookup -> mint nothing
        data = resp.get("data")
        return data if isinstance(data, Mapping) else None

    return verify_transaction
