"""Enterprise SaaS BILLING — the payment-provider boundary: EVIDENCE (a verified webhook) → owner-signed FACT.

This is the billing analog of VIGIL's soundness doctrine. A payment-provider webhook is UNTRUSTED input; only
its provider SIGNATURE makes it EVIDENCE, and only the sovereign plane converts that evidence into an
owner-signed grant on the spine (the wallet / subscription / plan-credit ledgers). The LLM never grants and no
agent-asserted field decides money: the mapping from a verified event to a sovereign mint is DETERMINISTIC and
driven by an owner-controlled price→entitlement CATALOG.

  * `BillingProvider` (ABC) + `BillingEvent` (normalised) — a swappable, CAPABILITY-DECLARING provider interface
    (each adapter declares the operations it supports, so an unsupported flow raises `UnsupportedCapability`
    rather than silently simulating success). `FlutterwaveBillingProvider` is the PRIMARY production adapter
    (Flutterwave v3: `verif-hash` constant-time compare + MANDATORY server-side transaction re-verify before any
    mint; card + Francophone Mobile Money; Payment-Plan recurring). `StripeBillingProvider` is an optional
    REFERENCE adapter, DISABLED BY DEFAULT (prohibited in production unless explicitly enabled), kept only to
    prove the interface is genuinely swappable. `MockBillingProvider` is the deterministic sandbox for tests.
    All adapters satisfy one contract: verify → return a normalised `BillingEvent`, or None (mint nothing).
  * `BillingSigner.ingest(raw_body, sig_header, now)` — the crux. It (1) VERIFIES the provider signature and
    REJECTS (mints nothing) on any failure — a forged/tampered/stale webhook cannot credit; (2) maps the verified
    event through the injected catalog into exactly one sovereign mint; (3) is IDEMPOTENT by the provider
    `event_id` (wallet/plan `entry_id == event_id`; the subscription uses the event's own timestamp as issued_at
    so a replay is stale under the per-org high-water), so a provider's at-least-once duplicate delivery — or a
    replayed capture — is inert.

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, `assert_no_offense()` at import; the signer holds the owner key
(it mints), the providers do not (they only verify signatures). org_id == tenant_id is validated by the
registries this composes. The public HTTP endpoint that RECEIVES the webhook and the live provider keys are
owner-provisioned infra; this module is the verify→mint core they call, callable and fully testable offline.

DEFERRED (owner / later slices, documented not half-wired): the real price→entitlement catalog numbers (Slice 7);
the HTTP front door + live keys (owner infra); provider APIs beyond webhook ingestion (checkout/portal creation)
— added to the provider interface when the signup/portal flows (Slice 5/7) need them.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .metering import refill_active_subscription  # noqa: E402  (period-idempotent subscription->plan refill)
from .orgs import org_tenant_id  # noqa: E402  (org_id == tenant-id validation; fail-closed)

# Normalised event kinds the signer knows how to mint. A provider adapter maps its native event types onto these;
# an unmapped/irrelevant provider event parses to None (ignored, never minted).
EVENT_TOPUP = "topup_purchased"              # a one-off credit purchase  -> wallet `topup` grant
EVENT_SUBSCRIPTION_ACTIVE = "subscription_active"   # new/renewed paid period -> subscribe + plan refill
EVENT_SUBSCRIPTION_CANCELED = "subscription_canceled"  # ended -> subscription.cancel (safe direction)
EVENT_PAYMENT_FAILED = "payment_failed"      # dunning -> subscription.mark_past_due (safe direction)
_EVENT_KINDS = frozenset({EVENT_TOPUP, EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED,
                          EVENT_PAYMENT_FAILED})

# Default Stripe signature tolerance: reject an event whose timestamp is more than this many seconds from `now`
# (replay-window bound, matching Stripe's documented default).
_DEFAULT_TOLERANCE_S = 300.0

# Provider CAPABILITIES — each adapter DECLARES what it supports, so an unsupported operation is an explicit
# error (`UnsupportedCapability`), never a silent no-op or a simulated success. Outbound flows call
# `provider.require(cap)` before an operation; `UNATTENDED_TOPUP` in particular is approval-gated at the provider
# (Flutterwave NOAUTH, Stripe off-session) and must stay false until the merchant account is approved.
CAP_VERIFY_WEBHOOK = "verify_webhook"            # inbound webhook verify + parse (every real provider)
CAP_VERIFY_TRANSACTION = "verify_transaction"    # server-side re-verify of a transaction before granting value
CAP_HOSTED_CHECKOUT = "hosted_checkout"          # create a hosted payment/checkout URL
CAP_ONE_TIME_CARD = "one_time_card"              # one-off card payment
CAP_MOBILE_MONEY = "mobile_money"                # mobile money (e.g. Francophone MoMo — Cameroon XAF)
CAP_RECURRING_PLAN = "recurring_plan"            # provider-scheduled recurring subscription (auto-renew)
CAP_UNATTENDED_TOPUP = "unattended_topup"        # unattended subsequent charge (NOAUTH / off-session) — approval-gated
CAP_REFUND = "refund"                            # refund a transaction
CAP_RECONCILE = "reconcile"                      # list transactions/settlements / resend missed webhooks


class UnsupportedCapability(RuntimeError):
    """Raised when a billing operation is requested of a provider that does not DECLARE the capability. Surfaced
    explicitly (never a silent simulation) so an unsupported flow fails loudly rather than appearing to succeed."""


@dataclass(frozen=True)
class BillingEvent:
    """A provider-verified billing event, normalised. `event_id` is the provider's globally-unique id — the
    idempotency anchor the signer carries into the sovereign mint so an at-least-once duplicate is inert.
    `price_id` keys the owner's catalog (price → entitlement); the signer never trusts an amount/credit count
    off the wire, only the catalog's mapping of the price the provider says was paid."""
    event_id: str
    kind: str
    org_id: str
    created: float                 # the provider's event timestamp (used as the deterministic issued_at)
    price_id: str = ""             # the paid price/plan id (catalog key); "" when not applicable
    amount_minor: int = 0          # the VERIFIED paid amount in minor units (Slice F cross-check); 0 if unknown
    currency: str = ""             # ISO-4217 of the verified amount; "" when the provider did not populate one
    data: Mapping[str, Any] = field(default_factory=dict)   # extra normalised fields (verbatim, untrusted detail)


class BillingProvider(ABC):
    """A swappable payment provider. The ONLY trust operation is `verify_and_parse`: authenticate the raw webhook
    bytes against the provider's signature and return a normalised `BillingEvent`, or None if the signature does
    not verify OR the event is not one we mint on. No method here ever touches the owner key."""

    @abstractmethod
    def verify_and_parse(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[BillingEvent]:
        ...

    def capabilities(self) -> frozenset[str]:
        """The operations this adapter supports. Default: inbound webhook verification only; adapters override to
        declare the outbound/provider operations they can actually perform."""
        return frozenset({CAP_VERIFY_WEBHOOK})

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities()

    def require(self, capability: str) -> None:
        """Assert a capability before an operation — raises `UnsupportedCapability` if the adapter does not
        declare it (so an unsupported operation is explicit, never silently simulated)."""
        if capability not in self.capabilities():
            raise UnsupportedCapability(f"{type(self).__name__} does not support capability {capability!r}")


def _ct_equal(a: str, b: str) -> bool:
    """Constant-time string compare (never short-circuit on the first differing byte — no timing oracle on the
    signature). Fail-CLOSED (False) on a non-ASCII / non-str operand: `hmac.compare_digest` raises TypeError on
    non-ASCII `str`, so a crafted header must reject cleanly, never raise a 500."""
    try:
        return hmac.compare_digest(a, b)
    except TypeError:
        return False


def _parse_org_id(obj: object) -> Optional[str]:
    """Pull the tenant org_id out of a provider event's metadata, fail-closed. The provider carries it in the
    checkout/subscription `metadata.org_id` (set when the checkout session is created). Returns a VALIDATED
    tenant id or None (an event with no/invalid org_id is ignored, never minted against a guessed tenant)."""
    if not isinstance(obj, str) or not obj:
        return None
    try:
        return org_tenant_id(obj)
    except ValueError:
        return None


class StripeBillingProvider(BillingProvider):
    """Stripe webhook verification in the stdlib — no `stripe` SDK, no network. Implements the documented
    `Stripe-Signature` scheme: header `t=<unix>,v1=<hex hmac>`; signed payload is `"{t}.{raw_body}"`; the MAC is
    HMAC-SHA256 under the endpoint's `whsec_` secret; compared constant-time; and `|now - t|` must be within the
    tolerance window (replay bound). Maps Stripe event `type`s onto the normalised kinds via the injected
    price→entitlement catalog's knowledge of which price is a plan vs a top-up (the signer owns that mapping; the
    provider only needs org_id + price_id + type)."""

    def __init__(self, signing_secret: str, *, tolerance_s: float = _DEFAULT_TOLERANCE_S,
                 enable_reference_adapter: bool = False):
        # Stripe is an OPTIONAL REFERENCE adapter: DISABLED BY DEFAULT and prohibited in production unless
        # EXPLICITLY enabled (Flutterwave is the primary production provider). Enable only with an explicit
        # opt-in — the `enable_reference_adapter=True` flag (contract/parity tests) or env
        # VIGIL_BILLING_ENABLE_STRIPE in {1,true,yes}. This keeps the second adapter available to prove the
        # interface is swappable without letting it serve production by accident.
        if not enable_reference_adapter and \
                os.environ.get("VIGIL_BILLING_ENABLE_STRIPE", "").strip().lower() not in ("1", "true", "yes"):
            raise UnsupportedCapability(
                "StripeBillingProvider is a disabled-by-default reference adapter; Flutterwave is the primary "
                "provider. Enable explicitly with enable_reference_adapter=True or VIGIL_BILLING_ENABLE_STRIPE=1.")
        if not isinstance(signing_secret, str) or not signing_secret:
            raise ValueError("Stripe signing secret (whsec_...) is required")
        self._secret = signing_secret.encode("utf-8")
        self._tolerance = float(tolerance_s)

    def capabilities(self) -> frozenset[str]:
        # NOTE: no CAP_UNATTENDED_TOPUP — off-session recurring is approval-gated at the provider, so the reference
        # adapter does not DECLARE it unconditionally (declaring it would let an outbound flow `require()` it and
        # believe unattended charging is available when it has not been approved).
        return frozenset({CAP_VERIFY_WEBHOOK, CAP_VERIFY_TRANSACTION, CAP_HOSTED_CHECKOUT, CAP_ONE_TIME_CARD,
                          CAP_RECURRING_PLAN, CAP_REFUND, CAP_RECONCILE})

    def _verify_signature(self, raw_body: bytes, sig_header: str, now: float) -> bool:
        if not isinstance(sig_header, str) or not sig_header:
            return False
        ts: Optional[str] = None
        v1s: list[str] = []
        for part in sig_header.split(","):
            k, _, v = part.strip().partition("=")
            if k == "t":
                ts = v
            elif k == "v1":
                v1s.append(v)
        if ts is None or not v1s:
            return False
        try:
            t = float(ts)
        except (TypeError, ValueError):
            return False
        if abs(now - t) > self._tolerance:           # replay-window bound (stale or future-dated -> reject)
            return False
        signed = ts.encode("ascii") + b"." + raw_body
        expected = hmac.new(self._secret, signed, hashlib.sha256).hexdigest()
        return any(_ct_equal(expected, v1) for v1 in v1s)   # any valid v1 (Stripe may send several on rotation)

    def verify_and_parse(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[BillingEvent]:
        if not isinstance(raw_body, (bytes, bytearray)):
            return None
        raw_body = bytes(raw_body)
        if not self._verify_signature(raw_body, sig_header, now):
            return None                              # fail-CLOSED: unverified -> no event, no mint
        try:
            obj = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        return _map_stripe_event(obj)


def _as_float(v: object, default: float = 0.0) -> float:
    import math
    try:
        f = float(v)                                  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default
    return f if math.isfinite(f) else default


def _map_stripe_event(obj: Mapping[str, Any]) -> Optional[BillingEvent]:
    """Map a verified Stripe event object onto a normalised BillingEvent, or None for an event type we do not mint
    on. Pure + deterministic (no owner key, no catalog): it only normalises shape; the signer does the money
    mapping via the catalog."""
    etype = obj.get("type")
    event_id = obj.get("id")
    if not isinstance(etype, str) or not isinstance(event_id, str) or not event_id:
        return None
    created = _as_float(obj.get("created"))
    data_obj = obj.get("data")
    sub = data_obj.get("object") if isinstance(data_obj, dict) else None
    sub = sub if isinstance(sub, dict) else {}
    meta_raw = sub.get("metadata")
    meta = meta_raw if isinstance(meta_raw, dict) else {}
    org_id = _parse_org_id(meta.get("org_id"))
    if org_id is None:
        return None                                   # no validated tenant -> ignore (never mint on a guess)
    price_id = _stripe_price_id(sub)
    kind = {
        "checkout.session.completed": EVENT_TOPUP,            # a one-off purchase (top-up); plan checkouts use
        #                                                        customer.subscription.* below
        "invoice.paid": EVENT_SUBSCRIPTION_ACTIVE,            # a paid (renewal) invoice -> active period
        "customer.subscription.deleted": EVENT_SUBSCRIPTION_CANCELED,
        "invoice.payment_failed": EVENT_PAYMENT_FAILED,
    }.get(etype)
    if kind is None:
        return None
    # A top-up checkout is distinguished from a subscription checkout by mode; a subscription-mode checkout is
    # handled by the invoice.paid event, so a checkout.session in subscription mode is ignored here.
    if kind == EVENT_TOPUP and sub.get("mode") == "subscription":
        return None
    # Only a NEW-PERIOD invoice advances the plan period: an invoice.paid with billing_reason subscription_create
    # or subscription_cycle. A MID-CYCLE invoice (subscription_update / proration / a manual or one-off invoice)
    # must NOT re-grant a full period — it would mint a second allotment for an overlapping window — so it is
    # ignored here (the period it belongs to was already funded by its cycle invoice).
    if kind == EVENT_SUBSCRIPTION_ACTIVE:
        reason = sub.get("billing_reason")
        if reason not in ("subscription_create", "subscription_cycle"):
            return None
    return BillingEvent(event_id=event_id, kind=kind, org_id=org_id, created=created, price_id=price_id,
                        data={"raw_type": etype})


def _stripe_price_id(sub: Mapping[str, Any]) -> str:
    """Best-effort pull of the price id from a Stripe object (checkout line item or subscription item). Returns
    "" when absent — the signer then treats the event as having no catalog entry (minted only if the catalog has
    a default, else ignored)."""
    # subscription object: items.data[0].price.id ; checkout: not expanded by default -> metadata.price_id
    items = sub.get("items")
    if isinstance(items, dict):
        data = items.get("data")
        if isinstance(data, list) and data and isinstance(data[0], dict):
            price = data[0].get("price")
            if isinstance(price, dict) and isinstance(price.get("id"), str):
                return price["id"]
    meta_raw = sub.get("metadata")
    meta = meta_raw if isinstance(meta_raw, dict) else {}
    pid = meta.get("price_id")
    return pid if isinstance(pid, str) else ""


class MockBillingProvider(BillingProvider):
    """Deterministic sandbox provider for tests + local dev. Signature = hex HMAC-SHA256 of the raw body under a
    shared secret (no timestamp/tolerance — the sandbox is not replay-bounded; replay-safety is proven at the
    signer/ledger layer). The event JSON is already in normalised shape: {event_id, kind, org_id, created,
    price_id?, data?}."""

    def __init__(self, secret: str = "mock-secret"):
        self._secret = secret.encode("utf-8")

    def capabilities(self) -> frozenset[str]:
        return frozenset({CAP_VERIFY_WEBHOOK, CAP_VERIFY_TRANSACTION, CAP_HOSTED_CHECKOUT, CAP_ONE_TIME_CARD,
                          CAP_MOBILE_MONEY, CAP_RECURRING_PLAN, CAP_UNATTENDED_TOPUP, CAP_REFUND, CAP_RECONCILE})

    def sign(self, raw_body: bytes) -> str:
        return hmac.new(self._secret, bytes(raw_body), hashlib.sha256).hexdigest()

    def verify_and_parse(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[BillingEvent]:
        if not isinstance(raw_body, (bytes, bytearray)):
            return None
        raw_body = bytes(raw_body)
        if not isinstance(sig_header, str) or not _ct_equal(self.sign(raw_body), sig_header):
            return None                               # fail-closed
        try:
            obj = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        kind, event_id = obj.get("kind"), obj.get("event_id")
        if kind not in _EVENT_KINDS or not isinstance(event_id, str) or not event_id:
            return None
        org_id = _parse_org_id(obj.get("org_id"))
        if org_id is None:
            return None
        data_raw = obj.get("data")
        return BillingEvent(event_id=event_id, kind=str(kind), org_id=org_id,
                            created=_as_float(obj.get("created")),
                            price_id=str(obj.get("price_id") or ""),
                            data=data_raw if isinstance(data_raw, dict) else {})


# A server-side transaction re-verifier: given a Flutterwave transaction id, return the authoritative
# `/v3/transactions/{id}/verify` `data` object (or None). The HTTP call is owner-provisioned infra; it is
# INJECTED so this module stays offline-testable and the deterministic signer never performs I/O.
TransactionVerifier = Callable[[str], Optional[Mapping[str, Any]]]

# A hosted-checkout creator (Slice F): given the Flutterwave /v3/payments request body (which WE build), perform
# the owner-provisioned outbound HTTPS POST and return the parsed JSON response (or None). INJECTED so this module
# stays offline-testable and performs NO I/O itself — the exact sibling of TransactionVerifier on the inbound side.
CheckoutCreator = Callable[[Mapping[str, Any]], Optional[Mapping[str, Any]]]

# ISO-4217 minor-unit exponents that are NOT 2, to convert between the catalog's minor units and the major-unit
# number a provider `amount` field carries. Everything unlisted is 2 decimals (USD, EUR, NGN, GBP, …).
_ZERO_DECIMAL_CCY = frozenset({"BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX",
                               "VND", "VUV", "XAF", "XOF", "XPF"})
_THREE_DECIMAL_CCY = frozenset({"BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"})


def _ccy_decimals(ccy: str) -> int:
    c = (ccy or "").strip().upper()
    if c in _ZERO_DECIMAL_CCY:
        return 0
    if c in _THREE_DECIMAL_CCY:
        return 3
    return 2


def _to_major(amount_minor: int, ccy: str):
    """Minor units -> the major-unit number a provider `amount` field carries (an int for a 0-decimal currency)."""
    d = _ccy_decimals(ccy)
    return int(amount_minor) if d == 0 else int(amount_minor) / (10 ** d)


def _flw_amount_minor(verified: Mapping[str, Any]) -> "tuple[int, str]":
    """`(amount_minor, currency)` from a Flutterwave VERIFIED object, fail-closed to `(0, ccy_or_"")`. The verified
    `amount` is in MAJOR units; converted to minor via the ISO exponent so it compares against the owner catalog's
    `amount_minor`. A non-finite / unparseable amount yields 0 (which the signer's cross-check refuses when an
    expected price exists for the price_id)."""
    ccy = verified.get("currency")
    ccy = ccy.strip().upper() if isinstance(ccy, str) else ""
    amt = verified.get("amount")
    if amt is None or not ccy:
        return 0, ccy
    try:
        f = float(amt)
        if not math.isfinite(f):
            return 0, ccy
        return int(round(f * (10 ** _ccy_decimals(ccy)))), ccy
    except (TypeError, ValueError):
        return 0, ccy


def _flw_checkout_link(resp: object) -> Optional[str]:
    """The hosted-checkout URL from a Flutterwave /v3/payments response, fail-closed. Success shape:
    `{"status":"success","data":{"link":"https://checkout.flutterwave.com/..."}}`. ONLY an https link is accepted;
    a missing / non-https / `data:` / `javascript:` link is refused (never hand the browser a hostile URL)."""
    if not isinstance(resp, Mapping) or resp.get("status") != "success":
        return None
    data = resp.get("data")
    link = data.get("link") if isinstance(data, Mapping) else None
    return link if isinstance(link, str) and link.startswith("https://") else None


@dataclass(frozen=True)
class CheckoutSession:
    """A created hosted-checkout session (Slice F). `tx_ref` (= `vigil:<org>:<nonce>`) binds the tenant into the ONE
    field Flutterwave echoes on the webhook + verify, so the inbound mint recovers the SAME tenant and can never be
    re-aimed at another org. `amount_minor`/`currency`/`price_id` are the OWNER-CATALOG values this checkout will
    collect — never caller-supplied."""
    tx_ref: str
    hosted_link: str
    org_id: str
    price_id: str
    amount_minor: int
    currency: str


# tx_ref convention: we set it when creating a checkout/charge so the tenant is recoverable from the one field
# Flutterwave guarantees to echo everywhere. Format: "vigil:<org_id>:<nonce>" (org_id has no ':').
_TX_REF_PREFIX = "vigil"


def _org_from_tx_ref(tx_ref: object) -> Optional[str]:
    if not isinstance(tx_ref, str):
        return None
    parts = tx_ref.split(":")
    if len(parts) >= 3 and parts[0] == _TX_REF_PREFIX:
        return _parse_org_id(parts[1])
    return None


def _flw_org_id(data: Mapping[str, Any]) -> Optional[str]:
    """Recover the validated tenant org_id from a Flutterwave transaction/subscription object, fail-closed.
    Prefer `tx_ref` (the one field Flutterwave guarantees to echo on webhook + verify), then `meta.org_id`, then
    a flat `meta_1`. Each candidate is validated via org_tenant_id — an object with no recoverable tenant yields
    None and is never minted against a guess."""
    org = _org_from_tx_ref(data.get("tx_ref"))
    if org is not None:
        return org
    meta = data.get("meta")
    if isinstance(meta, dict):
        org = _parse_org_id(meta.get("org_id"))
        if org is not None:
            return org
    if isinstance(meta, list):                      # Flutterwave sometimes returns meta as a list of {metaname,metavalue}
        for row in meta:
            if isinstance(row, dict) and row.get("metaname") == "org_id":
                org = _parse_org_id(row.get("metavalue"))
                if org is not None:
                    return org
    return _parse_org_id(data.get("meta_1"))


def _flw_price_id(data: Mapping[str, Any]) -> str:
    """The catalog price id for a one-time charge — carried in `meta.price_id` / `meta_1`-style fields (we set it
    at checkout). "" when absent (the signer then finds no catalog entry and mints nothing)."""
    meta = data.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("price_id"), str):
        return meta["price_id"]
    if isinstance(meta, list):
        for row in meta:
            if isinstance(row, dict) and row.get("metaname") == "price_id" and isinstance(row.get("metavalue"), str):
                return row["metavalue"]
    pid = data.get("meta_price_id")
    return pid if isinstance(pid, str) else ""


def _flw_created(data: Mapping[str, Any]) -> Optional[float]:
    """Parse a Flutterwave transaction's creation time to a STABLE epoch float, fail-closed (None) when it cannot
    be parsed. Flutterwave returns `created_at` on the verify object as an ISO-8601 string
    (e.g. "2024-01-02T03:04:05.000Z"); some shapes carry a numeric epoch. The signer uses this as the
    deterministic issued_at / subscription-period anchor, so it MUST be stable across at-least-once duplicate
    deliveries. A wall-clock `now` fallback would make a replay advance the period (orphaning tranches, even
    resurrecting a lapsed sub), so there is NO `now` fallback here: an unparseable/absent/non-positive timestamp
    yields None and mints nothing."""
    raw = data.get("created_at")
    if isinstance(raw, bool):                           # bool is an int subclass — never a timestamp
        return None
    if isinstance(raw, (int, float)):
        return raw if math.isfinite(raw) and raw > 0 else None
    if isinstance(raw, str) and raw.strip():
        s = raw.strip()
        try:                                            # a numeric epoch rendered as a string (rare but seen)
            f = float(s)
            return f if math.isfinite(f) and f > 0 else None
        except ValueError:
            pass
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s   # accept a trailing 'Z' as UTC (defensive on <3.11)
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            return None
        if dt.tzinfo is None:                           # a naive stamp -> assume UTC so the epoch is deterministic
            dt = dt.replace(tzinfo=timezone.utc)
        ts = dt.timestamp()
        return ts if math.isfinite(ts) and ts > 0 else None
    return None


class FlutterwaveBillingProvider(BillingProvider):
    """Flutterwave v3 webhook verification — the PRIMARY production adapter.

    v3 authenticates a webhook by sending the configured Secret Hash verbatim in the `verif-hash` header
    (PLAINTEXT equality, NOT an HMAC over the body, no timestamp / replay bound). That header alone is a WEAK
    authenticator, so this adapter (1) constant-time-compares `verif-hash` to the stored secret hash, then
    (2) RE-VERIFIES the transaction server-side against `/v3/transactions/{id}/verify` (the injected `verifier`)
    and only trusts the AUTHORITATIVE verified object — a webhook whose transaction does not independently verify
    as `status == "successful"` mints nothing. This matches Flutterwave's own documented guidance ("verify before
    giving value") and makes a forged/replayed/mismatched webhook inert.

    EVERYTHING that decides money or a tenant — org_id, plan-vs-topup, the event timestamp, the status — is read
    from the AUTHORITATIVE verified object ONLY, NEVER from the webhook body (the body is trusted solely for the
    transaction id to go re-verify). org_id is recovered from the verified object's tx_ref (which we set), then
    meta, validated fail-closed. The event timestamp is parsed to a STABLE epoch; an unparseable one mints nothing
    (a wall-clock fallback would let a replay advance a subscription period). Idempotency rides the Flutterwave
    transaction `id` (stable across at-least-once duplicate deliveries), which the signer carries as the ledger
    entry_id. The verifier does the only I/O; everything here is pure.

    SCOPE (this slice): we mint ONLY on a re-verified successful `charge.completed` (top-up or plan period). We do
    NOT act on `subscription.cancelled` / failed-charge webhooks — the body cannot name the victim tenant soundly
    and the verify endpoint is per-transaction, not per-subscription, so there is no authoritative
    subscription→org mapping yet. A lapsed/cancelled plan EXPIRES at period_end via the meter's active-subscription
    check (non-rollover) — the safe, body-independent outcome. Webhook-driven cancel/dunning returns in the
    outbound-surfaces slice once an authoritative subscription→org mapping exists.

    NOTE (sandbox-confirm): exact field shapes (meta echo as dict vs list, `payment_plan` presence on a plan
    charge, `created_at` string format) should be confirmed against a Flutterwave sandbox; this handles the
    documented shapes and fails closed on anything it cannot validate. Mobile Money / card / checkout creation
    and refunds are declared capabilities exercised by the outbound flows (next slice)."""

    def __init__(self, secret_hash: str, verifier: TransactionVerifier, *, noauth_approved: bool = False,
                 checkout_creator: "Optional[CheckoutCreator]" = None):
        if not isinstance(secret_hash, str) or not secret_hash:
            raise ValueError("Flutterwave webhook secret hash is required")
        if not callable(verifier):
            raise ValueError("a server-side transaction verifier is required — Flutterwave's verif-hash header "
                             "alone is too weak to grant value; inject a /transactions/{id}/verify caller")
        self._secret_hash = secret_hash
        self._verifier = verifier
        self._noauth_approved = bool(noauth_approved)
        # Slice F: the outbound hosted-checkout poster (owner-provisioned HTTPS). None ⇒ create_checkout refuses
        # (never silently simulates a checkout). Injected so this module does no I/O and stays offline-testable.
        self._checkout_creator = checkout_creator

    def capabilities(self) -> frozenset[str]:
        caps = {CAP_VERIFY_WEBHOOK, CAP_VERIFY_TRANSACTION, CAP_HOSTED_CHECKOUT, CAP_ONE_TIME_CARD,
                CAP_MOBILE_MONEY, CAP_RECURRING_PLAN, CAP_REFUND, CAP_RECONCILE}
        if self._noauth_approved:
            caps.add(CAP_UNATTENDED_TOPUP)          # NOAUTH unattended recurring — only once Flutterwave approves
        return frozenset(caps)

    def verify_and_parse(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[BillingEvent]:
        if not isinstance(raw_body, (bytes, bytearray)):
            return None
        raw_body = bytes(raw_body)
        if not isinstance(sig_header, str) or not _ct_equal(self._secret_hash, sig_header):
            return None                               # verif-hash mismatch/absent -> reject (fail-closed)
        try:
            obj = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        return self._reverify_and_map(obj)

    def _reverify_and_map(self, obj: Mapping[str, Any]) -> Optional[BillingEvent]:
        # Flutterwave's `verif-hash` authenticates ONLY the caller (plaintext secret equality); it does NOT sign
        # the body, so NOTHING in `obj` is trustworthy here beyond "which transaction id to go re-verify". Every
        # field that decides money or a tenant (org_id, plan-vs-topup, timestamp, status) is taken from the
        # AUTHORITATIVE `/v3/transactions/{id}/verify` object only. We therefore mint solely on a `charge.completed`
        # whose transaction INDEPENDENTLY re-verifies as successful.
        #
        # We deliberately do NOT act on `subscription.cancelled` / failed-charge webhooks (no webhook-driven cancel
        # or dunning): the body cannot name the victim tenant soundly, and the verify endpoint is per-TRANSACTION,
        # not per-subscription, so there is no authoritative subscription→org mapping yet (that lands in the
        # outbound-surfaces slice). Until then a lapsed/cancelled plan simply EXPIRES at period_end via the meter's
        # active-subscription check (non-rollover) — the safe, body-independent outcome.
        if obj.get("event") != "charge.completed":
            return None
        data_raw = obj.get("data")
        txid = data_raw.get("id") if isinstance(data_raw, dict) else None
        if txid is None:
            return None                               # the body is trusted ONLY for the transaction id to verify
        verified = self._verifier(str(txid))          # AUTHORITATIVE server-side re-verify — the ONLY trust source
        if not isinstance(verified, dict) or verified.get("status") != "successful":
            return None                               # unverifiable / not successful -> mint nothing
        vid = verified.get("id")                      # the idempotency anchor is the CANONICAL verified id, NEVER
        if vid is None:                               # the body's spelling: two body spellings of one real tx that
            return None                               # /verify maps to the same id must collapse to ONE grant (the
        event_id = str(vid)                           # body is trusted ONLY to name which tx to fetch); fail-closed.
        org = _flw_org_id(verified)                   # tenant from the VERIFIED object only (never the body)
        if org is None:
            return None                               # successful but no recoverable tenant -> never mint on a guess
        created = _flw_created(verified)              # stable epoch from the VERIFIED object; fail-closed if absent
        if created is None:
            return None                               # replay-safety needs a stable timestamp -> no `now` fallback
        tx_ref = verified.get("tx_ref")
        amt_minor, ccy = _flw_amount_minor(verified)  # Slice F: the VERIFIED amount for the signer's price cross-check
        if verified.get("payment_plan"):              # plan-vs-topup decided by the VERIFIED object only
            return BillingEvent(event_id=event_id, kind=EVENT_SUBSCRIPTION_ACTIVE, org_id=org, created=created,
                                price_id=str(verified.get("payment_plan") or ""), amount_minor=amt_minor,
                                currency=ccy, data={"tx_ref": tx_ref})
        return BillingEvent(event_id=event_id, kind=EVENT_TOPUP, org_id=org, created=created,
                            price_id=_flw_price_id(verified), amount_minor=amt_minor, currency=ccy,
                            data={"tx_ref": tx_ref})

    def create_checkout(self, org_id: str, price_id: str, *, expected: Mapping[str, Any],
                        customer_email: "Optional[str]" = None, redirect_url: "Optional[str]" = None,
                        nonce: "Optional[str]" = None) -> CheckoutSession:
        """Create a tenant-bound hosted checkout for `price_id` (Slice F — the outbound money-in surface).

        MONEY DOCTRINE, enforced here: the amount + currency are taken from the OWNER CATALOG (`expected[price_id]`,
        i.e. `catalog.expected_amounts()`), NEVER from the caller — a customer can name neither a price nor an
        amount, and an unknown price_id is REFUSED rather than charged at a caller-chosen figure. TENANT BINDING:
        the org is validated (`org_tenant_id`, fail-closed) and bound into BOTH `tx_ref = vigil:<org>:<nonce>` AND
        `meta.org_id`, so the inbound webhook recovers the SAME tenant from the authoritative verified object and a
        checkout can never be re-aimed at another org. Fail-closed throughout: no creator, an invalid org, an
        unknown/empty price, or a provider response without an https hosted link RAISES — never a half-formed,
        unpriced, or wrongly-attributed checkout."""
        self.require(CAP_HOSTED_CHECKOUT)
        if self._checkout_creator is None:
            raise UnsupportedCapability("hosted checkout requires an injected checkout_creator (the outbound "
                                        "HTTPS poster); refusing to simulate a checkout")
        try:
            org = org_tenant_id(org_id)               # canonical tenant id; fail-closed on an invalid/foreign org
        except ValueError as exc:
            raise ValueError(f"invalid org_id for checkout: {exc}") from None
        exp = expected.get(price_id) if hasattr(expected, "get") else None
        if exp is None:
            raise ValueError(f"unknown price_id {price_id!r}: not in the owner catalog — checkout refused "
                             "(the catalog, never the caller, decides what may be charged)")
        amount_minor, currency = int(exp[0]), str(exp[1]).strip().upper()
        if amount_minor <= 0 or not currency:
            raise ValueError(f"catalog price {price_id!r} has a non-positive amount / empty currency — refused")
        n = nonce or secrets.token_urlsafe(18)
        if not isinstance(n, str) or ":" in n or not n:
            raise ValueError("checkout nonce must be a non-empty string without ':' (the tx_ref delimiter)")
        tx_ref = f"{_TX_REF_PREFIX}:{org}:{n}"
        payload: "dict[str, Any]" = {
            "tx_ref": tx_ref,
            "amount": _to_major(amount_minor, currency),   # major units, from the CATALOG (never the caller)
            "currency": currency,
            "meta": {"org_id": org, "price_id": price_id},  # redundant tenant+price binding (belt-and-suspenders)
        }
        if redirect_url:
            payload["redirect_url"] = str(redirect_url)
        if customer_email:
            payload["customer"] = {"email": str(customer_email)}
        link = _flw_checkout_link(self._checkout_creator(payload))
        if not link:
            raise UnsupportedCapability("checkout creation failed: the provider returned no https hosted link")
        return CheckoutSession(tx_ref=tx_ref, hosted_link=link, org_id=org, price_id=price_id,
                               amount_minor=amount_minor, currency=currency)


@dataclass(frozen=True)
class Entitlement:
    """What a catalog price grants when its payment is confirmed. For a top-up: `credits` into the wallet. For a
    subscription period: `plan_id` + `allotment` + the period length `period_s` (so the signer computes
    period_end = event.created + period_s). Owner-controlled DATA (the real values are the Slice-7 catalog)."""
    kind: str                      # EVENT_TOPUP or EVENT_SUBSCRIPTION_ACTIVE
    credits: int = 0               # top-up credits
    plan_id: str = ""              # subscription plan id
    allotment: int = 0             # subscription per-period credit allotment
    period_s: float = 0.0          # subscription period length in seconds


class BillingSigner:
    """Converts a provider-VERIFIED billing event into exactly one owner-signed sovereign mint — the
    EVIDENCE→FACT boundary. Composes the sovereign registries (wallet, subscription, plan-credit ledger) and an
    owner-controlled price→entitlement `catalog`. Deterministic + idempotent; never mints from an unverified
    event and never lets an on-the-wire amount decide money (only the catalog does)."""

    def __init__(self, provider: BillingProvider, *, wallet, subscriptions, plan, catalog: Mapping[str, Entitlement],
                 expected: "Optional[Mapping[str, Any]]" = None):
        self.provider = provider
        self.wallet = wallet
        self.subscriptions = subscriptions
        self.plan = plan
        self.catalog = dict(catalog)
        # Slice F: the owner catalog's EXPECTED (amount_minor, currency) per price_id (= catalog.expected_amounts()),
        # for the defense-in-depth underpay / wrong-currency cross-check in apply(). Empty ⇒ the cross-check is
        # skipped (backward-compatible; the primary binding is still "the catalog decides the entitlement for the
        # price_id we set at checkout").
        self._expected = {str(k): (int(v[0]), str(v[1]).upper()) for k, v in dict(expected or {}).items()}

    def ingest(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[int]:
        """Verify, then mint. Returns the appended spine seq, or None when the event does not verify, carries no
        catalog entitlement, or maps to a no-op. Idempotent by the provider event_id."""
        event = self.provider.verify_and_parse(raw_body, sig_header, now=now)
        if event is None:
            return None                               # unverified / unhandled -> mint nothing
        return self.apply(event, now=now)

    def apply(self, event: BillingEvent, *, now: float) -> Optional[int]:
        """Mint the sovereign record for an ALREADY-VERIFIED event. Separated from `ingest` so a caller that has
        its own verified-event source can reuse the deterministic mapping; external callers use `ingest`, which
        is the only path that enforces signature verification."""
        oid = event.org_id                            # already validated in verify_and_parse (_parse_org_id)
        if event.kind == EVENT_SUBSCRIPTION_CANCELED:
            return self.subscriptions.cancel(oid)     # safe direction, honored on sight, replay-safe
        if event.kind == EVENT_PAYMENT_FAILED:
            return self.subscriptions.mark_past_due(oid)
        ent = self.catalog.get(event.price_id)
        if ent is None:
            return None                               # unknown price -> no entitlement -> mint nothing
        # Slice F — DEFENSE-IN-DEPTH underpay / wrong-currency guard. For a value-GRANTING event, refuse a VERIFIED
        # amount below the owner catalog's expected price (or in the wrong currency): belt-and-suspenders on top of
        # "the price_id we set at checkout". Fires only when (a) an expected price is configured for this price_id
        # AND (b) the event carries a verified amount (currency present) — a provider that does not populate the
        # amount is still bound by the price_id -> entitlement mapping, not silently refused here.
        if event.kind in (EVENT_TOPUP, EVENT_SUBSCRIPTION_ACTIVE):
            exp = self._expected.get(event.price_id)
            if exp is not None and event.currency:
                if event.currency.upper() != exp[1] or int(event.amount_minor) < exp[0]:
                    return None                       # underpaid / wrong currency -> mint nothing (fail-closed)
        if event.kind == EVENT_TOPUP and ent.kind == EVENT_TOPUP and ent.credits > 0:
            # idempotent by event_id: a duplicate delivery reuses the same wallet entry_id -> folded once.
            return self.wallet.grant(oid, int(ent.credits), "topup", source_ref=event.event_id,
                                     entry_id=event.event_id, issued_at=event.created)
        if event.kind == EVENT_SUBSCRIPTION_ACTIVE and ent.kind == EVENT_SUBSCRIPTION_ACTIVE \
                and ent.plan_id and ent.period_s > 0.0:
            period_end = event.created + float(ent.period_s)
            # subscribe is LWW by issued_at; using the event's OWN created time makes a replay stale (<= the
            # per-org high-water the first delivery set) and therefore inert — the subscription keeps the first
            # delivery's plan/period.
            self.subscriptions.subscribe(oid, ent.plan_id, int(ent.allotment), period_start=event.created,
                                         period_end=period_end, issued_at=event.created)
            # Refill the plan tranche for the now-active period via the canonical bridge: one tranche per period
            # (append-level pre-check). A REPLAY (same event -> same `created` -> stale subscribe, same period)
            # finds the tranche already present and no-ops. A genuine RENEWAL (new event, greater `created`) made
            # the subscribe above fresh -> the period advanced -> the bridge grants the new period's tranche (the
            # prior tranche simply expires: non-rollover).
            return refill_active_subscription(self.subscriptions, self.plan, oid, issued_at=event.created)
        return None
