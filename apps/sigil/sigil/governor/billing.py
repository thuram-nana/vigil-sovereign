"""Enterprise SaaS BILLING — the payment-provider boundary: EVIDENCE (a verified webhook) → owner-signed FACT.

This is the billing analog of VIGIL's soundness doctrine. A payment-provider webhook is UNTRUSTED input; only
its provider SIGNATURE makes it EVIDENCE, and only the sovereign plane converts that evidence into an
owner-signed grant on the spine (the wallet / subscription / plan-credit ledgers). The LLM never grants and no
agent-asserted field decides money: the mapping from a verified event to a sovereign mint is DETERMINISTIC and
driven by an owner-controlled price→entitlement CATALOG.

  * `BillingProvider` (ABC) + `BillingEvent` (normalised) — a swappable provider interface. `StripeBillingProvider`
    implements Stripe's webhook signature scheme in the stdlib (HMAC-SHA256 over `"{t}.{payload}"`, constant-time
    compare, a timestamp tolerance window) — no SDK, no network, no live key beyond the `whsec_` signing secret.
    `MockBillingProvider` is the deterministic sandbox provider for tests + local dev.
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
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

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
    data: Mapping[str, Any] = field(default_factory=dict)   # extra normalised fields (verbatim, untrusted detail)


class BillingProvider(ABC):
    """A swappable payment provider. The ONLY trust operation is `verify_and_parse`: authenticate the raw webhook
    bytes against the provider's signature and return a normalised `BillingEvent`, or None if the signature does
    not verify OR the event is not one we mint on. No method here ever touches the owner key."""

    @abstractmethod
    def verify_and_parse(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[BillingEvent]:
        ...


def _ct_equal(a: str, b: str) -> bool:
    """Constant-time string compare (never short-circuit on the first differing byte — no timing oracle on the
    signature)."""
    return hmac.compare_digest(a, b)


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

    def __init__(self, signing_secret: str, *, tolerance_s: float = _DEFAULT_TOLERANCE_S):
        if not isinstance(signing_secret, str) or not signing_secret:
            raise ValueError("Stripe signing secret (whsec_...) is required")
        self._secret = signing_secret.encode("utf-8")
        self._tolerance = float(tolerance_s)

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

    def __init__(self, provider: BillingProvider, *, wallet, subscriptions, plan, catalog: Mapping[str, Entitlement]):
        self.provider = provider
        self.wallet = wallet
        self.subscriptions = subscriptions
        self.plan = plan
        self.catalog = dict(catalog)

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
