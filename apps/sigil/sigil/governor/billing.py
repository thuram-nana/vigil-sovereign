"""Enterprise SaaS BILLING — the payment-provider boundary: EVIDENCE (a verified webhook) → owner-signed FACT.

This is the billing analog of VIGIL's soundness doctrine. A payment-provider webhook is UNTRUSTED input; only
its provider SIGNATURE makes it EVIDENCE, and only the sovereign plane converts that evidence into an
owner-signed grant on the spine (the wallet / subscription / plan-credit ledgers). The LLM never grants and no
agent-asserted field decides money: the mapping from a verified event to a sovereign mint is DETERMINISTIC and
driven by an owner-controlled price→entitlement CATALOG.

  * `BillingProvider` (ABC) + `BillingEvent` (normalised) — a swappable, CAPABILITY-DECLARING provider interface
    (each adapter declares the operations it supports, so an unsupported flow raises `UnsupportedCapability`
    rather than silently simulating success). `StripeBillingProvider` is the DEFAULT production adapter (selected
    when `VIGIL_BILLING_PROVIDER` is unset): `Stripe-Signature` HMAC + a MANDATORY server-side re-fetch of the
    Checkout Session / Invoice / Subscription, minting from the fetched objects only — but still refusing to
    construct without an explicit opt-in (`enable_reference_adapter` / `VIGIL_BILLING_ENABLE_STRIPE`), a
    money-safety belt. `FlutterwaveBillingProvider` is the RETAINED Flutterwave adapter (development paused per the
    owner's decision; selectable with `VIGIL_BILLING_PROVIDER=flutterwave`): Flutterwave v3 `verif-hash`
    constant-time compare + MANDATORY server-side transaction re-verify before any mint; card + Francophone Mobile
    Money; Payment-Plan recurring. `MockBillingProvider` is the deterministic sandbox for tests.
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
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, cast
from urllib.parse import urlsplit

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
#: W5 — a processor took (part of) a paid top-up back: a dispute or a refund. Produced only by a provider built with
#: ``reversals=True`` (``config.billing_reversals_enabled``) and applied only by a signer given a reversal ledger;
#: never a mock-provider kind (``_EVENT_KINDS``), so it cannot arrive while the flag is off.
EVENT_REVERSAL = "payment_reversal"

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


class UnaccountedPayment(ValueError):
    """A charge the processor RE-VERIFIED as ``successful`` that this drain cannot account for (no recoverable
    tenant, or a price absent from the owner catalog). Raised ONLY when the owner opted in (plan checkout ON):
    the inbound spool then QUARANTINES the envelope — the drain unit stays FAILED and the dead-man alarms — instead
    of archiving a paid-but-uncredited charge as a silent no-op. Mints nothing either way (never act on a guess)."""


class ReversalUnaccounted(ValueError):
    """W5 — a SIGNED processor reversal (a dispute or a refund) VIGIL cannot account for: the charge is neither a
    credited top-up (from a checkout or an automatic top-up) nor the refund of a credited plan period (an unknown
    payment, a disputed plan charge or automatic top-up, a plan period with no credits), its dispute has a status this build does not know, more than one dispute, checkout
    session or invoice claims it, or its currency differs from the purchase's. Nothing moves; the drain QUARANTINES
    the envelope and the owner reconciles it by hand (never a guessed removal)."""


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


#: Why ``BillingSigner.ingest_outcome`` moved money or not — REPORT-ONLY (the billing drain records it beside each
#: archived envelope; the dangling-checkout sweep reads it). No money path ever reads it.
OUTCOME_MINTED = "minted"                    # the mint (or the state change) was appended now
OUTCOME_ALREADY_MINTED = "already_minted"    # a credit-plan period this event paid for is already delivered
#: the no-op reasons, one per place the signer mints nothing
NOOP_REASONS: "tuple[str, ...]" = (
    "not_mintable",            # the provider verified nothing it mints on (or did not verify)
    "no_line",                 # a cancel / failed charge for a line this signer does not hold
    "unknown_price",           # the price is not in the owner catalog
    "no_verified_amount",      # a priced event without a verified currency (require_verified_amount)
    "underpaid_or_currency",   # below the catalog price, or in another currency
    "bad_event_id",            # an event id the ledgers cannot key
    "no_monitoring_line",      # a monitoring period on a signer without the monitoring line
    "stale_or_inert",          # a replayed / out-of-order event the fold does not honour
    "no_entitlement",          # the event kind and the catalog entry do not mint together
    "unrecorded",              # the signer's ingest was replaced and gave no outcome
)


@dataclass(frozen=True)
class IngestOutcome:
    """What one ingested webhook did: the appended spine ``seq`` (None when nothing was appended), the verified
    ``event`` (None when the provider returned none) and the ``reason`` (``OUTCOME_MINTED``,
    ``OUTCOME_ALREADY_MINTED`` or one of ``NOOP_REASONS``)."""
    seq: Optional[int]
    event: Optional["BillingEvent"]
    reason: str

    @property
    def minted(self) -> bool:
        """True iff the payment this event carries is credited (now, or by an earlier delivery of it)."""
        return self.reason in (OUTCOME_MINTED, OUTCOME_ALREADY_MINTED)


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

    def create_checkout(self, org_id: str, price_id: str, *, expected: Mapping[str, Any],
                        customer_email: "Optional[str]" = None, redirect_url: "Optional[str]" = None,
                        nonce: "Optional[str]" = None, payment_plan: "Optional[str]" = None,
                        session_minutes: "Optional[int]" = None,
                        save_future_payments: bool = False) -> "CheckoutSession":
        """Open a tenant-bound hosted checkout. The base adapter has none: it refuses with `UnsupportedCapability`
        (an explicit refusal, never an AttributeError from a duck-typed call). Adapters that can override it.
        `session_minutes` (plan checkouts only; None leaves the payload unchanged) bounds how long the hosted page
        can be paid, so the provisioner's pending plan-checkout record cannot lapse while the link could bill."""
        raise UnsupportedCapability(f"{type(self).__name__} does not support capability {CAP_HOSTED_CHECKOUT!r}")


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


_STRIPE_TS_MAX_DIGITS = 12   # unix seconds (12 digits reaches year 33658); also keeps int() off a huge digit string


class StripeEventRefused(ValueError):
    """A SIGNED Stripe event that must never be read as a no-op: it names a connected account, or it (or the object
    fetched for it) belongs to the other mode (test vs live) than this endpoint serves. Raised so the drain
    QUARANTINES it for an operator; nothing is minted."""


# The only event types acted on. Everything else (customer.subscription.deleted included: a cancelled plan expires
# at period_end, exactly as on Flutterwave) maps to nothing.
_STRIPE_EVENT_TYPES = frozenset({"checkout.session.completed", "checkout.session.async_payment_succeeded",
                                 "invoice.paid", "invoice.payment_failed"})
# A1 auto top-up: the OFF-SESSION charge's success event. Handled ONLY when the adapter is built with
# `auto_topup=True` (else it is not in the instance's handled set → byte-identical webhook behaviour, and a normal
# checkout's own PaymentIntent is never minted here). An auto-top-up PaymentIntent carries `metadata.vigil_auto_topup`.
_STRIPE_PI_SUCCEEDED = "payment_intent.succeeded"
_STRIPE_CS_ID = re.compile(r"cs_(?:test|live)_[A-Za-z0-9]{1,255}")
_STRIPE_IN_ID = re.compile(r"in_[A-Za-z0-9]{1,255}")
_STRIPE_SUB_ID = re.compile(r"sub_[A-Za-z0-9]{1,255}")
# W5 — the reversal events (verified names, docs.stripe.com/api/events/types). Acted on only by a provider built with
# reversals=True; each one names (or leads to) a CHARGE, which is re-fetched with its disputes and its checkout session.
_STRIPE_REVERSAL_TYPES = frozenset({"charge.dispute.created", "charge.dispute.funds_withdrawn",
                                    "charge.dispute.updated", "charge.dispute.closed",
                                    "charge.dispute.funds_reinstated", "charge.refunded", "charge.refund.updated",
                                    "refund.created", "refund.updated", "refund.failed"})
_STRIPE_DISPUTE_ID = re.compile(r"(?:du|dp)_[A-Za-z0-9]{1,255}")
_STRIPE_REFUND_ID = re.compile(r"(?:re|pyr)_[A-Za-z0-9]{1,255}")
_STRIPE_CHARGE_ID = re.compile(r"(?:ch|py)_[A-Za-z0-9]{1,255}")
_STRIPE_PI_ID = re.compile(r"pi_[A-Za-z0-9]{1,255}")
# A1 auto top-up: the saved Stripe Customer + PaymentMethod ids (captured from a top-up checkout, never card data).
_STRIPE_CUS_ID = re.compile(r"cus_[A-Za-z0-9]{1,255}")
_STRIPE_PM_ID = re.compile(r"pm_[A-Za-z0-9]{1,255}")
# The dispute statuses (docs.stripe.com/api/disputes/object). The owner's decision (2026-11-16): the disputed credits
# leave when the dispute OPENS (an inquiry too) and stay out while it is open, under appeal or LOST; they come back
# when it is WON, when an inquiry closes without becoming a dispute (warning_closed) and when it was PREVENTED from
# becoming a chargeback. Any other status is refused (quarantine), never guessed.
_DISPUTE_HOLDS_FUNDS = frozenset({"warning_needs_response", "warning_under_review", "needs_response",
                                  "under_review", "appeal_needs_response", "appeal_under_review", "lost"})
_DISPUTE_RETURNS_FUNDS = frozenset({"won", "warning_closed", "prevented"})
# Only a NEW-PERIOD invoice advances the plan period; a mid-cycle one (an update / proration / manual invoice) must
# never re-grant a full allotment for an overlapping window.
_STRIPE_NEW_PERIOD_REASONS = frozenset({"subscription_create", "subscription_cycle"})
_STRIPE_TS_MAX = 10 ** 12

StripeObjectFetcher = Callable[[str, str], Mapping[str, Any]]
# Currencies Stripe checkout may charge in: ones whose Stripe minor unit is confirmed to equal the catalog's (ISO 4217)
# minor unit, so unit_amount and the inbound amount mean the same money. Extend only after checking Stripe's currency
# notes (ISK, HUF, TWD, UGX and the three-decimal currencies have special rules; MGA is zero-decimal in Stripe).
_STRIPE_CHECKOUT_CURRENCIES = frozenset({"USD"})
# A bounded plan session: Stripe's Checkout `expires_at` must fall 30 min .. 24 h after Stripe creates the session.
# Our clock is read before the create reaches Stripe, so the bound we send carries a little slack above the asked
# minutes (never past the 24 h ceiling); the pending plan-checkout record's drain margin absorbs it.
_STRIPE_SESSION_MIN_RANGE = (30, 1440)
_STRIPE_SESSION_SLACK_S = 60
# A plan (subscription-mode) session accepts these payment methods only; the response must echo them.
_STRIPE_PLAN_PAYMENT_METHODS = ("card",)
# The text of the required Terms of Service checkbox (VIGIL_STRIPE_TERMS_CONSENT). Stripe's custom_text
# terms_of_service_acceptance REPLACES Stripe's default agreement text (the one that links the Terms URL set in the
# dashboard), so this text carries the link itself, as the Markdown link Stripe's custom text supports: the acceptance
# of the terms and, for a consumer, the express request for immediate supply and the acknowledgement of when the right
# of withdrawal ends (Terms §8).
_STRIPE_TERMS_URL = "https://vigilguard.net/terms"
_STRIPE_TERMS_CONSENT_MESSAGE = (
    f"I agree to the VIGIL [Terms of Service]({_STRIPE_TERMS_URL}). I ask SIGIL SARL to start supplying the service "
    "as soon as I use the credits I am buying, and I understand that I lose my right of withdrawal for this purchase "
    "once all of its credits have been used.")
# An AEGIS monitoring plan buys host monitoring, not credits (allotment 0): its box carries the plain agreement to the
# Terms, with no credit wording.
_STRIPE_TERMS_AGREEMENT_MESSAGE = f"I agree to the VIGIL [Terms of Service]({_STRIPE_TERMS_URL})."
StripeCheckoutCreator = Callable[..., Mapping[str, Any]]      # (params, *, idempotency_key) -> session


class StripeBillingProvider(BillingProvider):
    """Stripe webhook verification + server-side re-fetch, in the stdlib (no `stripe` SDK, no network here).

    The `Stripe-Signature` header (`t=<unix>,v1=<hex hmac>` over `"{t}.{raw_body}"`, HMAC-SHA256 under the
    endpoint's `whsec_` secret, constant-time, within the tolerance window) authenticates the delivery. Even so,
    NOTHING that decides money or a tenant is read from the body: the body is trusted only for the event type and
    the id of the object to go fetch. The injected `fetcher` (`stripe_egress.make_object_fetcher`) GETs that
    Checkout Session / Invoice / Subscription with our own API key, and the tenant, price, amount, currency,
    status and timestamp all come from the FETCHED objects. This is the Flutterwave re-verify doctrine.

      * `checkout.session.completed` / `.async_payment_succeeded`: a `payment`-mode session that is `complete` and
        `paid` -> TOPUP. Anchor: the session id, so both events for one session mint once. A subscription-mode
        session -> nothing (its `invoice.paid` mints the period).
      * `invoice.paid`: a `paid` invoice with billing_reason subscription_create / subscription_cycle ->
        SUBSCRIPTION_ACTIVE at `status_transitions.paid_at`. Tenant + price from the fetched subscription's metadata
        (set at our checkout). Anchor: the invoice id.
      * `invoice.payment_failed`: a subscription invoice still `open` / `uncollectible` -> PAYMENT_FAILED with the
        invoice's `created` as the down-latch freshness key (a failure later cured by payment is older than the
        activation it would contradict, so it is inert).
      * (W5, only with ``reversals=True``) a dispute or refund event: the dispute / refund is re-fetched for its
        charge, the CHARGE is re-fetched (amount, amount_refunded), its disputes and its checkout session are read as
        filtered lists -> EVENT_REVERSAL for the top-up (session) that charge paid, carrying how much is refunded and
        how much an open (or lost) dispute holds. A REFUND of a charge no checkout session paid maps through the
        charge's invoice to the subscription (tenant + plan price) and that plan period -> EVENT_REVERSAL for the
        period (``plan_invoice``), or, when no invoice names it either, to the automatic top-up its PaymentIntent is
        (A1) -> EVENT_REVERSAL for that top-up. Anything it cannot account for raises ``ReversalUnaccounted``.
      * Anything else -> None.

    Tenant: `client_reference_id` / `metadata.tx_ref` (`vigil:<org>:<nonce>`) and `metadata.org_id`; when more than
    one is present they must name the same org. A connected-account event or a mode mismatch RAISES
    `StripeEventRefused`; a fetch failure RAISES (transient or definitive, never a silent no-op). With
    `alarm_unaccounted_plans`, a PAID object with no tenant, timestamp or currency raises `UnaccountedPayment`.

    Stripe is the DEFAULT provider (selected when `VIGIL_BILLING_PROVIDER` is unset), but constructing the adapter
    still requires an explicit opt-in — `enable_reference_adapter=True` or `VIGIL_BILLING_ENABLE_STRIPE=1` — a
    deliberate money-safety belt: Stripe keys present in the environment never build the adapter (and so never open
    a checkout) without that opt-in."""

    def __init__(self, signing_secret: str, *, fetcher: StripeObjectFetcher, expected_mode: str,
                 tolerance_s: float = _DEFAULT_TOLERANCE_S, enable_reference_adapter: bool = False,
                 alarm_unaccounted_plans: bool = False, checkout_creator: "Optional[StripeCheckoutCreator]" = None,
                 plan_periods: "Optional[Mapping[str, float]]" = None, strict: bool = False,
                 reversals: bool = False,
                 auto_topup: bool = False,
                 payment_intent_creator: "Optional[StripeCheckoutCreator]" = None):
        if not enable_reference_adapter and \
                os.environ.get("VIGIL_BILLING_ENABLE_STRIPE", "").strip().lower() not in ("1", "true", "yes"):
            raise UnsupportedCapability(
                "StripeBillingProvider is the default provider but still requires an explicit construction opt-in "
                "(a money-safety belt). Enable it with enable_reference_adapter=True or VIGIL_BILLING_ENABLE_STRIPE=1.")
        if not isinstance(signing_secret, str) or not signing_secret:
            raise ValueError("Stripe signing secret (whsec_...) is required")
        if not callable(fetcher):
            raise ValueError("a server-side Stripe object fetcher is required — a signed webhook body is never "
                             "trusted for money; inject stripe_egress.make_object_fetcher()")
        if expected_mode not in ("live", "test"):
            raise ValueError("expected_mode must be 'live' or 'test' (the mode of the API key and the endpoint)")
        self._secret = signing_secret.encode("utf-8")
        self._tolerance = float(tolerance_s)
        self._fetch = fetcher
        self._mode = expected_mode
        self._livemode = expected_mode == "live"
        self._alarm_unaccounted_plans = bool(alarm_unaccounted_plans)
        # The outbound Checkout Session poster (stripe_egress.make_checkout_creator). None => create_checkout
        # refuses (never simulates a checkout). plan_periods: {catalog plan price_id: period seconds}, from the
        # owner catalog — the recurring interval of a plan checkout.
        self._checkout_creator = checkout_creator
        self._plan_periods: "dict[str, float]" = dict(plan_periods or {})
        # The drain lane sets strict: every envelope in its spool was already authenticated by the proxy, so a body
        # that does not verify with the DRAIN's secret (the proxy and drain secrets differ, or the envelope was
        # altered at rest), or that is not a JSON object, is an anomaly to QUARANTINE (unit FAILED, alarm), never a
        # silent no-op that buries a paid charge.
        self._strict = bool(strict)
        # W5 (config.billing_reversals_enabled): act on the dispute and refund events. False (the default) maps them to
        # None exactly as every other unhandled event type.
        self._reversals = bool(reversals)
        # A1 auto top-up: the OFF-SESSION PaymentIntent poster (stripe_egress.make_payment_intent_creator). None =>
        # create_off_session_topup refuses (never simulates a charge). `auto_topup` gates whether this adapter
        # HANDLES the off-session success webhook at all — off => payment_intent.succeeded is NOT in the instance's
        # handled set (byte-identical webhook behaviour), so a normal checkout's own PaymentIntent is never minted
        # here (its checkout.session.* event mints the credit, keyed on the session id — no double mint).
        self._payment_intent_creator = payment_intent_creator
        self._auto_topup = bool(auto_topup)
        self._event_types = (_STRIPE_EVENT_TYPES | {_STRIPE_PI_SUCCEEDED}) if self._auto_topup \
            else _STRIPE_EVENT_TYPES

    def capabilities(self) -> frozenset[str]:
        # Webhook verification + the server-side object re-fetch, and hosted checkout (card, one-off or recurring)
        # once a creator is injected. CAP_UNATTENDED_TOPUP (off-session charging) ONLY when the A1 adapter is built
        # with a payment-intent creator; refund / reconcile are not implemented, so never declared.
        caps = {CAP_VERIFY_WEBHOOK, CAP_VERIFY_TRANSACTION}
        if self._checkout_creator is not None:
            caps |= {CAP_HOSTED_CHECKOUT, CAP_ONE_TIME_CARD, CAP_RECURRING_PLAN}
        if self._auto_topup and self._payment_intent_creator is not None:
            caps.add(CAP_UNATTENDED_TOPUP)
        return frozenset(caps)

    def create_checkout(self, org_id: str, price_id: str, *, expected: Mapping[str, Any],
                        customer_email: "Optional[str]" = None, redirect_url: "Optional[str]" = None,
                        nonce: "Optional[str]" = None, payment_plan: "Optional[str]" = None,
                        session_minutes: "Optional[int]" = None,
                        save_future_payments: bool = False) -> "CheckoutSession":
        """Create a tenant-bound Stripe Checkout Session for `price_id` — the same contract as the Flutterwave
        adapter (the checkout endpoint authorizes first; this primitive BINDS).

        The amount and currency come from the OWNER CATALOG (`expected[price_id]`) as inline `price_data`, never
        from the caller; an unknown price is refused. The tenant is bound three ways that the inbound mapper
        requires to agree: `client_reference_id = vigil:<org>:<nonce>` plus `metadata` org_id / price_id / tx_ref on
        the session and on the PaymentIntent (one-off) or the Subscription (plan). A plan (`payment_plan`, which
        must equal `price_id`) recurs every `plan_periods[price_id]` seconds as a whole number of days (at most
        365). `redirect_url` is required: it becomes the success and cancel URLs, with `status=` appended to the
        URL's query (in the hash when there is one, where the customer app reads it). The create carries the
        Idempotency-Key `vigil-co-<nonce>`. The response must be a session echoing our reference, mode, mode
        (test/live), catalog amount (one-off) and currency, with an https link on exactly `checkout.stripe.com`.
        `session_minutes` (a plan checkout; None sends no bound, as before) sets the session's `expires_at` so the
        link stops being payable before the provisioner's pending plan-checkout record lapses; the response must
        then echo that same `expires_at`. A plan session is card-only (`payment_method_types`), and the response
        must echo that too; a top-up's payload is unchanged. With `VIGIL_STRIPE_TERMS_CONSENT` on, the session
        requires the Terms of Service box with VIGIL's text (a monitoring plan's carries the plain agreement, no
        credit wording), and the response must echo both the requirement and exactly that text. Fail-closed throughout: any refusal raises `UnsupportedCapability` / `ValueError`."""
        self.require(CAP_HOSTED_CHECKOUT)
        creator = self._checkout_creator
        if creator is None:                            # unreachable once require() passed; kept for type narrowing
            raise UnsupportedCapability("hosted checkout requires an injected checkout_creator")
        try:
            org = org_tenant_id(org_id)
        except ValueError as exc:
            raise ValueError(f"invalid org_id for checkout: {exc}") from None
        exp = expected.get(price_id) if hasattr(expected, "get") else None
        if exp is None:
            raise ValueError(f"unknown price_id {price_id!r}: not in the owner catalog — checkout refused "
                             "(the catalog, never the caller, decides what may be charged)")
        amount_minor, currency = int(exp[0]), str(exp[1]).strip().upper()
        if amount_minor <= 0 or not currency:
            raise ValueError(f"catalog price {price_id!r} has a non-positive amount / empty currency — refused")
        if currency not in _STRIPE_CHECKOUT_CURRENCIES:
            raise ValueError(f"Stripe checkout is not enabled for {currency}: its Stripe minor unit must first be "
                             "confirmed to match the catalog's (ISK and MGA, for example, differ) — refused")
        n = nonce or secrets.token_urlsafe(18)
        if not isinstance(n, str) or ":" in n or not n or any(not (0x21 <= ord(c) <= 0x7e) for c in n):
            raise ValueError("checkout nonce must be a non-empty printable string without ':' (the tx_ref "
                             "delimiter)")
        success_url, cancel_url = _stripe_return_urls(redirect_url)
        tx_ref = checkout_tx_ref(org, n)
        meta = {"org_id": org, "price_id": price_id, "tx_ref": tx_ref}
        price_data: "dict[str, Any]" = {"currency": currency.lower(), "unit_amount": amount_minor,
                                        "product_data": {"name": price_id}}
        mode = "payment"
        if payment_plan is not None:
            if payment_plan != price_id:
                raise ValueError("a Stripe plan checkout's payment_plan must be its catalog price_id")
            price_data["recurring"] = {"interval": "day", "interval_count": _stripe_plan_days(
                self._plan_periods.get(price_id), price_id)}
            mode = "subscription"
        # A1: a TOP-UP checkout may ask Stripe to SAVE the card for later off-session auto top-ups. Only for a
        # one-off payment (a plan already saves its method), and only when the caller opts in — default False keeps
        # the payload byte-identical. `vigil_save_method` rides the session metadata so the inbound mapper can carry
        # the Customer + PaymentIntent to the capture hook.
        save = bool(save_future_payments) and mode == "payment"
        if save:
            meta["vigil_save_method"] = "1"
        intent_data: "dict[str, Any]" = {"metadata": dict(meta)}
        if save:
            intent_data["setup_future_usage"] = "off_session"   # attach the PaymentMethod to the Customer, reusable
        params: "dict[str, Any]" = {
            "mode": mode,
            "line_items": [{"price_data": price_data, "quantity": 1}],
            "client_reference_id": tx_ref,
            "metadata": meta,
            ("subscription_data" if mode == "subscription" else "payment_intent_data"): intent_data,
            "success_url": success_url,
            "cancel_url": cancel_url,
            # the charge must be in the catalog currency: never let Stripe localise it on this session
            "adaptive_pricing": {"enabled": False},
        }
        if save:
            params["customer_creation"] = "always"   # a saved PaymentMethod needs a Customer to attach to
        if mode == "subscription":
            # a plan is paid by card only (this adapter's hosted checkout is card), so its first invoice is
            # settled when the checkout completes rather than days later by a delayed-notification method
            params["payment_method_types"] = list(_STRIPE_PLAN_PAYMENT_METHODS)
        from .. import config as _config
        if _config.stripe_terms_consent_enabled():
            # the customer must tick the required terms box to pay; its text is VIGIL's (it replaces Stripe's default
            # agreement text) and links the Terms
            from .catalog import monitoring_price_ids
            monitoring = price_id in monitoring_price_ids()
            params["consent_collection"] = {"terms_of_service": "required"}
            params["custom_text"] = {"terms_of_service_acceptance": {
                "message": _STRIPE_TERMS_AGREEMENT_MESSAGE if monitoring else _STRIPE_TERMS_CONSENT_MESSAGE}}
        if session_minutes is not None:
            sm, (lo, hi) = session_minutes, _STRIPE_SESSION_MIN_RANGE
            if not isinstance(sm, int) or not lo <= sm <= hi:      # (a bool is below the range's floor)
                raise ValueError(f"session_minutes must be an int in [{lo}, {hi}] for a Stripe checkout")
            params["expires_at"] = int(time.time()) + min(sm * 60 + _STRIPE_SESSION_SLACK_S, hi * 60)
        if customer_email:
            params["customer_email"] = str(customer_email)
        try:
            resp = creator(params, idempotency_key=f"vigil-co-{n}")
        except Exception as exc:  # noqa: BLE001 — any outbound failure is a REFUSAL, re-raised as the contract type
            raise UnsupportedCapability(f"checkout creation failed ({type(exc).__name__})") from None
        if "expires_at" in params and (not isinstance(resp, Mapping) or resp.get("expires_at") != params["expires_at"]):
            raise UnsupportedCapability("checkout creation failed: the provider did not confirm the bounded payment "
                                        "session")
        if "payment_method_types" in params and (not isinstance(resp, Mapping)
                                                 or resp.get("payment_method_types") != params["payment_method_types"]):
            raise UnsupportedCapability("checkout creation failed: the provider did not confirm a card-only plan "
                                        "session")
        if "consent_collection" in params:
            echoed = resp.get("consent_collection") if isinstance(resp, Mapping) else None
            if not isinstance(echoed, Mapping) or echoed.get("terms_of_service") != "required":
                raise UnsupportedCapability("checkout creation failed: the provider did not confirm the required "
                                            "Terms of Service acceptance")
            # the box's text carries the consumer's request for immediate supply (Terms §8): Stripe must show exactly
            # the text sent, so the session's own custom text must equal it
            text = resp.get("custom_text") if isinstance(resp, Mapping) else None
            tos = text.get("terms_of_service_acceptance") if isinstance(text, Mapping) else None
            shown = tos.get("message") if isinstance(tos, Mapping) else None
            if not isinstance(shown, str) or shown != params["custom_text"]["terms_of_service_acceptance"]["message"]:
                raise UnsupportedCapability("checkout creation failed: the provider did not echo the Terms of Service "
                                            "acceptance text VIGIL sent")
        link = self._checkout_link(resp, tx_ref=tx_ref, mode=mode, amount_minor=amount_minor, currency=currency)
        if not link:
            raise UnsupportedCapability("checkout creation failed: the provider returned no matching session with "
                                        "an https checkout.stripe.com link")
        return CheckoutSession(tx_ref=tx_ref, hosted_link=link, org_id=org, price_id=price_id,
                               amount_minor=amount_minor, currency=currency)

    def _checkout_link(self, resp: object, *, tx_ref: str, mode: str, amount_minor: int,
                       currency: str) -> Optional[str]:
        """The session's hosted link iff the response is the session we asked for, else None (fail-closed)."""
        from .. import config
        if not isinstance(resp, Mapping) or resp.get("object") != "checkout.session":
            return None
        sid = resp.get("id")
        if not isinstance(sid, str) or not _STRIPE_CS_ID.fullmatch(sid):
            return None
        if resp.get("client_reference_id") != tx_ref or resp.get("mode") != mode \
                or resp.get("livemode") is not self._livemode:
            return None
        echoed_ccy = resp.get("currency")
        if not isinstance(echoed_ccy, str) or echoed_ccy.upper() != currency:
            return None
        if mode == "payment":
            total = resp.get("amount_total")
            if isinstance(total, bool) or total != amount_minor:
                return None
        return _https_link_on(resp.get("url"), exact_hosts=frozenset(config.STRIPE_CHECKOUT_LINK_HOSTS))

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
        # The timestamp is plain ASCII decimal digits only. float() would also accept "1e3", "+1000", " 1000",
        # "nan" and non-ASCII digits (which then made ts.encode("ascii") raise instead of refusing).
        if not (ts.isascii() and ts.isdigit() and 1 <= len(ts) <= _STRIPE_TS_MAX_DIGITS):
            return False
        t = int(ts)
        if abs(now - t) > self._tolerance:           # replay-window bound (stale or future-dated -> reject)
            return False
        signed = ts.encode("ascii") + b"." + raw_body
        expected = hmac.new(self._secret, signed, hashlib.sha256).hexdigest()
        # any valid v1 (Stripe may send several on rotation); _ct_equal is constant-time and returns False for a
        # malformed (non-ASCII / wrong-length) candidate rather than raising
        return any(_ct_equal(expected, v1) for v1 in v1s)

    def verify_and_parse(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[BillingEvent]:
        if not isinstance(raw_body, (bytes, bytearray)):
            return None
        raw_body = bytes(raw_body)
        if not self._verify_signature(raw_body, sig_header, now):
            if self._strict:
                raise StripeEventRefused("the Stripe-Signature does not verify with this drain's webhook secret (the "
                                         "proxy and drain secrets differ, or the envelope was altered at rest)")
            return None                              # fail-CLOSED: unverified -> no event, no mint
        try:
            obj = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            obj = None
        if not isinstance(obj, dict):
            if self._strict:
                raise StripeEventRefused("a signed Stripe body is not a JSON object")
            return None
        if "account" in obj:
            raise StripeEventRefused("signed Stripe event names a connected account — refused (standard account "
                                     "only)")
        if obj.get("livemode") is not self._livemode:
            raise StripeEventRefused(f"signed Stripe event is not a {self._mode}-mode event")
        etype = obj.get("type")
        if etype not in self._event_types:           # A1: payment_intent.succeeded is handled only in auto_topup mode
            if self._reversals and etype in _STRIPE_REVERSAL_TYPES:   # W5: a dispute/refund event
                return self._reversal(str(etype), obj)
            return None
        data = obj.get("data")
        body_obj = data.get("object") if isinstance(data, dict) else None
        object_id = body_obj.get("id") if isinstance(body_obj, dict) else None
        if not isinstance(object_id, str):
            return None                              # the body is trusted ONLY for which object to fetch
        if etype.startswith("checkout.session."):
            if not _STRIPE_CS_ID.fullmatch(object_id):
                return None
            session = self._fetched("checkout_session", object_id, "checkout.session")
            return None if session is None else self._map_checkout(session)
        if etype == _STRIPE_PI_SUCCEEDED:
            if not _STRIPE_PI_ID.fullmatch(object_id):
                return None
            pi = self._fetched("payment_intent", object_id, "payment_intent")
            return None if pi is None else self._map_payment_intent(pi)
        if not _STRIPE_IN_ID.fullmatch(object_id):
            return None
        invoice = self._fetched("invoice", object_id, "invoice")
        if invoice is None:
            return None
        if etype == "invoice.paid":
            return self._map_invoice_paid(invoice)
        return self._map_invoice_failed(invoice)

    # -- the authoritative objects ---------------------------------------------------------------------------
    def _fetched(self, kind: str, object_id: str, object_type: str) -> "Optional[Mapping[str, Any]]":
        """The AUTHORITATIVE object, fetched with our key. A fetch failure RAISES (the drain retries a transient
        one and quarantines a definitive one); an object that is not the one asked for maps to nothing; one from
        the other mode raises."""
        obj = self._fetch(kind, object_id)
        if not isinstance(obj, Mapping) or obj.get("object") != object_type or obj.get("id") != object_id:
            return None
        if obj.get("livemode") is not self._livemode:
            raise StripeEventRefused(f"fetched Stripe {object_type} is not a {self._mode}-mode object")
        return obj

    # -- W5: reversals (disputes and refunds) ----------------------------------------------------------------------
    def _listed(self, kind: str, filter_id: str, item_type: str) -> "list[Mapping[str, Any]]":
        """The items of the AUTHORITATIVE Stripe list ``kind`` filtered by ``filter_id``: every item must be a
        ``item_type`` of this endpoint's mode, and the list complete (``has_more`` false) — else refused."""
        lst = self._fetch(kind, filter_id)
        if not isinstance(lst, Mapping) or lst.get("object") != "list" or not isinstance(lst.get("data"), list) \
                or lst.get("has_more") is not False:
            raise ReversalUnaccounted(f"the Stripe {kind} list for {filter_id} is not one complete list")
        items: "list[Mapping[str, Any]]" = []
        for it in lst["data"]:
            if not isinstance(it, Mapping) or it.get("object") != item_type or not isinstance(it.get("id"), str):
                raise ReversalUnaccounted(f"the Stripe {kind} list for {filter_id} holds an unexpected object")
            if it.get("livemode") is not self._livemode:
                raise StripeEventRefused(f"fetched Stripe {item_type} is not a {self._mode}-mode object")
            items.append(it)
        return items

    def _reversal(self, etype: str, obj: "Mapping[str, Any]") -> Optional[BillingEvent]:
        """A dispute or refund event -> the CHARGE it concerns -> ``_map_reversal``. The body names only the object to
        fetch; the dispute / refund is re-fetched to find its charge, and the charge itself is re-fetched."""
        data = obj.get("data")
        body_obj = data.get("object") if isinstance(data, dict) else None
        object_id = body_obj.get("id") if isinstance(body_obj, dict) else None
        if not isinstance(object_id, str):
            return None
        if etype.startswith("charge.dispute."):
            if not _STRIPE_DISPUTE_ID.fullmatch(object_id):
                return None
            parent = self._fetched("dispute", object_id, "dispute")
            trigger = "dispute"
        elif etype == "charge.refunded":
            if not _STRIPE_CHARGE_ID.fullmatch(object_id):
                return None
            parent, trigger = {"charge": object_id}, "refund"
        else:
            if not _STRIPE_REFUND_ID.fullmatch(object_id):
                return None
            parent = self._fetched("refund", object_id, "refund")
            trigger = "refund"
        if parent is None:
            return None
        charge_id = _stripe_ref(parent.get("charge"))
        if charge_id is None or not _STRIPE_CHARGE_ID.fullmatch(charge_id):
            raise ReversalUnaccounted(f"Stripe {etype} {object_id} names no charge VIGIL can read")
        charge = self._fetched("charge", charge_id, "charge")
        if charge is None:
            raise ReversalUnaccounted(f"Stripe {etype} {object_id}: its charge {charge_id} could not be read")
        return self._map_reversal(charge, trigger)

    def _map_reversal(self, charge: "Mapping[str, Any]", trigger: str) -> BillingEvent:
        """The reversal facts of a re-fetched CHARGE (pure but for the authoritative lists and objects): how much of it
        is refunded, how much a dispute that holds the funds covers, and the top-up (Checkout Session) and tenant it
        paid for — or, for a charge no checkout session paid, the plan period its invoice paid
        (``_map_plan_reversal``), or with no invoice either, the automatic top-up its PaymentIntent is
        (``_map_auto_topup_reversal``). Anything VIGIL cannot account for raises ``ReversalUnaccounted``
        (quarantine)."""
        cid = str(charge["id"])
        amount, refunded = charge.get("amount"), charge.get("amount_refunded")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0 or isinstance(refunded, bool) \
                or not isinstance(refunded, int) or refunded < 0:
            raise ReversalUnaccounted(f"Stripe charge {cid} carries no usable amount / amount_refunded")
        _amt, ccy = _stripe_amount(amount, charge.get("currency"))
        if not ccy:
            raise ReversalUnaccounted(f"Stripe charge {cid} has no currency")
        created = _stripe_ts(charge.get("created"))
        if created is None:
            raise ReversalUnaccounted(f"Stripe charge {cid} has no usable timestamp")
        disputes = self._listed("disputes_for_charge", cid, "dispute")
        if any(_stripe_ref(d.get("charge")) != cid for d in disputes) or len(disputes) > 1:
            raise ReversalUnaccounted(f"Stripe charge {cid} does not have one dispute VIGIL can read")
        disputed, status = 0, ""
        if disputes:
            d = disputes[0]
            _status = d.get("status")
            status = _status if isinstance(_status, str) else ""
            if status not in _DISPUTE_HOLDS_FUNDS and status not in _DISPUTE_RETURNS_FUNDS:
                raise ReversalUnaccounted(f"Stripe dispute {d.get('id')} has a status VIGIL does not know ({status!r})")
            d_amount, d_ccy = _stripe_amount(d.get("amount"), d.get("currency"))
            if d_ccy != ccy or isinstance(d.get("amount"), bool) or not isinstance(d.get("amount"), int):
                raise ReversalUnaccounted(f"Stripe dispute {d.get('id')} is not in the charge's currency")
            if status in _DISPUTE_HOLDS_FUNDS:
                disputed = d_amount
        pi = _stripe_ref(charge.get("payment_intent"))
        if pi is None or not _STRIPE_PI_ID.fullmatch(pi):
            raise ReversalUnaccounted(f"Stripe charge {cid} was not paid through a checkout top-up")
        sessions = self._listed("checkout_sessions_for_payment_intent", pi, "checkout.session")
        if not sessions:
            # no checkout session paid this charge: the refund of a PLAN period maps through its invoice; a charge
            # with no invoice either may be an automatic top-up's own PaymentIntent (A1), which names its pack
            pays = None
            if _stripe_ref(charge.get("invoice")) is None:
                pays = self._listed("invoice_payments_for_payment_intent", pi, "invoice_payment")
                if not pays:
                    return self._map_auto_topup_reversal(charge, pi, trigger=trigger, disputed=bool(disputes),
                                                         amount=amount, refunded=refunded, ccy=ccy, created=created)
            return self._map_plan_reversal(charge, pi, trigger=trigger, disputed=bool(disputes), amount=amount,
                                           refunded=refunded, ccy=ccy, created=created, pays=pays)
        if len(sessions) != 1:
            raise ReversalUnaccounted(f"Stripe charge {cid} does not belong to one checkout session")
        sess = sessions[0]
        sid = str(sess["id"])
        if not _STRIPE_CS_ID.fullmatch(sid) or sess.get("mode") != "payment" \
                or _stripe_ref(sess.get("payment_intent")) != pi:
            raise ReversalUnaccounted(f"Stripe charge {cid} was not paid through a checkout top-up")
        meta = sess.get("metadata")
        org = _stripe_tenant(sess.get("client_reference_id"), meta)
        if org is None:
            raise ReversalUnaccounted(f"Stripe checkout session {sid} has no single recoverable tenant")
        return BillingEvent(event_id=f"reversal:{cid}", kind=EVENT_REVERSAL, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"), amount_minor=amount, currency=ccy,
                            data={"topup": sid, "charge": cid, "refunded_minor": min(refunded, amount),
                                  "disputed_minor": min(disputed, amount), "dispute_status": status,
                                  "trigger": trigger, "tx_ref": sess.get("client_reference_id")})

    def _map_auto_topup_reversal(self, charge: "Mapping[str, Any]", pi: str, *, trigger: str, disputed: bool,
                                 amount: int, refunded: int, ccy: str, created: float) -> BillingEvent:
        """A REFUND of a charge that no checkout session and no invoice paid, whose PaymentIntent is an AUTOMATIC
        top-up (A1: an off-session PaymentIntent VIGIL created, marked ``metadata.vigil_auto_topup``): the PaymentIntent
        is re-fetched; the pack is that PaymentIntent (its id is the top-up's billing-history id and grant entry, as
        ``_map_payment_intent`` minted it) and the tenant is its metadata, exactly as minted. The signer then removes
        the pack's credits like a checkout top-up's. Only a succeeded PaymentIntent this one charge paid in full, in
        the charge's currency, maps; any other PaymentIntent, a dispute of an automatic top-up, or anything else
        raises ``ReversalUnaccounted`` (quarantine, nothing moves)."""
        cid = str(charge["id"])
        intent = self._fetched("payment_intent", pi, "payment_intent")
        if intent is None or _stripe_meta(intent.get("metadata"), "vigil_auto_topup") != "1":
            raise ReversalUnaccounted(f"Stripe charge {cid} does not belong to one paid invoice or automatic top-up")
        pid = str(intent["id"])
        if trigger != "refund" or disputed:
            raise ReversalUnaccounted(f"Stripe charge {cid} paid an automatic top-up and is disputed: a dispute of an "
                                      f"automatic top-up is reconciled by hand")
        received, received_ccy = _stripe_amount(intent.get("amount_received"), intent.get("currency"))
        if intent.get("status") != "succeeded" or received != amount or received_ccy != ccy:
            raise ReversalUnaccounted(f"Stripe charge {cid} is not the whole succeeded payment of automatic top-up "
                                      f"{pid}: reconcile its refund by hand")
        meta = intent.get("metadata")
        org = _stripe_tenant(None, meta)
        if org is None:
            raise ReversalUnaccounted(f"Stripe automatic top-up {pid} has no single recoverable tenant")
        return BillingEvent(event_id=f"reversal:{cid}", kind=EVENT_REVERSAL, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"), amount_minor=amount, currency=ccy,
                            data={"topup": pid, "charge": cid, "refunded_minor": min(refunded, amount),
                                  "disputed_minor": 0, "dispute_status": "", "trigger": trigger,
                                  "tx_ref": _stripe_meta(meta, "tx_ref")})

    def _charge_invoice(self, charge: "Mapping[str, Any]", pi: str,
                        pays: "Optional[list[Mapping[str, Any]]]" = None) -> str:
        """The invoice a re-fetched charge paid. API versions before 2025-03-31 name it on the charge (``invoice``);
        later ones list it as the one paid ``invoice_payment`` of the charge's PaymentIntent (``pays``: that list,
        when the caller already read it). Raises ``ReversalUnaccounted`` unless exactly one invoice is named."""
        cid = str(charge["id"])
        ref = _stripe_ref(charge.get("invoice"))
        if ref is None:
            if pays is None:
                pays = self._listed("invoice_payments_for_payment_intent", pi, "invoice_payment")
            pay = pays[0] if len(pays) == 1 else None
            payment = pay.get("payment") if pay is not None else None
            if (pay is None or pay.get("status") != "paid" or not isinstance(payment, Mapping)
                    or payment.get("type") != "payment_intent" or _stripe_ref(payment.get("payment_intent")) != pi):
                raise ReversalUnaccounted(f"Stripe charge {cid} does not belong to one paid invoice")
            ref = _stripe_ref(pay.get("invoice"))
        if ref is None or not _STRIPE_IN_ID.fullmatch(ref):
            raise ReversalUnaccounted(f"Stripe charge {cid} does not belong to one paid invoice")
        return ref

    def _map_plan_reversal(self, charge: "Mapping[str, Any]", pi: str, *, trigger: str, disputed: bool, amount: int,
                           refunded: int, ccy: str, created: float,
                           pays: "Optional[list[Mapping[str, Any]]]" = None) -> BillingEvent:
        """A REFUND of a charge that paid a PLAN period: charge -> its invoice -> the invoice's subscription, whose
        metadata names the tenant and the plan price (set at our checkout), exactly as ``invoice.paid`` minted the
        period. Only a paid new-period invoice that this one charge paid in full maps (the ones VIGIL credits); the
        signer then removes that period's plan credits in the refunded proportion. A dispute of a plan charge, a
        charge that paid only part of its invoice, or a charge VIGIL cannot trace to one such invoice and tenant,
        raises ``ReversalUnaccounted`` (quarantine, nothing moves)."""
        cid = str(charge["id"])
        if trigger != "refund" or disputed:
            raise ReversalUnaccounted(f"Stripe charge {cid} is not a checkout top-up and is disputed: a dispute of a "
                                      f"plan charge is reconciled by hand")
        iid = self._charge_invoice(charge, pi, pays)
        inv = self._fetched("invoice", iid, "invoice")
        if inv is None or inv.get("status") != "paid" or inv.get("billing_reason") not in _STRIPE_NEW_PERIOD_REASONS:
            raise ReversalUnaccounted(f"Stripe charge {cid} did not pay a plan period VIGIL credits ({iid})")
        paid, paid_ccy = _stripe_amount(inv.get("amount_paid"), inv.get("currency"))
        if paid_ccy != ccy:
            raise ReversalUnaccounted(f"Stripe invoice {iid} is not in the currency of its charge {cid}")
        if paid != amount:
            # the refunded proportion is sized against the charge, and a refund total is read per charge: both hold
            # only when this one charge paid the whole invoice (an invoice paid in parts is reconciled by hand)
            raise ReversalUnaccounted(f"Stripe charge {cid} ({amount}) did not pay the whole of invoice {iid} "
                                      f"({paid} paid): reconcile its refund by hand")
        sub = self._invoice_subscription(inv)
        meta = sub.get("metadata") if sub is not None else None
        org = _stripe_tenant(None, meta) if sub is not None else None
        if sub is None or org is None:
            raise ReversalUnaccounted(f"Stripe invoice {iid} has no subscription with a single recoverable tenant")
        return BillingEvent(event_id=f"reversal:{cid}", kind=EVENT_REVERSAL, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"), amount_minor=amount, currency=ccy,
                            data={"plan_invoice": iid, "charge": cid, "refunded_minor": min(refunded, amount),
                                  "disputed_minor": 0, "dispute_status": "", "trigger": trigger,
                                  "subscription": sub.get("id"), "tx_ref": _stripe_meta(meta, "tx_ref")})

    def _invoice_subscription(self, invoice: "Mapping[str, Any]") -> "Optional[Mapping[str, Any]]":
        """The fetched subscription an invoice belongs to. The id is read from `subscription` (older API versions)
        and `parent.subscription_details.subscription` (newer ones); when both are present they must agree."""
        ids: set = set()
        top = invoice.get("subscription")
        parent = invoice.get("parent")
        details = parent.get("subscription_details") if isinstance(parent, Mapping) else None
        nested = details.get("subscription") if isinstance(details, Mapping) else None
        for ref in (top, nested):
            if isinstance(ref, Mapping):
                ref = ref.get("id")
            if isinstance(ref, str):
                ids.add(ref)
        if len(ids) != 1:
            return None
        sub_id = ids.pop()
        if not _STRIPE_SUB_ID.fullmatch(sub_id):
            return None
        return self._fetched("subscription", sub_id, "subscription")

    def _unaccounted(self, what: str) -> Optional[BillingEvent]:
        """A PAID object this adapter cannot account for: loud (quarantine + alarm) when the alarm is armed, else a
        no-op. Mints nothing either way."""
        if self._alarm_unaccounted_plans:
            raise UnaccountedPayment(f"{what} — paid but UN-MINTED; reconcile by hand")
        return None

    # -- mapping (pure; every field from the fetched objects) -----------------------------------------------
    def _map_checkout(self, s: "Mapping[str, Any]") -> Optional[BillingEvent]:
        if s.get("mode") != "payment":
            return None                              # a subscription session: its invoice.paid mints the period
        if s.get("status") != "complete" or s.get("payment_status") != "paid":
            return None                              # unpaid / async pending / expired -> nothing yet
        sid = str(s["id"])
        meta = s.get("metadata")
        org = _stripe_tenant(s.get("client_reference_id"), meta)
        if org is None:
            return self._unaccounted(f"paid Stripe checkout session {sid} has no single recoverable tenant")
        created = _stripe_ts(s.get("created"))
        if created is None:
            return self._unaccounted(f"paid Stripe checkout session {sid} has no usable timestamp")
        amount, ccy = _stripe_amount(s.get("amount_total"), s.get("currency"))
        if not ccy:
            return self._unaccounted(f"paid Stripe checkout session {sid} for org {org!r} has no currency")
        data: "dict[str, Any]" = {"tx_ref": s.get("client_reference_id")}
        # A1: when this checkout asked Stripe to SAVE the card (metadata.vigil_save_method), carry the Customer and
        # PaymentIntent ids so the signer's capture hook can record the saved method. Purely ADDITIVE and only when
        # the marker is present (an A1-created checkout) — a normal checkout's event.data is byte-identical.
        if _stripe_meta(meta, "vigil_save_method") == "1":
            cus, pi = s.get("customer"), s.get("payment_intent")
            if isinstance(cus, str) and _STRIPE_CUS_ID.fullmatch(cus) and isinstance(pi, str) \
                    and _STRIPE_PI_ID.fullmatch(pi):
                data["save_method_customer"] = cus
                data["save_method_payment_intent"] = pi
        return BillingEvent(event_id=sid, kind=EVENT_TOPUP, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"), amount_minor=amount, currency=ccy, data=data)

    def _map_invoice_paid(self, inv: "Mapping[str, Any]") -> Optional[BillingEvent]:
        if inv.get("status") != "paid" or inv.get("billing_reason") not in _STRIPE_NEW_PERIOD_REASONS:
            return None
        iid = str(inv["id"])
        sub = self._invoice_subscription(inv)
        if sub is None:
            return self._unaccounted(f"paid Stripe subscription invoice {iid} has no readable subscription")
        meta = sub.get("metadata")
        org = _stripe_tenant(None, meta)
        if org is None:
            return self._unaccounted(f"paid Stripe invoice {iid} has no single recoverable tenant")
        transitions = inv.get("status_transitions")
        created = _stripe_ts(transitions.get("paid_at") if isinstance(transitions, Mapping) else None)
        if created is None:
            return self._unaccounted(f"paid Stripe invoice {iid} has no usable paid_at")
        amount, ccy = _stripe_amount(inv.get("amount_paid"), inv.get("currency"))
        if not ccy:
            return self._unaccounted(f"paid Stripe invoice {iid} for org {org!r} has no currency")
        return BillingEvent(event_id=iid, kind=EVENT_SUBSCRIPTION_ACTIVE, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"), amount_minor=amount, currency=ccy,
                            data={"subscription": sub.get("id"), "tx_ref": _stripe_meta(meta, "tx_ref")})

    def _map_invoice_failed(self, inv: "Mapping[str, Any]") -> Optional[BillingEvent]:
        if inv.get("status") not in ("open", "uncollectible"):
            return None                              # paid since (or void / draft): nothing to reduce
        sub = self._invoice_subscription(inv)
        if sub is None:
            return None                              # a one-off invoice reduces nothing
        meta = sub.get("metadata")
        org = _stripe_tenant(None, meta)
        created = _stripe_ts(inv.get("created"))
        if org is None or created is None:
            return None
        return BillingEvent(event_id=str(inv["id"]), kind=EVENT_PAYMENT_FAILED, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"),
                            data={"subscription": sub.get("id"), "tx_ref": _stripe_meta(meta, "tx_ref")})

    def _map_payment_intent(self, pi: "Mapping[str, Any]") -> Optional[BillingEvent]:
        """Map a fetched OFF-SESSION auto-top-up PaymentIntent -> EVENT_TOPUP (A1). ONLY an auto-top-up-marked PI
        (`metadata.vigil_auto_topup == "1"`) mints here — a normal checkout's own PaymentIntent is credited by its
        `checkout.session.*` event, so minting it here too would DOUBLE-credit; the marker gate refuses it. Every
        money/tenant field comes from the fetched object (never the webhook body). The idempotency anchor is the
        PaymentIntent id, so the wallet grant folds once however many times the webhook is delivered."""
        meta = pi.get("metadata")
        if _stripe_meta(meta, "vigil_auto_topup") != "1":
            return None                              # not our off-session top-up -> never mint (no double credit)
        if pi.get("status") != "succeeded":
            return None                              # only a captured success mints (a decline never reaches here)
        pid = str(pi["id"])
        org = _stripe_tenant(None, meta)
        if org is None:
            return self._unaccounted(f"paid Stripe off-session top-up {pid} has no single recoverable tenant")
        created = _stripe_ts(pi.get("created"))
        if created is None:
            return self._unaccounted(f"paid Stripe off-session top-up {pid} has no usable timestamp")
        amount, ccy = _stripe_amount(pi.get("amount_received"), pi.get("currency"))
        if not ccy:
            return self._unaccounted(f"paid Stripe off-session top-up {pid} for org {org!r} has no currency")
        return BillingEvent(event_id=pid, kind=EVENT_TOPUP, org_id=org, created=created,
                            price_id=_stripe_meta(meta, "price_id"), amount_minor=amount, currency=ccy,
                            data={"tx_ref": _stripe_meta(meta, "tx_ref"), "auto_topup": "1"})

    def create_off_session_topup(self, org_id: str, price_id: str, *, customer_id: str, payment_method_id: str,
                                 expected: Mapping[str, Any], nonce: "Optional[str]" = None) -> OffSessionCharge:
        """Create an OFF-SESSION Stripe PaymentIntent that charges a saved card for a credit pack (A1 — the
        auto-top-up money-out surface). MONEY DOCTRINE: the amount + currency come from the OWNER CATALOG
        (`expected[price_id]`), never the caller; an unknown price is refused. The tenant is bound into
        `metadata.org_id` + `metadata.tx_ref` (= `vigil:<org>:<nonce>`) and marked `vigil_auto_topup=1`, so the
        inbound `payment_intent.succeeded` mints exactly this org's top-up and a checkout's own PaymentIntent is
        never minted on this path. `off_session=true` + `confirm=true` charges the saved PaymentMethod immediately;
        the Idempotency-Key `vigil-at-<nonce>` makes a retried create reuse the ONE PaymentIntent (one crossing
        charges once). Returns an `OffSessionCharge` (`accepted` iff Stripe took the charge). CREDIT is minted ONLY
        by the verified webhook, never from this call. Fail-closed: no creator / invalid org / unknown or
        non-USD-minor-unit price / bad Stripe ids raise; a decline raises `StripeEgressError` (the charger records
        it). This primitive CHARGES; the caller (AutoTopUpCharger) AUTHORIZES via the owner-signed settings."""
        self.require(CAP_UNATTENDED_TOPUP)
        creator = self._payment_intent_creator
        if creator is None:                            # unreachable once require() passed; kept for type narrowing
            raise UnsupportedCapability("off-session top-up requires an injected payment_intent_creator")
        try:
            org = org_tenant_id(org_id)
        except ValueError as exc:
            raise ValueError(f"invalid org_id for off-session top-up: {exc}") from None
        exp = expected.get(price_id) if hasattr(expected, "get") else None
        if exp is None:
            raise ValueError(f"unknown price_id {price_id!r}: not in the owner catalog — off-session top-up refused "
                             "(the catalog, never the caller, decides what may be charged)")
        amount_minor, currency = int(exp[0]), str(exp[1]).strip().upper()
        if amount_minor <= 0 or not currency:
            raise ValueError(f"catalog price {price_id!r} has a non-positive amount / empty currency — refused")
        if currency not in _STRIPE_CHECKOUT_CURRENCIES:
            raise ValueError(f"Stripe off-session top-up is not enabled for {currency}: its Stripe minor unit must "
                             "first be confirmed to match the catalog's — refused")
        if not (isinstance(customer_id, str) and _STRIPE_CUS_ID.fullmatch(customer_id)):
            raise ValueError("a saved Stripe customer id (cus_...) is required for an off-session charge")
        if not (isinstance(payment_method_id, str) and _STRIPE_PM_ID.fullmatch(payment_method_id)):
            raise ValueError("a saved Stripe payment method id (pm_...) is required for an off-session charge")
        n = nonce or secrets.token_urlsafe(18)
        if not isinstance(n, str) or ":" in n or not n or any(not (0x21 <= ord(c) <= 0x7e) for c in n):
            raise ValueError("off-session nonce must be a non-empty printable string without ':' (the tx_ref "
                             "delimiter)")
        tx_ref = checkout_tx_ref(org, n)
        params: "dict[str, Any]" = {
            "amount": amount_minor,
            "currency": currency.lower(),
            "customer": customer_id,
            "payment_method": payment_method_id,
            "payment_method_types": ["card"],
            "off_session": True,
            "confirm": True,
            "metadata": {"org_id": org, "price_id": price_id, "tx_ref": tx_ref, "vigil_auto_topup": "1"},
        }
        resp = creator(params, idempotency_key=f"vigil-at-{n}")   # a decline/egress fault raises (the charger maps it)
        return self._off_session_result(resp, amount_minor=amount_minor, currency=currency)

    @staticmethod
    def _off_session_result(resp: object, *, amount_minor: int, currency: str) -> OffSessionCharge:
        """Parse the PaymentIntent the creator returned into an ``OffSessionCharge``, fail-closed (a response that
        is not our auto-top-up PaymentIntent is NOT accepted)."""
        if not isinstance(resp, Mapping) or resp.get("object") != "payment_intent":
            return OffSessionCharge("", amount_minor, currency, "unknown", False)
        pid = resp.get("id")
        if not isinstance(pid, str) or not _STRIPE_PI_ID.fullmatch(pid):
            return OffSessionCharge("", amount_minor, currency, "unknown", False)
        status = str(resp.get("status") or "")
        accepted = status in ("succeeded", "processing", "requires_capture")
        return OffSessionCharge(pid, amount_minor, currency, status, accepted)


def _stripe_return_urls(redirect_url: object) -> "tuple[str, str]":
    """(success_url, cancel_url) from the configured return URL: `status=successful&session_id={CHECKOUT_SESSION_ID}`
    / `status=cancelled` appended to the query of the hash fragment (or of the URL when it has no fragment)."""
    if not isinstance(redirect_url, str) or not redirect_url:
        raise ValueError("a Stripe checkout needs a return URL (VIGIL_CUSTOMER_BILLING_RETURN_URL) for its success "
                         "and cancel pages — refused")
    u = urlsplit(redirect_url)
    if u.scheme != "https" or not u.hostname or "@" in (u.netloc or "") \
            or any(ord(c) < 0x21 or ord(c) == 0x7f for c in redirect_url):
        raise ValueError("the Stripe checkout return URL must be an absolute https:// URL")
    tail = redirect_url.split("#", 1)[1] if "#" in redirect_url else redirect_url
    sep = "&" if "?" in tail else "?"
    return (f"{redirect_url}{sep}status=successful&session_id={{CHECKOUT_SESSION_ID}}",
            f"{redirect_url}{sep}status=cancelled")


def _stripe_plan_days(period_s: object, price_id: str) -> int:
    """A plan's recurring interval in whole days (1..365), from the catalog period; anything else is refused."""
    if isinstance(period_s, bool) or not isinstance(period_s, (int, float)) or not math.isfinite(period_s):
        raise ValueError(f"no catalog period for Stripe plan {price_id!r} — refused")
    days, rem = divmod(float(period_s), 86400.0)
    if rem != 0.0 or not 1 <= days <= 365:
        raise ValueError(f"Stripe plan {price_id!r} period must be a whole number of days between 1 and 365")
    return int(days)


def _stripe_meta(meta: object, key: str) -> str:
    v = meta.get(key) if isinstance(meta, Mapping) else None
    return v if isinstance(v, str) else ""


def _stripe_ref(v: object) -> Optional[str]:
    """The id of a Stripe reference field: the string itself, or the ``id`` of an expanded object; None otherwise."""
    if isinstance(v, Mapping):
        v = v.get("id")
    return v if isinstance(v, str) and v else None


def _stripe_tenant(tx_ref: object, meta: object) -> Optional[str]:
    """The ONE tenant named by the fetched object: `tx_ref` (client_reference_id) and `metadata.tx_ref` /
    `metadata.org_id`, each validated. None when none is valid or when two of them disagree (never act on a guess)."""
    found = {o for o in (_org_from_tx_ref(tx_ref), _org_from_tx_ref(_stripe_meta(meta, "tx_ref") or None),
                         _parse_org_id(_stripe_meta(meta, "org_id") or None)) if o is not None}
    return found.pop() if len(found) == 1 else None


def _stripe_ts(v: object) -> Optional[float]:
    """A Stripe unix timestamp (an integer) as a stable epoch float, or None. Never a wall-clock fallback."""
    if isinstance(v, bool) or not isinstance(v, int) or not 0 < v < _STRIPE_TS_MAX:
        return None
    return float(v)


def _stripe_amount(amount: object, currency: object) -> "tuple[int, str]":
    """(minor-unit amount, ISO-4217 upper) from a fetched object. The currency must be three ASCII letters (else
    ""); the amount must be a non-negative integer (else 0, which the signer's underpay check refuses)."""
    ccy = currency.upper() if isinstance(currency, str) and len(currency) == 3 and currency.isascii() \
        and currency.isalpha() else ""
    amt = amount if isinstance(amount, int) and not isinstance(amount, bool) and amount >= 0 else 0
    return amt, ccy


def refund_credits(cap: int, refunded: int, amount: int) -> int:
    """The credits a processor REFUND of ``refunded`` minor units removes from a purchase of ``cap`` credits that
    was charged ``amount``. A refund of the whole charge removes all ``cap`` credits (Terms §8: in the same
    proportion). A partial refund removes the smaller of the refunded proportion rounded down (``cap x refunded /
    amount``) and the fewest credits whose price in proportion, rounded UP to the minor unit, comes to ``refunded``
    or more. The withdrawal runbook refunds N unused credits of a pack at their price rounded up, and below the whole
    price unless every credit is unused (``sigil billing-reversal unused``), so that refund never removes more than N
    credits, whichever of the drain and the owner's refund verb comes first, including for a pack worth more than one
    credit per minor unit. PURE."""
    r = min(max(0, int(refunded)), int(amount))
    if r <= 0 or cap <= 0:
        return 0
    if r == amount:
        return cap
    return min(cap * r // amount, cap * (r - 1) // amount + 1)


def _as_float(v: object, default: float = 0.0) -> float:
    import math
    try:
        f = float(v)                                  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default
    return f if math.isfinite(f) else default


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
    `{"status":"success","data":{"link":"https://checkout.flutterwave.com/..."}}`. HARDENED (red-pen): accept ONLY
    an https link on the Flutterwave hosted-checkout domain, carrying NO whitespace / control characters (so a
    smuggled CR/LF can never split a later `Location:` header) and NO embedded credentials — a missing / non-https
    / `data:` / `javascript:` / foreign-host / control-char link is refused (never hand the browser a hostile or
    header-splitting URL, even from a compromised/MITM'd provider response)."""
    if not isinstance(resp, Mapping) or resp.get("status") != "success":
        return None
    data = resp.get("data")
    link = data.get("link") if isinstance(data, Mapping) else None
    return _https_link_on(link, suffix_domains=_FLW_CHECKOUT_DOMAINS)


_FLW_CHECKOUT_DOMAINS = frozenset({"flutterwave.com"})


def _https_link_on(link: object, *, exact_hosts: "frozenset[str] | tuple[str, ...]" = (),
                   suffix_domains: "frozenset[str] | tuple[str, ...]" = ()) -> Optional[str]:
    """``link`` if it is a safe hosted-checkout URL on a pinned host, else None (fail-closed). Safe means: an
    ``https://`` URL with NO whitespace / control characters (a smuggled CR/LF can never split a later
    ``Location:`` header), NO embedded credentials, a host, and a host that is EXACTLY one of ``exact_hosts`` or is
    one of ``suffix_domains`` / a subdomain of one (``host == d or host.endswith("." + d)`` — never a bare suffix
    match, so ``evilflutterwave.com`` is refused). Shared by every provider's checkout-link check."""
    if not isinstance(link, str) or not link.startswith("https://"):
        return None
    if any(ord(c) < 0x21 or ord(c) == 0x7f for c in link):     # whitespace / control chars (CRLF response-split)
        return None
    try:
        u = urlsplit(link)
    except ValueError:
        return None
    host = (u.hostname or "").lower()
    if u.scheme != "https" or "@" in (u.netloc or "") or not host:   # no userinfo; must have a host
        return None
    if host in exact_hosts:
        return link
    if any(host == d or host.endswith("." + d) for d in suffix_domains):
        return link
    return None                                                # pin the provider's hosted-checkout domain


def checkout_tx_ref(org_id: str, nonce: str) -> str:
    """The tenant-binding checkout reference ``vigil:<org>:<nonce>`` every provider carries (Flutterwave ``tx_ref``,
    Stripe ``client_reference_id``), so the inbound mint and the dangling-reference sweep read one format. It is
    also the tx_ref ``create_checkout`` sets for ``(org_id, nonce)``, so a caller can record it BEFORE the outbound
    call (the provisioner's pending plan-checkout record). Validates the org and the nonce (fail-closed)."""
    org = org_tenant_id(org_id)
    if not isinstance(nonce, str) or ":" in nonce or not nonce:
        raise ValueError("checkout nonce must be a non-empty string without ':' (the tx_ref delimiter)")
    return f"{_TX_REF_PREFIX}:{org}:{nonce}"


@dataclass(frozen=True)
class OffSessionCharge:
    """The result of an A1 OFF-SESSION top-up charge (``StripeBillingProvider.create_off_session_topup``). ``accepted``
    is True iff Stripe took the charge (status ``succeeded`` / ``processing`` / ``requires_capture``); the CREDIT is
    still minted only by the verified ``payment_intent.succeeded`` webhook, keyed on this ``payment_intent_id``. The
    ``amount_minor`` / ``currency`` are the OWNER-CATALOG values this charge collected — never caller-supplied."""
    payment_intent_id: str
    amount_minor: int
    currency: str
    status: str
    accepted: bool


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
    """Flutterwave v3 webhook verification — the RETAINED Flutterwave adapter (development paused; selectable with
    ``VIGIL_BILLING_PROVIDER=flutterwave``, no longer the default — Stripe is).

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

    SCOPE: we act ONLY on a re-verified `charge.completed`, taking EVERY tenant/money/status field from the
    AUTHORITATIVE verify object (never the body). A SUCCESSFUL charge mints (top-up or plan period). A definitively
    FAILED RECURRING charge (verified status `failed` + a `payment_plan`) drives DUNNING — EVENT_PAYMENT_FAILED, so
    the subscription latches to past_due (access-reducing, reversible; H4). Both are sound because the org is taken
    from the RE-VERIFIED tx_ref we set at our own checkout, so a verif-hash holder cannot name a victim tenant. We
    still do NOT act on a bare `subscription.cancelled` webhook — with no transaction to re-verify there is no
    authoritative subscription→org mapping — so a cancelled plan instead EXPIRES at period_end via the meter's
    active-subscription check (non-rollover), the safe body-independent outcome; webhook-driven cancel awaits that
    mapping (a reconcile capability).

    NOTE (sandbox-confirm): exact field shapes (meta echo as dict vs list, `payment_plan` presence on a plan
    charge, `created_at` string format) should be confirmed against a Flutterwave sandbox; this handles the
    documented shapes and fails closed on anything it cannot validate. Mobile Money / card / checkout creation
    and refunds are declared capabilities exercised by the outbound flows (next slice)."""

    def __init__(self, secret_hash: str, verifier: TransactionVerifier, *, noauth_approved: bool = False,
                 checkout_creator: "Optional[CheckoutCreator]" = None, alarm_unaccounted_plans: bool = False):
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
        # Plan checkout (CHK-1b): a RECURRING renewal must still attribute to its tenant. Whether the processor
        # echoes our tx_ref / meta.org_id on renewals is a sandbox-confirm item, so with plan checkout ON a
        # verified-SUCCESSFUL payment_plan charge with no recoverable tenant RAISES UnaccountedPayment (quarantine +
        # alarm) instead of a silent no-op. Default OFF ⇒ byte-identical.
        self._alarm_unaccounted_plans = bool(alarm_unaccounted_plans)

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
        # AUTHORITATIVE `/v3/transactions/{id}/verify` object only. We therefore act solely on a `charge.completed`
        # whose transaction INDEPENDENTLY re-verifies: a `successful` one MINTS (top-up or plan period); a
        # definitively `failed` RECURRING one (a `payment_plan` charge) drives DUNNING (EVENT_PAYMENT_FAILED ->
        # past_due; H4) — sound because org/status/timestamp all come from the verify object, so a verif-hash holder
        # cannot name a victim (the tx_ref is one we set at our own checkout).
        #
        # We deliberately do NOT act on a bare `subscription.cancelled` webhook (no webhook-driven CANCEL): with no
        # transaction to re-verify, the verify endpoint is per-TRANSACTION, not per-subscription, so there is no
        # authoritative subscription→org mapping yet (that lands with a reconcile capability). Until then a
        # cancelled plan simply EXPIRES at period_end via the meter's active-subscription check (non-rollover).
        if obj.get("event") != "charge.completed":
            return None
        data_raw = obj.get("data")
        txid = data_raw.get("id") if isinstance(data_raw, dict) else None
        if txid is None:
            return None                               # the body is trusted ONLY for the transaction id to verify
        verified = self._verifier(str(txid))          # AUTHORITATIVE server-side re-verify — the ONLY trust source
        if not isinstance(verified, dict):
            return None                               # unverifiable -> act on nothing
        status = verified.get("status")
        vid = verified.get("id")                      # the idempotency / audit anchor is the CANONICAL verified id,
        if vid is None:                               # NEVER the body's spelling (two spellings of one real tx that
            return None                               # /verify collapses to one id must collapse to ONE action);
        event_id = str(vid)                           # fail-closed without it.
        org = _flw_org_id(verified)                   # tenant from the VERIFIED object only (never the body)
        if org is None:
            if self._alarm_unaccounted_plans and status == "successful" and verified.get("payment_plan"):
                raise UnaccountedPayment(f"verified successful payment_plan charge {event_id} has no recoverable "
                                         f"tenant (tx_ref/meta) — paid but UN-MINTED; reconcile by hand")
            return None                               # no recoverable tenant -> never act on a guess
        created = _flw_created(verified)              # stable epoch from the VERIFIED object; fail-closed if absent
        if created is None:
            if self._alarm_unaccounted_plans and status == "successful" and verified.get("payment_plan"):
                raise UnaccountedPayment(f"verified successful payment_plan charge {event_id} has no parseable "
                                         f"timestamp — paid but UN-MINTED; reconcile by hand")
            return None                               # replay-safety needs a stable timestamp -> no `now` fallback
        tx_ref = verified.get("tx_ref")
        if status == "successful":
            amt_minor, ccy = _flw_amount_minor(verified)  # Slice F: the VERIFIED amount for the signer's price cross-check
            if not ccy:
                # A verified SUCCESSFUL charge must name its currency. Without one, BillingSigner.apply's underpay /
                # wrong-currency cross-check is skipped (it keys on event.currency) and the catalog entitlement would
                # mint on the price_id alone. Flutterwave populates the currency on every real charge, so its absence
                # is a malformed verify object: mint nothing (fail-closed). With the alarm armed this is loud for ANY
                # paid charge, not only payment_plan ones: returning here also skips apply()'s catalog-aware alarm
                # for a plan price that arrived without payment_plan, which must not go quiet.
                if self._alarm_unaccounted_plans:
                    raise UnaccountedPayment(f"verified successful charge {event_id} for org {org!r} has no "
                                             f"currency — paid but UN-MINTED; reconcile by hand")
                return None
            if verified.get("payment_plan"):          # plan-vs-topup decided by the VERIFIED object only
                return BillingEvent(event_id=event_id, kind=EVENT_SUBSCRIPTION_ACTIVE, org_id=org, created=created,
                                    price_id=str(verified.get("payment_plan") or ""), amount_minor=amt_minor,
                                    currency=ccy, data={"tx_ref": tx_ref})
            return BillingEvent(event_id=event_id, kind=EVENT_TOPUP, org_id=org, created=created,
                                price_id=_flw_price_id(verified), amount_minor=amt_minor, currency=ccy,
                                data={"tx_ref": tx_ref})
        # H4 — webhook-driven DUNNING (access-REDUCING only). A charge that AUTHORITATIVELY re-verifies as `failed`
        # AND carries a `payment_plan` is a failed RECURRING (subscription) debit -> emit EVENT_PAYMENT_FAILED so the
        # signer latches the subscription to past_due (REVERSIBLE: a later successful renewal re-activates). SOUND
        # because org + status + timestamp all come from the RE-VERIFIED object, never the untrusted body — a
        # verif-hash holder cannot name a victim (the tx_ref it would need is one WE set at our own checkout). The
        # `created` rides through as the down-latch's freshness key (subscription._fold), so a stale / out-of-order /
        # replayed failure cannot re-suspend a recovered tenant. A failed ONE-TIME top-up carries no payment_plan and
        # reduces nothing -> no-op. A non-terminal status (pending/...) -> no-op (never reduce on a non-definitive
        # answer; a TRANSIENT verify failure RAISES out of the verifier per its contract, never reaching here as a
        # definitive non-success). We still do NOT act on a bare `subscription.cancelled` webhook: with no
        # transaction to re-verify there is no sound subscription->org mapping, and such a plan already EXPIRES at
        # period_end (non-rollover) — webhook-driven cancel awaits that mapping (a reconcile capability).
        if status == "failed" and verified.get("payment_plan"):
            return BillingEvent(event_id=event_id, kind=EVENT_PAYMENT_FAILED, org_id=org, created=created,
                                price_id=str(verified.get("payment_plan") or ""),
                                data={"tx_ref": tx_ref, "dunning": "payment_failed"})
        return None

    def create_checkout(self, org_id: str, price_id: str, *, expected: Mapping[str, Any],
                        customer_email: "Optional[str]" = None, redirect_url: "Optional[str]" = None,
                        nonce: "Optional[str]" = None, payment_plan: "Optional[str]" = None,
                        session_minutes: "Optional[int]" = None,
                        save_future_payments: bool = False) -> CheckoutSession:
        """Create a tenant-bound hosted checkout for `price_id` (Slice F — the outbound money-in surface).

        ``save_future_payments`` (A1) is a Stripe-only concern (saving a card for off-session auto top-ups); the
        Flutterwave flow saves no card here, so it is accepted and IGNORED (the payload is unchanged).

        MONEY DOCTRINE, enforced here: the amount + currency are taken from the OWNER CATALOG (`expected[price_id]`,
        i.e. `catalog.expected_amounts()`), NEVER from the caller — a customer can name neither a price nor an
        amount, and an unknown price_id is REFUSED rather than charged at a caller-chosen figure. TENANT BINDING
        (consistency, NOT authorization): the org is validated for FORMAT (`org_tenant_id`, fail-closed) and bound
        into BOTH `tx_ref = vigil:<org>:<nonce>` AND `meta.org_id`, so the inbound mint credits exactly the org
        named at checkout and the two bindings can never disagree. This does NOT authorize the caller to name that
        org — the CHECKOUT ENDPOINT MUST gate first with `OrgRegistry.admit_customer(requester, org_id, <billing
        permission>)` (admit-first, as the provisioner does) so a customer cannot open a checkout that funds
        another tenant. This primitive BINDS; the edge AUTHORIZES. Fail-closed throughout: no creator, an invalid
        org, an unknown/empty price, a creator that raises, or a response without an https hosted link on the
        provider domain RAISES (`UnsupportedCapability`/`ValueError`) — never a half-formed, unpriced, or
        wrongly-attributed checkout."""
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
        tx_ref = checkout_tx_ref(org, nonce or secrets.token_urlsafe(18))   # validates the nonce (fail-closed)
        payload: "dict[str, Any]" = {
            "tx_ref": tx_ref,
            "amount": _to_major(amount_minor, currency),   # major units, from the CATALOG (never the caller)
            "currency": currency,
            "meta": {"org_id": org, "price_id": price_id},  # redundant tenant+price binding (belt-and-suspenders)
        }
        if redirect_url:
            payload["redirect_url"] = str(redirect_url)
        if payment_plan is not None:
            # CHK-1b: a SUBSCRIPTION checkout subscribes the payer to the processor's recurring plan. The catalog's
            # subscription price_id IS that payment_plan id, so every renewal re-verifies with payment_plan ==
            # price_id and maps back to the same catalog entitlement. Validated like any field we post.
            pp = str(payment_plan)
            if not pp or len(pp) > 128 or any(ord(c) < 0x21 or ord(c) == 0x7f for c in pp):
                raise ValueError("payment_plan must be a non-empty printable id")
            payload["payment_plan"] = pp
        if session_minutes is not None:
            # Audit E1b: bound how long the hosted payment page can be paid (Flutterwave Standard `session_duration`,
            # minutes, ceiling 1440: once it elapses the processor closes the page and fails any uncompleted
            # transaction) — so the provisioner's pending plan-checkout record, which outlives this session, cannot
            # lapse while its link could still bill.
            sm = session_minutes
            if isinstance(sm, bool) or not isinstance(sm, int) or not 1 <= sm <= 1440:
                raise ValueError("session_minutes must be an int in [1, 1440]")
            payload["configurations"] = {"session_duration": sm}
        if customer_email:
            payload["customer"] = {"email": str(customer_email)}
        try:
            resp = self._checkout_creator(payload)
        except Exception as exc:  # noqa: BLE001 — any outbound failure (timeout/TLS/connection-reset/5xx) is a
            raise UnsupportedCapability(                       # REFUSAL, re-raised as the documented contract type;
                f"checkout creation failed ({type(exc).__name__})") from None   # provider internals are dropped
        link = _flw_checkout_link(resp)
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


def _is_monitoring_entitlement(ent: "Entitlement") -> bool:
    """True iff the catalog entitlement is an AEGIS monitoring plan (the CATALOG decides — lazy import: catalog
    imports this module)."""
    from .catalog import monitoring_plan
    return ent.kind == EVENT_SUBSCRIPTION_ACTIVE and bool(ent.plan_id) and monitoring_plan(ent.plan_id) is not None


class BillingSigner:
    """Converts a provider-VERIFIED billing event into exactly one owner-signed sovereign mint — the
    EVIDENCE→FACT boundary. Composes the sovereign registries (wallet, subscription, plan-credit ledger) and an
    owner-controlled price→entitlement `catalog`. Deterministic + idempotent; never mints from an unverified
    event and never lets an on-the-wire amount decide money (only the catalog does)."""

    def __init__(self, provider: BillingProvider, *, wallet, subscriptions, plan, catalog: Mapping[str, Entitlement],
                 expected: "Optional[Mapping[str, Any]]" = None, invoices=None, monitoring_subscriptions=None,
                 on_monitoring_change=None, alarm_unaccounted_plans: bool = False, report_unlocks=None,
                 require_verified_amount: bool = False, alarm_unaccounted_topups: bool = False, reversals=None,
                 on_saved_payment_method=None):
        self.provider = provider
        # W5: the owner-signed reversal ledger (governor.billing_reversal), given only while
        # config.billing_reversals_enabled(). With it, a verified EVENT_REVERSAL moves credits out of (or back into)
        # the wallet, and every top-up first repays what the org owes. None keeps every path byte-identical.
        self.reversals = reversals
        # A1: the saved-payment-method capture hook. When wired (A1 on), a TOP-UP checkout mint whose session asked
        # Stripe to save the card calls `on_saved_payment_method(org_id, customer_id, payment_intent_id, created)`;
        # the hook resolves the pm id (a PaymentIntent fetch) and records it owner-signed. None (default) => no-op,
        # byte-identical: the mint path is unchanged and a session that did not ask to save the card never reaches
        # the hook anyway (the ids are absent from event.data).
        self.on_saved_payment_method = on_saved_payment_method
        # Pricing S4: the owner-signed report-unlock ledger (governor.report_unlock). When injected, the FIRST
        # verified credit purchase of an org (a top-up, or a credit-plan period the fold honours) also records a
        # billing unlock — decided once, here, at mint time. None keeps every record byte-identical to before.
        self.report_unlocks = report_unlocks
        # AEGIS: a catalog MONITORING plan mints onto its OWN line (governor.monitoring_subscription), never the
        # credit-plan `subscriptions` record (which drives the plan-credit refill). None => monitoring plans mint
        # nothing (fail-closed). `on_monitoring_change(org_id, now)` is the sovereign provisioner hook that
        # enforces the new plan on existing grants and re-mints renewals (owner key, republish).
        self.monitoring_subscriptions = monitoring_subscriptions
        self.on_monitoring_change = on_monitoring_change
        self.wallet = wallet
        self.subscriptions = subscriptions
        self.plan = plan
        # Slice H: the optional per-tenant invoice / billing-history ledger. When injected, each value-granting
        # mint ALSO records one owner-signed billing-history line (idempotent by the SAME provider event_id, so a
        # webhook replay folds once — no duplicate charge). None keeps every existing caller byte-identical (no
        # invoice emitted). The money amount on the line is the owner-CATALOG price (`expected`), NEVER the wire
        # amount — the money doctrine, identical to how the catalog (not the webhook) decides the entitlement.
        self.invoices = invoices
        self.catalog = dict(catalog)
        # Slice F: the owner catalog's EXPECTED (amount_minor, currency) per price_id (= catalog.expected_amounts()),
        # for the defense-in-depth underpay / wrong-currency cross-check in apply(). Empty ⇒ the cross-check is
        # skipped (backward-compatible; the primary binding is still "the catalog decides the entitlement for the
        # price_id we set at checkout").
        self._expected = {str(k): (int(v[0]), str(v[1]).upper()) for k, v in dict(expected or {}).items()}
        # CHK-1b: with plan checkout ON, a verified subscription charge whose price is NOT in the owner catalog is
        # a paid-but-uncredited charge -> raise UnaccountedPayment (quarantine + alarm). Default OFF ⇒ byte-identical
        # (the deliberate top-up "unknown price is a safe no-op" decision is untouched either way).
        self._alarm_unaccounted_plans = bool(alarm_unaccounted_plans)
        # Opt-in (default OFF => byte-identical): a priced TOPUP / plan ACTIVE event must carry a verified currency,
        # or it mints nothing (a plan raises UnaccountedPayment when the alarm is on); the underpay check then
        # bounds the amount. The Flutterwave adapter already enforces this itself (#1093); a signer serving another
        # provider sets it.
        self._require_verified_amount = bool(require_verified_amount)
        # Opt-in (default OFF => byte-identical): a verified TOP-UP the signer cannot credit at the catalog's price —
        # a price not in the catalog (with a verified paid amount), no verified currency (require_verified_amount),
        # or less than / another currency than the catalog price — raises UnaccountedPayment (the drain quarantines
        # and alarms) instead of archiving a paid charge as a no-op. Nothing is written either way.
        self._alarm_unaccounted_topups = bool(alarm_unaccounted_topups)
        self._last_outcome: Optional[IngestOutcome] = None

    def ingest(self, raw_body: bytes, sig_header: str, *, now: float) -> Optional[int]:
        """Verify, then mint. Returns the appended spine seq, or None when the event does not verify, carries no
        catalog entitlement, or maps to a no-op. Idempotent by the provider event_id."""
        out = self._ingest(raw_body, sig_header, now=now)
        self._last_outcome = out
        return out.seq

    def ingest_outcome(self, raw_body: bytes, sig_header: str, *, now: float) -> IngestOutcome:
        """``ingest``, also returning WHY it minted or not (``IngestOutcome``; report-only). It goes through
        ``ingest`` itself, so a subclass that wraps ``ingest`` still sees every call; when such a wrapper returns
        a seq this signer did not produce, the outcome is ``unrecorded`` (or minted, for a seq)."""
        self._last_outcome = None
        seq = self.ingest(raw_body, sig_header, now=now)
        out, self._last_outcome = self._last_outcome, None
        if out is None or out.seq != seq:
            return IngestOutcome(seq, None, OUTCOME_MINTED if seq is not None else "unrecorded")
        return out

    def _ingest(self, raw_body: bytes, sig_header: str, *, now: float) -> IngestOutcome:
        event = self.provider.verify_and_parse(raw_body, sig_header, now=now)
        if event is None:
            return IngestOutcome(None, None, "not_mintable")   # unverified / unhandled -> mint nothing
        seq, reason = self._apply_outcome(event, now=now)
        return IngestOutcome(seq, event, reason)

    def apply(self, event: BillingEvent, *, now: float) -> Optional[int]:
        """Mint the sovereign record for an ALREADY-VERIFIED event. Separated from `ingest` so a caller that has
        its own verified-event source can reuse the deterministic mapping; external callers use `ingest`, which
        is the only path that enforces signature verification."""
        return self._apply_outcome(event, now=now)[0]

    @staticmethod
    def _done(seq: Optional[int]) -> "tuple[Optional[int], str]":
        """A state change that appended ``seq`` (minted), or nothing the fold would honour (stale_or_inert)."""
        return seq, (OUTCOME_MINTED if seq is not None else "stale_or_inert")

    def _apply_outcome(self, event: BillingEvent, *, now: float) -> "tuple[Optional[int], str]":
        """``apply`` with the reason (``IngestOutcome.reason``) beside the seq. Every money decision is ``apply``'s;
        the reason only names which of them was taken."""
        if event.kind == EVENT_REVERSAL:
            return self._apply_reversal(event, now=now)
        oid = event.org_id                            # already validated in verify_and_parse (_parse_org_id)
        ent = self.catalog.get(event.price_id)
        # Route by the FULL, flag-independent catalog (never the flag-filtered entitlements): a down event for a
        # known AEGIS price goes to the monitoring line ONLY, never the credit plan. NOTE: the Stripe reference
        # adapter (disabled by default) must carry metadata.price_id on payment_failed for this routing to apply;
        # a down event with an unknown/absent price keeps the pre-AEGIS behaviour (credit line).
        from .catalog import monitoring_price_ids
        monitoring = event.price_id in monitoring_price_ids() or (ent is not None and _is_monitoring_entitlement(ent))
        line = self.monitoring_subscriptions if monitoring else self.subscriptions
        if event.kind in (EVENT_SUBSCRIPTION_CANCELED, EVENT_PAYMENT_FAILED) and line is None:
            return None, "no_line"
        if event.kind == EVENT_SUBSCRIPTION_CANCELED:
            return self._done(line.cancel(oid))       # safe direction, honored on sight, replay-safe
        if event.kind == EVENT_PAYMENT_FAILED:
            # Webhook-driven dunning (H4): carry the provider event's `created` as the down-latch freshness key so
            # a stale / out-of-order / replayed failed-charge cannot re-suspend a tenant who has since recovered.
            return self._done(line.mark_past_due(oid, issued_at=event.created))
        # CHK-1b red-pen MED: a verified SUCCESSFUL charge for a catalog SUBSCRIPTION price that arrived WITHOUT
        # payment_plan maps to a top-up and would fall through to "mint nothing" — the charged-for-nothing hole
        # again. With the plan alarm armed it is quarantined (loud), never a silent no-op.
        if (self._alarm_unaccounted_plans and event.kind == EVENT_TOPUP and ent is not None
                and ent.kind == EVENT_SUBSCRIPTION_ACTIVE):
            raise UnaccountedPayment(f"verified charge {event.event_id} for org {oid!r} names subscription price "
                                     f"{event.price_id!r} but carries no payment_plan — paid but UN-MINTED; "
                                     f"reconcile by hand")
        if ent is None:
            if self._alarm_unaccounted_plans and event.kind == EVENT_SUBSCRIPTION_ACTIVE:
                raise UnaccountedPayment(f"verified subscription charge {event.event_id} for org {oid!r} names "
                                         f"price {event.price_id!r}, which is not in the owner catalog — paid but "
                                         f"UN-MINTED; reconcile by hand")
            if (self._alarm_unaccounted_topups and event.kind == EVENT_TOPUP and event.currency
                    and int(event.amount_minor) > 0):
                raise UnaccountedPayment(f"verified top-up {event.event_id} for org {oid!r} paid "
                                         f"{event.amount_minor} {event.currency} for price {event.price_id!r}, which "
                                         f"is not in the owner catalog — paid but UN-MINTED; refund it or "
                                         f"reconcile (runbook)")
            return None, "unknown_price"              # unknown price -> no entitlement -> mint nothing
        # Slice F — DEFENSE-IN-DEPTH underpay / wrong-currency guard. For a value-GRANTING event, refuse a VERIFIED
        # amount below the owner catalog's expected price (or in the wrong currency): belt-and-suspenders on top of
        # "the price_id we set at checkout". Fires only when (a) an expected price is configured for this price_id
        # AND (b) the event carries a verified amount (currency present) — a provider that does not populate the
        # amount is still bound by the price_id -> entitlement mapping, not silently refused here.
        if event.kind in (EVENT_TOPUP, EVENT_SUBSCRIPTION_ACTIVE):
            exp = self._expected.get(event.price_id)
            # (an amount below the catalog price, including 0, is refused by the underpay check just below)
            if exp is not None and self._require_verified_amount and not event.currency:
                if self._alarm_unaccounted_plans and event.kind == EVENT_SUBSCRIPTION_ACTIVE:
                    raise UnaccountedPayment(
                        f"verified plan charge {event.event_id} for org {oid!r} carries no verified amount/currency "
                        f"for {event.price_id!r} — paid but UN-MINTED; reconcile the processor plan vs the catalog")
                if self._alarm_unaccounted_topups and event.kind == EVENT_TOPUP:
                    raise UnaccountedPayment(
                        f"verified top-up {event.event_id} for org {oid!r} carries no verified amount/currency, the "
                        f"catalog expects {exp[0]} {exp[1]} for {event.price_id!r} — paid but UN-MINTED; refund it "
                        f"or reconcile (runbook)")
                return None, "no_verified_amount"     # no verified amount/currency -> mint nothing (fail-closed)
            if exp is not None and event.currency:
                if event.currency.upper() != exp[1] or int(event.amount_minor) < exp[0]:
                    if self._alarm_unaccounted_plans and event.kind == EVENT_SUBSCRIPTION_ACTIVE:
                        # CHK-1b red-pen MED: a plan renewal billed at an amount/currency that no longer matches
                        # the catalog (e.g. the owner repriced) would silently mint nothing every period.
                        raise UnaccountedPayment(
                            f"verified plan charge {event.event_id} for org {oid!r} paid "
                            f"{event.amount_minor} {event.currency} but the catalog expects {exp[0]} {exp[1]} for "
                            f"{event.price_id!r} — paid but UN-MINTED; reconcile the processor plan vs the catalog")
                    if self._alarm_unaccounted_topups and event.kind == EVENT_TOPUP:
                        raise UnaccountedPayment(
                            f"verified top-up {event.event_id} for org {oid!r} paid {event.amount_minor} "
                            f"{event.currency}, the catalog expects {exp[0]} {exp[1]} for {event.price_id!r} — paid "
                            f"but UN-MINTED; refund it or reconcile (runbook)")
                    return None, "underpaid_or_currency"   # underpaid / wrong currency -> mint nothing (fail-closed)
            # Red-pen FINDING 1: event_id is the idempotency anchor for the wallet entry_id (top-up) AND the
            # invoice_id (both value paths), but verify_and_parse only checks it is a non-empty str. Bound it to
            # the SAME shape the wallet/invoice ledgers require (<= 128, non-control) HERE, so a pathological id
            # fails the WHOLE value-granting event CLOSED (mint nothing) — symmetric across top-up and
            # subscription — instead of the asymmetric half-mint (top-up's wallet.grant raised and aborted, but
            # subscribe/refill never touch event_id, so the subscription committed while only its invoice raised).
            # .strip() to match the ledger validators EXACTLY (_check_entry_id/_check_invoice_id both strip then
            # require non-empty): a whitespace-only event_id (" ") would otherwise pass this bound yet strip to ""
            # inside invoice.record() and raise AFTER the subscription mint committed — re-opening the half-mint
            # this bound closes (red-pen completeness-critic). Stripping fails it CLOSED here, symmetric.
            eid = str(event.event_id or "").strip()
            if not eid or len(eid) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in eid):
                return None, "bad_event_id"
        if event.kind == EVENT_TOPUP and ent.kind == EVENT_TOPUP and ent.credits > 0:
            # idempotent by event_id: a duplicate delivery reuses the same wallet entry_id -> folded once.
            seq = self.wallet.grant(oid, int(ent.credits), "topup", source_ref=event.event_id,
                                    entry_id=event.event_id, issued_at=event.created)
            if seq is not None:                       # record the history line only for a mint that took effect
                self._maybe_unlock(oid, event, "topup")
                self._record_invoice(oid, event, "topup", credits=int(ent.credits))
                self._maybe_capture_method(oid, event)   # A1: capture a saved card from this checkout (hook-gated)
            self._repay_arrears(oid, event, now=now)  # W5: a top-up first repays what the org owes (re-drive safe)
            return self._done(seq)
        if event.kind == EVENT_SUBSCRIPTION_ACTIVE and ent.kind == EVENT_SUBSCRIPTION_ACTIVE \
                and ent.plan_id and ent.period_s > 0.0 and monitoring:
            return self._apply_monitoring(oid, event, ent)
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
            seq = refill_active_subscription(self.subscriptions, self.plan, oid, issued_at=event.created)
            # Red-pen FINDING 2, kept: the billing history never shows a period the plan ledger did not deliver.
            # The refill returns None once the period's tranche exists, so gating ONLY on its seq would lose the
            # invoice (and the unlock) for good if a crash fell between the refill and the invoice. So the record
            # is also written on a re-drive that finds this event's period honoured, active and DELIVERED (its
            # tranche granted) yet not invoiced under any event id — never for a stale event, an undelivered
            # period, or a second distinct event for a period already invoiced.
            delivered = self._period_delivered_unrecorded(oid, event, ent, period_end)
            if delivered:
                self._maybe_unlock(oid, event, "subscription")
                self._record_invoice(oid, event, "subscription", credits=int(ent.allotment),
                                     period_start=event.created, period_end=period_end)
            if seq is None and delivered:
                return None, OUTCOME_ALREADY_MINTED   # this event's period is the honoured, delivered one
            return self._done(seq)
        return None, "no_entitlement"

    # -- W5: reversals and the arrears they leave ----------------------------------------------------------------
    def _repay_arrears(self, oid: str, event: BillingEvent, *, now: float) -> None:
        """After a top-up's grant, repay what the org owes from its wallet (``BillingReversalLedger.repay``: exactly
        once per debt, so a duplicate or a re-drive of the event repays nothing twice), then mirror the hold for the
        owner's alarms. No-op without a reversal ledger (flag off)."""
        if self.reversals is None:
            return
        res = self.reversals.repay(oid, event.event_id, now=float(now))
        from .billing_hold import sync_hold
        sync_hold(oid, res.owed)

    def _apply_reversal(self, event: BillingEvent, *, now: float) -> "tuple[Optional[int], str]":
        """A verified reversal of a top-up: move that purchase's removed credits to its target (``reconcile``) from the
        processor's facts, converted to credits at the purchase's own rate: a dispute as ``credits x amount / charge
        amount``, rounded down, and a refund by ``refund_credits`` (never more than that, nor more than the unused
        credits a runbook refund paid back); never more than the purchase granted. The purchase's credits come from
        its owner-signed billing-history line and its grant must be on the spine; a purchase not credited YET is
        retried (``ReversalRetry``), one VIGIL cannot account for is refused (``ReversalUnaccounted``)."""
        if self.reversals is None:
            return None, "not_mintable"               # unreachable: a provider maps reversals only with the flag on
        if "plan_invoice" in (event.data or {}):
            return self._apply_plan_reversal(event, now=now)
        from .billing_hold import sync_hold
        from .billing_reversal import ReversalRetry
        oid, data = event.org_id, event.data or {}
        topup, trigger = data.get("topup"), data.get("trigger")
        refunded, disputed, amount = data.get("refunded_minor"), data.get("disputed_minor"), event.amount_minor

        def _nn_int(v: object) -> bool:
            return isinstance(v, int) and not isinstance(v, bool) and v >= 0
        if not (isinstance(topup, str) and topup and trigger in ("dispute", "refund")
                and _nn_int(refunded) and _nn_int(disputed) and isinstance(amount, int)
                and not isinstance(amount, bool) and amount > 0):
            raise ReversalUnaccounted(f"reversal {event.event_id} for org {oid!r} is malformed")
        if self.invoices is None:
            raise ReversalUnaccounted(f"reversal {event.event_id} for org {oid!r}: no billing history to price it")
        line = next((i for i in self.invoices.invoices(oid) if i.invoice_id == topup and i.kind == "topup"), None)
        if line is None or line.credits <= 0 or not self.wallet.has_grant_entry(oid, topup):
            raise ReversalRetry(f"purchase {topup} of org {oid!r} is not credited yet; its reversal is retried")
        if line.currency and event.currency and line.currency.upper() != event.currency.upper():
            raise ReversalUnaccounted(f"reversal {event.event_id} for org {oid!r} is in {event.currency}, the purchase "
                                      f"{topup} in {line.currency}")
        cap, amt = int(line.credits), int(amount)                  # amount is narrowed to int above
        sr, dd = cast(int, refunded), cast(int, disputed)          # validated non-negative ints above
        res = self.reversals.reconcile(oid, topup, cap=cap, reason=str(trigger), now=float(now),
                                       processor_refunded=refund_credits(cap, sr, amt),
                                       disputed=cap * min(dd, amt) // amt)
        sync_hold(oid, res.owed)
        return self._done(res.seq)

    def _apply_plan_reversal(self, event: BillingEvent, *, now: float) -> "tuple[Optional[int], str]":
        """A verified REFUND of a plan period: remove that period's plan credits in the refunded proportion
        (``allotment x refunded / charge amount``, rounded down) from what remains of its tranche
        (``BillingReversalLedger.reconcile_plan``: never more than remains, never negative, never a grant). The period
        is the owner-signed billing-history line of the invoice, and its tranche must be on the spine; a period not
        credited YET is retried (``ReversalRetry``), one with no credits (a monitoring plan), in another currency, or
        whose charge is not the price the line records (the price the owner's plan-withdraw verb sizes the same
        refund against) is refused (``ReversalUnaccounted``)."""
        from .billing_reversal import ReversalRetry
        oid, data = event.org_id, event.data or {}
        iid, trigger = data.get("plan_invoice"), data.get("trigger")
        refunded, disputed, amount = data.get("refunded_minor"), data.get("disputed_minor"), event.amount_minor
        if not (isinstance(iid, str) and iid and trigger == "refund" and disputed == 0
                and isinstance(refunded, int) and not isinstance(refunded, bool) and refunded >= 0
                and isinstance(amount, int) and not isinstance(amount, bool) and amount > 0):
            raise ReversalUnaccounted(f"plan reversal {event.event_id} for org {oid!r} is malformed")
        if self.invoices is None or self.reversals is None:
            raise ReversalUnaccounted(f"plan reversal {event.event_id} for org {oid!r}: no billing history to price it")
        line = next((i for i in self.invoices.invoices(oid) if i.invoice_id == iid and i.kind == "subscription"), None)
        if line is None:
            raise ReversalRetry(f"plan invoice {iid} of org {oid!r} is not credited yet; its reversal is retried")
        if line.credits <= 0:
            raise ReversalUnaccounted(f"plan invoice {iid} of org {oid!r} granted no credits (a monitoring plan); "
                                      f"reconcile its refund by hand")
        if not any(t.period_end == float(line.period_end) and t.granted > 0 for t in self.plan.tranches(oid)):
            raise ReversalRetry(f"the plan period of invoice {iid} of org {oid!r} is not delivered yet; retried")
        if line.currency and event.currency and line.currency.upper() != event.currency.upper():
            raise ReversalUnaccounted(f"plan reversal {event.event_id} for org {oid!r} is in {event.currency}, the "
                                      f"invoice {iid} in {line.currency}")
        if int(line.amount_minor) != amount:
            # the owner's plan-withdraw verb sizes the same refund against the line's price: both paths size it
            # against one amount, or the refund is reconciled by hand
            raise ReversalUnaccounted(f"plan reversal {event.event_id} for org {oid!r}: its charge ({amount}) is not "
                                      f"the price ({line.amount_minor}) the invoice {iid} line records; reconcile by "
                                      f"hand")
        cap = int(line.credits)
        res = self.reversals.reconcile_plan(oid, iid, cap=cap, period_end=float(line.period_end), now=float(now),
                                            processor_refunded=cap * min(refunded, amount) // amount)
        return self._done(res.seq)

    def sweep_plan_reversals(self, now: float) -> "list[tuple[str, str, int]]":
        """Re-apply every refunded plan period whose removal fell short of its target
        (``BillingReversalLedger.plan_shortfalls``) and that has plan credits again: credits a launch held when the
        refund was reconciled come back to the period when it settles, and must not stay spendable there. Each one
        is ``reconcile_plan`` with the facts already recorded (the target never changes here, so nothing is ever
        removed beyond it; never more than remains). A period that has ended is skipped (its plan credits expired).
        Run by the Stripe drain after each pass. Returns ``(org, invoice, credits removed)`` for each period that
        moved. A period VIGIL refuses to reconcile is reported on stderr and skipped; a busy lock waits for the next
        pass. No-op without the reversal ledger (``VIGIL_BILLING_REVERSALS`` off)."""
        if self.reversals is None or self.invoices is None:
            return []
        import sys as _sys

        from .billing_reversal import ReversalRefused, ReversalRetry
        moved: "list[tuple[str, str, int]]" = []
        for oid, iid, cap, _removed, _target in self.reversals.plan_shortfalls():
            line = next((i for i in self.invoices.invoices(oid) if i.invoice_id == iid and i.kind == "subscription"),
                        None)
            if line is None or int(line.credits) != cap:
                _sys.stderr.write(f"vigil billing-drain: WARNING the refunded plan period of invoice {iid} of org "
                                  f"{oid!r} has no matching billing-history line; reconcile it by hand\n")
                continue
            pe = float(line.period_end)
            if float(now) >= pe or self.plan.remaining_for_period(oid, pe) <= 0:
                continue
            try:
                res = self.reversals.reconcile_plan(oid, iid, cap=cap, period_end=pe, now=float(now),
                                                    note="plan credits that came back to a refunded plan period")
            except ReversalRetry:
                continue                                 # the money lock is busy: the next pass retries
            except ReversalRefused as exc:
                _sys.stderr.write(f"vigil billing-drain: WARNING the refunded plan period of invoice {iid} of org "
                                  f"{oid!r} could not be re-applied: {exc}\n")
                continue
            if res.seq is not None and res.moved > 0:
                moved.append((oid, iid, res.moved))
        return moved

    def _apply_monitoring(self, oid: str, event: BillingEvent, ent: Entitlement) -> "tuple[Optional[int], str]":
        """A paid AEGIS monitoring period: mint the SEPARATE monitoring line (no credit refill; the credit-plan
        subscription is untouched), record the invoice only if the mint is the one the fold honors (a stale /
        replayed period is inert), then hand the change to the provisioner hook."""
        if self.monitoring_subscriptions is None:
            # S1: the drain mints from the FULL catalog, so a paid monitoring period can reach here on a signer
            # that has no monitoring line. Under the plan alarm that is a paid-but-un-minted charge -> loud
            # quarantine, never a silent drop. Alarm off keeps the historical no-op.
            if self._alarm_unaccounted_plans:
                raise UnaccountedPayment(f"verified monitoring charge {event.event_id} for org {oid!r} "
                                         f"(price {event.price_id!r}) reached a signer with no monitoring line "
                                         f"— paid but UN-MINTED; reconcile by hand")
            return None, "no_monitoring_line"
        period_end = event.created + float(ent.period_s)
        seq = self.monitoring_subscriptions.subscribe(oid, ent.plan_id, 0, period_start=event.created,
                                                      period_end=period_end, issued_at=event.created)
        s = self.monitoring_subscriptions.subscription(oid)
        if s is None or (s.plan_id, s.period_start, s.period_end) != (ent.plan_id, float(event.created), period_end):
            return None, "stale_or_inert"
        self._record_invoice(oid, event, "subscription", credits=0, period_start=event.created,
                             period_end=period_end)
        if self.on_monitoring_change is not None:
            self.on_monitoring_change(oid, event.created)
        return self._done(seq)

    def _period_delivered_unrecorded(self, oid: str, event: BillingEvent, ent: Entitlement,
                                     period_end: float) -> bool:
        """Whether this credit-plan event's record (invoice + unlock) is due: its period is the one the subscription
        fold honours, the plan ledger holds a GRANTED tranche for that period (delivered — whatever the status has
        become since), and no other event id has an invoice line for that period. Covers the first delivery and
        the crash re-drive alike; a re-drive of the same event is harmless (first line per event id wins)."""
        s = self.subscriptions.subscription(oid)
        if s is None or (s.plan_id, s.period_start, s.period_end) != (
                ent.plan_id, float(event.created), period_end):
            return False
        if not any(t.period_end == period_end and t.granted > 0 for t in self.plan.tranches(oid)):
            return False
        if self.invoices is not None and any(
                i.kind == "subscription" and i.period_end == period_end and i.invoice_id != event.event_id
                for i in self.invoices.invoices(oid)):
            return False
        return True

    def _unlock_eligible(self, event: BillingEvent) -> bool:
        """A verified, catalog-priced credit purchase whose amount AND currency were present and passed the
        cross-check: the catalog prices it above 0, the verified currency is non-empty and equals the catalog's,
        and the verified amount is at least the catalog's. Decided once at mint time (no read-time floor), so the
        unlock never moves when the catalog changes later."""
        exp = self._expected.get(event.price_id)
        if exp is None or exp[0] <= 0:
            return False
        cur = str(event.currency or "").strip().upper()
        return bool(cur) and cur == exp[1] and int(event.amount_minor) >= exp[0]

    def _maybe_unlock(self, oid: str, event: BillingEvent, source_kind: str) -> None:
        """Record the billing unlock for a credit purchase (top-up or an honoured credit-plan period) that is
        eligible. Never called for monitoring, seats, refunds, the trial or postpaid/payment lines. The ledger
        keeps the first billing unlock per org, so a re-drive is harmless."""
        if self.report_unlocks is None or not self._unlock_eligible(event):
            return
        self.report_unlocks.unlock(oid, source_kind, source_ref=event.event_id, issued_at=event.created)

    def _maybe_capture_method(self, oid: str, event: BillingEvent) -> None:
        """A1: hand a saved card to the capture hook after a TOP-UP checkout mint whose session asked Stripe to
        save it (`_map_checkout` put the Customer + PaymentIntent ids on `event.data`). No hook, or no save-method
        ids on the event, is a no-op (byte-identical). The hook resolves the pm id and records it owner-signed; a
        hook fault must never undo the already-committed credit, so it is swallowed (the capture retries on the
        provider's at-least-once webhook redelivery)."""
        if self.on_saved_payment_method is None:
            return
        data = event.data if isinstance(event.data, Mapping) else {}
        cus = data.get("save_method_customer")
        pi = data.get("save_method_payment_intent")
        if not (isinstance(cus, str) and cus and isinstance(pi, str) and pi):
            return
        try:
            self.on_saved_payment_method(oid, cus, pi, event.created)
        except Exception:  # noqa: BLE001 — capture is best-effort; the credit mint already committed
            pass

    def _record_invoice(self, oid: str, event: BillingEvent, kind: str, *, credits: int,
                        period_start: float = 0.0, period_end: float = 0.0) -> None:
        """Record ONE owner-signed billing-history line for a value-granting mint that TOOK EFFECT (Slice H).
        No-op when no invoice ledger is injected. The caller invokes this ONLY after the mint's seq is not None
        (red-pen FINDING 2), and ``event.event_id`` is already bounded by ``apply`` before the mint (red-pen
        FINDING 1), so the (org, event_id) line is written for exactly the mints that delivered value.

        MONEY DOCTRINE: the line's ``amount_minor``/``currency`` are the owner-CATALOG expected price for
        ``event.price_id`` (``self._expected``), NEVER the wire amount — when the catalog does not price it, the
        line carries amount 0 (the credits/plan are still recorded). The owner-catalog money fields are coerced
        to ``record()``-safe values here (a malformed expected amount/currency — an owner CONFIG error — DEGRADES
        the line's money to 0/'' rather than raising after money has already moved), and ``org_id``/``kind``/
        ``credits`` are valid by construction at this point, so this never raises on validation. A genuine
        store-IO fault still propagates (it was never a ValueError and never silently swallowed): the money mint
        has committed, and the provider's at-least-once retry re-records the line idempotently."""
        if self.invoices is None:
            return
        exp = self._expected.get(event.price_id)
        amount_minor, currency = (exp[0], exp[1]) if exp is not None else (0, "")
        # Coerce the owner-catalog money fields to values record() accepts, so an owner misconfiguration degrades
        # the money on this history line instead of dropping a committed mint's line entirely (FINDING 1 spirit).
        amount_minor = amount_minor if isinstance(amount_minor, int) and amount_minor >= 0 else 0
        currency = currency if (isinstance(currency, str) and currency.isalpha() and len(currency) <= 8) else ""
        self.invoices.record(oid, invoice_id=event.event_id, kind=kind, price_id=event.price_id,
                             amount_minor=amount_minor, currency=currency, credits=credits,
                             period_start=period_start, period_end=period_end, issued_at=event.created)
