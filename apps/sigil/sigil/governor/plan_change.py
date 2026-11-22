"""PR-G (Area 6) — the self-serve CREDIT-PLAN change: switch to another plan, keep the current one, or end it, AT THE
NEXT RENEWAL.

THE MONEY DOCTRINE IS UNCHANGED, BY CONSTRUCTION. Nothing here mints, grants or moves a credit, and the billing drain
and its signer are untouched. A change is written to the PROCESSOR's subscription only — Stripe: the subscription item's
next price becomes the OWNER CATALOG's price for the chosen plan, with ``proration_behavior=none`` and the SAME billing
interval (so the billing anchor stays put and no mid-period invoice, charge or refund is created), or
``cancel_at_period_end``. The plan then changes exactly when the processor renews: the renewal invoice
(``subscription_cycle``) is the new catalog price, and the EXISTING verified webhook drain mints the new period through
the EXISTING owner catalog (``billing.BillingSigner`` reads the plan from the subscription's metadata, the catalog decides
the allotment, and the underpay cross-check holds because nothing was prorated). An ended plan simply does not renew; the
period already paid for runs to its end. "Proration" is therefore zero by design: the current period is delivered in full
at the price already paid, and the new price starts with the next period.

SAFETY RAILS — each one a refusal (``PlanChangeRefused``) that changes nothing at the processor:
  * credit plans only (never a top-up, never an AEGIS monitoring plan, which bills on its own line), and only to a plan
    ON SALE (``catalog.credit_plan_entries``) — or back to the plan already in force;
  * the target's billing period must equal the current plan's: another interval would move Stripe's billing anchor and
    invoice at once — a charge the drain does not mint;
  * the current plan must be ``active`` and more than ``CHANGE_CUTOFF_S`` from its renewal: the processor drafts the
    renewal invoice at the period boundary, and a change racing it could bill one plan and mint another;
  * the subscription is located from the org's OWN owner-signed billing history (the processor invoice that paid the
    current period), then re-fetched: its tenant (``billing._stripe_tenant``), mode, status, single item and recurring
    interval must agree, and its price must be the owner catalog's price for the plan its metadata names;
  * the processor's answer to the update must echo exactly what was asked, else ``PlanChangeUnconfirmed``.

DISPLAY RECORD. The change is also kept locally as an owner-signed record under SIGIL_HOME (``PlanChangeLedger``), so the
Plans screen can say "changes to Team on <date>" without calling the processor on each view. It is display only and
decides nothing (the processor's subscription and the drain do); a record that does not verify, or that names another
period, is simply not shown. The ledger's per-org ``flock`` also serialises concurrent changes of one org.

FATAL-2: sovereign-side (``assert_no_offense`` at import); stdlib + the sovereign billing/catalog/authn helpers only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional

from ..reuse import assert_no_offense

assert_no_offense()

try:
    import fcntl  # noqa: E402  POSIX advisory lock: one change per org at a time, across processes
except ImportError:  # pragma: no cover - non-POSIX: every change then refuses (fail-closed)
    fcntl = None  # type: ignore[assignment]

from .authn import signed_payload, verify_signed  # noqa: E402
from .billing import _stripe_plan_days, _stripe_tenant  # noqa: E402  (pure helpers, read-only reuse)
from .catalog import CatalogEntry, credit_plan_entries  # noqa: E402
from .subscription import STATUS_ACTIVE  # noqa: E402

SIGNAL = "governor.plan_change"
CHANGE_CUTOFF_S = 24 * 3600.0          # no change in the last day before a renewal
EGRESS_TIMEOUT_S = 6.0                 # per blocking socket op; 4 calls x (connect + read) stays inside the edge hop
KIND_CHANGE, KIND_KEEP, KIND_CANCEL = "change", "keep", "cancel"
_RECORD_CORE = ("signal", "org_id", "kind", "from_price_id", "to_price_id", "period_end", "subscription_ref",
                "issued_at")
_IN_ID = re.compile(r"in_[A-Za-z0-9]{1,255}")
_SUB_ID = re.compile(r"sub_[A-Za-z0-9]{1,255}")
_SI_ID = re.compile(r"si_[A-Za-z0-9]{1,255}")
_PROD_ID = re.compile(r"prod_[A-Za-z0-9]{1,255}")


class PlanChangeRefused(ValueError):
    """A plan change that was NOT made — nothing changed at the processor. ``str()`` is customer-safe; ``code`` names
    the refusal for the audit row."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class PlanChangeUnconfirmed(RuntimeError):
    """The update was sent but its result could not be confirmed (a transport fault after sending, or an answer that
    does not echo the request). The subscription may or may not have changed: the customer is told to check with
    support before trying again, and no display record is written."""


@dataclass(frozen=True)
class CurrentPlan:
    """The credit plan in force, from the SOVEREIGN records: the catalog line it was bought at (possibly retired since),
    its period, and the processor invoice that paid that period (from the owner-signed billing history)."""
    entry: CatalogEntry
    period_start: float
    period_end: float
    invoice_id: str


@dataclass(frozen=True)
class StripeSubscription:
    """The fields of a fetched Stripe subscription a change relies on — validated, never the raw object."""
    sub_id: str
    item_id: str
    product_id: str
    price_id: str             # metadata.price_id: the catalog plan the subscription renews as
    unit_amount: int
    currency: str
    interval: str
    interval_count: int
    cancel_at_period_end: bool


@dataclass(frozen=True)
class Decision:
    kind: str                                    # change | keep | cancel
    target: Optional[CatalogEntry]               # the plan that renews (None: the plan ends)
    params: dict = field(default_factory=dict)   # the subscription update (product id filled in by the changer)
    new_price: bool = False                      # True: a new item price, so a product is created first


def plan_days(entry: CatalogEntry) -> int:
    """The catalog plan's recurring interval in whole days — exactly what its checkout set (``billing``)."""
    return _stripe_plan_days(entry.period_s, entry.price_id)


def offered_plans() -> "dict[str, CatalogEntry]":
    return {e.price_id: e for e in credit_plan_entries(offered_only=True)}


def known_plans() -> "dict[str, CatalogEntry]":
    return {e.price_id: e for e in credit_plan_entries(offered_only=False)}


def current_plan(subscription, invoices: "Iterable[Any]", *, now: float) -> CurrentPlan:
    """The credit plan a change starts from: the sovereign subscription (``active``, in period, more than
    ``CHANGE_CUTOFF_S`` from renewal) and the billing-history line that paid THIS period. Raises PlanChangeRefused."""
    if subscription is None:
        raise PlanChangeRefused("this workspace has no plan to change; choose one on Plans", code="refused_no_plan")
    if subscription.status != STATUS_ACTIVE:
        raise PlanChangeRefused("settle this plan's payment first; a plan that is not active cannot be changed",
                                code="refused_not_active")
    if now >= float(subscription.period_end):
        raise PlanChangeRefused("this plan's period has ended; change it once it has renewed",
                                code="refused_period_ended")
    if now >= float(subscription.period_end) - CHANGE_CUTOFF_S:
        raise PlanChangeRefused("this plan renews within a day; change it after the renewal",
                                code="refused_renewal_imminent")
    plans = known_plans()
    line = None
    for inv in invoices:                       # newest-first: the latest line that paid exactly this period wins
        if (getattr(inv, "kind", None) == "subscription" and getattr(inv, "price_id", None) in plans
                and float(getattr(inv, "period_start", -1.0)) == float(subscription.period_start)
                and float(getattr(inv, "period_end", -1.0)) == float(subscription.period_end)):
            line = inv
            break
    if line is None:
        raise PlanChangeRefused("this plan was not bought through self-serve checkout; contact support to change it",
                                code="refused_no_history")
    entry = plans[line.price_id]
    if entry.plan_id != subscription.plan_id:
        raise PlanChangeRefused("this plan's records disagree; contact support to change it",
                                code="refused_inconsistent")
    if not _IN_ID.fullmatch(str(line.invoice_id)):
        raise PlanChangeRefused("this plan's payment processor does not support self-serve changes; contact support",
                                code="refused_processor")
    return CurrentPlan(entry=entry, period_start=float(subscription.period_start),
                       period_end=float(subscription.period_end), invoice_id=str(line.invoice_id))


def _ref_id(v: object) -> Optional[str]:
    if isinstance(v, Mapping):
        v = v.get("id")
    return v if isinstance(v, str) and v else None


def parse_subscription(obj: object, org_id: str, *, livemode: bool) -> StripeSubscription:
    """Validate a fetched (or echoed) Stripe subscription for ``org_id``. Raises PlanChangeRefused on any mismatch."""
    def bad(what: str) -> PlanChangeRefused:
        return PlanChangeRefused("the payment processor's subscription does not match this workspace's plan; contact "
                                 "support", code=f"refused_subscription_{what}")
    if not isinstance(obj, Mapping) or obj.get("object") != "subscription":
        raise bad("object")
    sub_id = obj.get("id")
    if not isinstance(sub_id, str) or not _SUB_ID.fullmatch(sub_id):
        raise bad("id")
    if obj.get("livemode") is not livemode:
        raise bad("mode")
    if obj.get("status") != "active":
        raise bad("status")
    meta = obj.get("metadata")
    if _stripe_tenant(None, meta) != org_id:
        raise bad("tenant")
    items = obj.get("items")
    data = items.get("data") if isinstance(items, Mapping) else None
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], Mapping):
        raise bad("items")
    item = data[0]
    price = item.get("price")
    rec = price.get("recurring") if isinstance(price, Mapping) else None
    item_id, product = item.get("id"), _ref_id(price.get("product")) if isinstance(price, Mapping) else None
    amount = price.get("unit_amount") if isinstance(price, Mapping) else None
    ccy = price.get("currency") if isinstance(price, Mapping) else None
    count = rec.get("interval_count") if isinstance(rec, Mapping) else None
    if (not isinstance(item_id, str) or not _SI_ID.fullmatch(item_id) or not product or not _PROD_ID.fullmatch(product)
            or isinstance(amount, bool) or not isinstance(amount, int) or not isinstance(ccy, str)
            or not isinstance(rec, Mapping) or not isinstance(rec.get("interval"), str)
            or isinstance(count, bool) or not isinstance(count, int)):
        raise bad("price")
    plan_price = meta.get("price_id") if isinstance(meta, Mapping) else None
    cancel = obj.get("cancel_at_period_end")
    if not isinstance(plan_price, str) or not isinstance(cancel, bool):
        raise bad("metadata")
    return StripeSubscription(sub_id=sub_id, item_id=item_id, product_id=product, price_id=plan_price,
                              unit_amount=int(amount), currency=ccy.upper(), interval=str(rec["interval"]),
                              interval_count=int(count), cancel_at_period_end=cancel)


def decide(current: CurrentPlan, sub: StripeSubscription, *, target_price_id: str = "",
           cancel: bool = False) -> Decision:
    """What to send, from the sovereign current plan, the processor's subscription and the customer's choice. PURE.
    Raises PlanChangeRefused for every request that must not reach the processor."""
    known = known_plans()
    renewing = known.get(sub.price_id)
    if (renewing is None or sub.unit_amount != renewing.amount_minor or sub.currency != renewing.currency
            or sub.interval != "day" or sub.interval_count != plan_days(renewing)
            or plan_days(renewing) != plan_days(current.entry)):
        raise PlanChangeRefused("the payment processor's subscription does not match the plan VIGIL sold; contact "
                                "support", code="refused_subscription_price")
    if cancel:
        if sub.cancel_at_period_end:
            raise PlanChangeRefused("this plan is already set to end at the end of its period",
                                    code="refused_already_ending")
        return Decision(kind=KIND_CANCEL, target=None, params={"cancel_at_period_end": True})
    want = str(target_price_id or "")
    target = current.entry if want == current.entry.price_id else offered_plans().get(want)
    if target is None:
        raise PlanChangeRefused("that is not a plan this workspace can switch to", code="refused_unknown_plan")
    if plan_days(target) != plan_days(current.entry):
        raise PlanChangeRefused("plans with a different billing period cannot be switched here; contact support",
                                code="refused_period_mismatch")
    kind = KIND_KEEP if target.price_id == current.entry.price_id else KIND_CHANGE
    if target.price_id == sub.price_id:
        if not sub.cancel_at_period_end:
            raise PlanChangeRefused("this workspace is already on that plan" if kind == KIND_KEEP
                                    else "that change is already scheduled", code="refused_already")
        return Decision(kind=kind, target=target, params={"cancel_at_period_end": False})
    params = {"items": [{"id": sub.item_id, "price_data": {
                  "currency": target.currency.lower(), "product": "", "unit_amount": int(target.amount_minor),
                  "recurring": {"interval": "day", "interval_count": plan_days(target)}}}],
              "proration_behavior": "none", "cancel_at_period_end": False, "metadata": {"price_id": target.price_id}}
    return Decision(kind=kind, target=target, params=params, new_price=True)


class StripePlanChanger:
    """Locate the org's Stripe subscription and apply a :class:`Decision` to it, verifying every answer. The three
    callables are ``stripe_egress`` builders (``make_object_fetcher`` / ``make_subscription_updater`` /
    ``make_product_creator``), injected so this class stays offline-testable."""

    def __init__(self, *, fetch: Callable[..., Any], update_subscription: Callable[..., Any],
                 create_product: Callable[..., Any], livemode: bool) -> None:
        self._fetch, self._update, self._create = fetch, update_subscription, create_product
        self._livemode = bool(livemode)

    def locate(self, invoice_id: str, org_id: str) -> StripeSubscription:
        """The subscription that the invoice paying the current period belongs to. A fetch fault REFUSES (nothing was
        sent that could change anything)."""
        try:
            inv = self._fetch("invoice", invoice_id)
            parent = inv.get("parent") if isinstance(inv, Mapping) else None
            details = parent.get("subscription_details") if isinstance(parent, Mapping) else None
            ids = {r for r in (_ref_id(inv.get("subscription")) if isinstance(inv, Mapping) else None,
                               _ref_id(details.get("subscription")) if isinstance(details, Mapping) else None) if r}
            if len(ids) != 1 or not _SUB_ID.fullmatch(next(iter(ids))):
                raise PlanChangeRefused("this plan's subscription could not be found; contact support",
                                        code="refused_subscription_missing")
            obj = self._fetch("subscription", next(iter(ids)))
        except PlanChangeRefused:
            raise
        except Exception as exc:  # noqa: BLE001 — a read fault changes nothing: refuse, the customer may retry
            raise PlanChangeRefused("the payment processor could not be reached; nothing was changed",
                                    code=f"refused_processor_read:{type(exc).__name__}"[:32]) from None
        return parse_subscription(obj, org_id, livemode=self._livemode)

    def apply(self, sub: StripeSubscription, decision: Decision, org_id: str, *, nonce: str) -> StripeSubscription:
        """Send ``decision`` and verify the processor's answer echoes it. A fault BEFORE the update is a refusal (at most
        an unused product was created); a fault or a mismatched answer AFTER sending it is ``PlanChangeUnconfirmed``."""
        params = json.loads(json.dumps(decision.params))
        if decision.new_price:
            target = decision.target
            if target is None:                     # a new price always names its plan (decide builds it so)
                raise PlanChangeRefused("that is not a plan this workspace can switch to", code="refused_unknown_plan")
            try:
                prod = self._create({"name": target.display_name, "metadata": {"price_id": target.price_id}},
                                    idempotency_key=f"vigil-pp-{nonce}")
            except Exception as exc:  # noqa: BLE001 — nothing changed on the subscription
                raise PlanChangeRefused("the payment processor could not be reached; nothing was changed",
                                        code=f"refused_processor_write:{type(exc).__name__}"[:32]) from None
            pid = prod.get("id") if isinstance(prod, Mapping) else None
            if not isinstance(pid, str) or not _PROD_ID.fullmatch(pid) or prod.get("livemode") is not self._livemode:
                raise PlanChangeRefused("the payment processor's answer was not understood; nothing was changed",
                                        code="refused_product")
            params["items"][0]["price_data"]["product"] = pid
        try:
            resp = self._update(sub.sub_id, params, idempotency_key=f"vigil-pc-{nonce}")
        except Exception as exc:  # noqa: BLE001 — the request may have reached the processor: unconfirmed
            raise PlanChangeUnconfirmed(f"the update's answer was lost ({type(exc).__name__})") from None
        try:
            after = parse_subscription(resp, org_id, livemode=self._livemode)
        except PlanChangeRefused as exc:
            raise PlanChangeUnconfirmed(f"the update's answer did not verify ({exc.code})") from None
        target = decision.target
        want_price = target.price_id if target is not None else sub.price_id
        want_amount = int(target.amount_minor) if target is not None else sub.unit_amount
        want_days = plan_days(target) if target is not None else sub.interval_count
        if (after.sub_id != sub.sub_id or after.price_id != want_price or after.unit_amount != want_amount
                or after.interval != "day" or after.interval_count != want_days
                or after.cancel_at_period_end is not (decision.kind == KIND_CANCEL)):
            raise PlanChangeUnconfirmed("the update's answer does not echo the change")
        return after


class PlanChangeLedger:
    """The owner-signed, per-org DISPLAY record of the latest scheduled change (see the module docstring), and the
    per-org lock that serialises changes. Fail-closed: no owner key, no ``flock`` or an I/O fault refuses a change."""

    def __init__(self, path: "str | os.PathLike", *, owner_key, trusted_pubkey: Optional[str]) -> None:
        self.path = Path(path)
        self.owner_key = owner_key
        self.trusted_pubkey = trusted_pubkey

    def _base(self, org_id: str) -> Path:
        return self.path / hashlib.sha256(str(org_id).encode("utf-8")).hexdigest()[:40]

    @contextmanager
    def exclusive(self, org_id: str) -> Iterator[None]:
        """Hold the org's change lock (an exclusive ``flock`` on its own lock file) for the whole change."""
        if fcntl is None or self.owner_key is None:
            raise PlanChangeRefused("plan changes are unavailable right now", code="refused_unwired")
        try:
            self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(self._base(org_id)) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            raise PlanChangeRefused("plan changes are unavailable right now", code="refused_lock") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def record(self, org_id: str, *, kind: str, from_price_id: str, to_price_id: str, period_end: float,
               subscription_ref: str, issued_at: float) -> dict:
        """Write the org's display record (atomic replace). Returns the signed record."""
        core = {"signal": SIGNAL, "org_id": str(org_id), "kind": str(kind), "from_price_id": str(from_price_id),
                "to_price_id": str(to_price_id), "period_end": float(period_end),
                "subscription_ref": str(subscription_ref), "issued_at": float(issued_at)}
        rec = signed_payload(core, self.owner_key)
        final = Path(str(self._base(org_id)) + ".json")
        tmp = final.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, final)
        return rec

    def scheduled(self, org_id: str, *, period_end: float) -> "Optional[dict[str, Any]]":
        """The verified change scheduled for the period ending ``period_end`` — ``{kind, from_price_id, to_price_id,
        effective_at}`` for a ``change`` or ``cancel`` — or None (none, a ``keep``, another period, or a record that does
        not verify or cannot be read). Display only."""
        try:
            rec = json.loads(Path(str(self._base(org_id)) + ".json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(rec, dict) or not verify_signed(rec, _RECORD_CORE, self.trusted_pubkey):
            return None
        if rec.get("signal") != SIGNAL or rec.get("org_id") != str(org_id) or rec.get("kind") not in (KIND_CHANGE,
                                                                                                       KIND_CANCEL):
            return None
        pe = rec.get("period_end")
        if isinstance(pe, bool) or not isinstance(pe, (int, float)) or float(pe) != float(period_end):
            return None
        return {"kind": rec["kind"], "from_price_id": str(rec.get("from_price_id") or ""),
                "to_price_id": str(rec.get("to_price_id") or ""), "effective_at": float(pe)}


def subscription_ref(sub_id: str) -> str:
    """A non-reversible reference to the processor subscription for the audit row and the display record."""
    return "sha256:" + hashlib.sha256(str(sub_id).encode("utf-8")).hexdigest()[:24]
