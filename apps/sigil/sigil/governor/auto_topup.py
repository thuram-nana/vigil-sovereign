"""Auto top-up (A1) — the SOVEREIGN record of a tenant's owner-signed auto-top-up intent, saved payment method
and per-crossing charge decisions. DEFAULT-OFF behind ``config.billing_auto_topup_enabled()``.

The owner's A1 program (HANDOFF §11.13): a customer may ask VIGIL to buy a credit pack automatically whenever
their balance falls below a trigger, up to a MONTHLY CAP, using a card saved on their Stripe Customer. This module
is the spine-of-record for that intent; the OFF-SESSION CHARGE itself lives on the Stripe adapter
(``billing.StripeBillingProvider.create_off_session_topup``) and CREDIT is minted solely by the existing
verified-webhook drain (``billing.BillingSigner`` → ``wallet.grant``), never by the charge call. This module does
NO network and holds NO card data — only Stripe's opaque ``cus_`` / ``pm_`` ids.

Three owner-signed record kinds, each keyed per ``org_id`` (== tenant_id), each verified under the owner pubkey
valid AT ITS SEQ (succession-aware, fail-closed — an unsigned/forged/wrong-epoch record is inert):
  * SETTINGS (``governor.auto_topup_settings``) — LWW by ``issued_at`` per org: ``enabled`` + the trigger balance
    + the pack ``price_id`` (a catalog TOP-UP price) + the ``monthly_cap_credits``. A captured settings record can
    never be replayed to lift the cap (``issued_at`` strictly above the per-org high-water; the settings are inside
    the signed bytes).
  * METHOD (``governor.auto_topup_method``) — LWW by ``issued_at`` per org: the Stripe ``customer_id`` +
    ``payment_method_id`` captured during a normal checkout. Ids only; never card data.
  * CHARGE (``governor.auto_topup_charge``) — APPEND-ONLY, idempotent per (org, ``crossing_key``) [FIRST wins]: one
    record per balance CROSSING, carrying the outcome (``charged`` / ``declined`` / ``cap_blocked``), the pack, the
    owner-catalog credits/amount and the off-session PaymentIntent id. The monthly cap counts ``charged`` records
    only; a re-drive of the same crossing finds the record present and mints/charges nothing new.

CROSSING KEY (the idempotency anchor, mirrors the W5 low-balance alert's "once per crossing"): the ``entry_id`` of
the org's most recent credit-adding grant (``topup`` / ``trial``), or ``"genesis"`` when it has none. A successful
auto top-up mints a ``topup`` grant (via the webhook), which ADVANCES the anchor — re-arming the trigger for the
next crossing. So one charge per crossing, re-drive-safe, and the next low-balance episode is a fresh crossing.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); imports only sovereign siblings + shared ``vigil_core``.
HARD-PRUNE: a genesis signature-verifying scan of the live window (no snapshot seed in this slice — the same
posture as ``connected_repos``). The per-crossing Stripe Idempotency-Key and the webhook ``entry_id`` bound the
money regardless; seeding the charge rows into the snapshot, exactly as the wallet does, is a clean follow-on if a
hard prune can fall inside a billing month (documented risk).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (owner-key succession resolver, mirrors wallet/connected_repos)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id == tenant-id validation, fail-closed)
from .wallet import CREDIT_GRANT_SIGNAL, _GRANT_CORE as _WALLET_GRANT_CORE  # noqa: E402  (the crossing anchor)

SETTINGS_SIGNAL = "governor.auto_topup_settings"
METHOD_SIGNAL = "governor.auto_topup_method"
CHARGE_SIGNAL = "governor.auto_topup_charge"

#: The crossing-anchor grant kinds — a credit-ADDING grant re-arms the trigger (matches wallet.purchase_events).
_ANCHOR_KINDS = frozenset({"topup", "trial"})
#: When the org has no credit-adding grant yet, the first crossing anchors here (a valid, stable entry key).
GENESIS_ANCHOR = "genesis"

#: A charge record's terminal outcome. Only ``charged`` counts toward the monthly cap; all three CONSUME the
#: crossing (so a declined card or a capped month is not retried every sweep tick — the next top-up re-arms).
STATUS_CHARGED = "charged"        # the off-session PaymentIntent was accepted by Stripe (credit awaits the webhook)
STATUS_DECLINED = "declined"      # Stripe refused the off-session charge (card error / egress refusal)
STATUS_CAP_BLOCKED = "cap_blocked"  # the charge would exceed the org's monthly cap — not sent
_CHARGE_STATUSES = frozenset({STATUS_CHARGED, STATUS_DECLINED, STATUS_CAP_BLOCKED})

#: Stripe id shapes (never card data). cus_/pm_ captured at checkout; pi_ is the off-session PaymentIntent.
_STRIPE_CUS_ID = re.compile(r"cus_[A-Za-z0-9]{1,255}")
_STRIPE_PM_ID = re.compile(r"pm_[A-Za-z0-9]{1,255}")
_STRIPE_PI_ID = re.compile(r"pi_[A-Za-z0-9]{1,255}")

_SETTINGS_CORE = ("signal", "org_id", "enabled", "trigger_credits", "pack_price_id", "monthly_cap_credits",
                  "issued_at")
_METHOD_CORE = ("signal", "org_id", "customer_id", "payment_method_id", "issued_at")
_CHARGE_CORE = ("signal", "org_id", "crossing_key", "status", "pack_price_id", "credits", "amount_minor",
                "currency", "payment_intent_id", "issued_at")


#: The largest trigger / monthly-limit value a setting may carry (a sanity bound on customer input, in credits —
#: not a price). Larger values are refused at binding time.
MAX_SETTING_CREDITS = 10_000_000


# -- validation (fail-closed at binding time; a clean ValueError now, never a bad record later) ----------------
def _check_nonneg_int(v: object, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError(f"{what} must be a non-negative integer")
    return v


def check_setting_credits(v: object, what: str) -> int:
    """A trigger / monthly-limit setting: a whole number of credits in ``[0, MAX_SETTING_CREDITS]`` (a bool, a float,
    a string or an out-of-range value is refused). Shared by the registry and the provisioner edge."""
    n = _check_nonneg_int(v, what)
    if n > MAX_SETTING_CREDITS:
        raise ValueError(f"{what} must be at most {MAX_SETTING_CREDITS}")
    return n


def _check_pack_price_id(pack_price_id: str) -> str:
    """A pack must be a catalog TOP-UP price (lazy import — the catalog imports billing, not this module)."""
    from .billing import EVENT_TOPUP
    from .catalog import mintable_entitlements
    p = str(pack_price_id or "").strip()
    ent = mintable_entitlements().get(p)
    if ent is None or ent.kind != EVENT_TOPUP or ent.credits <= 0:
        raise ValueError(f"pack_price_id {pack_price_id!r} is not a catalog top-up price with credits > 0")
    return p


def _check_stripe_id(value: object, shape: "re.Pattern[str]", what: str) -> str:
    v = str(value or "").strip()
    if not shape.fullmatch(v):
        raise ValueError(f"{what} must match the Stripe id shape {shape.pattern}")
    return v


@dataclass(frozen=True)
class AutoTopUpSettings:
    """A tenant's owner-signed auto-top-up intent. ``trigger_credits``: charge when available < this.
    ``monthly_cap_credits``: the most auto-top-up credits that may be bought per UTC calendar month."""
    org_id: str
    enabled: bool
    trigger_credits: int
    pack_price_id: str
    monthly_cap_credits: int
    issued_at: float


@dataclass(frozen=True)
class SavedMethod:
    """The Stripe card saved for off-session charges — IDS ONLY (no card data ever)."""
    org_id: str
    customer_id: str
    payment_method_id: str
    issued_at: float


@dataclass(frozen=True)
class Charge:
    """One per-crossing auto-top-up decision (the durable receipt of record)."""
    org_id: str
    crossing_key: str
    status: str
    pack_price_id: str
    credits: int
    amount_minor: int
    currency: str
    payment_intent_id: str
    issued_at: float

    @property
    def is_charged(self) -> bool:
        return self.status == STATUS_CHARGED


def _utc_month(now: float) -> "tuple[int, int]":
    """The (year, month) of ``now`` in UTC — the monthly-cap window key, fail-closed to the epoch's month."""
    try:
        dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        dt = datetime.fromtimestamp(0, tz=timezone.utc)
    return dt.year, dt.month


class AutoTopUpRegistry:
    """Owner-signed per-tenant auto-top-up records on the spine. Construction mirrors ``WalletRegistry`` /
    ``ConnectedRepoRegistry``: the owner signing key + trusted pubkey default to the persisted owner identity;
    a pure-read caller passes ``owner_key=None`` so the private key is never touched on a read path."""

    _LOAD = object()

    def __init__(self, store, *, owner_key=_LOAD, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_keypair() if owner_key is AutoTopUpRegistry._LOAD else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations --------------------------------------------------------------------------------------
    def set_settings(self, org_id: str, *, enabled: bool, trigger_credits: int, pack_price_id: str,
                     monthly_cap_credits: int, issued_at: float) -> int:
        """Owner-sign the org's auto-top-up settings (LWW by ``issued_at``). Fail-closed ``ValueError`` on a bad
        org / pack / trigger / cap or a missing signing key. The pack must be a catalog top-up price; the trigger
        and cap are non-negative credits; the settings are inside the signed bytes, so a tenant cannot lift the cap
        without a fresh owner signature. Returns the spine seq."""
        if self.owner_key is None:
            raise ValueError("auto-top-up settings require the owner signing key")
        oid = org_tenant_id(org_id)
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a bool")
        trig = check_setting_credits(trigger_credits, "trigger_credits")
        cap = check_setting_credits(monthly_cap_credits, "monthly_cap_credits")
        pack = _check_pack_price_id(pack_price_id)
        core = {"signal": SETTINGS_SIGNAL, "org_id": oid, "enabled": bool(enabled), "trigger_credits": trig,
                "pack_price_id": pack, "monthly_cap_credits": cap, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"auto-top-up settings for {oid} (owner-signed)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def capture_payment_method(self, org_id: str, customer_id: str, payment_method_id: str, *,
                               issued_at: float) -> int:
        """Owner-sign the org's saved Stripe payment method (LWW by ``issued_at``) — IDS ONLY. Captured from a
        normal checkout that asked Stripe to save the card. Fail-closed ``ValueError`` on a bad org / id shape or a
        missing signing key. Returns the spine seq."""
        if self.owner_key is None:
            raise ValueError("capturing a saved payment method requires the owner signing key")
        oid = org_tenant_id(org_id)
        cus = _check_stripe_id(customer_id, _STRIPE_CUS_ID, "customer_id")
        pm = _check_stripe_id(payment_method_id, _STRIPE_PM_ID, "payment_method_id")
        core = {"signal": METHOD_SIGNAL, "org_id": oid, "customer_id": cus, "payment_method_id": pm,
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"auto-top-up saved method for {oid} (owner-signed)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def record_charge(self, org_id: str, *, crossing_key: str, status: str, pack_price_id: str, credits: int,
                      amount_minor: int, currency: str, payment_intent_id: str, issued_at: float) -> "Optional[int]":
        """Owner-sign ONE per-crossing charge decision (append-only). IDEMPOTENT: returns None (appends nothing)
        when (org, crossing_key) already has a record — one charge per crossing, re-drive-safe. Returns the seq of
        a NEW record. Fail-closed ``ValueError`` on bad inputs / a missing signing key. ``payment_intent_id`` is ""
        for a non-charged outcome (declined / cap_blocked)."""
        if self.owner_key is None:
            raise ValueError("recording an auto-top-up charge requires the owner signing key")
        oid = org_tenant_id(org_id)
        ck = str(crossing_key or "").strip()
        if not ck or len(ck) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in ck):
            raise ValueError("crossing_key must be a non-empty, non-control string of <= 128 chars")
        st = str(status or "").strip()
        if st not in _CHARGE_STATUSES:
            raise ValueError(f"status must be one of {sorted(_CHARGE_STATUSES)}")
        pack = _check_pack_price_id(pack_price_id)
        cr = _check_nonneg_int(credits, "credits")
        amt = _check_nonneg_int(amount_minor, "amount_minor")
        ccy = str(currency or "").strip().upper()
        if not (len(ccy) == 3 and ccy.isalpha()):
            raise ValueError("currency must be an ISO-4217 alpha-3 code")
        pi = ""
        if payment_intent_id:
            pi = _check_stripe_id(payment_intent_id, _STRIPE_PI_ID, "payment_intent_id")
        if st == STATUS_CHARGED and not pi:
            raise ValueError("a charged record must carry its PaymentIntent id")
        if self.has_charge(oid, ck):
            return None                               # idempotent: this crossing already decided
        core = {"signal": CHARGE_SIGNAL, "org_id": oid, "crossing_key": ck, "status": st, "pack_price_id": pack,
                "credits": cr, "amount_minor": amt, "currency": ccy, "payment_intent_id": pi,
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"auto-top-up {st} for {oid} (crossing {ck[:24]})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (succession-aware genesis scan of the live window; fail-closed) ---------------------------------
    def _fold(self) -> "tuple[dict, dict, dict]":
        """(settings_by_org, method_by_org, charges_by_org): each signed record authenticated under the owner
        pubkey valid AT ITS SEQ. Settings + method are LWW by ``issued_at`` (a replay/stale re-append is inert);
        charges are append-only, FIRST wins per (org, crossing_key)."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        settings: "dict[str, AutoTopUpSettings]" = {}
        s_hw: "dict[str, float]" = {}
        method: "dict[str, SavedMethod]" = {}
        m_hw: "dict[str, float]" = {}
        charges: "dict[str, dict[str, Charge]]" = {}
        for r in self.store.iter_records():
            self._apply(r, resolver, settings, s_hw, method, m_hw, charges)
        return settings, method, charges

    def _apply(self, r, resolver, settings: dict, s_hw: dict, method: dict, m_hw: dict, charges: dict) -> None:
        p = getattr(r, "payload", None)
        if not isinstance(p, dict):
            return
        sig = p.get("signal")
        if sig == SETTINGS_SIGNAL:
            if not verify_signed(p, _SETTINGS_CORE, resolver.at(r.seq)):
                return
            oid = p.get("org_id")
            if not (isinstance(oid, str) and oid):
                return
            at = as_issued_at(p.get("issued_at"))
            if at <= s_hw.get(oid, NO_HIGHWATER):
                return                                 # replay / stale re-append of an already-honoured record
            s_hw[oid] = at
            settings[oid] = AutoTopUpSettings(
                org_id=oid, enabled=bool(p.get("enabled")),
                trigger_credits=_as_nonneg(p.get("trigger_credits")),
                pack_price_id=str(p.get("pack_price_id") or ""),
                monthly_cap_credits=_as_nonneg(p.get("monthly_cap_credits")), issued_at=at)
        elif sig == METHOD_SIGNAL:
            if not verify_signed(p, _METHOD_CORE, resolver.at(r.seq)):
                return
            oid = p.get("org_id")
            if not (isinstance(oid, str) and oid):
                return
            at = as_issued_at(p.get("issued_at"))
            if at <= m_hw.get(oid, NO_HIGHWATER):
                return
            m_hw[oid] = at
            method[oid] = SavedMethod(org_id=oid, customer_id=str(p.get("customer_id") or ""),
                                      payment_method_id=str(p.get("payment_method_id") or ""), issued_at=at)
        elif sig == CHARGE_SIGNAL:
            if not verify_signed(p, _CHARGE_CORE, resolver.at(r.seq)):
                return
            oid, ck = p.get("org_id"), p.get("crossing_key")
            if not (isinstance(oid, str) and oid and isinstance(ck, str) and ck):
                return
            org_charges = charges.setdefault(oid, {})
            if ck in org_charges:
                return                                 # FIRST wins: a re-appended crossing is folded once
            org_charges[ck] = Charge(
                org_id=oid, crossing_key=ck, status=str(p.get("status") or ""),
                pack_price_id=str(p.get("pack_price_id") or ""), credits=_as_nonneg(p.get("credits")),
                amount_minor=_as_nonneg(p.get("amount_minor")), currency=str(p.get("currency") or ""),
                payment_intent_id=str(p.get("payment_intent_id") or ""),
                issued_at=as_issued_at(p.get("issued_at")))

    def settings(self, org_id: str) -> "Optional[AutoTopUpSettings]":
        """The org's current auto-top-up settings, or None (fail-closed: unknown/empty org, or no record)."""
        if not isinstance(org_id, str) or not org_id:
            return None
        return self._fold()[0].get(_safe_org(org_id))

    def enabled_orgs(self) -> "list[str]":
        """Every org whose CURRENT settings are enabled, in org order — the sweep's work list (owner side only; a
        per-tenant caller reads ``settings`` for its own org)."""
        return sorted(o for o, s in self._fold()[0].items() if s.enabled)

    def payment_method(self, org_id: str) -> "Optional[SavedMethod]":
        """The org's saved Stripe method (ids only), or None."""
        if not isinstance(org_id, str) or not org_id:
            return None
        return self._fold()[1].get(_safe_org(org_id))

    def charges(self, org_id: str) -> "list[Charge]":
        """Every per-crossing charge record for the org, oldest first (the durable receipts)."""
        if not isinstance(org_id, str) or not org_id:
            return []
        rows = self._fold()[2].get(_safe_org(org_id), {})
        return sorted(rows.values(), key=lambda c: (c.issued_at, c.crossing_key))

    def has_charge(self, org_id: str, crossing_key: str) -> bool:
        """True iff a charge record already exists for (org, crossing_key) — the per-crossing idempotency gate."""
        if not (isinstance(org_id, str) and org_id and isinstance(crossing_key, str) and crossing_key):
            return False
        return crossing_key in self._fold()[2].get(_safe_org(org_id), {})

    def month_charged_credits(self, org_id: str, now: float) -> int:
        """The monthly-cap tally: the auto-top-up credits bought in ``now``'s UTC calendar month. It is the UNION of
        the org's ``charged`` records and the off-session top-up GRANTS the webhook minted (a ``topup`` grant keyed
        on a ``pi_`` PaymentIntent id — only an auto-top-up PaymentIntent mints that way), each PaymentIntent counted
        once. The grant leg makes the cap hold even when a charge succeeded at Stripe but its response was lost (a
        transient egress fault records nothing) and the webhook then minted it: that purchase is still counted.
        Declined / cap_blocked crossings spent no money and count nothing."""
        ym = _utc_month(now)
        charged = [c for c in self.charges(org_id) if c.status == STATUS_CHARGED]
        recorded = {c.payment_intent_id for c in charged if c.payment_intent_id}
        total = sum(c.credits for c in charged if _utc_month(c.issued_at) == ym)
        for at, _seq, eid, kind, credits in self._credit_grants(org_id):
            if kind == "topup" and _STRIPE_PI_ID.fullmatch(eid) and eid not in recorded and _utc_month(at) == ym:
                recorded.add(eid)
                total += credits
        return total

    # -- the org's verified credit-adding grants (a live scan) ------------------------------------------------
    def _credit_grants(self, org_id: str) -> "list[tuple[float, int, str, str, int]]":
        """``(issued_at, seq, entry_id, kind, credits)`` for every owner-signed credit-ADDING grant (topup / trial) of
        ``org_id``, verified under the owner pubkey valid at each grant's seq (fail-closed: an unsigned / forged /
        wrong-epoch grant is ignored); a replayed entry counts once."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = org_tenant_id(org_id)
        except ValueError:
            return []
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        seen: "set[str]" = set()
        out: "list[tuple[float, int, str, str, int]]" = []
        for r in self.store.iter_records():
            p = getattr(r, "payload", None)
            if not isinstance(p, dict) or p.get("signal") != CREDIT_GRANT_SIGNAL or p.get("org_id") != oid:
                continue
            kind = p.get("kind")
            if kind not in _ANCHOR_KINDS:
                continue
            eid = p.get("entry_id")
            if not (isinstance(eid, str) and eid) or eid in seen \
                    or not verify_signed(p, _WALLET_GRANT_CORE, resolver.at(r.seq)):
                continue
            seen.add(eid)
            out.append((as_issued_at(p.get("issued_at")), int(getattr(r, "seq", -1)), eid, str(kind),
                        _as_nonneg(p.get("credits"))))
        return out

    # -- the crossing anchor ---------------------------------------------------------------------------------
    def last_credit_anchor(self, org_id: str) -> str:
        """The crossing key: the ``entry_id`` of the org's most recent credit-ADDING grant (topup / trial), or
        ``GENESIS_ANCHOR`` when it has none (ordered by ``(issued_at, seq)``). A successful auto top-up mints a
        ``topup`` grant → the anchor advances → the trigger re-arms for the next crossing."""
        grants = self._credit_grants(org_id)
        if not grants:
            return GENESIS_ANCHOR
        return max(grants, key=lambda g: (g[0], g[1]))[2]


def _as_nonneg(v: object) -> int:
    """A folded credits/amount → a non-negative int (junk/NaN/over-large → 0). The signature already bounds a real
    record; this only keeps the fold from crashing on a hostile spine."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float, str)):
        try:
            n = int(v)
        except (TypeError, ValueError, OverflowError):
            return 0
        return n if n > 0 else 0
    return 0


def _safe_org(org_id: str) -> str:
    try:
        return org_tenant_id(org_id)
    except ValueError:
        return ""


# ==================================================================================================
# The policy (PURE) + the charger (reads the wallet, decides, charges off-session, records, notifies).
# ==================================================================================================
@dataclass(frozen=True)
class Decision:
    """The pure auto-top-up decision for one evaluation. ``charge`` is the only acting reason."""
    reason: str                 # disabled | above_trigger | no_method | already_charged | cap_exceeded | charge
    pack_price_id: str = ""
    credits: int = 0
    amount_minor: int = 0
    currency: str = ""

    @property
    def should_charge(self) -> bool:
        return self.reason == "charge"


def decide(settings: "Optional[AutoTopUpSettings]", *, available: int, has_method: bool, already_charged: bool,
           month_charged: int, pack_credits: int, pack_amount_minor: int, pack_currency: str) -> Decision:
    """The complete, PURE auto-top-up policy. Fail-closed: any missing precondition refuses with its reason, and
    only a genuine below-trigger crossing with a saved method, a fresh crossing and room under the monthly cap
    returns ``charge``. The monthly cap is checked against ``month_charged + pack_credits`` so the cap is NEVER
    exceeded."""
    if settings is None or not settings.enabled:
        return Decision("disabled")
    if int(available) >= int(settings.trigger_credits):
        return Decision("above_trigger")
    if not has_method:
        return Decision("no_method")
    if already_charged:
        return Decision("already_charged")           # this crossing already decided (idempotent)
    base = Decision("charge", pack_price_id=settings.pack_price_id, credits=int(pack_credits),
                    amount_minor=int(pack_amount_minor), currency=str(pack_currency))
    if int(month_charged) + int(pack_credits) > int(settings.monthly_cap_credits):
        return Decision("cap_exceeded", pack_price_id=settings.pack_price_id, credits=int(pack_credits),
                        amount_minor=int(pack_amount_minor), currency=str(pack_currency))
    return base


@dataclass(frozen=True)
class ChargeResult:
    """The outcome of one ``AutoTopUpCharger.run``. ``recorded`` is the new charge record (None when nothing was
    appended — a non-acting decision, an idempotent re-drive, or a transient egress fault). ``reason`` mirrors
    ``Decision.reason`` plus the charge outcomes: ``charged`` / ``declined`` (recorded, the crossing consumed) and
    ``transient`` (nothing recorded; the next sweep retries under the same Idempotency-Key)."""
    reason: str
    recorded: "Optional[Charge]" = None
    payment_intent_id: str = ""


ReceiptFn = Callable[[str, Charge], None]


def crossing_nonce(org_id: str, crossing_key: str) -> str:
    """The deterministic per-crossing nonce of an off-session charge: ``at`` + 32 hex of sha256(org, crossing). It
    keys the Stripe Idempotency-Key (``vigil-at-<nonce>``) and the PaymentIntent's ``tx_ref``, so every retry of one
    crossing reuses the ONE PaymentIntent. Hashed because a crossing key is a grant ``entry_id`` that may hold a
    ``:`` (the tx_ref delimiter) or other characters an Idempotency-Key must not carry."""
    import hashlib
    digest = hashlib.sha256(f"{org_id}\x00{crossing_key}".encode("utf-8")).hexdigest()
    return "at" + digest[:32]


class AutoTopUpCharger:
    """Evaluate one org's auto-top-up and, on a genuine crossing, create the off-session Stripe charge, record the
    owner-signed decision (idempotent per crossing) and fire ONE receipt/notification. CREDIT is NOT minted here —
    the off-session PaymentIntent's ``payment_intent.succeeded`` webhook mints it through the existing drain.

    Injected: the ``reg`` (AutoTopUpRegistry, owner-signing), the ``wallet`` (balance read), the ``provider``
    (``billing.StripeBillingProvider`` with ``auto_topup=True`` and a payment-intent creator; in tests the repo's
    FAKE creator) and an optional ``notify(org_id, charge)`` — fired exactly once per NEW record (charged → a
    receipt; declined / cap_blocked → an alert). A re-drive fires nothing."""

    def __init__(self, reg: AutoTopUpRegistry, wallet, provider, *, notify: "Optional[ReceiptFn]" = None):
        self.reg = reg
        self.wallet = wallet
        self.provider = provider
        self.notify = notify

    def run(self, org_id: str, *, now: float) -> ChargeResult:
        oid = org_tenant_id(org_id)
        settings = self.reg.settings(oid)
        available = self.wallet.available(oid)
        method = self.reg.payment_method(oid)
        anchor = self.reg.last_credit_anchor(oid)
        already = self.reg.has_charge(oid, anchor)
        pack_credits, pack_amount, pack_ccy = _pack_values(getattr(settings, "pack_price_id", ""))
        d = decide(settings, available=available, has_method=method is not None, already_charged=already,
                   month_charged=self.reg.month_charged_credits(oid, now), pack_credits=pack_credits,
                   pack_amount_minor=pack_amount, pack_currency=pack_ccy)
        if d.reason in ("disabled", "above_trigger", "no_method", "already_charged"):
            return ChargeResult(d.reason)
        if d.reason == "cap_exceeded":
            return self._record_and_notify(oid, anchor, STATUS_CAP_BLOCKED, d, "", now)
        # d.reason == "charge": create the off-session PaymentIntent (money from the owner catalog, never here).
        from .billing import UnsupportedCapability
        from .stripe_egress import StripeEgressError
        assert method is not None                      # has_method guaranteed by decide()
        try:
            charge = self.provider.create_off_session_topup(
                oid, d.pack_price_id, customer_id=method.customer_id, payment_method_id=method.payment_method_id,
                expected={d.pack_price_id: (d.amount_minor, d.currency)}, nonce=crossing_nonce(oid, anchor))
        except StripeEgressError as exc:
            if getattr(exc, "transient", False):
                # A transport fault / HTTP 408/425/429/5xx: Stripe MAY have taken the charge. Record nothing — the
                # next sweep retries under the SAME Idempotency-Key (Stripe hands back the one PaymentIntent), and
                # if the webhook mints it first, the monthly tally still counts it (its grant leg).
                return ChargeResult("transient")
            return self._record_and_notify(oid, anchor, STATUS_DECLINED, d, "", now)
        except (UnsupportedCapability, ValueError):
            return self._record_and_notify(oid, anchor, STATUS_DECLINED, d, "", now)
        if charge is None or not getattr(charge, "accepted", False):
            return self._record_and_notify(oid, anchor, STATUS_DECLINED, d, "", now)
        return self._record_and_notify(oid, anchor, STATUS_CHARGED, d, charge.payment_intent_id, now)

    def _record_and_notify(self, oid: str, anchor: str, status: str, d: Decision, pi_id: str,
                           now: float) -> ChargeResult:
        seq = self.reg.record_charge(oid, crossing_key=anchor, status=status, pack_price_id=d.pack_price_id,
                                     credits=d.credits, amount_minor=d.amount_minor, currency=d.currency,
                                     payment_intent_id=pi_id, issued_at=now)
        rec: "Optional[Charge]" = None
        if seq is not None:                            # a NEW record — surface exactly one receipt/notification
            rec = next((c for c in self.reg.charges(oid) if c.crossing_key == anchor), None)
            if self.notify is not None and rec is not None:
                self.notify(oid, rec)
        reason = {STATUS_CHARGED: "charged", STATUS_DECLINED: "declined",
                  STATUS_CAP_BLOCKED: "cap_exceeded"}[status]
        return ChargeResult(reason, recorded=rec, payment_intent_id=pi_id)


def _pack_values(pack_price_id: str) -> "tuple[int, int, str]":
    """(credits, amount_minor, currency) for a pack from the OWNER CATALOG — never a caller/wire value. (0, 0, "")
    for an unknown/empty pack (decide() then never reaches a charge for it)."""
    p = str(pack_price_id or "").strip()
    if not p:
        return 0, 0, ""
    from .billing import EVENT_TOPUP
    from .catalog import mintable_entitlements, mintable_expected
    ent = mintable_entitlements().get(p)
    if ent is None or ent.kind != EVENT_TOPUP:
        return 0, 0, ""
    amt = mintable_expected().get(p, (0, ""))
    return int(ent.credits), int(amt[0]), str(amt[1])


def maybe_auto_topup(reg: AutoTopUpRegistry, wallet, provider, org_id: str, *, now: float,
                     notify: "Optional[ReceiptFn]" = None) -> ChargeResult:
    """The seam the billing/settle path (or the W5 low-balance trigger) calls inline right after a debit, and the
    ``auto-topup-run`` sweep calls per org: evaluate the org and, on a genuine crossing, charge once. Fail-closed
    (byte-identical caller behaviour on any non-acting reason). A thin wrapper over ``AutoTopUpCharger.run``."""
    return AutoTopUpCharger(reg, wallet, provider, notify=notify).run(org_id, now=now)
