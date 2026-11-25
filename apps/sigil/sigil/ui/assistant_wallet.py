"""PR-J2 — the customer security assistant's ACCOUNTING: every assistant turn admitted against the asking org's rate
limit and daily turn budget, audited before its model request, and — with metered billing on — billed to the org's own
credits (the WALLET DRAW) with an exact settle and a statement line.

THE ADMISSION (every billing mode, :func:`turn_opener`). Before a turn's one model request is sent — and before its
grant is even minted — the turn is decided under the spine lock and the cross-process settle lock: the org's admitted
turns in the last hour and the last day are counted from the owner-signed turn ledger (``governor.assistant_turns``),
the turn is refused as RATE LIMITED (:class:`TurnRateLimited`, with the seconds until a slot frees) when either is at
``config.assistant_turns_per_hour`` / ``config.assistant_turns_per_day``, and otherwise the turn's owner-signed AUDIT
record (who asked, for which org, under which grant nonce, how it is paid for, its worst case) is appended FIRST — a
turn whose record cannot be written is refused, so no model request is ever made unaudited. In a flat-billed deployment
that is the whole of it (:meth:`AssistantTurns.admit_flat`): the turn draws nothing, and its cost to VIGIL is bounded by
its grant's cap, so an org's assistant costs VIGIL at most ``turns_per_day x cap`` a day.

THE WALLET DRAW (metered billing on). Every customer model request is then charged from the org's prepaid credits
through the model gateway's per-grant ALLOWANCE (W2b-2). A launch's allowance is its owner-signed lease; an assistant
turn has no lease and must never get one (a lease on the cross-plane seam is a capability the keyless offense plane
arms). This module gives ONE assistant turn the money semantics of a metered launch, built entirely from the ledger
vocabulary the launch path already speaks — so the wallet fold, the org's sub-credit remainder, the snapshot /
hard-prune seed, the statement's balance-after timeline (I4) and the reservation scan all read a turn with no new
record kind and no new signer:

  * **the turn's slug** — ``asst_<24 hex of sha256("assistant" NUL org_id)>`` (:func:`assistant_slug`): one per org,
    RE-DERIVED from the org on every read, so a turn is only ever its own org's; never a ``cust_`` launch slug (no
    launch-target check, seam lease or launch sweep can confuse the two) and free of ``:`` (the ledger's entry-id
    separator). The turn's NONCE is its model grant's nonce (128 random bits, fresh per turn): the turn's reserve, its
    meter (``meter_id(slug, nonce)``) and its settle are all keyed by the grant.
  * **reserve** (:meth:`AssistantTurns.reserve`) — BEFORE the model request, under the spine lock and the
    cross-process settle lock (the sub-credit remainder only moves under it), the WORST case of the turn's ONE request
    (``model_gateway.plain_request_worst_mc`` of the exact bytes it will send — what the gateway itself reserves for
    it) is HELD from the org's credits in whole credits, exactly as a metered launch's reservation: plan credits
    first, then the wallet (``LaunchGate._spend``: ``reserve-plan:`` / ``reserve-wallet:{slug}:{nonce}``), or the
    owner-signed postpaid credit line (``reserve-postpaid:``). Refused, with NOTHING held, when the org is at its rate
    limit or turn budget, while it is on a billing hold (W5), when its EXACT balance (whole credits less its
    sub-credit remainder) — or its credit line's headroom — cannot cover it, or when the nonce was already used (the
    availability-delta invariant: a replayed reserve's idempotent records no-op, so no delta, so refused). It never
    overdraws: the size is decided against the live exact balance inside both locks, so racing turns never jointly
    hold more than the org has. The turn's audit record is appended in the same critical section, before the hold.
  * **the gateway allowance** (:meth:`AssistantTurns.allowance_mc`, reached through ``LaunchAllowance``) — ``1000 x``
    the turn's OWN owner-signed reserve records, for a grant whose slug is its own org's assistant slug and whose
    ``(org, slug, nonce)`` names an UNSETTLED reservation; anything else is None (the gateway refuses). Never
    extended: a turn's hold is exactly its one request's worst case.
  * **settle** (:meth:`AssistantTurns.settle`) — after the turn, whatever happened: the meter is CLOSED first (the
    grant can spend nothing more; the usage is final), the exact use is read as the statement prices it
    (``LaunchGate.metered_use_mc``), and the SAME exactly-once settle transaction a launch uses
    (``LaunchGate._settle_reservation`` -> ``_settle_once``) keeps ``floor((r + used) / 1000)`` whole credits — never
    more than the turn held — carries the rest as the org's remainder in the owner-signed v3
    ``governor.launch_settled`` decision (basis ``assistant``) and returns the unused hold to the bucket it came from.
    It reads and writes nothing on the seam (``seam=False``): the spine's decision record is the settlement evidence.
  * **a turn a crash left unsettled** (:meth:`AssistantTurns.stale`) — once its grant can no longer be admitted (its
    life plus a grace), the org's next turn settles it first (:meth:`AssistantTurns.settle_stale`), the cockpit
    settles every org's in the background (:func:`start_background`), and ``sigil ops-sweep reservations`` lists —
    with ``--apply`` settles — them too; a settle a crash interrupted after its decision is finished from the
    RECORDED decision, never re-decided. Like E7's superseded release, the amount is read from the turn's LIVE
    reserve records, so these settle it long before any hard prune could reach them.

Every amount comes from owner-signed records or the hash-chained meter, never from a caller's number. Behind
``config.customer_assistant_wallet_enabled()`` (default OFF; the callers check it). FATAL-2: ``assert_no_offense()``
at import; nothing here imports ``engine/crucible`` (framework / strix).
"""
from __future__ import annotations

import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.rate_card import MC_PER_CREDIT  # noqa: E402  (one credit = 1,000 milli-credits)

__all__ = ["ASSISTANT_SLUG_PREFIX", "AssistantTurns", "MAX_TURN_MC", "Mint", "SETTLE_BASIS", "STALE_GRACE_S",
           "STATEMENT_OPERATION", "SWEEP_INTERVAL_S", "TURN_DIAL_TIMEOUT_S", "TURN_LIFE_S", "TurnRateLimited",
           "TurnRefused", "assistant_slug", "is_assistant_slug", "start_background", "turn_need_mc", "turn_opener"]

_log = logging.getLogger(__name__)

ASSISTANT_SLUG_PREFIX = "asst_"
_SLUG_RE = re.compile(r"asst_[0-9a-f]{24}")
#: A turn's nonce is its grant's (``vigil_core.model_grant.new_grant_id``): 128 random bits, 32 lowercase hex.
_NONCE_RE = re.compile(r"[0-9a-f]{32}")
#: The life of a turn's model grant — what ``provision.Provisioner._mint_assistant_grant`` gives it (pinned equal by
#: ``test_assistant_wallet``). After it the gateway admits no request on the grant.
TURN_LIFE_S = 300.0
#: How long after its grant's life an unsettled turn is left to its own settle before the org's next turn (or the
#: reservation sweep) settles it: a request admitted just before expiry may still be finishing (its settle then waits
#: on the live meter — ``MeterBusy`` — and is retried, never forced).
STALE_GRACE_S = 60.0
#: The most one turn may hold, in milli-credits (a sanity bound on a hostile / corrupt size: a million credits).
MAX_TURN_MC = MC_PER_CREDIT * 1_000_000
#: The settle decision's ``basis`` (``governor.launch_settlement.BASES``).
SETTLE_BASIS = "assistant"
#: The OPERATION a turn's charge is listed under on the customer statement (``ui.billing.billing_usage``).
STATEMENT_OPERATION = "Security assistant"
#: How long the cockpit waits on the gateway for ONE accounted turn's model request (seconds). The customer edge waits
#: longer for the whole turn (``custui._ASSISTANT_ACCOUNTED_HOP_S``, pinned above this by ``test_assistant_wallet``),
#: so an answer the org is billed for is never reported to it as failed.
TURN_DIAL_TIMEOUT_S = 40.0

_INSUFFICIENT = "insufficient credits for an assistant answer: top up your wallet to continue"
_REPLAYED = "this assistant turn's hold did not apply (its grant nonce was already used)"
_BUSY = "billing is busy right now; please ask again in a moment"


class TurnRefused(RuntimeError):
    """A turn was refused before anything was sent (not enough credits, a billing hold, a replayed nonce, a busy
    ledger, an audit record that could not be written). The provisioner answers it as a denial."""


class TurnRateLimited(TurnRefused):
    """A turn was refused because the org is at its assistant rate limit or daily turn budget (the owner-signed turn
    ledger, ``governor.assistant_turns``); ``retry_after`` is the seconds until a slot frees. The provisioner answers it
    as rate limited (``ProvisionRateLimited``)."""

    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = float(retry_after)


#: Mints the owner-signed model grant of ONE admitted turn — ``mint(slug=, nonce=, now=, cap_nano_usd=)``; ``slug`` is
#: the turn's hold slug when it is billed to the org's credits, None for a flat turn (the provisioner's
#: ``_mint_assistant_grant``, which holds the owner key; this module never does).
Mint = Callable[..., str]


def assistant_slug(org_id: str) -> str:
    """The assistant slug of ``org_id``: ``asst_`` + 24 hex of ``sha256("assistant" NUL org_id)``. Deterministic per
    org (one-way: it names no org), so every read re-derives it from the org — a turn is only ever its own org's."""
    from ..reuse import sha256_hex
    return ASSISTANT_SLUG_PREFIX + sha256_hex(("assistant\x00" + str(org_id)).encode("utf-8"))[:24]


def is_assistant_slug(slug: object) -> bool:
    """True iff ``slug`` has the shape of an assistant slug (``asst_`` + 24 lowercase hex). A launch slug (``cust_``,
    or an operator host slug) never does."""
    return isinstance(slug, str) and _SLUG_RE.fullmatch(slug) is not None


def _valid_nonce(nonce: object) -> bool:
    return isinstance(nonce, str) and _NONCE_RE.fullmatch(nonce) is not None


def turn_need_mc(raw_len: int, max_tokens: int) -> int:
    """What ONE assistant turn must hold, in milli-credits: the gateway's prepaid worst case for the turn's request of
    ``raw_len`` bytes asking for ``max_tokens`` output, at the published rate card (``plain_request_worst_mc``).
    Raises ``ValueError`` (``RateCardError`` included) on a malformed card or an impossible size — never a guess."""
    from vigil_core.rate_card import rate_card
    from ..model_gateway import plain_request_worst_mc
    return plain_request_worst_mc(rate_card(), raw_len, max_tokens)


class AssistantTurns:
    """The money side of customer assistant turns over ONE :class:`~sigil.ui.launch_gate.LaunchGate` (its store,
    owner key, ledgers and locks — the launch path's own, reused, never re-implemented)."""

    def __init__(self, gate: Any):
        self.gate = gate

    # -- the turn ledger (rate limit + daily budget + audit record), shared by both billing modes --------------------
    def _ledger(self) -> Any:
        from ..governor.assistant_turns import AssistantTurnLedger
        return AssistantTurnLedger(self.gate.store, owner_key=self.gate.owner_key)

    @staticmethod
    def _limits(per_hour: Optional[int], per_day: Optional[int]) -> "tuple[int, int]":
        from .. import config
        return (config.assistant_turns_per_hour() if per_hour is None else per_hour,
                config.assistant_turns_per_day() if per_day is None else per_day)

    def _admit_locked(self, ledger: Any, oid: str, *, nonce: str, requester: str, mode: str, cap_nano_usd: int,
                      hold_mc: int, now_ts: float, per_hour: int, per_day: int) -> Optional[dict]:
        """THE admission, inside the caller's critical section (the spine lock and the settle lock held): the org's
        rate limit and daily turn budget decided from the turn ledger, then the turn's owner-signed audit record
        appended. None when the turn is admitted (its record is on the spine); else the refusal, with nothing written.
        Fail-closed: a ledger that cannot be read or written refuses the turn."""
        try:
            limited = ledger.refusal(oid, now=now_ts, per_hour=per_hour, per_day=per_day)
        except ValueError as e:
            return {"ok": False, "error": f"the assistant's limits are invalid (fail-closed): {e}"}
        except Exception as e:  # noqa: BLE001 — an unreadable ledger never admits a turn
            return {"ok": False, "retry": True, "error": f"the assistant's usage cannot be read right now: "
                    f"{type(e).__name__}"}
        if limited is not None:
            return {"ok": False, "rate_limited": True, "retry_after": limited.retry_after, "window": limited.window,
                    "error": limited.message}
        try:
            ledger.record(oid, nonce=nonce, requester=requester, mode=mode, cap_nano_usd=cap_nano_usd,
                          hold_mc=hold_mc, now=now_ts)
        except ValueError as e:
            return {"ok": False, "error": f"the assistant turn cannot be recorded (fail-closed): {e}"}
        except Exception as e:  # noqa: BLE001 — no audit record, no turn
            return {"ok": False, "retry": True, "error": f"the assistant turn cannot be recorded right now: "
                    f"{type(e).__name__}"}
        return None

    def admit_flat(self, *, org_id: str, nonce: str, requester: str, cap_nano_usd: int, now: Any,
                   per_hour: Optional[int] = None, per_day: Optional[int] = None) -> dict:
        """ADMIT one turn of a FLAT-billed deployment (metered billing off): under the spine lock and the cross-process
        settle lock, refused when the org is at its rate limit or daily turn budget (``rate_limited``, with
        ``retry_after``), else the turn's owner-signed audit record (mode ``flat``, its grant's ``cap_nano_usd``) is
        appended. Nothing is drawn from the org's credits. Returns ``{ok: True, org_id, nonce}`` or the refusal (``retry``
        when the ledger is busy); on a refusal nothing is written. ``per_hour`` / ``per_day`` default to the config."""
        from contextlib import ExitStack

        from ..governor.assistant_turns import MODE_FLAT
        from ..governor.orgs import _check_org_id

        g = self.gate
        if g.owner_key is None:
            return {"ok": False, "error": "an assistant turn's record must be owner-signed (internal: no owner key)"}
        try:
            oid = _check_org_id(org_id)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        if not _valid_nonce(nonce):
            return {"ok": False, "error": "an assistant turn is named by its grant nonce (32 lowercase hex)"}
        try:
            now_ts = g._as_dt(now).timestamp()
        except (TypeError, ValueError, OSError, OverflowError):
            return {"ok": False, "error": "now must be a datetime or a POSIX timestamp"}
        hour, day = self._limits(per_hour, per_day)
        ledger = self._ledger()
        with ExitStack() as held:
            held.enter_context(g._lock)
            locked = g._settle_lock_into(held)
            if locked is not None:
                return {"ok": False, "retry": True, "error": _BUSY} if locked.get("retry") else locked
            refused = self._admit_locked(ledger, oid, nonce=nonce, requester=requester, mode=MODE_FLAT,
                                         cap_nano_usd=cap_nano_usd, hold_mc=0, now_ts=now_ts, per_hour=hour,
                                         per_day=day)
            if refused is not None:
                return refused
        return {"ok": True, "action": "assistant_turn_admitted", "org_id": oid, "nonce": nonce}

    # -- reserve -----------------------------------------------------------------------------------------------------
    def reserve(self, *, org_id: str, nonce: str, need_mc: int, now: Any, requester: str, cap_nano_usd: int,
                per_hour: Optional[int] = None, per_day: Optional[int] = None) -> dict:
        """ADMIT one turn BILLED to the org's credits and HOLD ``need_mc`` (rounded UP to whole credits) of
        ``org_id``'s credits for it under its grant ``nonce`` — see the module docstring. Returns ``{ok: True, slug,
        nonce, units_reserved, allowance_mc}`` or ``{ok: False, error}`` (``rate_limited`` + ``retry_after`` at the
        org's rate limit / turn budget, ``retry`` when the ledger is busy), and on any refusal NOTHING is held.
        ``org_id`` / ``requester`` must be the hop-bound session principal the caller already admitted; ``need_mc`` is
        the server's own sizing, validated here anyway; ``cap_nano_usd`` is the cap of the grant the turn will be
        minted with (its audit record carries it)."""
        from contextlib import ExitStack

        from vigil_core.model_grant import meter_id

        from .. import config
        from ..governor.assistant_turns import MODE_METERED
        from ..governor.orgs import _check_org_id
        from ..governor.postpaid import RESERVE_ENTRY_PREFIX, postpaid_is_overdue
        from ..model_gateway import GrantMeter

        g = self.gate
        if g.owner_key is None:
            return {"ok": False, "error": "an assistant turn's hold must be owner-signed (internal: no owner key)"}
        try:
            oid = _check_org_id(org_id)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        if not _valid_nonce(nonce):
            return {"ok": False, "error": "an assistant turn is named by its grant nonce (32 lowercase hex)"}
        if isinstance(need_mc, bool) or not isinstance(need_mc, int) or not 1 <= need_mc <= MAX_TURN_MC:
            return {"ok": False, "error": f"need_mc must be an integer in [1, {MAX_TURN_MC}]"}
        try:
            now_ts = g._as_dt(now).timestamp()
        except (TypeError, ValueError, OSError, OverflowError):
            return {"ok": False, "error": "now must be a datetime or a POSIX timestamp"}
        hour, day = self._limits(per_hour, per_day)
        ledger = self._ledger()
        slug = assistant_slug(oid)
        units = -(-need_mc // MC_PER_CREDIT)          # whole credits that cover the worst case (never fewer)

        def _gated() -> Optional[str]:
            held = g._billing_hold_refusal(oid)       # W5: an org that owes credits after a reversal is on hold
            if held is not None:
                return held
            acct = g.postpaid.account(oid)
            if acct is not None and acct.is_enabled():
                if postpaid_is_overdue(g.invoices, g.postpaid, oid, now_ts):
                    return ("your postpaid line is overdue: settle the outstanding invoice to keep using the "
                            "assistant")
                if g._exact_room(oid, acct.credit_limit - g.arrears.accrued(oid)) < units:
                    return "your postpaid credit line has no room left for an assistant answer"
                return None
            if g._exact_room(oid, g.meter.available(oid, now_ts)) < units:
                return _INSUFFICIENT
            return None

        pre = _gated()                                 # a cheap refusal outside the locks
        if pre is not None:
            return {"ok": False, "error": pre}
        with ExitStack() as held:
            held.enter_context(g._lock)
            locked = g._settle_lock_into(held)         # the exact balance's remainder only moves under it
            if locked is not None:
                return {"ok": False, "retry": True, "error": _BUSY} if locked.get("retry") else locked
            again = _gated()                           # TOCTOU: every conjunct re-decided under both locks
            if again is not None:
                return {"ok": False, "error": again}
            # the rate limit / turn budget, then the turn's audit record — before anything is held or sent
            refused = self._admit_locked(ledger, oid, nonce=nonce, requester=requester, mode=MODE_METERED,
                                         cap_nano_usd=cap_nano_usd, hold_mc=MC_PER_CREDIT * units, now_ts=now_ts,
                                         per_hour=hour, per_day=day)
            if refused is not None:
                return refused
            try:
                # before any credit moves: the turn is billed metered, so its settle always CLOSES its meter (the
                # one revocation of its grant), whether or not its request ever reached the gateway
                GrantMeter(config.MODEL_METER_DIR).mark_metered(meter_id(slug, nonce))
            except OSError as e:
                return {"ok": False, "retry": True,
                        "error": f"the assistant cannot record its usage right now; retry: {type(e).__name__}"}
            acct = g.postpaid.account(oid)
            if acct is not None and acct.is_enabled():
                before_acc = g.arrears.accrued(oid)
                g.arrears.accrue(oid, units, engagement_id=slug, entry_id=f"{RESERVE_ENTRY_PREFIX}{slug}:{nonce}",
                                 issued_at=now_ts)
                if g.arrears.accrued(oid) - before_acc < units:
                    return {"ok": False, "error": _REPLAYED}
            else:
                before = g.meter.available(oid, now_ts)
                g._spend(oid, units, slug, nonce, now_ts)  # plan-first then wallet, idempotent per (slug, nonce)
                if before - g.meter.available(oid, now_ts) < units:
                    return {"ok": False, "error": _REPLAYED}
        return {"ok": True, "action": "assistant_turn_reserved", "org_id": oid, "slug": slug, "nonce": nonce,
                "units_reserved": units, "allowance_mc": MC_PER_CREDIT * units}

    # -- the gateway's allowance source (through ``launch_gate.LaunchAllowance``) -----------------------------------
    def allowance_mc(self, grant: Any) -> Optional[int]:
        """What the turn of ``grant`` may be charged in all, in milli-credits: ``1000 x`` its OWN owner-signed reserve
        records (``scan_reservations``, verified under the owner key valid at their seq), or None — the grant's slug
        is not its own org's assistant slug (a turn is never another org's), its nonce is not a turn nonce, no such
        reservation is on the spine, it is already settled, or it carries an extension (a turn is never extended):
        the gateway then refuses the request. Raises what the spine read raises (the gateway: retryable)."""
        from ..governor.launch_reservations import scan_reservations
        kp = self.gate.owner_key
        if kp is None:
            return None
        org = getattr(grant, "org_id", None)
        slug = getattr(grant, "engagement_slug", None)
        nonce = getattr(grant, "nonce", None)
        if (not (isinstance(org, str) and org) or not isinstance(slug, str) or slug != assistant_slug(org)
                or not isinstance(nonce, str) or not _valid_nonce(nonce)):
            return None
        ix = scan_reservations(self.gate.store, kp.public_key_b64, org_id=org, slug=slug)
        key = (org, slug, nonce)
        res = ix.reservations.get(key)
        if res is None or key in ix.settled or res.extensions:
            return None
        return MC_PER_CREDIT * res.reserved

    @staticmethod
    def available_credits(grant: Any) -> int:
        """A turn never draws more than its hold: nothing is available to extend it."""
        return 0

    @staticmethod
    def extend(grant: Any, credits: int) -> dict:
        """Refused: a turn's hold is exactly its one request's worst case and is never extended."""
        return {"ok": False, "insufficient": True, "error": "an assistant turn's hold is never extended"}

    @staticmethod
    def note_credit_pause(grant: Any, now: float) -> bool:
        """A turn has nothing to park: the gateway's terminal credit stop simply ends the turn."""
        return True

    # -- settle ------------------------------------------------------------------------------------------------------
    def settle(self, *, org_id: str, nonce: str, now: Any) -> dict:
        """Settle turn ``nonce`` of ``org_id`` EXACTLY, exactly once — see the module docstring. The amount held comes
        from the turn's own owner-signed reserve records; what it used from its CLOSED meter (each confirmed response
        at the rate it was recorded with, as the statement prices it); the money moves in ``LaunchGate``'s one
        exactly-once settle transaction (``seam=False``). Returns that transaction's result (``launch_settled`` /
        ``launch_already_settled``, with ``consumed_mc`` / ``remainder_mc``), or ``{ok: False, error}`` with
        ``retry`` while it must wait (a request still in flight, a busy lock, a pricing setting it cannot apply) —
        the hold then stays until a retry settles it. A broken meter or inconsistent records refuse without moving
        anything (fail-closed)."""
        from vigil_core import model_metering as mm
        from vigil_core.model_grant import meter_id
        from vigil_core.rate_card import RateCardError

        from .. import config
        from .. import model_gateway as _gw
        from ..governor.launch_reservations import RESERVE_WALLET_PREFIX, scan_reservations
        from ..governor.orgs import _check_org_id
        from ..governor.postpaid import RESERVE_ENTRY_PREFIX

        g = self.gate
        kp = g.owner_key
        if kp is None:
            return {"ok": False, "error": "an assistant turn's settle must be owner-signed (internal: no owner key)"}
        try:
            oid = _check_org_id(org_id)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        if not _valid_nonce(nonce):
            return {"ok": False, "error": "an assistant turn is named by its grant nonce (32 lowercase hex)"}
        try:
            now_ts = g._as_dt(now).timestamp()
        except (TypeError, ValueError, OSError, OverflowError):
            return {"ok": False, "error": "now must be a datetime or a POSIX timestamp"}
        slug = assistant_slug(oid)
        ix = scan_reservations(g.store, kp.public_key_b64, org_id=oid, slug=slug)
        res = ix.reservations.get((oid, slug, nonce))
        if res is None:
            return {"ok": False, "error": "no owner-signed hold for this assistant turn"}
        # the bucket(s) it drew from must be the ones its settle returns to (detected exactly as a launch's settle)
        postpaid = g.arrears.was_accrued(oid, f"{RESERVE_ENTRY_PREFIX}{slug}:{nonce}")
        if (res.extensions or res.reserved <= 0
                or set(res.units) - ({"postpaid"} if postpaid else {"plan", "wallet"})
                or (not postpaid and "wallet" not in res.units
                    and g.wallet.has_debit_entry(oid, f"{RESERVE_WALLET_PREFIX}{slug}:{nonce}"))):
            return {"ok": False, "error": "the assistant turn's hold records are inconsistent (fail-closed)"}
        mid = meter_id(slug, nonce)
        try:
            # CLOSED first: the grant can spend nothing more, so the use read next is final
            _gw.GrantMeter(config.MODEL_METER_DIR).close(mid, now=now_ts)
        except _gw.MeterBusy:
            return {"ok": False, "retry": True, "error": "the turn's model request is still in flight; retry the settle"}
        except OSError as e:
            return {"ok": False, "retry": True,
                    "error": f"the turn's model meter cannot be written right now; retry: {type(e).__name__}"}
        except ValueError as e:
            return {"ok": False, "error": f"the turn's model meter is broken (fail-closed): {type(e).__name__}"}
        try:
            used = int(g.metered_use_mc(slug, nonce))
        except (mm.MeteringError, RateCardError) as e:
            return {"ok": False, "retry": True, "error": f"the turn's charge waits on its pricing configuration: {e}"}
        except ValueError as e:
            return {"ok": False, "error": f"the turn's model meter is broken (fail-closed): {type(e).__name__}"}
        # never more than the turn held (a response the provider over-billed past the gateway's worst case is VIGIL's
        # cost, never the customer's), never negative
        exact = min(max(0, used), MC_PER_CREDIT * res.reserved)
        out = g._settle_reservation(oid, slug, nonce, res.reserved, 0, now_ts, None, SETTLE_BASIS, exact_mc=exact,
                                    seam=False)
        if out.get("ok"):
            _gw.forget_closed_meter(mid)               # the cockpit's gateway drops the closed turn's memory
        return out

    # -- turns a crash left behind -----------------------------------------------------------------------------------
    def stale(self, *, now: float, org_id: Optional[str] = None) -> "list[dict]":
        """READ-ONLY: every assistant turn (of ``org_id``, or of every org) that needs a settle nobody else will give
        it — ``why="unsettled"``: held, unsettled, and past its grant's life plus :data:`STALE_GRACE_S` (no request
        can be admitted on it any more); ``why="settle_interrupted"``: settled by a recorded decision whose money has
        not all landed (``LaunchGate.unlanded_settlement``, with its pending amounts). A turn still within its grant's
        life is never listed (its own settle owns it). One pass over the spine; writes nothing."""
        from ..governor.launch_reservations import scan_reservations
        g = self.gate
        kp = g.owner_key
        if kp is None:
            return []
        slug = assistant_slug(org_id) if org_id is not None else None
        ix = scan_reservations(g.store, kp.public_key_b64, org_id=org_id, slug=slug, evidence=True)
        rows: "list[dict]" = []
        for res in sorted(ix.reservations.values(), key=lambda r: r.seq):
            if not is_assistant_slug(res.slug) or res.slug != assistant_slug(res.org_id):
                continue                               # a launch, or a slug that is not its org's own
            row = {"org_id": res.org_id, "slug": res.slug, "nonce": res.nonce, "units_reserved": res.reserved,
                   "reserved_at": res.issued_at}
            if res.key in ix.settled:
                pending = g.unlanded_settlement(org_id=res.org_id, slug=res.slug, nonce=res.nonce,
                                                evidence=ix.settlement(res.key))
                if pending:
                    rows.append({**row, "why": "settle_interrupted", **pending})
                continue
            if not now >= res.issued_at + TURN_LIFE_S + STALE_GRACE_S:
                continue                               # its grant may still be admitted (or the time is unreadable)
            rows.append({**row, "why": "unsettled"})
        return rows

    def settle_stale(self, *, org_id: Optional[str], now: float) -> "list[dict]":
        """Settle every turn :meth:`stale` lists (of ``org_id``, or of every org): an unsettled one exactly (what its
        meter confirmed, the rest returned — a crash never charges a customer what it cannot prove), an interrupted
        one by finishing its recorded decision. Returns one ``{row..., "result": <settle result>}`` per turn. Never
        raises: a turn whose settle fails stays held and is listed again next time."""
        out: "list[dict]" = []
        try:
            rows = self.stale(now=now, org_id=org_id)
        except Exception:  # noqa: BLE001 — housekeeping never blocks a turn; the next pass retries
            import logging
            logging.getLogger(__name__).warning("could not list stale assistant turns", exc_info=True)
            return out
        for row in rows:
            try:
                result = self.settle(org_id=row["org_id"], nonce=row["nonce"], now=now)
            except Exception as e:  # noqa: BLE001 — a settle that breaks leaves the hold for the next pass
                result = {"ok": False, "error": f"settle failed: {type(e).__name__}"}
            out.append({**row, "result": result})
        return out


# -- one turn, end to end: what the provisioner's gateway dial calls before it sends -----------------------------------
def _settle_quietly(turns: AssistantTurns, org_id: str, nonce: str) -> None:
    """Settle a turn billed to the org's credits once its request is over. Never raises: a settle that must wait (a
    request still in flight, a busy lock) leaves the hold for the org's next turn, the cockpit's background close-out
    or ``ops-sweep reservations`` — none of which ever charges more than the turn's meter proves."""
    try:
        out = turns.settle(org_id=org_id, nonce=nonce, now=time.time())
    except Exception as e:  # noqa: BLE001 — the hold stays; a later settle finishes it
        out = {"ok": False, "error": f"settle failed: {type(e).__name__}"}
    if not out.get("ok"):
        _log.warning("an assistant turn's settle must wait (its hold stays until it is settled later): %s",
                     str(out.get("error", ""))[:200])


def turn_opener(gate: Any, *, org_id: str, requester: str, mint: Mint, metered: bool) -> "Callable[[bytes, int], tuple]":
    """The ``open_turn`` of ``assistant.accounted_gateway_model_call`` for the session principal ``requester`` of
    ``org_id`` (both hop-bound, already admitted by the caller). Each call admits ONE model request as one turn under
    a fresh grant nonce, BEFORE anything is sent:

      * ``metered`` (metered billing on): a turn of this org a crash left unsettled is settled first (best effort),
        then the request's worst case — sized from its EXACT bytes — is held from the org's credits by
        :meth:`AssistantTurns.reserve` (rate limit, turn budget and the audit record decided in the same critical
        section); the grant is minted for that hold, and the returned closer settles the turn exactly once the request
        is over (a grant that cannot be minted returns the hold at once);
      * flat (metered billing off): :meth:`AssistantTurns.admit_flat` (rate limit, turn budget, audit record), then the
        grant — nothing is drawn and there is nothing to close.

    A refusal raises :class:`TurnRateLimited` (at the org's limit) or :class:`TurnRefused` (anything else) and NOTHING
    is sent. The limits and the grant's cap are read from the config on every call."""
    from vigil_core.model_grant import new_grant_id

    from .. import config

    turns = AssistantTurns(gate)

    def open_turn(raw: bytes, max_tokens: int) -> "tuple[str, Optional[Callable[[], None]]]":
        now = time.time()
        nonce = new_grant_id()
        cap = config.assistant_cap_nano_usd()
        if metered:
            turns.settle_stale(org_id=org_id, now=now)  # never raises: a stale turn that must wait stays held
            try:
                need = turn_need_mc(len(raw), int(max_tokens))
            except ValueError:
                raise TurnRefused("the assistant cannot be priced right now (fail-closed)") from None
            r = turns.reserve(org_id=org_id, nonce=nonce, need_mc=need, now=now, requester=requester,
                              cap_nano_usd=cap)
        else:
            r = turns.admit_flat(org_id=org_id, nonce=nonce, requester=requester, cap_nano_usd=cap, now=now)
        if not r.get("ok"):
            why = str(r.get("error") or "the assistant turn could not be admitted")
            if r.get("rate_limited"):
                raise TurnRateLimited(why, float(r.get("retry_after") or 1.0))
            raise TurnRefused(why)
        if not metered:
            return mint(slug=None, nonce=nonce, now=now, cap_nano_usd=cap), None
        try:
            token = mint(slug=str(r["slug"]), nonce=nonce, now=now, cap_nano_usd=cap)
        except BaseException:
            _settle_quietly(turns, org_id, nonce)       # no grant, no request: the hold goes straight back
            raise
        return token, lambda: _settle_quietly(turns, org_id, nonce)

    return open_turn


# -- the cockpit's background close-out of turns a crash left behind -------------------------------------------------
#: How often the cockpit settles stale assistant turns (seconds). One spine pass each time; a crash is rare.
SWEEP_INTERVAL_S = 600.0
_STARTED: "set[str]" = set()
_STARTED_LOCK = threading.Lock()


def start_background(store_factory: Callable[[], Any], *, interval_s: float = SWEEP_INTERVAL_S
                     ) -> "Optional[threading.Event]":
    """Start, once per process and spine, the cockpit's background close-out of every org's stale assistant turns
    (:meth:`AssistantTurns.settle_stale` over all orgs, every ``interval_s``) — so a turn a crash left held is settled
    exactly even if its org never asks again and no operator runs ``ops-sweep reservations``. Started only while
    ``config.customer_assistant_wallet_enabled()`` and ``config.metered_billing_enabled()`` (both re-read before every
    pass: off, a pass does nothing). Returns the stop event (tests), or None when nothing was started. A pass that
    fails is logged and retried at the next interval; it never takes the cockpit down."""
    from .. import config
    if not (config.customer_assistant_wallet_enabled() and config.metered_billing_enabled()):
        return None
    try:
        ident = str(Path(store_factory().path).resolve())
    except Exception:  # noqa: BLE001 — an unresolvable store: nothing to sweep
        return None
    with _STARTED_LOCK:
        if ident in _STARTED:
            return None
        _STARTED.add(ident)
    stop = threading.Event()

    def _run() -> None:
        from .launch_gate import LaunchGate
        while not stop.wait(float(interval_s)):
            if not (config.customer_assistant_wallet_enabled() and config.metered_billing_enabled()):
                continue
            try:
                done = AssistantTurns(LaunchGate(store_factory())).settle_stale(org_id=None, now=time.time())
                if done:
                    _log.info("settled %d stale assistant turn(s)", sum(1 for d in done if d["result"].get("ok")))
            except Exception:  # noqa: BLE001 — a failed pass is retried at the next interval
                _log.exception("the stale assistant-turn close-out failed (retried at the next interval)")

    worker = threading.Thread(target=_run, name="assistant-turns", daemon=True)
    stop.thread = worker                              # type: ignore[attr-defined]  # tests join it after stop.set()
    worker.start()
    return stop
