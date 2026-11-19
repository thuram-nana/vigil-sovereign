"""PR-J2 — the customer security assistant's per-org TURN LEDGER: the owner-signed audit record of every assistant turn
VIGIL answers, and the per-org rate limit + daily turn budget that ledger is the single source of truth for.

With ``VIGIL_CUSTOMER_ASSISTANT_WALLET`` on, every assistant turn is ADMITTED before its one model request is sent
(``ui.assistant_wallet``): under the spine lock and the cross-process settle lock the org's turns in the last hour and
in the last day are counted HERE (:meth:`AssistantTurnLedger.refusal`), the turn is refused — rate limited, with the
seconds until a slot frees — when either count is at its limit, and otherwise ONE owner-signed
``governor.assistant_turn`` record is appended (:meth:`AssistantTurnLedger.record`) before anything is held or sent:

  * **who asked** — the hop-bound session principal (``requester``) and the session org (``org_id``); never a body
    field, and never the question itself (that is the customer's data, not an audit field);
  * **under which grant** — the turn's grant ``nonce`` (128 random bits, fresh per turn): it keys the turn's model
    meter and, for a turn billed to the org's credits, its hold and its exact settle (``ui.assistant_wallet``), so the
    audit record, the meter, the wallet entries and the statement line of one turn all join on it;
  * **how it is paid for** — ``mode``: ``metered`` (drawn from the org's own credits, metered billing on) or ``flat``
    (a flat-billed deployment: VIGIL bears the model cost, bounded below);
  * **its worst case** — ``cap_nano_usd``, the grant's cap (the gateway reserves every request against it, so the
    turn can never cost VIGIL more), and ``hold_mc``, what a metered turn held from the org's credits (0 when flat).

THE LIMITS (``config.assistant_turns_per_hour`` / ``config.assistant_turns_per_day``): at most that many admitted turns
per org in ANY rolling hour / rolling day. Each turn's model spend is bounded by its grant's cap, so a flat-billed org
can cost VIGIL at most ``turns_per_day x assistant_cap`` in a day, and one org's assistant can never take more than that
share of the gateway's account-wide daily ceiling from the other tenants. The decision and the append are one critical
section in the caller (both locks held), so racing turns never jointly pass a limit.

Only VERIFIED records count — owner-signed under the key valid at their seq (``key_history``), each nonce once: a
record anyone else appended is inert (it can neither fill a slot nor free one). Writes ``kind="event"``,
``source="governor"`` records with this module's own literal signal; no latch fold reads it.

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports only sovereign siblings — never ``engine/crucible``.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import _USERNAME_RE, _check_org_id  # noqa: E402

__all__ = ["DAY_S", "HOUR_S", "MAX_CAP_NANO_USD", "MAX_HOLD_MC", "MODES", "MODE_FLAT", "MODE_METERED", "RECORD_VERSION",
           "SIGNAL", "AssistantTurnLedger", "LimitRefusal", "TurnRecord"]

SIGNAL = "governor.assistant_turn"
RECORD_VERSION = 1
_CORE = ("signal", "v", "org_id", "nonce", "requester", "mode", "cap_nano_usd", "hold_mc", "issued_at")
MODE_METERED, MODE_FLAT = "metered", "flat"
MODES = frozenset({MODE_METERED, MODE_FLAT})
HOUR_S, DAY_S = 3600.0, 86400.0
#: Sanity bounds on a record's worst-case amounts (a hostile / corrupt value is refused at write and inert at read).
MAX_CAP_NANO_USD = 10 ** 12
MAX_HOLD_MC = 10 ** 12
#: A turn's nonce is its grant's (``vigil_core.model_grant.new_grant_id``): 128 random bits, 32 lowercase hex.
_NONCE_RE = re.compile(r"[0-9a-f]{32}")
_LOAD_FROM_VAULT = object()


@dataclass(frozen=True)
class TurnRecord:
    """One VERIFIED admitted assistant turn, every field from an owner-signed ``governor.assistant_turn`` record."""
    org_id: str
    nonce: str
    requester: str
    mode: str
    cap_nano_usd: int
    hold_mc: int
    issued_at: float
    seq: int


@dataclass(frozen=True)
class LimitRefusal:
    """Why a NEW turn of an org is refused right now: which window is full (``hour`` / ``day``), how many turns it
    holds against which limit, and ``retry_after`` — the seconds until the oldest turn that keeps it full ages out."""
    window: str
    used: int
    limit: int
    retry_after: float

    @property
    def message(self) -> str:
        span = "hour" if self.window == "hour" else "day"
        return (f"the security assistant answers at most {self.limit} questions per {span} for your organization; "
                f"please ask again in {max(1, int(self.retry_after + 0.999))} seconds")


def _amount(v: Any, most: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= most


def _limit(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ValueError("a turn limit must be a positive integer")
    return v


class AssistantTurnLedger:
    """The owner-signed per-org assistant-turn ledger over ONE spine ``store``."""

    def __init__(self, store: Any, *, owner_key: Any = _LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        if trusted_pubkey is None and self.owner_key is not None:
            trusted_pubkey = self.owner_key.public_key_b64
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- the owner mutation (the caller holds the admission's locks) ----------------------------------------------
    def record(self, org_id: str, *, nonce: str, requester: str, mode: str, cap_nano_usd: int, hold_mc: int,
               now: float) -> int:
        """Owner-sign + append the audit record of ONE admitted turn and return its seq. Fail-closed ``ValueError`` on
        a bad org id / nonce / requester / mode / amount / time or a missing signing key (nothing is appended); an
        append failure raises (``OSError``) — the caller then refuses the turn. Idempotent per (org, nonce) in every
        read: a re-append of the same nonce never counts twice."""
        if self.owner_key is None:
            raise ValueError("recording an assistant turn requires the owner signing key")
        oid = _check_org_id(org_id)
        if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
            raise ValueError("an assistant turn is named by its grant nonce (32 lowercase hex)")
        who = str(requester or "").strip()
        if not _USERNAME_RE.match(who):
            raise ValueError("requester must be the session username (1-64 chars of [A-Za-z0-9._-])")
        if mode not in MODES:
            raise ValueError(f"mode must be one of {sorted(MODES)}")
        if not _amount(cap_nano_usd, MAX_CAP_NANO_USD) or not _amount(hold_mc, MAX_HOLD_MC):
            raise ValueError("cap_nano_usd / hold_mc must be non-negative integers within their bounds")
        if mode == MODE_FLAT and hold_mc:
            raise ValueError("a flat turn holds nothing from the org's credits")
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now < 0:
            raise ValueError("now must be a finite, non-negative POSIX timestamp")
        core = {"signal": SIGNAL, "v": RECORD_VERSION, "org_id": oid, "nonce": nonce, "requester": who,
                "mode": mode, "cap_nano_usd": int(cap_nano_usd), "hold_mc": int(hold_mc), "issued_at": float(now)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": who, "tier": "A0",
                   "decision": "auto", "reason": f"security assistant turn ({mode}) for org {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads -----------------------------------------------------------------------------------------------------
    def turns(self, org_id: str, *, since: float = 0.0) -> "list[TurnRecord]":
        """The org's VERIFIED turns issued at or after ``since``, oldest first, each nonce once (its first verified
        record). A record that does not verify under the owner key valid at its seq, or whose fields are malformed,
        is inert — never raises on a hostile payload. An invalid org id has no turns."""
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        if not self.trusted_pubkey:
            return []
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        out: "list[TurnRecord]" = []
        seen: "set[str]" = set()
        for r in self.store.iter_records():
            p = getattr(r, "payload", None)
            if not isinstance(p, dict) or p.get("signal") != SIGNAL or p.get("org_id") != oid:
                continue
            if getattr(r, "kind", None) != "event" or getattr(r, "source", None) != "governor":
                continue
            non = p.get("nonce")
            if not isinstance(non, str) or not _NONCE_RE.fullmatch(non) or non in seen:
                continue
            if not verify_signed(p, _CORE, resolver.at(r.seq)):
                continue
            issued = p.get("issued_at")
            mode, cap, hold, who = p.get("mode"), p.get("cap_nano_usd"), p.get("hold_mc"), p.get("requester")
            if (isinstance(issued, bool) or not isinstance(issued, (int, float)) or not math.isfinite(issued)
                    or mode not in MODES or not isinstance(cap, int) or not _amount(cap, MAX_CAP_NANO_USD)
                    or not isinstance(hold, int) or not _amount(hold, MAX_HOLD_MC)
                    or not isinstance(who, str) or p.get("v") != RECORD_VERSION):
                continue
            seen.add(non)
            if float(issued) >= float(since):
                out.append(TurnRecord(org_id=oid, nonce=non, requester=who, mode=str(mode), cap_nano_usd=cap,
                                      hold_mc=hold, issued_at=float(issued), seq=int(r.seq)))
        out.sort(key=lambda t: (t.issued_at, t.seq))
        return out

    def refusal(self, org_id: str, *, now: float, per_hour: int, per_day: int) -> Optional[LimitRefusal]:
        """The rate-limit / budget decision for ONE new turn of ``org_id`` at ``now``: None when it may be admitted,
        else the :class:`LimitRefusal` of the fuller window (the longer wait when both are full). A turn counts in a
        window when it was issued within it — ``(now - window, now]`` — or after ``now`` (a clock step back never frees
        a slot). ``per_hour`` / ``per_day`` must be positive integers (``ValueError`` otherwise)."""
        hour, day = _limit(per_hour), _limit(per_day)
        t = float(now)
        recent = [x.issued_at for x in self.turns(org_id, since=t - DAY_S) if x.issued_at > t - DAY_S]
        worst: Optional[LimitRefusal] = None
        for window, span, limit in (("hour", HOUR_S, hour), ("day", DAY_S, day)):
            inside = sorted(ts for ts in recent if ts > t - span)
            if len(inside) < limit:
                continue
            # the slot frees when the (n - limit)-th oldest counted turn leaves the window
            frees = inside[len(inside) - limit] + span
            r = LimitRefusal(window=window, used=len(inside), limit=limit, retry_after=max(1.0, frees - t))
            if worst is None or r.retry_after > worst.retry_after:
                worst = r
        return worst
