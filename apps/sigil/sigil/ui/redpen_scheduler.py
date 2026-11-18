"""Red-Pen System scheduler — the SOVEREIGN producer of whole-repository review tickets (R4).

Two entry points, one owner-key producer:

  * :meth:`RedPenScheduler.enqueue_system_review` — the ON-DEMAND action (the Code screen → edge → provisioner
    calls it): reserve + mint a System review for ONE connected repo and drop an owner-signed ticket on the seam.
    Idempotent (the ticket IS the idempotency record): a repeat with the same nonce re-uses the pending ticket and
    neither double-reserves nor writes a second one.
  * :meth:`RedPenScheduler.tick` — the SCHEDULED pass (``sigil redpen-schedule``, the systemd timer): for every
    schedule that is DUE this calendar period, enqueue a System review once and advance the per-period high-water.

The producer reuses the W2 path VERBATIM: ``LaunchGate.reserve_redpen_review`` authorizes against the owner-signed
connected-repo record, REFUSES at the per-repo monthly spending limit (decision O-2) / an empty wallet / a
disconnected repo, mints the owner-signed ``CreditLaunchLease``, and this writes the ticket the keyless integration
drain (``jobs.redpen_system_trigger``) turns into a ``SecurityJob(profile="full")``. The producer NEVER runs a job —
execution stays behind ``JobRunner`` + the gate, which re-verifies the ticket's lease owner-pinned.

Behind ``config.redpen_enabled()`` (default OFF ⇒ every action refuses / the tick is a no-op, byte-identical): a
whole Red-Pen pipeline is inert when the flag is off, so this writes no ticket and no spine record.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` via the ui package); the ticket seam is a both-planes
``vigil_core``+stdlib module (``live.redpen_system_seam``) — no ``framework`` / ``strix`` import here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import SignedCreditLaunchLease, TrustRoot, check_connected_repo  # noqa: E402

from .. import config  # noqa: E402
from ..governor.asset_ownership import _check_org_id  # noqa: E402
from ..governor.redpen_schedule import RedPenScheduleRegistry, period_key  # noqa: E402
from .launch_gate import LaunchGate  # noqa: E402
from .target_authorization import _customer_slug  # noqa: E402

_REDPEN_OFF = "Red-Pen is off (VIGIL_REDPEN_ENABLED): refusing a System review (fail-closed)"


class RedPenScheduler:
    """The sovereign producer. ``gate`` / ``registry`` are injected for tests; in production both default to the
    owner-key-backed sovereign objects over ``store``. ``base_dir`` is the seam root tickets are written under
    (defaults to the shared seam base the drains read)."""

    def __init__(self, store, *, gate: Optional[LaunchGate] = None,
                 registry: Optional[RedPenScheduleRegistry] = None, base_dir: Optional[str] = None):
        self.store = store
        self._base_dir = base_dir
        self._gate = gate if gate is not None else LaunchGate(store, base_dir=base_dir)
        self._registry = registry if registry is not None else RedPenScheduleRegistry(store)

    def _seam_base(self) -> str:
        from vigil_core.seam_base import resolve_seam_base
        return resolve_seam_base(self._base_dir)

    def enqueue_system_review(self, org_id: str, repo: str, *, now: float,
                              nonce: Optional[str] = None) -> dict:
        """Reserve + mint a whole-repository (System) review for a connected repo and drop an owner-signed ticket
        on the seam — THE on-demand provisioner action. Returns ``{ok: True, slug, nonce, repo, org_id}`` (or
        ``already=True`` when the same-nonce ticket is already pending), or ``{ok: False, error, refused|retry}``
        (fail-closed; nothing debited, no ticket written, on any failing conjunct). The default nonce is per-DAY
        (``od-YYYY-MM-DD``) so a double-clicked "Review now" the same day is idempotent; a caller (the tick) may
        pass its own per-period nonce."""
        if not config.redpen_enabled():
            return {"ok": False, "error": _REDPEN_OFF, "refused": True}
        try:
            oid = _check_org_id(org_id)
            repo_ref = check_connected_repo(repo)
        except ValueError as e:
            return {"ok": False, "error": str(e), "refused": True}
        non = str(nonce) if nonce else f"od-{_day(now)}"
        if ":" in non or not non:
            return {"ok": False, "error": "nonce must be a non-empty string without ':'", "refused": True}
        slug = _customer_slug(oid, repo_ref)
        base = self._seam_base()
        # Idempotency: the ticket IS the record. A pending ticket with the SAME nonce means this review is already
        # reserved + enqueued — return ok without re-reserving (so a retry/double-click neither double-charges nor
        # writes a second ticket).
        from vigil_integration.live.redpen_system_seam import read_system_ticket, write_system_ticket
        existing = read_system_ticket(base, slug)
        if existing is not None and _ticket_nonce(existing) == non:
            return {"ok": True, "slug": slug, "nonce": non, "repo": repo_ref, "org_id": oid, "already": True}
        res = self._gate.reserve_redpen_review(org_id=oid, repo=repo_ref, now=now, nonce=non)
        if not res.get("ok"):
            out = {"ok": False, "error": str(res.get("error") or "the review could not be reserved"),
                   "refused": True}
            if res.get("retry"):
                out["retry"] = True
            return out
        try:
            signed = SignedCreditLaunchLease.model_validate(res["lease"])
            trust_root = TrustRoot.model_validate(res["trust_root"])
        except Exception:  # noqa: BLE001 — an unexpected reserve payload is a fail-closed refusal (nothing written)
            return {"ok": False, "error": "the review reservation produced no usable lease (fail-closed)",
                    "refused": True}
        write_system_ticket(base, res["slug"], org_id=oid, repo=repo_ref, signed_lease=signed,
                            trust_root=trust_root)
        return {"ok": True, "slug": res["slug"], "nonce": non, "repo": repo_ref, "org_id": oid}

    def tick(self, now: float) -> dict:
        """One scheduled pass: enqueue a System review for every DUE schedule (the current calendar period not yet
        enqueued), advancing the per-period high-water so each period is attempted ONCE. Returns
        ``{enqueued, refused, deferred, details}``. A no-op (``{..., skipped: True}``) when Red-Pen is off —
        byte-identical, no spine read or write. Cross-tenant (the owner-side ``due`` view); per-repo authorization
        + the monthly limit still apply at ``enqueue_system_review``."""
        if not config.redpen_enabled():
            return {"enqueued": 0, "refused": 0, "deferred": 0, "details": [], "skipped": True}
        enqueued = refused = deferred = 0
        details: "list[dict]" = []
        for oid, repo_ref, cadence in self._registry.due(now):
            period = period_key(cadence, now)
            res = self.enqueue_system_review(oid, repo_ref, now=now, nonce=f"sch-{period}")
            # A TRANSIENT refusal does NOT advance the high-water — the next tick retries this same period off the
            # untouched schedule: billing momentarily busy (``retry``), or the owner's kill switch / customer_launch
            # latch HALTING new reservations (re-read AFTER the refusal, so a halt engaged mid-tick is caught too). A
            # halt is the owner's temporary stop, never a reason to silently drop a customer's scheduled review.
            if res.get("retry") or (not res.get("ok") and self._gate._new_launch_refusal() is not None):
                deferred += 1
                details.append({"org_id": oid, "repo": repo_ref, "period": period, "outcome": "deferred"})
                continue
            # A TERMINAL outcome (enqueued, or refused by limit/credits/disconnect): advance the high-water so the
            # period is attempted exactly once (no per-tick spin). A mid-period top-up is picked up NEXT period.
            self._registry.record_enqueue(oid, repo_ref, period=period, now=now)
            if res.get("ok"):
                enqueued += 1
                details.append({"org_id": oid, "repo": repo_ref, "period": period, "outcome": "enqueued"})
            else:
                refused += 1
                details.append({"org_id": oid, "repo": repo_ref, "period": period, "outcome": "refused",
                                "reason": res.get("error", "")})
        return {"enqueued": enqueued, "refused": refused, "deferred": deferred, "details": details}


def _day(now: float) -> str:
    return datetime.fromtimestamp(float(now), tz=timezone.utc).strftime("%Y-%m-%d")


def _ticket_nonce(ticket: Any) -> str:
    try:
        return str(ticket.signed_lease.document.nonce)
    except Exception:  # noqa: BLE001
        return ""
