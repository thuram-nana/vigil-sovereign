"""Slice G — the offense-launch authorization gate (the billing != testing enforcement at the launch path).

``LaunchGate.reserve_launch`` is the single fail-closed chokepoint a customer offense launch passes BEFORE
any traffic. It composes FOUR independent conjuncts, each refused in isolation, and only when ALL hold does
the owner key reserve the credits and mint a ``CreditLaunchLease``:

  1. MEMBERSHIP (testing axis): ``orgs.admit_customer(requester, org_id, run_engagement)`` — a billing-only
     org_admin, a viewer, and a non-member are all refused. Paying / administering billing is not launching.
  2. OWNERSHIP PROOF (billing != testing): ``AssetOwnershipRegistry.has_current_proof(org_id, host, now)`` —
     a current, infrastructure-bound proof is required. Credits alone never authorize a test.
  3. TARGET AUTHORITY (testing-authz): a CURRENT ``EngagementAuthority`` for this exact host must be on the
     seam and VERIFY against a LOCALLY-PINNED owner trust root (scope == [host], window covers now). The seam
     is cross-plane and the offense plane is keyless/untrusted, so the bundle's OWN trust_root is discarded
     for the trust decision — we require that OUR owner key SIGNED it (not merely that it is listed, which a
     seam-writer could forge with the owner's public key). The G0 mint is the only legitimate producer.
  4. CREDIT BALANCE (spend): ``CreditMeter.available(org_id, now) >= units`` (units in [1, 1e6], fail-closed).

Only then, under the spine lock (all four conjuncts RE-CHECKED inside it — TOCTOU): RESERVE the credits and
MINT the owner-signed lease. The reservation is bound to OWNER-SIGNED LEDGER RECORDS, never to a wire amount:
  * reserve SPENDS plan-credits-first then the wallet (``_spend``) and then ENFORCES an availability-delta
    invariant — ``CreditMeter.available`` MUST have dropped by exactly ``units``, else it refuses and mints
    NOTHING. This makes the two buckets consistent (a plan-credit tenant is genuinely charged, not under-
    reserved) AND makes a reused nonce fail-closed (its idempotent debits no-op -> no delta -> refuse).
  * the minted lease carries the owner-signed ``units_reserved``; settle refunds strictly against THAT signed
    amount (``settle_launch`` takes the signed lease, verifies it owner-pinned, and refunds
    ``units_reserved - consumed`` capped so net spend == metered consumption) — no on-the-wire integer ever
    decides a refund (the money doctrine).

The signed lease is RETURNED for the caller (the provisioner/edge, Slice G commit 3) to drop on the seam;
the keyless offense launch then verifies it (``vigil_core.verify_credit_launch_lease``) as a separate
conjunct from the authority.

``requester``/``org_id`` are AUTHORITATIVE, supplied by trusted sovereign code (the provisioner, after the
edge's session binding) — never a client-supplied field. KNOWN CAVEAT (LOW, matches the codebase posture for
compound mutations, e.g. ``orgs.revoke_org``): the available-check -> debit is atomic within a process (the
spine lock) but the cross-process floor is the per-append flock, so two concurrent SIGIL PROCESSES on one
spine could over-reserve by at most one launch; the sovereign cockpit is single-process. FATAL-2:
sovereign-side, ``assert_no_offense`` at import; the authority broker (integration seam) is imported lazily.
"""
from __future__ import annotations

import contextlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..spine.store import spine_lock  # noqa: E402  (process-wide, path-keyed re-entrant txn lock)
from ..governor.postpaid import (RESERVE_ENTRY_PREFIX,  # noqa: E402  (single-source the gate<->ledger entry-id scheme)
                                 SETTLE_ENTRY_PREFIX, postpaid_is_overdue)

_MAX_UNITS = 1_000_000          # a sane upper bound on a single launch's reservation (fail-closed on garbage)
_DEFAULT_LEASE_HOURS = 8.0
_MAX_LEASE_HOURS = 24.0 * 7     # a launch lease caps at a week; a longer engagement re-leases
#: What ``resume_launch`` tells the customer when it lifts the pause of a lease whose window has closed.
_RESUMED_EXPIRED_DETAIL = ("this launch's lease window has closed: the pause is lifted, so a run still in "
                           "progress continues and settles normally, but a launch that has not started, or a run "
                           "that stopped for the pause, will not start again. Because it was paused when its window "
                           "closed, it is charged for what it used")


def _refusal(refuse_if: Optional[Callable[[], Optional[str]]]) -> Optional[str]:
    """A settle caller's precondition, evaluated inside the settle critical section: its reason to refuse, or None.
    A precondition that raises refuses (fail-closed)."""
    if refuse_if is None:
        return None
    try:
        why = refuse_if()
    except Exception as e:  # noqa: BLE001 — an unanswerable precondition never green-lights a settle
        return f"precondition check failed: {type(e).__name__}"
    return str(why) if why else None


class LaunchGate:
    """Compose the four launch conjuncts + reserve + mint. Registries/meter are INJECTED for tests; in
    production they default to the owner-key-backed sovereign registries over ``store``."""

    def __init__(self, store, *, orgs=None, ownership=None, meter=None, wallet=None,
                 postpaid=None, arrears=None, invoices=None, owner_key=None, base_dir: Optional[str] = None,
                 cost_ledger=None, pool=None):
        from ..governor.asset_ownership import AssetOwnershipRegistry
        from ..governor.cost_ledger import CostEnvelopeLedger
        from ..governor.cost_pool import GlobalCostPool
        from ..governor.identity import owner_keypair
        from ..governor.invoices import InvoiceRegistry
        from ..governor.metering import CreditMeter, PlanCreditLedger
        from ..governor.orgs import OrgRegistry
        from ..governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
        from ..governor.subscription import SubscriptionRegistry
        from ..governor.wallet import WalletRegistry
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.orgs = orgs if orgs is not None else OrgRegistry(store)
        self.ownership = ownership if ownership is not None else AssetOwnershipRegistry(store)
        self.wallet = wallet if wallet is not None else WalletRegistry(store)
        self.meter = meter if meter is not None else CreditMeter(
            self.wallet, PlanCreditLedger(store), SubscriptionRegistry(store))
        # PP-1 enterprise postpaid: a tenant with an owner-signed ENABLED credit line draws against it (accruing
        # arrears) instead of burning prepaid credits. Absent/disabled ⇒ the prepaid path below is byte-identical.
        self.postpaid = postpaid if postpaid is not None else PostpaidRegistry(store)
        self.arrears = arrears if arrears is not None else PostpaidArrearsLedger(store)
        # PP-3 dunning: the gate reads the owner-signed invoice ledger to refuse a launch when the line is OVERDUE.
        self.invoices = invoices if invoices is not None else InvoiceRegistry(store)
        # EC-5: the owner-signed cost ledger the gate WRITES the reserve/settle cost pair into (the EC-4
        # gate-writes-the-pair wiring, gated default-OFF behind config.cost_ledger_write_enabled), and the
        # GLOBAL cost-pool meter it reads as one more fail-closed conjunct. The pool reads the SAME ledger, so
        # the pair it meters is the pair the gate writes (single-sourced). DEFAULT-OFF: an unbounded pool
        # (config.global_pool_tokens() None) never folds and the write flag is off ⇒ byte-identical to pre-EC-5.
        self._cost_ledger = cost_ledger if cost_ledger is not None else CostEnvelopeLedger(
            store, owner_key=self.owner_key)
        from .. import config
        self._pool = pool if pool is not None else GlobalCostPool(
            self._cost_ledger, budget_tokens=config.global_pool_tokens())
        self._base_dir = base_dir
        self._lock = spine_lock(getattr(store, "path", ""))

    def _seam_base(self) -> str:
        if self._base_dir:
            return self._base_dir
        from .target_authorization import _base_dir
        return _base_dir()

    @staticmethod
    def _as_dt(now: Any) -> datetime:
        t = now() if callable(now) else now
        if not isinstance(t, datetime):
            t = datetime.fromtimestamp(float(t), tz=timezone.utc)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t

    def _authority_ok(self, host: str, slug: str, now_dt: datetime) -> bool:
        """True iff a CURRENT EngagementAuthority for exactly ``host`` is on the seam under ``slug`` and
        verifies against a LOCALLY-PINNED owner trust root (our owner key SIGNED it), scope == [host], window
        covers ``now``. Fail-closed on any read/verify error (never raises).

        SECURITY: the seam is cross-plane and written by untrusted code, so the bundle's OWN ``trust_root`` is
        NEVER trusted for the decision — an attacker who can write the seam could co-list the owner's PUBLIC
        key beside their own and sign with their own key, satisfying a mere 'owner key is listed' membership
        test. We instead verify against ``TrustRoot(threshold=1, [owner])`` built from OUR owner pubkey, so a
        bundle the owner did not sign is refused (the pinned-owner-key guarantee the seam contract requires)."""
        kp = self.owner_key
        if kp is None:
            return False
        try:
            from vigil_core import AuthorizerKey, TrustRoot, verify_engagement_authority
            from vigil_integration.live.authorization_broker import read_authorization
            ta = read_authorization(self._seam_base(), slug)
            if ta is None:
                return False
            owner_root = TrustRoot(threshold=1, authorizers=[
                AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
            ok, _ = verify_engagement_authority(ta.signed_authority, owner_root)   # PINNED, not ta.trust_root
            if not ok:
                return False
            doc = ta.signed_authority.document
            if list(doc.scope) != [host]:                        # EXACTLY this host — no parent/wildcard
                return False
            return doc.not_before <= now_dt < doc.not_after       # window covers now
        except Exception:  # noqa: BLE001 — a missing/corrupt/foreign bundle is simply "not authorized"
            return False

    def _spend(self, oid: str, units: int, slug: str, nonce: str, now_ts: float) -> None:
        """Debit ``units`` across PLAN-credits-first then the WALLET, so ``CreditMeter.available`` drops by
        ``units``. Each bucket debit is idempotent per (slug, nonce), so a reused nonce re-appends the SAME
        entry_ids and no-ops — the caller's availability-delta invariant then sees no drop and refuses. Never
        over-debits: ``from_plan`` is clamped to the live plan remainder and the caller already checked
        ``available >= units``."""
        pos = self.meter.position(oid, now_ts)
        from_plan = min(units, max(0, pos.plan_live))
        if from_plan > 0:
            sub = self.meter.subscriptions.active_subscription(oid, now_ts)
            if sub is not None:
                self.meter.plan.debit(oid, from_plan, period_end=sub.period_end, engagement_id=slug,
                                      entry_id=f"reserve-plan:{slug}:{nonce}", issued_at=now_ts)
        from_wallet = units - from_plan
        if from_wallet > 0:
            self.wallet.debit(oid, from_wallet, engagement_id=slug,
                              entry_id=f"reserve-wallet:{slug}:{nonce}", issued_at=now_ts)

    def _write_cost_reserve(self, oid: str, units: int, slug: str, nonce: str, now_ts: float) -> None:
        """EC-5: owner-sign the cost-ledger RESERVE for this launch — the token envelope ``units * E`` it may
        spend — gated DEFAULT-OFF behind ``config.cost_ledger_write_enabled()`` (off ⇒ NO record appended,
        byte-identical). Idempotent per ``(slug, nonce)`` via the shared ``reserve-cost:`` prefix contract.
        FAIL-SAFE: the cost ledger is ADVISORY metering, NEVER a gate on the real launch beyond the explicit
        pool-REFUSE conjunct — a cost-write error is swallowed (logged) so it can never break a real launch."""
        from .. import config
        if not config.cost_ledger_write_enabled():
            return
        try:
            from vigil_core import ENVELOPE_TOKENS_PER_CREDIT
            from ..governor.cost_ledger import RESERVE_COST_PREFIX
            self._cost_ledger.reserve(oid, units * ENVELOPE_TOKENS_PER_CREDIT,
                                      entry_id=f"{RESERVE_COST_PREFIX}{slug}:{nonce}", engagement_id=slug,
                                      issued_at=now_ts)
        except Exception:  # noqa: BLE001 — advisory metering: a cost-write failure never breaks the launch
            import logging
            logging.getLogger(__name__).warning("EC-5 cost-reserve write failed (advisory; launch unaffected)",
                                                 exc_info=True)

    def _write_cost_settle(self, oid: str, slug: str, nonce: str, consumed: int, reserved: int,
                           now_ts: float) -> None:
        """EC-5: owner-sign the cost-ledger SETTLE for this launch — the ACTUAL tokens consumed (the
        conservative credit-envelope PROXY ``consumed * E`` until the keyless actual-token delivery lands),
        CLAMPED to the reserved envelope ``reserved * E`` so a forged over-report can never over-settle. All
        arguments come from the VERIFIED lease (never a wire value). Gated DEFAULT-OFF + idempotent per
        ``(slug, nonce)`` via the ``settle-cost:`` prefix. FAIL-SAFE (advisory metering, same as the reserve)."""
        from .. import config
        if not config.cost_ledger_write_enabled():
            return
        try:
            from vigil_core import ENVELOPE_TOKENS_PER_CREDIT
            from ..governor.cost_ledger import SETTLE_COST_PREFIX
            self._cost_ledger.settle(oid, consumed * ENVELOPE_TOKENS_PER_CREDIT,
                                     entry_id=f"{SETTLE_COST_PREFIX}{slug}:{nonce}",
                                     reserved_cap=reserved * ENVELOPE_TOKENS_PER_CREDIT, engagement_id=slug,
                                     issued_at=now_ts)
        except Exception:  # noqa: BLE001 — advisory metering: a cost-write failure never breaks the settle
            import logging
            logging.getLogger(__name__).warning("EC-5 cost-settle write failed (advisory; settle unaffected)",
                                                 exc_info=True)

    def reserve_launch(self, *, requester: str, org_id: str, host: str, units: int, now: Any,
                       duration_hours: Any = _DEFAULT_LEASE_HOURS, nonce: Optional[str] = None) -> dict:
        """Authorize + reserve + mint for ONE launch. Returns ``{ok: True, lease, ...}`` with the signed lease
        on success, or ``{ok: False, error}`` (fail-closed) on any failing conjunct — and on a refusal NOTHING
        is debited and NO lease is minted. ``units`` is the reservation cap (>= 1)."""
        from ..governor.orgs import _check_org_id
        from ..governor.asset_ownership import _check_host
        from .target_authorization import _customer_slug
        from vigil_core import AuthorizerKey, CreditLaunchLease, TrustRoot, sign_credit_launch_lease

        kp = self.owner_key
        if kp is None:
            return {"ok": False, "error": "a launch lease must be owner-signed (internal: no owner key)"}
        try:
            oid = _check_org_id(org_id)
            h = _check_host(host)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        try:
            u = int(units)
        except (TypeError, ValueError):
            return {"ok": False, "error": "units must be an integer"}
        if not (1 <= u <= _MAX_UNITS):
            return {"ok": False, "error": f"units must be in [1, {_MAX_UNITS}]"}
        try:
            dur = float(duration_hours)
        except (TypeError, ValueError):
            return {"ok": False, "error": "duration_hours must be a number"}
        if not (0 < dur <= _MAX_LEASE_HOURS):
            return {"ok": False, "error": f"duration_hours must be in (0, {_MAX_LEASE_HOURS}]"}
        try:
            t = self._as_dt(now)
        except (TypeError, ValueError, OSError, OverflowError):
            return {"ok": False, "error": "now must be a datetime or a POSIX timestamp"}
        now_ts = t.timestamp()
        slug = _customer_slug(oid, h)
        non = str(nonce) if nonce is not None else secrets.token_urlsafe(16)
        if not non or ":" in non:
            return {"ok": False, "error": "nonce must be a non-empty string without ':'"}

        def _gated() -> Optional[str]:
            """Return None if all four conjuncts hold, else the refusal reason. Resolved LIVE each call."""
            if not self.orgs.admit_customer(username=requester, org_id=oid, permission="run_engagement"):
                return "requester may not launch assessments for this org (membership is not testing authority)"
            if not self.ownership.has_current_proof(oid, h, now=now_ts):
                return (f"no current ownership proof for {h} (org {oid}): prove control of the asset before an "
                        f"assessment can be launched — ownership is separate from billing")
            if not self._authority_ok(h, slug, t):
                return (f"no current owner-signed engagement authority for {h} (org {oid}) — the owner must "
                        f"authorize this target (offense_authority stays at the owner key)")
            acct = self.postpaid.account(oid)
            if acct is not None and acct.is_enabled():
                # POSTPAID (PP-1): the credit conjunct is the owner-signed credit LINE, not the prepaid balance —
                # admit the launch iff the drawn arrears plus this reservation stay within the signed limit.
                acc = self.arrears.accrued(oid)
                if acc + u > acct.credit_limit:
                    return (f"over postpaid credit line: drawing {u} on top of {acc} accrued would exceed the "
                            f"{acct.credit_limit}-credit limit (org {oid})")
                # PP-3 DUNNING: an OVERDUE line (any unpaid arrears invoice past its net-terms due date) refuses
                # NEW launches — the SAFE access-reducing direction. Reversible: paying the invoice (PP-2b) clears
                # it and launches resume. An already in-flight launch still settles; only new reserves are refused.
                if postpaid_is_overdue(self.invoices, self.postpaid, oid, now_ts):
                    return (f"postpaid line is OVERDUE (unpaid arrears invoice past net terms, org {oid}): settle "
                            f"the outstanding invoice before launching new assessments")
            elif self.meter.available(oid, now_ts) < u:
                return f"insufficient credits: need {u}, have {self.meter.available(oid, now_ts)}"
            # EC-5 GLOBAL COST POOL conjunct (AFTER the per-tenant credit conjunct): when the pool is ARMED and
            # over capacity (REFUSE_NEW / HARD_STOP, or unmeasurable ⇒ fail-closed REFUSE_NEW) refuse this NEW
            # launch — the safe, reversible access-reducing direction (an in-flight launch still settles and
            # frees the pool, so the pool auto-relaxes with no owner-signed un-latch). UNBOUNDED (default) ⇒
            # gate_refusal() short-circuits to None WITHOUT folding ⇒ byte-identical no-op.
            pool_refusal = self._pool.gate_refusal()
            if pool_refusal is not None:
                return pool_refusal
            return None

        pre = _gated()                                   # cheap pre-check outside the lock (fast refusal)
        if pre is not None:
            return {"ok": False, "error": pre}
        with self._lock:
            re = _gated()                                # TOCTOU: re-check every conjunct inside the lock
            if re is not None:
                return {"ok": False, "error": re}
            acct = self.postpaid.account(oid)
            if acct is not None and acct.is_enabled():
                # POSTPAID (PP-1): ACCRUE `u` against the credit line. The accrual-delta invariant mirrors the
                # prepaid availability-delta — a reused nonce's idempotent accrue no-ops ⇒ no delta ⇒ refuse and
                # mint NOTHING, so a reservation is ALWAYS backed by a real, incremental draw. No prepaid bucket
                # is touched, so a postpaid tenant never consumes wallet/plan credits.
                before_acc = self.arrears.accrued(oid)
                self.arrears.accrue(oid, u, engagement_id=slug,
                                    entry_id=f"{RESERVE_ENTRY_PREFIX}{slug}:{non}", issued_at=now_ts)
                if self.arrears.accrued(oid) - before_acc < u:
                    return {"ok": False, "error": "this launch reservation did not apply (nonce already used)"}
            else:
                before = self.meter.available(oid, now_ts)
                self._spend(oid, u, slug, non, now_ts)   # plan-first then wallet (idempotent per slug/nonce)
                if before - self.meter.available(oid, now_ts) < u:
                    # the spend did NOT consume `u` (a reused nonce's debits no-op'd, or a bucket shortfall) —
                    # refuse and mint NOTHING, so a reservation is ALWAYS backed by a real, incremental debit.
                    return {"ok": False, "error": "this launch reservation did not apply (nonce already used)"}
            # EC-5: after the real (incremental) reserve succeeds, write the cost-ledger RESERVE for the pool
            # meter — the signed envelope `u * E`. Gated default-OFF + fail-safe (advisory; never breaks the
            # launch). Keyed on the SAME (slug, nonce) as the credit debit, so it is idempotent with it.
            self._write_cost_reserve(oid, u, slug, non, now_ts)
            doc = CreditLaunchLease(
                engagement_slug=slug, org_id=oid, scope_host=h, units_reserved=u,
                not_before=t, not_after=t + timedelta(hours=dur), nonce=non, issued_at=now_ts)
            signed = sign_credit_launch_lease(doc, {"owner": kp.private_key_b64})
            trust_root = TrustRoot(threshold=1, authorizers=[
                AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
        return {
            "ok": True, "action": "launch_reserved", "org_id": oid, "host": h, "slug": slug,
            "units_reserved": u, "nonce": non,
            "not_before": doc.not_before.isoformat(), "not_after": doc.not_after.isoformat(),
            "lease": signed.model_dump(mode="json"),
            "trust_root": trust_root.model_dump(mode="json"),
        }

    def settle_launch(self, *, signed_lease: Any, consumed_units: int, now: Any,
                      expect_org_id: Optional[str] = None,
                      refuse_if: Optional[Callable[[], Optional[str]]] = None,
                      basis: str = "settle", finish_only: bool = False) -> dict:
        """Close out a reservation: refund the UNUSED portion so net spend == metered consumption. The refund
        is bound to the OWNER-SIGNED LEASE, never to a wire amount — ``signed_lease`` (the object
        ``reserve_launch`` returned) is VERIFIED under a locally-pinned owner trust root and
        ``units_reserved`` / ``org_id`` / ``slug`` / ``nonce`` are taken from the VERIFIED document, so a
        forged or wire-asserted amount cannot mint a refund (the HIGH the red-pen found). Refund =
        ``units_reserved - clamp(consumed_units, 0, units_reserved)``, granted back to the wallet. Idempotent
        per the lease's (slug, nonce), ACROSS PROCESSES (``_settle_once``): the first settle fixes the outcome and
        every later one (any caller, any process) returns ``launch_already_settled`` — moving nothing, or only the
        not-yet-landed entries of a RECORDED decision a crash interrupted (``rolled_forward``). ``consumed_units ==
        0`` is the cancel/release case (full refund); a crash before settle simply leaves the cap debited
        (fail-closed, never over-refunds).

        ``refuse_if`` is an optional caller precondition evaluated INSIDE the settle critical section on a FRESH
        settle, BEFORE the settle closes the run's meter and before any record: a non-empty answer refuses with
        nothing written (``refused``). ``basis`` names the caller in the decision record
        (``launch_settlement.BASES``). ``finish_only`` may only finish a recorded settlement: a lease that is not
        settled at all is left untouched (``launch_not_settled``).

        MONEY-DOCTRINE CLOSE-OUT (K4-1): settling/cancelling refunds the credits AND makes the lease
        non-runnable. settle records a ``(slug, nonce)`` settlement marker before any money moves and tombstones
        the seam copy LAST (nonce-matched so a newer re-lease is never clobbered); ``publish_lease`` refuses a
        lease whose reservation is already settled; and the keyless arm re-checks settlement in
        ``verify_customer_launch_lease`` before it burns the single-use floor — so a settled lease is no
        longer a live bearer capability. The ``reserved - refund == consumed`` net-spend invariant is
        load-bearing on this refund path, and K4-5 settle-on-completion asserts net-spend ==
        metered-consumption end-to-end."""
        from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
        from ..governor.launch_settlement import SettlementDecision
        kp = self.owner_key
        if kp is None:
            return {"ok": False, "error": "a refund must be owner-signed (internal: no owner key)"}
        try:
            signed = SignedCreditLaunchLease.model_validate(signed_lease)
        except Exception:  # noqa: BLE001 — a malformed lease is a fail-closed refusal
            return {"ok": False, "error": "settle requires the signed launch lease from reserve_launch"}
        owner_root = TrustRoot(threshold=1, authorizers=[
            AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
        ok, reason = verify_credit_launch_lease(signed, owner_root)
        if not ok:
            return {"ok": False, "error": f"lease does not verify under the owner key: {reason}"}
        doc = signed.document
        oid, s, non, reserved = doc.org_id, doc.engagement_slug, doc.nonce, int(doc.units_reserved)
        # TENANT BINDING: when the caller is a customer (the edge passes its session org), the lease's org
        # MUST match — so a customer cannot cancel/settle another tenant's reservation by presenting its lease.
        if expect_org_id is not None and oid != expect_org_id:
            return {"ok": False, "error": "this lease belongs to a different org"}
        try:
            consumed = int(consumed_units)
        except (TypeError, ValueError):
            return {"ok": False, "error": "consumed_units must be an integer"}
        if consumed < 0:
            return {"ok": False, "error": "consumed_units must be non-negative"}
        consumed = min(consumed, reserved)                 # can never claw back more than the signed reservation
        try:
            now_ts = self._as_dt(now).timestamp()
        except (TypeError, ValueError, OSError, OverflowError):
            return {"ok": False, "error": "now must be a datetime or a POSIX timestamp"}
        # PRICING M1c: every FRESH settle (completion, customer cancel, abandoned-lease sweep) closes the run's model
        # meter and retires its grant — inside the settle critical section, after the caller's precondition, before
        # the decision is recorded (``_settle_once``) — so a settled lease can spend nothing more through the
        # gateway, and a REFUSED settle (a started launch's cancel) never cripples a run that is still going.
        #
        # POSTPAID (PP-1) settle. Detect a postpaid reservation by its PRUNE-DURABLE arrears debit marker —
        # `arrears.was_accrued(reserve-postpaid:{slug}:{nonce})`, which reads the SnapshotState-seeded seen-set,
        # NOT a live scan of the individual debit record (a hard prune can drop that record while carrying only
        # the per-org balance + seen-set into the seed — the red-pen HIGH: a live scan read False post-prune and
        # mis-routed the settle to the prepaid wallet, minting credits + leaving the arrears un-reversed). It is
        # also NOT the account's CURRENT enabled state (the owner may disable the line between reserve and
        # settle). A postpaid reservation touched no plan/wallet bucket, so REVERSE the unconsumed draw
        # (refund = reserved - consumed, from the owner-signed lease) off the drawn balance; net arrears change
        # == consumed (the net-spend invariant). Idempotent per (slug, nonce) via `_settle_once` + the reverse
        # entry_id. consumed == 0 (cancel) fully reverses the draw.
        if self.arrears.was_accrued(oid, f"{RESERVE_ENTRY_PREFIX}{s}:{non}"):
            pp_eid = f"{SETTLE_ENTRY_PREFIX}{s}:{non}"

            def _move_postpaid(d: Any, landed: "set[str]", durable: bool) -> dict:
                # ALWAYS record the settlement — even a FULL-consumption settle whose refund is 0. The record's
                # presence clears the reserve from the arrears IN-FLIGHT set (`in_flight_reserved`), so PP-2 bills
                # the launch for its real consumption; a 0-refund settle is a balance no-op. (Red-pen HIGH: the
                # prior `if refund > 0` left a fully-consumed launch with no settle record -> invoiced $0.)
                if "postpaid" in landed or (durable and self.arrears.has_credit_entry(oid, pp_eid)):
                    return {"refunded": 0, "refunded_plan": 0, "refunded_wallet": 0, "wrote": False}
                self.arrears.settle(oid, d.refund_postpaid, entry_id=pp_eid, issued_at=now_ts)
                return {"refunded": d.refund_postpaid, "refunded_plan": 0, "refunded_wallet": 0, "wrote": True}

            return self._settle_once(oid, s, non, reserved, consumed, now_ts,
                                     SettlementDecision.postpaid(reserved, consumed, basis), _move_postpaid,
                                     refuse_if, finish_only)
        # BUCKET-SYMMETRIC REFUND (red-pen fix: plan-credit laundering). reserve_launch._spend debits
        # PLAN-credits-first (non-rollover, expire at period_end) then the WALLET (permanent). Refunding the
        # whole amount to the wallet would LAUNDER expiring plan credits into the permanent wallet on every
        # reserve+cancel cycle (defeating use-it-or-lose-it). So restore the SAME buckets: re-derive how much
        # was debited from the plan tranche (and which period) from the OWNER-SIGNED debit record (never a wire
        # amount), let consumption eat the expiring plan portion FIRST, refund the unconsumed plan portion back
        # to that SAME tranche, and only the remainder to the wallet. consumed == 0 (cancel) therefore restores
        # the reservation exactly — a no-op, with nothing moved plan->wallet. This split builds the FRESH decision
        # only: finishing a recorded decision moves the RECORDED split and never re-reads the (prune-sensitive) debit.
        plan_deb = self.meter.plan.debited_entry(oid, f"reserve-plan:{s}:{non}")   # (from_plan, period_end) | None
        from_plan = plan_deb[0] if plan_deb else 0
        plan_pe = plan_deb[1] if plan_deb else None
        refund = reserved - consumed
        plan_refund = max(0, from_plan - consumed)         # consumption eats the plan (expiring) portion first
        wallet_refund = refund - plan_refund               # the rest (wallet portion + any plan over-consumption)
        # MONEY-DOCTRINE INVARIANT (K4-1): net spend == metered consumption and NEITHER bucket is over-refunded.
        # The sum/net-spend clauses hold by construction (wallet_refund := refund - plan_refund; refund :=
        # reserved - consumed); the load-bearing clause is ``plan_refund < 0 or wallet_refund < 0``, which FIRES
        # when the owner-signed reserve debit record over-claims the plan bucket relative to the signed lease
        # (from_plan > reserved). Without it an inflated plan_refund would be granted while a NEGATIVE
        # wallet_refund is silently skipped (``if wallet_refund > 0``) — a net OVER-refund / under-charge. A drift
        # here is an internal inconsistency, not a wire value: refuse (fail-closed, no credits moved) rather than
        # move the wrong amount, so net spend can never fall below metered consumption. Checked BEFORE the lock.
        if (plan_refund < 0 or wallet_refund < 0 or plan_refund + wallet_refund != refund
                or reserved - refund != consumed):
            return {"ok": False, "error": "internal: refund invariant violated (bucket split / net-spend)"}
        plan_eid, wallet_eid = f"settle-plan:{s}:{non}", f"settle-wallet:{s}:{non}"

        def _move_prepaid(d: Any, landed: "set[str]", durable: bool) -> dict:
            # ONLY the decision's fields decide what moves: a roll-forward never re-derives the split.
            moved_plan = moved_wallet = 0
            if (d.refund_plan > 0 and d.plan_period_end > 0 and "plan" not in landed
                    and not (durable and self.meter.plan.has_grant_entry(oid, plan_eid))):
                self.meter.plan.grant(oid, d.refund_plan, period_end=d.plan_period_end, entry_id=plan_eid,
                                      issued_at=now_ts)
                moved_plan = d.refund_plan
            if (d.refund_wallet > 0 and "wallet" not in landed
                    and not (durable and self.wallet.has_grant_entry(oid, wallet_eid))):
                self.wallet.grant(oid, d.refund_wallet, "refund", source_ref=s, entry_id=wallet_eid,
                                  issued_at=now_ts)
                moved_wallet = d.refund_wallet
            return {"refunded": moved_plan + moved_wallet, "refunded_plan": moved_plan,
                    "refunded_wallet": moved_wallet, "wrote": bool(moved_plan or moved_wallet)}

        decision = SettlementDecision.prepaid(reserved, consumed, plan_refund, wallet_refund,
                                              plan_pe if plan_pe is not None else 0.0, basis)
        return self._settle_once(oid, s, non, reserved, consumed, now_ts, decision, _move_prepaid, refuse_if,
                                 finish_only)

    def _settle_once(self, oid: str, s: str, non: str, reserved: int, consumed: int, now_ts: float, decision: Any,
                     move: "Callable[[Any, set[str], bool], dict]",
                     refuse_if: Optional[Callable[[], Optional[str]]], finish_only: bool) -> dict:
        """THE exactly-once settle transaction of lease ``(s, non)``, shared by the prepaid and postpaid paths.
        ``decision`` is what THIS caller would decide (a ``SettlementDecision``); ``move(d, landed, durable)`` moves
        the money of decision ``d`` — writing only the settle entries NOT already ``landed`` (and, when ``durable``,
        not in the prune-durable seen-sets either) — and returns the amounts it moved plus ``wrote``.

        CROSS-PROCESS ATOMIC (E3c). The check "is this lease already settled?" and everything it decides run under
        ``self._lock`` then ``settle_lock`` (a bounded flock beside the spine, held across the check, the records
        and the money), so the settle-drain, ``ops-sweep reservations --apply`` and ``launch_cancel`` (separate
        processes) can never both settle one lease. A busy or unusable lock is a RETRY with nothing written.

        SETTLED = the spine says so (``scan_settlement``: an owner-signed ``governor.launch_settled`` decision
        record, or an owner-signed settle refund / postpaid entry) OR the seam settlement marker says so (E3b: the
        marker lives in the seam directory, which can be lost or restored out of step; the spine cannot).

        ORDER (fail-closed, K4-1). A FRESH settle: ``refuse_if`` -> its own meter close (strict) -> [the flag] the
        decision record -> the seam marker (the revocation; a failure moves NO money) -> the money -> the
        cost-ledger settle -> the nonce-matched tombstone (LAST, so a settle a crash interrupted is still found by the
        drain's re-drive and the sweep). A NOT-fresh settle re-asserts a lost marker and, when the spine carries a
        well-formed decision, finishes it — the recorded entries not yet landed, at the RECORDED amounts, never its
        own — so a crash can neither strand the refund nor pay it twice; its meter close is best-effort (OD-8)."""
        from contextlib import ExitStack
        from .. import config
        from ..governor.launch_settlement import record_launch_settled, scan_settlement, settle_lock
        from vigil_integration.live.credit_lease_broker import (
            is_lease_settled, record_lease_settlement, tombstone_credit_lease,
        )
        kp = self.owner_key
        if kp is None:                                       # settle_launch refuses first; kept fail-closed
            return {"ok": False, "error": "a refund must be owner-signed (internal: no owner key)"}
        pub = kp.public_key_b64
        base = self._seam_base()
        busy = {"ok": False, "retry": True,
                "error": "the settle lock is busy or its spine cannot be read right now; retry (fail-closed)"}
        try:
            ev = scan_settlement(self.store, pub, org_id=oid, slug=s, nonce=non)    # the full scan, unlocked
        except OSError:
            return busy
        with ExitStack() as held:
            held.enter_context(self._lock)
            try:
                held.enter_context(settle_lock(self.store))
            except ValueError as e:
                return {"ok": False, "error": f"could not take the cross-process settle lock (fail-closed): "
                        f"{type(e).__name__}"}
            except OSError:                                  # SettleLockBusy, or an unusable lock file
                return busy
            try:
                ev = scan_settlement(self.store, pub, org_id=oid, slug=s, nonce=non, since=ev)   # + since then
                on_seam = is_lease_settled(base, s, non)
            except OSError:
                return busy
            fresh = not (ev.settled or on_seam)
            if fresh and finish_only:
                return {"ok": True, "action": "launch_not_settled", "org_id": oid, "slug": s, "refunded": 0,
                        "refunded_plan": 0, "refunded_wallet": 0, "net_spend": 0}
            if fresh:
                why = _refusal(refuse_if)
                if why:
                    return {"ok": False, "error": f"settle refused: {why}", "refused": why}
                meter_refusal = self._close_model_meter(s, non, now_ts)
                if meter_refusal is not None:
                    return meter_refusal
            else:
                meter_refusal = self._close_model_meter(s, non, now_ts)
                if meter_refusal is not None:                # OD-8: settled already — never strand its refund on it
                    import logging
                    logging.getLogger(__name__).warning("a settled launch's model meter could not be closed: %s",
                                                        meter_refusal.get("error"))
            recorded = False
            if fresh and config.settle_spine_record_enabled():
                try:
                    record_launch_settled(self.store, kp, org_id=oid, slug=s, nonce=non, decision=decision,
                                          issued_at=now_ts)
                    recorded = True
                except OSError as e:
                    return {"ok": False, "retry": True,
                            "error": f"could not record the settlement (fail-closed): {type(e).__name__}"}
                except Exception as e:  # noqa: BLE001 — an invalid decision moves nothing
                    return {"ok": False, "error": f"internal: settlement decision invariant violated (fail-closed): "
                            f"{type(e).__name__}"}
            if not on_seam:
                try:
                    record_lease_settlement(base, s, non)    # revoke BEFORE any money moves (or re-assert a lost one)
                except Exception as e:  # noqa: BLE001 — a revocation failure refuses the settle (no money moved)
                    out = {"ok": False, "error": f"could not revoke the lease on settle (fail-closed): "
                           f"{type(e).__name__}"}
                    if isinstance(e, OSError):
                        out["retry"] = True
                    return out
            if fresh:
                decided = decision
                args: "tuple[Any, set[str], bool]" = (decision, set(), False)
            elif ev.decision is not None:
                if ev.decision.mode != decision.mode or ev.decision.reserved != reserved:
                    return {"ok": False, "error": "internal: recorded settlement disagrees with the lease (fail-closed)"}
                decided = ev.decision                        # the RECORDED decision — never this caller's
                args = (ev.decision, set(ev.landed), True)
            elif ev.malformed:
                return {"ok": False, "error": "internal: recorded settlement is unusable (fail-closed; operator)"}
            else:
                decided = None
            if decided is None:
                moved = {"refunded": 0, "refunded_plan": 0, "refunded_wallet": 0, "wrote": False}
            else:
                try:
                    moved = move(*args)
                except OSError:
                    if recorded or not fresh:                # a recorded decision: the next settle finishes it
                        return {"ok": False, "retry": True,
                                "error": "settle interrupted after its decision; a retry finishes it"}
                    raise
            if fresh:
                # EC-5: settle the cost ledger to the consumed envelope (clamped to the reserved cap), from the
                # VERIFIED lease. Gated default-OFF + fail-safe (advisory). Idempotent per (slug, nonce).
                self._write_cost_settle(oid, s, non, decided.consumed, reserved, now_ts)
            elif decided is not None:
                self._write_cost_settle_if_missing(oid, s, non, decided.consumed, reserved, now_ts)
            try:
                tombstone_credit_lease(base, s, non)         # nonce-matched: never clobber a newer re-lease
            except Exception:  # noqa: BLE001 — total by contract; the marker already revokes the lease
                pass
        out = {"ok": True, "action": "launch_settled" if fresh else "launch_already_settled", "org_id": oid,
               "slug": s, "refunded": int(moved["refunded"]), "refunded_plan": int(moved["refunded_plan"]),
               "refunded_wallet": int(moved["refunded_wallet"]),
               "net_spend": decided.consumed if decided is not None else consumed}
        if not fresh and moved.get("wrote"):
            out.update(rolled_forward=True, basis=decided.basis)
        return out

    def _write_cost_settle_if_missing(self, oid: str, slug: str, nonce: str, consumed: int, reserved: int,
                                      now_ts: float) -> None:
        """EC-5 on a NOT-fresh settle that finishes a recorded decision: write the cost-ledger settle only if it is
        absent (``CostEnvelopeLedger.was_settled``), so a crash between the money and the cost settle never leaves
        the reserve counting against the global pool, and a re-settle never appends a duplicate. Gated default-OFF
        and fail-safe (advisory), exactly like :meth:`_write_cost_settle`."""
        from .. import config
        if not config.cost_ledger_write_enabled():
            return
        try:
            from ..governor.cost_ledger import SETTLE_COST_PREFIX
            if self._cost_ledger.was_settled(oid, f"{SETTLE_COST_PREFIX}{slug}:{nonce}"):
                return
        except Exception:  # noqa: BLE001 — advisory metering: a cost-read failure never breaks the settle
            import logging
            logging.getLogger(__name__).warning("EC-5 cost-settle check failed (advisory; settle unaffected)",
                                                 exc_info=True)
            return
        self._write_cost_settle(oid, slug, nonce, consumed, reserved, now_ts)

    def interrupted_settlement(self, signed_lease: Any) -> Optional[dict]:
        """READ-ONLY: the not-yet-landed part of lease ``signed_lease``'s RECORDED settlement decision — what the
        next settle of it would finish — or None (no recorded decision, or every recorded entry landed). Verifies
        the lease owner-pinned, takes no lock and writes nothing (``ops-sweep reservations`` without ``--apply``
        reports it as ``settle_interrupted``)."""
        from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
        from ..governor.launch_settlement import scan_settlement
        kp = self.owner_key
        if kp is None:
            return None
        try:
            signed = SignedCreditLaunchLease.model_validate(signed_lease)
            root = TrustRoot(threshold=1, authorizers=[
                AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
            if not verify_credit_launch_lease(signed, root)[0]:
                return None
            doc = signed.document
            oid, s, non = doc.org_id, doc.engagement_slug, doc.nonce
            ev = scan_settlement(self.store, kp.public_key_b64, org_id=oid, slug=s, nonce=non)
            return self._unlanded(oid, s, non, ev)
        except Exception:  # noqa: BLE001 — a read-only report: an unreadable state reports nothing
            return None

    def _unlanded(self, oid: str, s: str, non: str, ev: Any) -> Optional[dict]:
        """The part of lease ``(s, non)``'s RECORDED settlement decision (``ev``, its spine evidence) whose money has
        not landed — each recorded entry the live scan did not find AND the prune-durable seen-sets confirm absent —
        or None when there is no recorded decision or every recorded entry landed. Raises when a ledger cannot be
        read (the caller decides: a report reports nothing, a publish refuses)."""
        from ..governor.launch_settlement import MODE_POSTPAID
        d = ev.decision
        if d is None:
            return None
        pend_plan = d.refund_plan if (d.refund_plan > 0 and d.plan_period_end > 0 and "plan" not in ev.landed
                                      and not self.meter.plan.has_grant_entry(oid, f"settle-plan:{s}:{non}")) else 0
        pend_wallet = d.refund_wallet if (d.refund_wallet > 0 and "wallet" not in ev.landed and not
                                          self.wallet.has_grant_entry(oid, f"settle-wallet:{s}:{non}")) else 0
        pend_pp = (d.mode == MODE_POSTPAID and "postpaid" not in ev.landed
                   and not self.arrears.has_credit_entry(oid, f"{SETTLE_ENTRY_PREFIX}{s}:{non}"))
        if not (pend_plan or pend_wallet or pend_pp):
            return None
        return {"pending_plan": int(pend_plan), "pending_wallet": int(pend_wallet),
                "pending_postpaid": int(d.refund_postpaid) if pend_pp else 0, "consumed": int(d.consumed),
                "basis": d.basis}

    def publish_lease(self, *, signed_lease: Any, expect_org_id: Optional[str] = None) -> dict:
        """Slice K3 (producer): drop an owner-signed lease on the cross-plane seam so the offense plane can
        read + keyless-verify it before a customer engagement runs. The lease is VERIFIED owner-pinned here
        (same locally-built owner TrustRoot as settle — a forged/tampered lease never reaches the seam) and
        TENANT-BOUND (``expect_org_id`` must match the lease's org, so a customer cannot publish another
        tenant's lease). Writes under the lease's OWN ``engagement_slug`` (== ``_customer_slug(org, host)``),
        co-located with the G0 EngagementAuthority. Idempotent: re-publishing the same lease re-writes the same
        bytes. Returns ``{ok: True, slug}`` or ``{ok: False, error}`` (fail-closed). The owner trust root is
        written alongside for parity with the authority seam; the offense reader PINS its own owner key and
        never trusts the seam-carried root (K2)."""
        from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
        kp = self.owner_key
        if kp is None:
            return {"ok": False, "error": "publishing a lease requires the owner key (internal)"}
        try:
            signed = SignedCreditLaunchLease.model_validate(signed_lease)
        except Exception:  # noqa: BLE001 — a malformed lease is a fail-closed refusal
            return {"ok": False, "error": "publish requires the signed launch lease from reserve_launch"}
        owner_root = TrustRoot(threshold=1, authorizers=[
            AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
        ok, reason = verify_credit_launch_lease(signed, owner_root)   # PINNED to our owner key, not the wire
        if not ok:
            return {"ok": False, "error": f"lease does not verify under the owner key: {reason}"}
        doc = signed.document
        if expect_org_id is not None and doc.org_id != expect_org_id:
            return {"ok": False, "error": "this lease belongs to a different org"}
        from .. import config
        try:
            from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
            from ..governor.launch_settlement import scan_settlement
            # K4-1: never re-publish a lease whose (slug, nonce) was already settled/canceled — else a settled
            # bearer capability is resurrected on the seam. (A fast refusal here; the decisive check — the seam
            # marker OR the spine's settlement evidence — re-runs under the settle critical section below.)
            if is_lease_settled(self._seam_base(), doc.engagement_slug, doc.nonce):
                return {"ok": False, "error": "this lease has already been settled/canceled and cannot be "
                        "re-published"}
            ev0 = scan_settlement(self.store, kp.public_key_b64, org_id=doc.org_id, slug=doc.engagement_slug,
                                  nonce=doc.nonce)                              # the full scan, unlocked
            # With the settle record on, the settlement evidence of the launch whose lease this publish would replace
            # is read the same way: the full scan here, unlocked, continued under the locks (_earlier_launch_in_flight).
            prior = None
            if config.settle_spine_record_enabled():
                cur0 = read_credit_lease(self._seam_base(), doc.engagement_slug)
                earlier0 = str(cur0.signed_lease.document.nonce) if cur0 is not None else ""
                if earlier0 and earlier0 != str(doc.nonce):
                    prior = (earlier0, scan_settlement(self.store, kp.public_key_b64, org_id=doc.org_id,
                                                       slug=doc.engagement_slug, nonce=earlier0))
        except Exception as e:  # noqa: BLE001 — a seam-read failure is a clean refusal, never a half-publish
            return {"ok": False, "error": f"could not publish the launch lease to the seam: {type(e).__name__}"}
        from ..governor.launch_settlement import SettleLockBusy, settle_lock
        guard = contextlib.ExitStack()
        try:
            was_metered = self._launch_was_metered(doc.engagement_slug, doc.nonce)
            involved = was_metered or config.metered_billing_enabled()
            # PRICING M1c: where metering is involved, the one-launch-per-host check, the grant and the lease write
            # are one step per org+host — across threads and across the cockpit and customer servers — so two
            # concurrent publishes can never both pass the check. A flat-only deployment takes no _publish_lock and
            # writes nothing under the meter directory (default-OFF unchanged).
            # E3c: then the per-process spine lock and the cross-process settle lock (bounded), in that order (the
            # global lock order: _publish_lock -> spine_lock -> settle_lock), so a publish can never land between a
            # settle's settled-check and its tombstone, nor a settle between this publish's check and its write.
            if involved:
                guard.enter_context(self._publish_lock(doc.engagement_slug))
            guard.enter_context(self._lock)
            guard.enter_context(settle_lock(self.store))
        except SettleLockBusy:
            guard.close()
            return {"ok": False, "retry": True,
                    "error": "could not publish the launch lease: the settle lock is busy; retry"}
        except Exception as e:  # noqa: BLE001 — a seam/meter-read failure is a clean refusal, never a half-publish
            guard.close()
            return {"ok": False, "error": f"could not publish the launch lease to the seam: {type(e).__name__}"}
        with guard:
            return self._publish_checked(doc, signed, owner_root, kp, ev0, prior)

    @staticmethod
    @contextlib.contextmanager
    def _publish_lock(slug: str) -> "Iterator[None]":
        """An exclusive per-org+host lock (``flock`` on a file beside the meters, so it holds across processes)."""
        import fcntl
        import hashlib
        from .. import config
        d = Path(config.MODEL_METER_DIR)
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = "publish-" + hashlib.sha256(str(slug).encode("utf-8")).hexdigest()[:32] + ".lock"
        fd = os.open(d / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _publish_checked(self, doc: Any, signed: Any, owner_root: Any, kp: Any, ev0: Any,
                         prior: "Optional[tuple[str, Any]]" = None) -> dict:
        """The rest of :meth:`publish_lease`, under the spine + settle locks (and its per-host lock where metering is
        involved). ``ev0`` is the unlocked settlement scan, continued here over what was appended since; ``prior`` is
        ``(nonce, its unlocked scan)`` of the lease this publish would replace (settle record on), or None."""
        from .. import config
        from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease, write_credit_lease
        from ..governor.launch_settlement import scan_settlement
        try:
            # Settled = the seam marker OR the spine's settlement evidence (a lost / stale-restored seam must not
            # resurrect a settled bearer capability either), decided under the settle critical section BEFORE any
            # grant is minted.
            ev = scan_settlement(self.store, kp.public_key_b64, org_id=doc.org_id, slug=doc.engagement_slug,
                                 nonce=doc.nonce, since=ev0)
            if ev.settled or is_lease_settled(self._seam_base(), doc.engagement_slug, doc.nonce):
                return {"ok": False, "error": "this lease has already been settled/canceled and cannot be "
                        "re-published"}
            # the billing mode as it is NOW, under the locks (another process may have marked it since the unlocked read)
            was_metered = self._launch_was_metered(doc.engagement_slug, doc.nonce)
            cur = read_credit_lease(self._seam_base(), doc.engagement_slug)
        except Exception as e:  # noqa: BLE001 — a spine/seam-read failure is a clean refusal, never a half-publish
            return {"ok": False, "error": f"could not publish the launch lease to the seam: {type(e).__name__}"}
        # The billing mode is decided ONCE, at the launch's first publish, and a re-publish keeps it whatever the
        # flag says now: a launch already marked metered is re-published with its grant, and one already on the seam
        # without a mark (published flat — its run is under way unmetered) is re-published flat, never switched.
        published_flat = (not was_metered and cur is not None
                          and str(cur.signed_lease.document.nonce) == str(doc.nonce))
        metered = was_metered or (config.metered_billing_enabled() and not published_flat)
        # PRICING M1c: the seam holds one lease per org+host, so a newer launch's lease would replace one still
        # running — its completion could then never settle, and a customer cancel would read it as never started.
        # Where metering is involved (this launch, or the one on the seam), one launch per host is in flight at a time.
        try:
            refusal = self._earlier_launch_in_flight(doc, metered, cur, prior)
        except Exception as e:  # noqa: BLE001 — a seam-read failure is a clean refusal, never a half-publish
            return {"ok": False, "error": f"could not publish the launch lease to the seam: {type(e).__name__}"}
        if refusal is not None:
            return refusal
        # With metered billing on, the run's model grant is minted and published BEFORE the lease, so a lease is never
        # on the seam without the grant its run must meter through. A grant that cannot be minted (bad pricing config)
        # refuses the publish — a run never starts unmetered.
        minted = False
        if metered:
            try:
                minted = self._publish_model_grant(doc, kp)
            except Exception as e:  # noqa: BLE001 — fail closed: no grant, no published lease
                return {"ok": False, "error": f"could not mint this run's metered model grant: {type(e).__name__}"}
        try:
            write_credit_lease(self._seam_base(), doc.engagement_slug, signed, owner_root)
        except Exception as e:  # noqa: BLE001 — a seam-write failure is a clean refusal, never a half-publish
            if minted:          # only a grant THIS call created: a re-publish never removes a live run's grant
                try:
                    from vigil_integration.live.model_grant_broker import remove_model_grant
                    remove_model_grant(self._seam_base(), doc.engagement_slug, expect_nonce=doc.nonce)
                except OSError:
                    pass        # its run never starts without the lease; the settle retires it
            return {"ok": False, "error": f"could not publish the launch lease to the seam: {type(e).__name__}"}
        return {"ok": True, "action": "launch_published", "org_id": doc.org_id, "slug": doc.engagement_slug,
                "scope_host": doc.scope_host}

    @staticmethod
    def _launch_was_metered(slug: str, nonce: str) -> bool:
        """Whether launch ``(slug, nonce)`` is billed metered: its metered marker (written before its grant, at
        publish) or its meter is on disk — never the current flag, which may have changed since."""
        from .. import config
        from vigil_core.model_grant import meter_id
        from ..model_gateway import GrantMeter
        return GrantMeter(config.MODEL_METER_DIR).was_metered(meter_id(str(slug), str(nonce)))

    def _close_model_meter(self, slug: str, nonce: str, now_ts: float) -> Optional[dict]:
        """Close the launch's model meter and retire its grant before its lease settles (PRICING M1c). Applies to a
        launch published metered (:meth:`_launch_was_metered`), whatever the flag says now; a no-op otherwise, so a
        flat launch's settle is unchanged. Returns the refusal to settle with: ``retry`` when the live gateway still
        has a request of this run in flight or the meter cannot be written right now; a broken meter refuses
        without ``retry`` (fail closed). The grant is removed only once the meter is closed; removing it is
        best-effort, as a grant whose meter is closed can spend nothing."""
        from .. import config
        from vigil_core.model_grant import meter_id
        from vigil_integration.live.model_grant_broker import remove_model_grant
        from ..model_gateway import GrantMeter, MeterBusy
        try:
            if not self._launch_was_metered(slug, nonce):
                return None
            GrantMeter(config.MODEL_METER_DIR).close(meter_id(str(slug), str(nonce)), now=float(now_ts))
        except MeterBusy:
            return {"ok": False, "retry": True, "error": "the run still has a model request in flight; retry the settle"}
        except OSError as e:
            return {"ok": False, "retry": True,
                    "error": f"the run's model meter cannot be written right now; retry the settle: {type(e).__name__}"}
        except ValueError as e:
            return {"ok": False, "error": f"could not close the run's model meter (fail-closed): {type(e).__name__}"}
        try:
            remove_model_grant(self._seam_base(), str(slug), expect_nonce=str(nonce))
        except OSError:
            import logging
            logging.getLogger(__name__).warning("could not remove a settled run's model grant", exc_info=True)
        return None

    def _earlier_launch_in_flight(self, doc: Any, metered: bool, cur: Any,
                                  prior: "Optional[tuple[str, Any]]" = None) -> Optional[dict]:
        """The refusal when an earlier, unsettled launch of the same org+host holds the seam (``cur``, the lease on it)
        and metering is involved (``metered`` for this launch, or the earlier one was published metered); None
        otherwise. With the settle record on, also the refusal (``retry``) while the earlier launch's RECORDED
        settlement still has money to move, whatever either launch's billing mode. ``prior`` is the unlocked scan of
        the earlier launch's evidence from :meth:`publish_lease` (continued here), or None."""
        from .. import config
        from vigil_integration.live.credit_lease_broker import is_lease_settled, record_lease_settlement
        if cur is None:
            return None
        earlier = str(cur.signed_lease.document.nonce)
        if earlier == str(doc.nonce):
            return None
        ev_e = None
        if config.settle_spine_record_enabled() and self.owner_key is not None:
            # E3bc: the seam holds ONE lease per org+host, and the drain's re-drive and the sweep finish an interrupted
            # settle only through that lease. So while the earlier launch's recorded decision has an entry that has not
            # landed, its lease stays on the seam: this publish is refused with a retry until the drain or the sweep
            # has finished it — the recorded refund always lands, exactly once. Its marker alone says nothing about
            # the money (it is written before the money moves).
            from ..governor.launch_settlement import scan_settlement
            since = prior[1] if prior is not None and prior[0] == earlier else None
            ev_e = scan_settlement(self.store, self.owner_key.public_key_b64, org_id=doc.org_id,
                                   slug=doc.engagement_slug, nonce=earlier, since=since)
            if self._unlanded(doc.org_id, doc.engagement_slug, earlier, ev_e) is not None:
                return {"ok": False, "retry": True,
                        "error": "an earlier launch on this host is still finishing its settlement; retry shortly"}
        if is_lease_settled(self._seam_base(), doc.engagement_slug, earlier):
            return None
        if not (metered or self._launch_was_metered(doc.engagement_slug, earlier)):
            return None
        if ev_e is not None and ev_e.settled:
            # E3bc (A5): with the settle record on, the SPINE also says whether the earlier launch settled — its marker
            # may have been lost with the seam. Its money has landed (checked above), so it is not in flight:
            # re-assert its lost marker (under the settle lock this publish holds; a failure refuses the publish) and
            # let the new launch through.
            record_lease_settlement(self._seam_base(), doc.engagement_slug, earlier)
            return None
        return {"ok": False, "error": "an earlier launch on this host has not settled yet; it must finish (or be "
                "settled) before another starts"}

    def _publish_model_grant(self, doc: Any, owner_key: Any) -> bool:
        """Mint the owner-signed model grant for ONE verified lease and publish its token on the seam (design
        §5.1). Every field comes from the verified lease or the owner's pricing config — never a wire value or the
        clock: the cap is the most AI spend whose marked-up charge fits the reservation, the effort is the run
        tier's, the grant is valid from the lease's start for the longest grant lifetime (a run armed inside the
        lease window may outlive it — a late start, a resume — and must keep its model access; the settle closes the
        meter, after which the grant spends nothing), and the grant id is derived from the lease — so re-publishing a
        lease mints the identical grant. The launch is marked metered (beside its meter) before its grant is
        written, so its settle bills it metered whatever the flag says later. Returns whether this call wrote the
        grant (False: the same grant was already on the seam). Raises on any failure (the caller refuses the
        publish), including no cancel-settlement policy (a metered run cannot start before the owner has chosen how a
        cancel settles) and a run model the price table cannot price."""
        import hashlib
        from vigil_core import model_metering as mm
        from vigil_core import run_tier
        from vigil_core.model_grant import MAX_GRANT_LIFETIME_S, ModelGrant, encode_token
        from vigil_integration.live.model_grant_broker import read_model_grant, write_model_grant
        from .. import config
        from ..model_gateway import GrantMeter
        units = int(doc.units_reserved)
        mm.cancel_settlement()
        model = config.run_model()
        if model not in mm.price_table():
            raise mm.MeteringError(f"the run model {model!r} has no price ({mm.PRICES_ENV})")
        slug, nonce = str(doc.engagement_slug), str(doc.nonce)
        grant = ModelGrant(
            grant_id=hashlib.sha256(f"model-grant\0{slug}\0{nonce}".encode()).hexdigest()[:32],
            org_id=str(doc.org_id), engagement_slug=slug, nonce=nonce, model=model,
            effort=run_tier.effort_for(run_tier.run_tier_for_units(units)),
            cap_nano_usd=mm.usd_cap_nano_for_credits(units, markup=mm.billing_markup()),
            not_after=float(doc.not_before.timestamp()) + MAX_GRANT_LIFETIME_S,
            issued_at=float(doc.not_before.timestamp()))
        token = encode_token(grant, owner_key.private_key_b64)
        GrantMeter(config.MODEL_METER_DIR).mark_metered(grant.meter_id)
        existed = read_model_grant(self._seam_base(), slug, expect_nonce=nonce) is not None
        write_model_grant(self._seam_base(), grant.engagement_slug, grant.nonce, token, config.model_gateway_url())
        return not existed

    def _verify_lease_for_pause(self, signed_lease: Any, expect_org_id: Optional[str]):
        """Owner-pinned verify + tenant-bind for a pause/resume request (same guarantee as publish/settle): the
        signed lease must verify under OUR owner key (never a wire/seam value) and — when a customer calls — its
        ``org_id`` must equal the session org, so a customer can never pause/resume another tenant's lease.
        Returns ``(doc, None)`` on success or ``(None, {ok: False, error})`` on any refusal (fail-closed)."""
        from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
        kp = self.owner_key
        if kp is None:
            return None, {"ok": False, "error": "pause/resume requires the owner key (internal)"}
        try:
            signed = SignedCreditLaunchLease.model_validate(signed_lease)
        except Exception:  # noqa: BLE001 — a malformed lease is a fail-closed refusal
            return None, {"ok": False, "error": "pause/resume requires the signed launch lease from reserve_launch"}
        owner_root = TrustRoot(threshold=1, authorizers=[
            AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
        ok, reason = verify_credit_launch_lease(signed, owner_root)   # PINNED to our owner key, not the wire
        if not ok:
            return None, {"ok": False, "error": f"lease does not verify under the owner key: {reason}"}
        doc = signed.document
        if expect_org_id is not None and doc.org_id != expect_org_id:
            return None, {"ok": False, "error": "this lease belongs to a different org"}
        return doc, None

    def pause_launch(self, *, signed_lease: Any, expect_org_id: Optional[str] = None) -> dict:
        """pause/resume PR-4b (producer) — RECORD a reversible ``(slug, nonce)`` pause marker for a customer's
        own owner-signed lease, so the already-merged PR-2..PR-4a money-safety plumbing HALTS the launch at every
        window (held, re-admitted on resume). Verifies the lease owner-pinned + tenant-binds (``expect_org_id``);
        the record is done UNDER ``self._lock`` and the cross-process settle lock (a short bounded wait), so a pause
        is linearized with every settle; the marker's own read-modify-write is cross-process exclusive by its
        per-file lock (E3bc). If the settle lock stays busy past its short wait the halt is still recorded and the
        reply says ``linearized: False`` (OWNER DECISION OD-1: a pause must always be able to HALT). Pausing moves
        NO money (no credit/amount/signature touched). A SETTLED/canceled lease is refused (it is no longer a
        runnable launch, so there is nothing to pause) — settled per the seam marker, or, with the settle record
        on, per the spine. Idempotent: re-pausing the same (slug, nonce) re-writes the same marker.

        An EXPIRED lease is deliberately NOT refused (the validity window is not checked here): the same marker
        is the in-flight HALT, and a run that armed inside the window keeps sending traffic after ``not_after``
        (the window is checked at the arm, not per action). The sovereign plane cannot know whether such a run is
        in flight, so refusing the pause would take away the customer's only stop control for it — a pause must
        always be able to HALT. On a lease that is expired and idle the marker is inert (the keyless verify
        refuses the window before it ever consults the pause), and :meth:`resume_launch` still clears it on an
        expired lease, so a pause is always reversible."""
        doc, err = self._verify_lease_for_pause(signed_lease, expect_org_id)
        if err is not None:
            return err
        s, non, oid = doc.engagement_slug, doc.nonce, doc.org_id
        linearized = True
        try:
            from .. import config
            from ..governor.launch_settlement import SettleLockBusy, scan_settlement, settle_lock
            from vigil_integration.live.credit_lease_broker import is_lease_settled
            from vigil_integration.live.credit_lease_pause import record_lease_pause
            base = self._seam_base()
            pub = self.owner_key.public_key_b64 if self.owner_key is not None else None
            # E3bc: the spine's settlement evidence is consulted only with the settle record on (so default
            # deployments pay no spine scan on the customer's stop control); the scan runs before any lock.
            ev0 = scan_settlement(self.store, pub, org_id=oid, slug=s, nonce=non) if (
                pub and config.settle_spine_record_enabled()) else None
            with self._lock:
                held = contextlib.ExitStack()
                try:
                    # LINEARIZE with every settle (the sweep / drain / cancel), so a pause either lands before a
                    # settle's in-lock pause re-read or is refused as settled. Bounded short (OD-7)...
                    held.enter_context(settle_lock(self.store, wait_s=min(2.0, config.settle_lock_wait_s())))
                except SettleLockBusy:
                    # ...and a busy lock never takes away the stop control: the halt is recorded anyway (OD-1).
                    import logging
                    logging.getLogger(__name__).warning("the settle lock is busy; recording the launch pause "
                                                        "without it (not linearized with a concurrent settle)")
                    linearized = False
                with held:
                    settled = is_lease_settled(base, s, non) or (
                        ev0 is not None and scan_settlement(self.store, pub, org_id=oid, slug=s, nonce=non,
                                                            since=ev0).settled)
                    if settled:
                        return {"ok": False,
                                "error": "this lease has already been settled/canceled and cannot be paused"}
                    record_lease_pause(base, s, non)         # under its own per-file cross-process lock
        except Exception as e:  # noqa: BLE001 — a seam-write failure is a clean refusal, never a half-pause
            return {"ok": False, "error": f"could not record the launch pause (fail-closed): {type(e).__name__}"}
        out = {"ok": True, "action": "launch_paused", "org_id": oid, "slug": s, "nonce": non}
        if not linearized:
            out["linearized"] = False
        return out

    def resume_launch(self, *, signed_lease: Any, expect_org_id: Optional[str] = None,
                      now: Any = None) -> dict:
        """pause/resume PR-4b (producer) — CLEAR the ``(slug, nonce)`` pause marker so the SAME lease re-arms
        (PR-2 re-check passes; PR-3/PR-4a re-admit the held delivery). Same owner-pinned verify + tenant-bind as
        :meth:`pause_launch`; the clear is UNDER ``self._lock`` and each marker write under its own per-file lock —
        but NEVER the settle lock (E3bc A1), so a pause can always be lifted: safe because the late record is written
        BEFORE the pause is cleared and every settle-side reader reads the pause BEFORE the late record. Clearing is
        always safe + idempotent (a clear of
        an absent/already-cleared pause is a no-op), so — unlike pause — it does not refuse a settled lease (a
        settled lease simply has no pause to clear and will not run regardless).

        An EXPIRED lease (``now >= not_after`` — the same half-open window the keyless verify enforces) is STILL
        CLEARED, and the reply says so (``expired: True`` plus a ``detail``). The marker is also the in-flight
        HALT: a run that armed inside the window keeps running after ``not_after`` (the window is checked at the
        arm, not per action) and the engine's halt checks read only the marker. Refusing the clear would leave
        such a run halted for good — floor burned, no completion, so the reservation could never settle, and a
        started lease cannot be cancelled — so a customer must always be able to lift their own pause. Clearing
        cannot make an expired lease runnable: the seam poller, the pickup gate and the arm all refuse the window,
        so a launch that has not started still never starts. ``now`` is a datetime / POSIX timestamp (``None`` ⇒
        the current time); an unreadable ``now`` or lease window refuses and clears nothing (fail-closed),
        because the reply could not say which of the two cases applies."""
        doc, err = self._verify_lease_for_pause(signed_lease, expect_org_id)
        if err is not None:
            return err
        s, non, oid = doc.engagement_slug, doc.nonce, doc.org_id
        try:
            # a NaN / infinite ``now`` cannot become a datetime (ValueError / OverflowError), so it refuses here
            now_ts = (datetime.now(timezone.utc) if now is None else self._as_dt(now)).timestamp()
            expired = now_ts >= doc.not_after.timestamp()
        except (TypeError, ValueError, OSError, OverflowError, AttributeError):
            return {"ok": False, "error": "could not read the lease validity window for resume (fail-closed)"}
        try:
            from vigil_integration.live.credit_lease_pause import (clear_lease_pause, lease_pause_state,
                                                                   record_paused_past_expiry)
            with self._lock:
                base = self._seam_base()
                # Owner decision 2026-11-13 (a launch paused and never resumed is charged for what it used): lifting a
                # pause after the window closed re-admits nothing, so it must not erase that the customer held the
                # launch paused through the end of its window. Record that first (a failed record refuses the resume
                # and clears nothing), then lift the halt as before so a run still in flight is never stranded.
                if expired and lease_pause_state(base, s, non) is True:
                    record_paused_past_expiry(base, s, non)
                clear_lease_pause(base, s, non)
        except Exception as e:  # noqa: BLE001 — a seam-write failure is a clean refusal, never a half-resume
            return {"ok": False, "error": f"could not clear the launch pause (fail-closed): {type(e).__name__}"}
        out = {"ok": True, "action": "launch_resumed", "org_id": oid, "slug": s, "nonce": non}
        if expired:
            out["expired"] = True
            out["detail"] = _RESUMED_EXPIRED_DETAIL
        return out
