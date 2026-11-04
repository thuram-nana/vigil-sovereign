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

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..spine.store import spine_lock  # noqa: E402  (process-wide, path-keyed re-entrant txn lock)

_MAX_UNITS = 1_000_000          # a sane upper bound on a single launch's reservation (fail-closed on garbage)
_DEFAULT_LEASE_HOURS = 8.0
_MAX_LEASE_HOURS = 24.0 * 7     # a launch lease caps at a week; a longer engagement re-leases


class LaunchGate:
    """Compose the four launch conjuncts + reserve + mint. Registries/meter are INJECTED for tests; in
    production they default to the owner-key-backed sovereign registries over ``store``."""

    def __init__(self, store, *, orgs=None, ownership=None, meter=None, wallet=None,
                 owner_key=None, base_dir: Optional[str] = None):
        from ..governor.asset_ownership import AssetOwnershipRegistry
        from ..governor.identity import owner_keypair
        from ..governor.metering import CreditMeter, PlanCreditLedger
        from ..governor.orgs import OrgRegistry
        from ..governor.subscription import SubscriptionRegistry
        from ..governor.wallet import WalletRegistry
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.orgs = orgs if orgs is not None else OrgRegistry(store)
        self.ownership = ownership if ownership is not None else AssetOwnershipRegistry(store)
        self.wallet = wallet if wallet is not None else WalletRegistry(store)
        self.meter = meter if meter is not None else CreditMeter(
            self.wallet, PlanCreditLedger(store), SubscriptionRegistry(store))
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
            if self.meter.available(oid, now_ts) < u:
                return f"insufficient credits: need {u}, have {self.meter.available(oid, now_ts)}"
            return None

        pre = _gated()                                   # cheap pre-check outside the lock (fast refusal)
        if pre is not None:
            return {"ok": False, "error": pre}
        with self._lock:
            re = _gated()                                # TOCTOU: re-check every conjunct inside the lock
            if re is not None:
                return {"ok": False, "error": re}
            before = self.meter.available(oid, now_ts)
            self._spend(oid, u, slug, non, now_ts)       # plan-first then wallet (idempotent per slug/nonce)
            if before - self.meter.available(oid, now_ts) < u:
                # the spend did NOT consume `u` (a reused nonce's debits no-op'd, or a bucket shortfall) —
                # refuse and mint NOTHING, so a reservation is ALWAYS backed by a real, incremental debit.
                return {"ok": False, "error": "this launch reservation did not apply (nonce already used)"}
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
                      expect_org_id: Optional[str] = None) -> dict:
        """Close out a reservation: refund the UNUSED portion so net spend == metered consumption. The refund
        is bound to the OWNER-SIGNED LEASE, never to a wire amount — ``signed_lease`` (the object
        ``reserve_launch`` returned) is VERIFIED under a locally-pinned owner trust root and
        ``units_reserved`` / ``org_id`` / ``slug`` / ``nonce`` are taken from the VERIFIED document, so a
        forged or wire-asserted amount cannot mint a refund (the HIGH the red-pen found). Refund =
        ``units_reserved - clamp(consumed_units, 0, units_reserved)``, granted back to the wallet. Idempotent
        per the lease's (slug, nonce): a re-settle no-ops. ``consumed_units == 0`` is the cancel/release case
        (full refund); a crash before settle simply leaves the cap debited (fail-closed, never over-refunds).

        MONEY-DOCTRINE CLOSE-OUT (K4-1): settling/cancelling refunds the credits AND makes the lease
        non-runnable. settle records a ``(slug, nonce)`` settlement marker and tombstones the seam copy
        (below, nonce-matched so a newer re-lease is never clobbered); ``publish_lease`` refuses a lease whose
        reservation is already settled; and the keyless arm re-checks settlement in
        ``verify_customer_launch_lease`` before it burns the single-use floor — so a settled lease is no
        longer a live bearer capability. The ``reserved - refund == consumed`` net-spend invariant is
        load-bearing on this refund path, and K4-5 settle-on-completion asserts net-spend ==
        metered-consumption end-to-end."""
        from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, verify_credit_launch_lease
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
        refund = reserved - consumed
        try:
            now_ts = self._as_dt(now).timestamp()
        except (TypeError, ValueError, OSError, OverflowError):
            return {"ok": False, "error": "now must be a datetime or a POSIX timestamp"}
        # BUCKET-SYMMETRIC REFUND (red-pen fix: plan-credit laundering). reserve_launch._spend debits
        # PLAN-credits-first (non-rollover, expire at period_end) then the WALLET (permanent). Refunding the
        # whole amount to the wallet would LAUNDER expiring plan credits into the permanent wallet on every
        # reserve+cancel cycle (defeating use-it-or-lose-it). So restore the SAME buckets: re-derive how much
        # was debited from the plan tranche (and which period) from the OWNER-SIGNED debit record (never a wire
        # amount), let consumption eat the expiring plan portion FIRST, refund the unconsumed plan portion back
        # to that SAME tranche, and only the remainder to the wallet. consumed == 0 (cancel) therefore restores
        # the reservation exactly — a no-op, with nothing moved plan->wallet.
        plan_deb = self.meter.plan.debited_entry(oid, f"reserve-plan:{s}:{non}")   # (from_plan, period_end) | None
        from_plan = plan_deb[0] if plan_deb else 0
        plan_pe = plan_deb[1] if plan_deb else None
        plan_refund = max(0, from_plan - consumed)         # consumption eats the plan (expiring) portion first
        wallet_refund = refund - plan_refund               # the rest (wallet portion + any plan over-consumption)
        # MONEY-DOCTRINE INVARIANT (K4-1): net spend == metered consumption and NEITHER bucket is over-refunded.
        # The sum/net-spend clauses hold by construction (wallet_refund := refund - plan_refund; refund :=
        # reserved - consumed); the load-bearing clause is ``plan_refund < 0 or wallet_refund < 0``, which FIRES
        # when the owner-signed reserve debit record over-claims the plan bucket relative to the signed lease
        # (from_plan > reserved). Without it an inflated plan_refund would be granted while a NEGATIVE
        # wallet_refund is silently skipped (``if wallet_refund > 0``) — a net OVER-refund / under-charge. A drift
        # here is an internal inconsistency, not a wire value: refuse (fail-closed, no credits moved) rather than
        # move the wrong amount, so net spend can never fall below metered consumption.
        if (plan_refund < 0 or wallet_refund < 0 or plan_refund + wallet_refund != refund
                or reserved - refund != consumed):
            return {"ok": False, "error": "internal: refund invariant violated (bucket split / net-spend)"}
        with self._lock:
            # K4-1 / K5 close-out: REVOKE the lease as a bearer capability BEFORE refunding — mark (slug, nonce)
            # settled (the keyless arm + publish_lease refuse it) and tombstone the published seam bundle. Order
            # matters and is fail-CLOSED: if we cannot DURABLY record the revocation we do NOT refund, so a lease
            # is never left refunded-but-still-runnable (the documented gap this slice closes). Idempotent: a
            # re-settle re-marks the same nonce + finds no bundle, and the refund grants dedupe on entry_id.
            try:
                from vigil_integration.live.credit_lease_broker import (
                    is_lease_settled, record_lease_settlement, tombstone_credit_lease,
                )
                # IDEMPOTENCY (K4-5 red-pen HIGH): a settle is a no-op for an already-settled (slug, nonce),
                # REGARDLESS of this call's consumed value. The refund-grant entry-id dedup alone does NOT
                # protect a refund=0 (COMPLETED) first-settle — it writes NO grant, so a LATER launch_cancel
                # (consumed=0 => refund=reserved) would be the FIRST writer of settle-wallet:{s}:{non} and
                # FULLY REFUND a charged, completed run (a free run / net-spend != consumption). The settlement
                # MARKER is written by EVERY settle (incl. refund=0), so guard on it here, atomically under the
                # lock, so settle_launch is truly idempotent per (slug, nonce) independent of the amount. NOTE:
                # launch_cancel's gate and the settle-drain's gate must share the settlement root — both default
                # to _base_dir(), so they align in the default deployment.
                if is_lease_settled(self._seam_base(), s, non):
                    return {"ok": True, "action": "launch_already_settled", "org_id": oid, "slug": s,
                            "refunded": 0, "refunded_plan": 0, "refunded_wallet": 0, "net_spend": consumed}
                record_lease_settlement(self._seam_base(), s, non)
                tombstone_credit_lease(self._seam_base(), s, non)   # nonce-matched: never clobber a newer re-lease
            except Exception as e:  # noqa: BLE001 — a seam-revocation failure refuses the settle (no refund yet)
                return {"ok": False, "error": f"could not revoke the lease on settle (fail-closed): "
                        f"{type(e).__name__}"}
            if plan_refund > 0 and plan_pe is not None:
                self.meter.plan.grant(oid, plan_refund, period_end=plan_pe,
                                      entry_id=f"settle-plan:{s}:{non}", issued_at=now_ts)
            if wallet_refund > 0:
                self.wallet.grant(oid, wallet_refund, "refund", source_ref=s,
                                  entry_id=f"settle-wallet:{s}:{non}", issued_at=now_ts)
        return {"ok": True, "action": "launch_settled", "org_id": oid, "slug": s,
                "refunded": refund, "refunded_plan": plan_refund, "refunded_wallet": wallet_refund,
                "net_spend": consumed}

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
        try:
            from vigil_integration.live.credit_lease_broker import is_lease_settled, write_credit_lease
            # K4-1: never re-publish a lease whose (slug, nonce) was already settled/canceled — else a settled
            # bearer capability is resurrected on the seam.
            if is_lease_settled(self._seam_base(), doc.engagement_slug, doc.nonce):
                return {"ok": False, "error": "this lease has already been settled/canceled and cannot be "
                        "re-published"}
            write_credit_lease(self._seam_base(), doc.engagement_slug, signed, owner_root)
        except Exception as e:  # noqa: BLE001 — a seam-write failure is a clean refusal, never a half-publish
            return {"ok": False, "error": f"could not publish the launch lease to the seam: {type(e).__name__}"}
        return {"ok": True, "action": "launch_published", "org_id": doc.org_id, "slug": doc.engagement_slug,
                "scope_host": doc.scope_host}
