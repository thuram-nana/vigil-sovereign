"""Slice G — the offense-launch authorization gate (the billing != testing enforcement at the launch path).

``LaunchGate.reserve_launch`` is the single fail-closed chokepoint a customer offense launch passes BEFORE
any traffic. It composes FOUR independent conjuncts, each refused in isolation, and only when ALL hold does
the owner key reserve the credits and mint a ``CreditLaunchLease``:

  1. MEMBERSHIP (testing axis): ``orgs.admit_customer(requester, org_id, run_engagement)`` — a billing-only
     org_admin, a viewer, and a non-member are all refused. Paying / administering billing is not launching.
  2. OWNERSHIP PROOF (billing != testing): ``AssetOwnershipRegistry.has_current_proof(org_id, host, now)`` —
     a current, infrastructure-bound proof is required. Credits alone never authorize a test.
  3. TARGET AUTHORITY (testing-authz): a CURRENT, owner-signed ``EngagementAuthority`` for this exact host
     must be on the seam and VERIFY under THIS owner key (scope == [host], window covers now). The G0 mint
     is the only producer; ``offense_authority``/``target_add`` stay at the owner key.
  4. CREDIT BALANCE (spend): ``CreditMeter.available(org_id, now) >= units`` (units >= 1, fail-closed).

Only then: RESERVE the credits (an owner-signed debit holds the spend cap) and MINT the owner-signed lease —
both under the process-wide spine lock so a concurrent reserve cannot double-spend or race a revoked
membership/proof (TOCTOU: the conjuncts are re-checked INSIDE the lock, immediately before the debit+mint).
The signed lease is RETURNED for the caller (the provisioner/edge, Slice G commit 3) to drop on the seam;
the keyless offense launch then verifies it (``vigil_core.verify_credit_launch_lease``) as a separate
conjunct from the authority. The release/settle (refund the unused reservation) + the offense-side verify +
the per-unit debit land in commit 3.

``requester``/``org_id`` are AUTHORITATIVE, supplied by trusted sovereign code (the provisioner, after the
edge's session binding) — never a client-supplied field. FATAL-2: sovereign-side, ``assert_no_offense`` at
import; the authority broker (integration seam) is imported lazily inside the method, exactly as
``target_authorization`` does.
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

    def _authority_ok(self, org_id: str, host: str, slug: str, now_dt: datetime) -> bool:
        """True iff a CURRENT owner-signed EngagementAuthority for exactly ``host`` is on the seam under
        ``slug`` and verifies under THIS owner key with its window covering ``now``. Fail-closed on any
        read/verify error (never raises). Mirrors ``target_authorization.authority_status``'s checks."""
        kp = self.owner_key
        if kp is None:
            return False
        try:
            from vigil_core import verify_engagement_authority
            from vigil_integration.live.authorization_broker import read_authorization
            ta = read_authorization(self._seam_base(), slug)
            if ta is None:
                return False
            ok, _ = verify_engagement_authority(ta.signed_authority, ta.trust_root)
            if not ok:
                return False
            owner_ids = {a.public_key_b64 for a in ta.trust_root.authorizers}
            if kp.public_key_b64 not in owner_ids:               # must be OUR owner key (not any signer)
                return False
            doc = ta.signed_authority.document
            if list(doc.scope) != [host]:                        # EXACTLY this host — no parent/wildcard
                return False
            return doc.not_before <= now_dt < doc.not_after       # window covers now
        except Exception:  # noqa: BLE001 — a missing/corrupt/foreign bundle is simply "not authorized"
            return False

    def reserve_launch(self, *, requester: str, org_id: str, host: str, units: int, now: Any,
                       duration_hours: Any = _DEFAULT_LEASE_HOURS, nonce: Optional[str] = None) -> dict:
        """Authorize + reserve + mint for ONE launch. Returns ``{ok: True, lease, ...}`` with the signed lease
        (serialized) on success, or ``{ok: False, error}`` (fail-closed) on any failing conjunct — and on a
        refusal NOTHING is debited and NO lease is minted. ``units`` is the reservation cap (>= 1)."""
        from ..governor.orgs import _check_org_id
        from ..governor.asset_ownership import _check_host
        from .target_authorization import _customer_slug
        from vigil_core import CreditLaunchLease, AuthorizerKey, TrustRoot, sign_credit_launch_lease

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

        t = now() if callable(now) else now
        if not isinstance(t, datetime):
            t = datetime.fromtimestamp(float(t), tz=timezone.utc)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
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
            if not self._authority_ok(oid, h, slug, t):
                return (f"no current owner-signed engagement authority for {h} (org {oid}) — the owner must "
                        f"authorize this target (offense_authority stays at the owner key)")
            if self.meter.available(oid, now_ts) < u:
                return f"insufficient credits: need {u}, have {self.meter.available(oid, now_ts)}"
            return None

        # Cheap pre-check OUTSIDE the lock (fast refusal without taking the lock).
        pre = _gated()
        if pre is not None:
            return {"ok": False, "error": pre}
        with self._lock:
            # TOCTOU: re-check EVERY conjunct inside the lock, immediately before the debit + mint, so a
            # membership/proof/authority revoked or credits spent concurrently cannot sign through.
            re = _gated()
            if re is not None:
                return {"ok": False, "error": re}
            # RESERVE: an owner-signed debit holds the spend cap (idempotent per entry_id on this launch).
            self.wallet.debit(oid, u, engagement_id=slug, entry_id=f"reserve:{slug}:{non}", issued_at=now_ts)
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

    def settle_launch(self, *, org_id: str, slug: str, nonce: str, units_reserved: int,
                      consumed_units: int, now: Any) -> dict:
        """Close out a reservation: refund the UNUSED portion so net spend == metered consumption. ``reserve``
        debited the full ``units_reserved`` cap; this grants back ``units_reserved - consumed_units`` (a
        ``refund`` grant). ``consumed_units == 0`` is the CANCEL / release case (full refund); a crash before
        settle simply leaves the cap debited (fail-closed, never over-refunds). Idempotent per (slug, nonce):
        a re-settle is a no-op (the grant dedups on ``entry_id``), so a retried settlement cannot double-refund.
        ``consumed_units`` is CLAMPED to ``[0, units_reserved]`` — the offense side can never claw back more
        than it reserved. Returns ``{ok, refunded, net_spend}``; fail-closed on bad inputs."""
        from ..governor.orgs import _check_org_id
        if self.owner_key is None:
            return {"ok": False, "error": "a refund must be owner-signed (internal: no owner key)"}
        try:
            oid = _check_org_id(org_id)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        try:
            reserved = int(units_reserved)
            consumed = int(consumed_units)
        except (TypeError, ValueError):
            return {"ok": False, "error": "units_reserved and consumed_units must be integers"}
        if reserved < 0 or consumed < 0:
            return {"ok": False, "error": "units_reserved and consumed_units must be non-negative"}
        s = str(slug or "").strip()
        non = str(nonce or "").strip()
        if not s or not non:
            return {"ok": False, "error": "slug and nonce are required to settle a reservation"}
        consumed = min(consumed, reserved)                 # offense can never consume past the reserved cap
        refund = reserved - consumed
        t = now() if callable(now) else now
        if isinstance(t, datetime):
            now_ts = t.timestamp()
        else:
            now_ts = float(t)
        with self._lock:
            if refund > 0:
                self.wallet.grant(oid, refund, "refund", source_ref=s,
                                  entry_id=f"settle:{s}:{non}", issued_at=now_ts)
        return {"ok": True, "action": "launch_settled", "org_id": oid, "slug": s,
                "refunded": refund, "net_spend": consumed}
