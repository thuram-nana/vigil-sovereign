"""Shard-assignment registry — the SOVEREIGN record of owner-signed TENANT→SHARD placements (Front C S2a).

A shard-assignment record places ONE tenant (``tenant_id`` == ``org_id`` == the ``CRUCIBLE_TENANT`` id) on ONE
``shard_id`` at a monotonic ``epoch``. It is the AUTHORITATIVE basis the routing edge directs a tenant's
requests/jobs against, and the signal the live-migration orchestrator (S3) bumps to switch a tenant between
shards: a route minted at an older epoch is detectably STALE and fails closed once the active assignment moves on.

This module is the spine-of-record (SOVEREIGN; the keyless routing edge never holds the owner key — it VERIFIES
the identical ``vigil_core.shard_assignment_record.SignedShardAssignmentRecord`` bytes stored directly as the spine
event payload, so there is ONE signed object rather than a mint-then-publish split). Mirrors
``connected_repos.py`` exactly.

ASYMMETRIC AUTHENTICATION (mirrors ``connected_repos`` / ``monitoring_authority``):
  * assign / reassign = the DANGEROUS direction → honored only if the record is OWNER-SIGNED (verified against the
    owner ``TrustRoot`` under the owner pubkey valid AT ITS SEQ) AND FRESH (``issued_at`` strictly above the
    per-tenant high-water). A captured record cannot resurrect a migrated-off placement, and the ``epoch`` is
    inside the signed bytes — a tenant cannot roll its placement back without a fresh owner signature.
  * unassign = the SAFE direction → a minimal ``state="unassigned"`` record honored even UNSIGNED (a replay merely
    re-removes the tenant; gating the fail-safe direction would make it fail OPEN).

EPOCH is registry-managed and monotonic BY CONSTRUCTION: the first ``assign`` is epoch 1; ``reassign`` reads the
current active epoch and writes epoch+1 — and is IDEMPOTENT (re-driving a committed migration is a no-op) and
EXACTLY-ONCE (it refuses to bump unless the current active placement is exactly the expected source), so the
migration commit (the epoch bump) can be crash-re-driven without ever double-bumping or splitting the placement.

CROSS-TENANT ISOLATION: every record is keyed per ``tenant_id`` and ``assignment`` returns only that tenant's
placement, so one tenant's assignment can never read, overwrite or redirect another tenant's.

HARD-PRUNE DURABILITY: a fail-closed TRIPWIRE (``spine.prune.stranded_active_shard_assignments``) refuses a hard
prune that would strand the authoritative latest record of any tenant (the fold here is a signature-verifying
genesis scan of the live window — no snapshot seed in this slice, exactly like ``connected_repos``).

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports only the shared ``vigil_core`` + sovereign siblings.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import (  # noqa: E402
    AuthorizerKey, ShardAssignmentRecord, SignedShardAssignmentRecord, TrustRoot,
    check_tenant_component, sign_shard_assignment_record, verify_shard_assignment_record,
)

from . import key_history as _kh  # noqa: E402  (owner-key succession resolver, mirrors connected_repos)
from .authn import NO_HIGHWATER, as_issued_at  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.shard_assignment"
_LOAD_FROM_VAULT = object()
_SKIP = object()


@dataclass(frozen=True)
class ShardPlacement:
    """The current active placement of a tenant: which shard owns it, at which epoch."""
    tenant_id: str
    shard_id: str
    epoch: int
    issued_at: float


class ShardAssignmentConflict(ValueError):
    """A ``reassign`` was asked to bump from a source placement that is not the current active one (a concurrent
    reassign, or a corrupt/forged intervening record). Fail-closed: the orchestrator must NOT proceed — bumping
    anyway could split the placement."""


class ShardAssignmentRegistry:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing paths load the owner key from the vault; a pure-read caller passes owner_key=None explicitly so
        # the sovereign private key is never touched on a read path (least-privilege, mirrors connected_repos).
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ------------------------------------------------------------------------------
    def _append_assignment(self, tenant_id: str, shard_id: str, epoch: int, issued_at: float) -> ShardAssignmentRecord:
        """Owner-sign and append ONE active placement (the DANGEROUS direction). Caller validated epoch
        monotonicity; the anti-replay high-water (``issued_at``) is enforced by the fold on read."""
        if self.owner_key is None:
            raise ValueError("assigning a tenant to a shard requires the owner signing key")
        doc = ShardAssignmentRecord(tenant_id=tenant_id, shard_id=shard_id, epoch=int(epoch),
                                    issued_at=float(issued_at), state="assigned")
        signed = sign_shard_assignment_record(doc, {"owner": self.owner_key.private_key_b64})
        payload = {"signal": SIGNAL, "record": signed.model_dump(mode="json"), "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"tenant {tenant_id} assigned to shard {shard_id} at epoch {epoch} (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return doc

    def assign(self, tenant_id: str, shard_id: str, *, issued_at: float) -> ShardAssignmentRecord:
        """Place an UNASSIGNED tenant on ``shard_id`` for the first time (epoch 1). Refused with ``ValueError`` if
        the tenant already has an active placement (use :meth:`reassign` to move it — that is the migration path,
        which bumps the epoch). Fail-closed on a bad tenant/shard id or a missing signing key."""
        tid = check_tenant_component(tenant_id, label="tenant_id")
        sid = check_tenant_component(shard_id, label="shard_id")
        if self.placement(tid) is not None:
            raise ValueError(f"tenant {tid} already has an active placement; use reassign (migration) to move it")
        return self._append_assignment(tid, sid, 1, issued_at)

    def reassign(self, tenant_id: str, to_shard: str, *, expected_from_shard: str, expected_from_epoch: int,
                 issued_at: float) -> ShardAssignmentRecord:
        """Move ``tenant_id`` to ``to_shard`` at epoch ``expected_from_epoch + 1`` — THE live-migration commit.

        IDEMPOTENT + EXACTLY-ONCE (crash-safe re-drive):
          * if the current active placement is ALREADY ``(to_shard, expected_from_epoch + 1)`` ⇒ no-op (return it);
          * else if it is exactly the expected source ``(expected_from_shard, expected_from_epoch)`` ⇒ append the
            bump;
          * else ⇒ :class:`ShardAssignmentConflict` (fail-closed — the placement moved under us; bumping anyway
            could split it).

        So a migration commit that crashed after the spine append but before its journal was updated re-drives to a
        clean no-op, and one that crashed before the append re-drives to exactly one bump."""
        tid = check_tenant_component(tenant_id, label="tenant_id")
        to_sid = check_tenant_component(to_shard, label="to_shard")
        from_sid = check_tenant_component(expected_from_shard, label="expected_from_shard")
        target_epoch = int(expected_from_epoch) + 1
        cur = self.placement(tid)
        if cur is not None and cur.shard_id == to_sid and cur.epoch == target_epoch:
            return ShardAssignmentRecord(tenant_id=tid, shard_id=to_sid, epoch=target_epoch,
                                         issued_at=cur.issued_at, state="assigned")   # already committed
        if cur is None or cur.shard_id != from_sid or cur.epoch != int(expected_from_epoch):
            raise ShardAssignmentConflict(
                f"reassign of {tid} expected source placement ({from_sid}, epoch {expected_from_epoch}) but the "
                f"current active placement is {cur!r} — refusing to bump (fail-closed, no split placement)")
        return self._append_assignment(tid, to_sid, target_epoch, issued_at)

    def unassign(self, tenant_id: str) -> int:
        """Remove ``tenant_id`` from the fleet — the SAFE direction (honored even unsigned, so it can never fail
        open). The routing edge then refuses the tenant (no active placement). Idempotent."""
        tid = check_tenant_component(tenant_id, label="tenant_id")
        payload = {"signal": SIGNAL, "tenant_id": tid, "state": "unassigned", "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"tenant {tid} removed from the shard fleet"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads ----------------------------------------------------------------------------------------
    def _fold(self) -> "dict[str, ShardAssignmentRecord]":
        """{tenant_id: ShardAssignmentRecord} for tenants whose latest state is ASSIGNED. A signature-verifying
        genesis scan of the live window: an owner-signed assignment is honored only under the owner pubkey valid at
        its seq and only when FRESH (LWW high-water); an unassign (even unsigned) supersedes."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: "dict[str, str]" = {}
        issued: "dict[str, float]" = {}
        rows: "dict[str, ShardAssignmentRecord]" = {}
        for r in self.store.iter_records():
            self._apply(r, resolver, state, issued, rows)
        return {t: doc for t, doc in rows.items() if state.get(t) == "assigned"}

    def _apply(self, r, resolver, state: dict, issued: dict, rows: dict):
        """Fold ONE spine record into (state, issued, rows). Returns the tenant_id it touched, or ``_SKIP``."""
        p = getattr(r, "payload", None)
        if not isinstance(p, dict) or p.get("signal") != SIGNAL:
            return _SKIP
        rec = p.get("record")
        if isinstance(rec, dict):                         # the DANGEROUS direction: a signed active assignment
            signed = _parse_signed(rec)
            if signed is None:
                return _SKIP
            doc = signed.document
            tid = doc.tenant_id
            root = _owner_root(resolver.at(r.seq))
            if root is None:
                return _SKIP
            ok, _ = verify_shard_assignment_record(signed, root)
            if not ok:
                return _SKIP                              # fail-closed: unsigned/forged/wrong-epoch-key record
            at = as_issued_at(doc.issued_at)
            if at <= issued.get(tid, NO_HIGHWATER):
                return _SKIP                              # REPLAY / stale re-append of an already-honored record
            issued[tid] = at
            state[tid] = "assigned"
            rows[tid] = doc
            return tid
        # the SAFE direction: a minimal unassign (honored even unsigned)
        if p.get("state") == "unassigned":
            tid = p.get("tenant_id")
            if isinstance(tid, str) and tid:
                state[tid] = "unassigned"
                return tid
        return _SKIP

    def assignment(self, tenant_id: str) -> Optional[ShardAssignmentRecord]:
        """The current active assignment record for ``tenant_id``, or None (fail-closed / DEFAULT-DENY: no record,
        an unassigned tenant, or a forged/stale record all refuse). THIS is what the routing edge resolves."""
        if not isinstance(tenant_id, str) or not tenant_id:
            return None
        try:
            tid = check_tenant_component(tenant_id, label="tenant_id")
        except ValueError:
            return None
        return self._fold().get(tid)

    def placement(self, tenant_id: str) -> Optional[ShardPlacement]:
        """The current :class:`ShardPlacement` of ``tenant_id`` (shard + epoch), or None if unassigned."""
        doc = self.assignment(tenant_id)
        return None if doc is None else ShardPlacement(tenant_id=doc.tenant_id, shard_id=doc.shard_id,
                                                       epoch=int(doc.epoch), issued_at=float(doc.issued_at))

    def placements(self) -> "list[ShardPlacement]":
        """Every active placement across all tenants, in tenant order. OWNER-side (the sovereign doctor / an owner
        report) — a per-tenant caller uses :meth:`placement` for isolation."""
        return [ShardPlacement(tenant_id=d.tenant_id, shard_id=d.shard_id, epoch=int(d.epoch),
                               issued_at=float(d.issued_at))
                for _t, d in sorted(self._fold().items())]


def _owner_root(trusted_pubkey: Optional[str]) -> Optional[TrustRoot]:
    """A threshold-1 owner ``TrustRoot`` from the pubkey valid at a record's seq, or None (⇒ fail-closed skip)."""
    if not trusted_pubkey:
        return None
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=trusted_pubkey)])


def _parse_signed(rec: dict) -> Optional[SignedShardAssignmentRecord]:
    """Reconstruct a ``SignedShardAssignmentRecord`` from a spine payload's ``record`` dict, fail-closed (a hostile
    or corrupt payload yields None, never raises out of the fold)."""
    try:
        return SignedShardAssignmentRecord.model_validate(rec)
    except Exception:  # noqa: BLE001 — a malformed payload is inert, never a crash in the fold
        return None
