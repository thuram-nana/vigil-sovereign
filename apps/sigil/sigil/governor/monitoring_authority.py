"""AEGIS-SaaS AE-0 — the SOVEREIGN record of owner-signed DEFENSIVE-MONITORING grants.

A monitoring grant authorizes AEGIS to monitor ONE tenant's traffic to ONE exact host for a bounded window, in
a mode: OBSERVE (inspect + alert only; never blocks) or BLOCK (inline enforcement PERMITTED — still gated per
request at the data plane by the fired-oracle certificate + the ``AEGIS_RESPOND`` entitlement; necessary,
never sufficient). Doctrine: ``own != offense-test != observe != block`` — this record is a DISTINCT capability
from the offense ``EngagementAuthority`` and from billing.

This module is the spine-of-record. The keyless data plane never reads it: AE-1 mints the publishable
``vigil_core.monitoring_authority.SignedMonitoringAuthority`` from an ACTIVE row here, and AE-2 verifies those
published bytes against the pinned owner TrustRoot (verify-only, no key).

ASYMMETRIC AUTHENTICATION (mirrors ``asset_ownership`` / ``orgs``):
  * grant = the DANGEROUS direction → honored only if OWNER-SIGNED and FRESH (``issued_at`` strictly above the
    per-(org_id, host) high-water). A captured grant cannot resurrect a revoked one.
  * revoke = the SAFE direction → honored even unsigned, fixed ``issued_at`` 0.0 (a replay merely re-revokes).

NECESSARY-NOT-SUFFICIENT on ownership (defense in depth; AE-1's mint path checks it too):
  * ``grant`` REFUSES without a CURRENT ownership proof for the exact (org_id, host), and CLAMPS ``not_after``
    to that proof's owner-signed ``expires_at`` — monitoring can never outlive proven ownership.
  * ``active_at`` re-checks the proof at read time — revoking the ownership proof makes the grant inert at once.

HARD-PRUNE DURABLE: the fold seeds from ``SnapshotState`` (schema v6) exactly like ``_fold_proofs``, and
``spine.prune.stranded_active_monitoring_authorities`` is the fail-closed tripwire that refuses a prune which
would drop an active grant the seed does not carry.

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports no framework/strix.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .asset_ownership import AssetOwnershipRegistry, _check_host, _check_org_id  # noqa: E402
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from ..spine.snapshot import SnapshotState  # noqa: E402

SIGNAL = "governor.monitoring_authority"
MODE_OBSERVE = "observe"
MODE_BLOCK = "block"
_MODES = frozenset({MODE_OBSERVE, MODE_BLOCK})
_CORE = ("signal", "org_id", "host", "mode", "not_before", "not_after", "proof_sha256", "state", "issued_at")
_MAX_WINDOW_S = 366.0 * 24.0 * 3600.0       # a single grant spans at most ~1 year (re-grant to extend)

_LOAD_FROM_VAULT = object()


def _check_mode(mode: str) -> str:
    m = str(mode or "").strip().lower()
    if m not in _MODES:
        raise ValueError(f"monitoring mode must be one of {sorted(_MODES)}")
    return m


@dataclass(frozen=True)
class MonitoringGrant:
    org_id: str
    host: str
    mode: str            # "observe" | "block"
    not_before: float
    not_after: float     # already clamped to the ownership proof's expires_at at grant time
    proof_sha256: str    # the ownership proof (token hash) this grant was minted against — a re-proof never revives it
    issued_at: float

    def covers(self, now: float) -> bool:
        return self.not_before <= float(now) < self.not_after


class MonitoringAuthorityRegistry:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def _ownership(self) -> AssetOwnershipRegistry:
        return AssetOwnershipRegistry(self.store, owner_key=None, trusted_pubkey=self.trusted_pubkey)

    # -- owner mutations ------------------------------------------------------------------------------
    def grant(self, org_id: str, host: str, *, mode: str = MODE_OBSERVE, not_before: float, not_after: float,
              now: float, issued_at: Optional[float] = None) -> MonitoringGrant:
        """Owner-sign a monitoring grant (the DANGEROUS direction). Fail-closed ``ValueError`` on a bad
        org/host/mode/window, a missing signing key, or no CURRENT ownership proof for the exact (org, host).
        ``not_after`` is clamped to the proof's expiry. Default mode is OBSERVE."""
        if self.owner_key is None:
            raise ValueError("granting monitoring authority requires the owner signing key")
        oid, h, m = _check_org_id(org_id), _check_host(host), _check_mode(mode)
        nb, na, t = float(not_before), float(not_after), float(now)
        if not (na > nb):
            raise ValueError("not_after must be strictly after not_before")
        if na - nb > _MAX_WINDOW_S:
            raise ValueError("monitoring window exceeds the maximum single-grant span")
        proof = self._ownership().proof(oid, h)
        if proof is None or not (t < proof.expires_at):
            raise ValueError(f"no current ownership proof for {h} (org {oid}) — monitoring requires proven ownership")
        na = min(na, float(proof.expires_at))
        if not (na > nb):
            raise ValueError("the ownership proof expires before the requested window starts")
        at = float(issued_at) if issued_at is not None else t
        core = {"signal": SIGNAL, "org_id": oid, "host": h, "mode": m, "not_before": nb, "not_after": na,
                "proof_sha256": proof.token_sha256, "state": "active", "issued_at": at}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"monitoring authority {m.upper()} for {h} (org {oid}) granted (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return MonitoringGrant(org_id=oid, host=h, mode=m, not_before=nb, not_after=na,
                               proof_sha256=proof.token_sha256, issued_at=at)

    def revoke(self, org_id: str, host: str) -> int:
        """Revoke a monitoring grant — the SAFE direction (honored even unsigned, fixed ``issued_at`` 0.0)."""
        oid, h = _check_org_id(org_id), _check_host(host)
        core = {"signal": SIGNAL, "org_id": oid, "host": h, "mode": "", "not_before": 0.0, "not_after": 0.0,
                "proof_sha256": "", "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"monitoring authority for {h} (org {oid}) REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def revoke_org(self, org_id: str) -> list[int]:
        """Revoke every active grant of one org (offboarding / decommission hook)."""
        oid = _check_org_id(org_id)
        return [self.revoke(oid, h) for (o, h) in sorted(self._fold()) if o == oid]

    # -- reads ----------------------------------------------------------------------------------------
    def _fold(self) -> dict:
        """{(org_id, host): row} for grants whose latest state is active. Seeds from SnapshotState (v6) then
        folds the live window; bypasses the seed (genesis scan) if the trusted anchor differs."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        if self.trusted_pubkey != snap.trusted_pubkey:
            state, issued, rows, since = {}, {}, {}, -1
        else:
            state = dict(snap.monitoring_authority_state_map())
            issued = dict(snap.monitoring_authority_issued_map())
            rows = {(r[0], r[1]): {"mode": r[2], "not_before": r[3], "not_after": r[4],
                                   "proof_sha256": (r[5] if len(r) > 5 else ""),
                                   "issued_at": issued.get((r[0], r[1]), 0.0)}
                    for r in snap.monitoring_authority_row}
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != SIGNAL:
                continue
            oid, host = p.get("org_id"), p.get("host")
            if not isinstance(oid, str) or not oid or not isinstance(host, str) or not host:
                continue
            key = (oid, host)
            st = p.get("state")
            if st == "revoked":
                state[key] = "revoked"
            elif st == "active":
                if p.get("mode") not in _MODES:
                    continue
                if not verify_signed(p, _CORE, resolver.at(r.seq)):
                    continue
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(key, NO_HIGHWATER):
                    continue
                issued[key] = at
                state[key] = "active"
                rows[key] = {"mode": p.get("mode"), "not_before": p.get("not_before"),
                             "not_after": p.get("not_after"), "proof_sha256": p.get("proof_sha256"),
                             "issued_at": at}
        return {k: row for k, row in rows.items() if state.get(k) == "active"}

    @staticmethod
    def _to_grant(key: tuple, row: dict) -> MonitoringGrant:
        return MonitoringGrant(org_id=key[0], host=key[1], mode=str(row.get("mode")),
                               not_before=float(as_issued_at(row.get("not_before"))),
                               not_after=float(as_issued_at(row.get("not_after"))),
                               proof_sha256=str(row.get("proof_sha256") or ""),
                               issued_at=float(as_issued_at(row.get("issued_at"))))

    def grant_for(self, org_id: str, host: str) -> Optional[MonitoringGrant]:
        """The current active grant record (window NOT applied), or None. Use ``active_at`` for a decision."""
        if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
            return None
        row = self._fold().get((org_id, host))
        return None if row is None else self._to_grant((org_id, host), row)

    def active_at(self, org_id: str, host: str, *, now: float) -> Optional[MonitoringGrant]:
        """The DECISION read: the grant iff active AND inside its window at ``now`` AND the exact (org, host)
        still holds a CURRENT ownership proof — the SAME proof the grant was minted against (a revoke-then-re-prove
        never revives an old grant). DEFAULT-DENY otherwise (other org, other host, revoked, expired, not yet
        valid, ownership lapsed or replaced)."""
        g = self.grant_for(org_id, host)
        if g is None or not g.covers(now) or not g.proof_sha256:
            return None
        own = self._ownership()
        if not own.has_current_proof(org_id, host, now=now):
            return None
        p = own.proof(org_id, host)
        if p is None or p.token_sha256 != g.proof_sha256:
            return None
        return g

    def grants(self, org_id: str) -> list[MonitoringGrant]:
        """Every active grant record of one org (window not applied), in host order."""
        return [self._to_grant(k, row) for k, row in sorted(self._fold().items()) if k[0] == org_id]
