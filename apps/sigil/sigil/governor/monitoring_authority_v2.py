"""AEGIS AS-2f — the SOVEREIGN record + mint path for owner-signed DEFENSIVE-MONITORING AUTHORITY **V2**.

This is the sovereign (owner-key-holding) side of the AS-2a authority-v2 contracts. It CONSUMES — never
re-codes — :mod:`vigil_core.authority_v2` (``MonitoringAuthorityV2``, ``EpochStatement``,
``MonitoringRevocationV2``, their ``sign_*`` / ``verify_*`` helpers and ``authority_publish_path``) and
:mod:`vigil_core.warden_tiers` (``classify`` / ``gate`` — the ONE authority-tier classifier of record). The
keyless AEGIS data plane (AS-2c) verifies the SAME published bytes against the pinned owner / release roots;
sovereign and data plane agree BY CONSTRUCTION because the contract lives once, in the shared integrity core.

Relationship to the v1 ``monitoring_authority.MonitoringAuthorityRegistry`` (the shipped AE-0/AE-1 record):
this module is a DISTINCT, additive v2 record. It does NOT touch the v1 registry, the v1 publish directory, or
the v1 spine signal — the whole v2 surface is gated OFF by default (``config.aegis_sovereign_v2_enabled``) so a
build with the flag off is byte-identical to before. The two can coexist during migration (AS-2c dual-accepts).

What AS-2f fixes (plan §1 defect #10, §12): a v1 grant labels its spine event ``tier="A0" decision="auto"`` —
a MACHINE-MADE authority. A monitoring grant / capability change / revocation is an **A3, explicit-required,
human-authorized** act. Here every authority mutation is CLASSIFIED through ``warden_tiers`` (``grant`` /
``revoke`` / ``respond`` are A3 danger tokens → ``gate(A3) == "explicit-required"``) and the spine event
carries the TRUE ``tier`` / ``decision`` labels, with an **intent row appended FIRST** (the recorded human
decision precedes the owner-signed mint).

Monotonicity (the "high-water mark" + "read-back" deliverables): every subject carries a per-subject monotone
EPOCH floor. Each mint READS BACK the current epoch high-water from the spine fold and mints at
``epoch = high_water + 1`` (strictly monotone), and its ``issued_at`` must be strictly above the per-subject
``issued_at`` anti-replay high-water (the DANGEROUS direction; mirrors the v1 asymmetric authn). The
``EpochStatement`` published alongside sets ``floor = max(local, statement)`` on the unit. A captured grant
can never resurrect a superseded one (a lower epoch sits below the floor and fails closed at the data plane).

Tenant origins are OUT of this slice (deferred to AS-2g): a v2 grant minted here carries NO ``origin`` /
``origin_binding_sha256`` (both absent is a valid, signable shape) and the default ``edge_chain=shared_actor``
sentinel. The ``origin_binding_sha256`` seam is where AS-2g will attach the proven binding.

Determinism: NO wallclock and NO global RNG on any signed or canonical path. The caller supplies ``now``,
``issued_at`` and the capability set; epochs come from the spine read-back; publish file names are the
content-addressed ``authority_publish_path`` hash. No LLM is in the loop (an authority decision is never a
model call — plan §9.1 doctrine "no AI on authority paths").

FATAL-2: SOVEREIGN-only (``assert_no_offense``). Imports only ``vigil_core`` (safe on both planes), sibling
governor modules and stdlib — no ``framework`` / ``strix``.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.authority_v2 import (  # noqa: E402  — the AS-2a contracts, consumed not re-coded
    AuthoritySubject,
    EpochStatement,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    MonitoringRevocationV2,
    SignedEpochStatement,
    SignedMonitoringAuthorityV2,
    SignedMonitoringRevocationV2,
    SubjectKind,
    authority_publish_path,
    sign_epoch_statement,
    sign_monitoring_authority_v2,
    sign_monitoring_revocation_v2,
    verify_monitoring_authority_v2,
)
from vigil_core.warden_tiers import classify, gate  # noqa: E402  — the ONE authority-tier classifier

from .asset_ownership import AssetOwnershipRegistry, _check_host, _check_org_id  # noqa: E402
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# The v2 spine signals — DISTINCT from the v1 ``governor.monitoring_authority`` signal so a v1 record can never
# be folded as a v2 record or vice versa (the fold skips any payload whose ``signal`` is not exactly ours).
SIGNAL_V2 = "governor.monitoring_authority_v2"
SIGNAL_V2_INTENT = "governor.monitoring_authority_v2.intent"
SIGNAL_V2_EPOCH = "governor.monitoring_authority_v2.epoch"

# The authenticated core of a v2 grant spine record (the fields the fold re-verifies the owner signature over).
_CORE = ("signal", "kind", "org_id", "host", "state", "capabilities", "epoch", "not_before", "not_after",
         "lease_not_before", "lease_not_after", "instance_id", "replica_index", "edge_chain", "proof_sha256",
         "issued_at")
# The authenticated core of a v2 revocation / epoch-statement spine record.
_CORE_REVOKE = ("signal", "kind", "org_id", "host", "state", "epoch", "issued_at")
_CORE_EPOCH = ("signal", "kind", "org_id", "host", "epoch", "issued_at")

STATE_ACTIVE = "active"
STATE_REVOKED = "revoked"

# The authority-tier labels, computed ONCE through the shared classifier so sovereign and kernel never drift:
# ``grant`` / ``revoke`` are A3 danger tokens, so every v2 authority mutation is A3 / explicit-required (the
# fix for the A0/auto mislabel). Captured here as module constants so a label can never silently regress to A0.
TIER_GRANT = classify("monitoring.grant")       # -> Tier.A3
TIER_REVOKE = classify("monitoring.revoke")     # -> Tier.A3
DECISION_GRANT = gate(TIER_GRANT)               # -> "explicit-required"
DECISION_REVOKE = gate(TIER_REVOKE)             # -> "explicit-required"

_LOAD_FROM_VAULT = object()


def v2_subject(org_id: str, host: str) -> AuthoritySubject:
    """The validated (kind=host, org_id, host) subject every v2 record binds. Fail-closed on a bad org/host via
    the SAME ``asset_ownership`` checks the v1 path uses, plus the contract's own hostname validator."""
    return AuthoritySubject(kind=SubjectKind.HOST, org_id=_check_org_id(org_id), host=_check_host(host))


def _dt(ts: float) -> datetime:
    """A tz-aware UTC datetime from a caller-supplied epoch-seconds float (the contracts carry datetimes)."""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc)


@dataclass(frozen=True)
class MonitoringGrantV2View:
    """The sovereign read view of the latest active v2 grant for a subject (window NOT applied; use
    :meth:`MonitoringAuthorityV2Registry.active_at` for a decision)."""

    org_id: str
    host: str
    capabilities: tuple[MonitoringCapability, ...]
    epoch: int
    not_before: float
    not_after: float
    lease_not_before: float
    lease_not_after: float
    instance_id: str
    replica_index: int
    edge_chain: str
    proof_sha256: str
    issued_at: float

    def covers(self, now: float) -> bool:
        return self.not_before <= float(now) < self.not_after


def _cap_values(caps) -> list[str]:
    """A sorted, de-duplicated list of capability VALUES (strings) for the canonical spine core — the SAME
    normalization the contract applies, so the signed spine record and the published grant agree byte-for-byte."""
    out = {MonitoringCapability(c).value if not isinstance(c, MonitoringCapability) else c.value for c in caps}
    return sorted(out)


class MonitoringAuthorityV2Registry:
    """The sovereign spine-of-record for v2 monitoring authority. Folds the append-only spine into per-subject
    (state, epoch high-water, issued_at high-water, active row); mints owner-signed grants / revocations /
    epoch statements with a strictly-monotone epoch; publishes the keyless-verifiable bytes atomically; and
    reads them back. Holds the owner key (sovereign side) — the data plane holds none."""

    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None,
                 publish_dir: Optional[str] = None):
        self.store = store
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        self._publish_dir = publish_dir

    def _ownership(self) -> AssetOwnershipRegistry:
        return AssetOwnershipRegistry(self.store, owner_key=None, trusted_pubkey=self.trusted_pubkey)

    def publish_dir(self) -> str:
        if self._publish_dir is not None:
            return self._publish_dir
        from .. import config
        return str(config.monitoring_v2_publish_dir())

    # -- fold -----------------------------------------------------------------------------------------
    def _seed(self, snap) -> "tuple[dict, int]":
        """The HARD-PRUNE SEED (``SnapshotState`` v13): the folded per-(org,host) ``{state, epoch_hw, issued_hw,
        row}`` of the pruned prefix, or the empty genesis start when the trusted anchor differs from the
        snapshot's. The epoch map is a SUPERSET of the state/row keys (a revoked or epoch-statement-only subject
        still carries its monotone epoch high-water), so a pruned subject's next grant STILL mints strictly above
        it — without this, the first hard prune would reset ``epoch_hw`` to 0 / ``issued_hw`` to ``-inf`` and the
        next grant would mint a DUPLICATE epoch (a captured old grant no longer detectably stale) while a
        still-published grant goes split-brain. Mirrors the v1 ``monitoring_authority._seed`` (the SAME
        ``seed_applies`` rule)."""
        from ..spine.snapshot import seed_applies
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return {}, -1
        st_map = snap.monitoring_authority_v2_state_map()
        iss_map = snap.monitoring_authority_v2_issued_map()
        ep_map = snap.monitoring_authority_v2_epoch_map()
        rows = {(r[0], r[1]): r for r in snap.monitoring_authority_v2_row}
        out: dict = {}
        for key in set(st_map) | set(iss_map) | set(ep_map) | set(rows):
            state = st_map.get(key)
            row = rows.get(key)
            out[key] = {"state": state, "epoch_hw": int(ep_map.get(key, 0)),
                        "issued_hw": float(iss_map.get(key, NO_HIGHWATER)),
                        "row": self._seed_row(row) if (state == STATE_ACTIVE and row is not None) else None}
        return out, snap.base_seq - 1

    @staticmethod
    def _seed_row(row) -> dict:
        """Reconstruct the active-grant row dict (the shape ``dict(p)`` carried in the live fold) from a snapshot
        row ``[org_id, host, capabilities, epoch, not_before, not_after, lease_not_before, lease_not_after,
        instance_id, replica_index, edge_chain, proof_sha256, issued_at]`` — exactly the keys ``_to_view`` reads."""
        return {"org_id": row[0], "host": row[1], "capabilities": row[2], "epoch": row[3],
                "not_before": row[4], "not_after": row[5], "lease_not_before": row[6], "lease_not_after": row[7],
                "instance_id": row[8], "replica_index": row[9], "edge_chain": row[10], "proof_sha256": row[11],
                "issued_at": row[12]}

    def _fold(self) -> dict:
        """{(org_id, host): dict} over the spine, SEEDED from the hard-prune snapshot (v13) then folded forward
        over the LIVE window only (``fold(seed, live)`` — every sub-state is associative: LWW state, max epoch/
        issued high-water). Each subject's dict carries ``state`` (active|revoked), the epoch high-water
        ``epoch_hw`` (max epoch seen across grant/revoke/epoch records — the read-back floor), the ``issued_hw``
        anti-replay high-water, and (when active) the latest active ``row``.

        Order-sensitive exactly like the v1 fold: a REVOKED record latches state=revoked; an ACTIVE record is
        honoured only if owner-signed AND its ``issued_at`` is strictly above the subject's issued high-water
        (the DANGEROUS direction — a replayed/old active can never resurrect a superseded grant). Every record's
        epoch advances ``epoch_hw`` so the next mint reads back a strictly-higher floor. Each live record is
        verified under the owner key valid AT ITS SEQ (``key_history`` succession) — byte-identical to the single
        ``trusted_pubkey`` verify for an un-rotated spine, and correct across a rotation on a pruned spine."""
        from . import key_history as _kh
        from ..spine.snapshot import SnapshotState
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        out, since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            p = getattr(r, "payload", None)
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig not in (SIGNAL_V2, SIGNAL_V2_INTENT, SIGNAL_V2_EPOCH):
                continue
            oid, host = p.get("org_id"), p.get("host")
            if not isinstance(oid, str) or not oid or not isinstance(host, str) or not host:
                continue
            key = (oid, host)
            st = out.setdefault(key, {"state": None, "epoch_hw": 0, "issued_hw": NO_HIGHWATER, "row": None})
            # The intent row is an audit marker only — it advances nothing and never sets state.
            if sig == SIGNAL_V2_INTENT:
                continue
            vpk = resolver.at(r.seq)
            ep = p.get("epoch")
            ep_i = int(ep) if isinstance(ep, int) and not isinstance(ep, bool) and ep >= 1 else 0
            if sig == SIGNAL_V2_EPOCH:
                if verify_signed(p, _CORE_EPOCH, vpk) and ep_i > st["epoch_hw"]:
                    st["epoch_hw"] = ep_i
                continue
            # SIGNAL_V2 grant / revoke
            state = p.get("state")
            if state == STATE_REVOKED:
                if verify_signed(p, _CORE_REVOKE, vpk):
                    st["state"] = STATE_REVOKED
                    st["row"] = None
                    if ep_i > st["epoch_hw"]:
                        st["epoch_hw"] = ep_i
                continue
            if state == STATE_ACTIVE:
                if _cap_values(p.get("capabilities") or []) == [] or not verify_signed(p, _CORE, vpk):
                    continue
                at = as_issued_at(p.get("issued_at"))
                if at <= st["issued_hw"]:
                    continue
                st["issued_hw"] = at
                st["state"] = STATE_ACTIVE
                st["row"] = dict(p)
                if ep_i > st["epoch_hw"]:
                    st["epoch_hw"] = ep_i
        return out

    def _subject_state(self, org_id: str, host: str) -> dict:
        if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
            return {"state": None, "epoch_hw": 0, "issued_hw": NO_HIGHWATER, "row": None}
        return self._fold().get((org_id, host), {"state": None, "epoch_hw": 0, "issued_hw": NO_HIGHWATER,
                                                 "row": None})

    def epoch_highwater(self, org_id: str, host: str) -> int:
        """The current per-subject monotone epoch floor read back from the spine (0 if no v2 record exists).
        The next mint uses ``epoch_highwater + 1`` — strictly monotone, so a captured lower-epoch grant is
        detectably STALE at the data plane (``floor = max(local, EpochStatement)``)."""
        return int(self._subject_state(org_id, host)["epoch_hw"])

    def issued_highwater(self, org_id: str, host: str) -> float:
        """The per-subject ``issued_at`` anti-replay high-water (``-inf`` if none). A grant mint must carry an
        ``issued_at`` STRICTLY above this (the DANGEROUS direction); used to SEED a fresh provisioner's
        ``_last_issued`` so a per-request provisioner never mints below the spine's existing high-water."""
        return float(self._subject_state(org_id, host)["issued_hw"])

    @staticmethod
    def _to_view(key: tuple, row: dict) -> MonitoringGrantV2View:
        caps = tuple(MonitoringCapability(c) for c in _cap_values(row.get("capabilities") or []))
        return MonitoringGrantV2View(
            org_id=key[0], host=key[1], capabilities=caps, epoch=int(row.get("epoch") or 0),
            not_before=as_issued_at(row.get("not_before")), not_after=as_issued_at(row.get("not_after")),
            lease_not_before=as_issued_at(row.get("lease_not_before")),
            lease_not_after=as_issued_at(row.get("lease_not_after")),
            instance_id=str(row.get("instance_id") or ""), replica_index=int(row.get("replica_index") or 0),
            edge_chain=str(row.get("edge_chain") or "shared_actor"),
            proof_sha256=str(row.get("proof_sha256") or ""), issued_at=as_issued_at(row.get("issued_at")))

    def grant_for(self, org_id: str, host: str) -> Optional[MonitoringGrantV2View]:
        """The current active v2 grant view (window NOT applied), or None (never granted / revoked / superseded)."""
        st = self._subject_state(org_id, host)
        if st["state"] != STATE_ACTIVE or st["row"] is None:
            return None
        return self._to_view((org_id, host), st["row"])

    def active_at(self, org_id: str, host: str, *, now: float) -> Optional[MonitoringGrantV2View]:
        """The DECISION read: the grant iff active AND inside its window at ``now`` AND the exact (org, host)
        still holds the SAME current ownership proof it was minted against (a revoke-then-re-prove never revives
        it). DEFAULT-DENY otherwise. Mirrors the v1 ``active_at`` ownership re-check."""
        g = self.grant_for(org_id, host)
        if g is None or not g.covers(now):
            return None
        if not g.proof_sha256:
            return None
        own = self._ownership()
        if not own.has_current_proof(org_id, host, now=now):
            return None
        p = own.proof(org_id, host)
        return g if (p is not None and p.token_sha256 == g.proof_sha256) else None

    def grants(self, org_id: str) -> list[MonitoringGrantV2View]:
        """Every active v2 grant view of one org (window not applied), in host order."""
        folded = self._fold()
        return [self._to_view(k, v["row"]) for k, v in sorted(folded.items())
                if k[0] == org_id and v["state"] == STATE_ACTIVE and v["row"] is not None]

    # -- intent (the recorded human decision, appended FIRST) -----------------------------------------
    def record_intent(self, *, requester: str, org_id: str, host: str, capabilities, now: float,
                      issued_at: float, step_up_at: float = 0.0, note: str = "") -> int:
        """Append the INTENT row BEFORE any owner-signed mint: the explicit, human-authorized decision to
        change authority. A3 / explicit-required labels. Returns the spine seq. A mint without a preceding
        intent row for the same (requester, subject, epoch window) is an auditable anomaly."""
        caps = _cap_values(capabilities)
        core = {"signal": SIGNAL_V2_INTENT, "kind": SubjectKind.HOST.value, "org_id": _check_org_id(org_id),
                "host": _check_host(host), "requester": str(requester), "capabilities": caps,
                "now": float(now), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key),
                   "by": "owner", "requested_by": str(requester),
                   "tier": TIER_GRANT.label, "decision": DECISION_GRANT,
                   "step_up_at": float(step_up_at),
                   "reason": note or (f"INTENT: authorize monitoring {'+'.join(caps)} for {host} "
                                      f"(org {org_id}) requested by {requester}")}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- owner mutations ------------------------------------------------------------------------------
    def grant(self, org_id: str, host: str, *, capabilities, not_before: float, not_after: float,
              lease_not_before: float, lease_not_after: float, instance_id: str, now: float, issued_at: float,
              replica_index: int = 0, edge_chain: str = "shared_actor",
              origin: "Optional[object]" = None, origin_binding_sha256: "Optional[str]" = None
              ) -> tuple[MonitoringGrantV2View, SignedMonitoringAuthorityV2]:
        """Owner-sign + RETURN the publishable v2 grant (the DANGEROUS direction) and record it on the spine.

        Fail-closed ``ValueError`` on a bad subject/capabilities/window, a missing key, or no CURRENT ownership
        proof for the exact (org, host). ``not_after`` is clamped to the proof's owner-signed expiry (monitoring
        never outlives proven ownership). The epoch is read back from the spine and minted at ``high_water + 1``
        (strictly monotone). ``issued_at`` must be strictly above the subject's issued high-water.

        AS-2g binding seam: ``origin`` (an :class:`vigil_core.authority_v2.OriginTuple`) + ``origin_binding_sha256``
        (the sha256 of the published :class:`vigil_core.aegis_origin_binding.AegisOriginBinding`) are BOTH None by
        default — an unbound grant, byte-identical to the AS-2f shape. When supplied (both together; the contract
        refuses one without the other) the grant is BOUND to that published binding, and ``edge_chain`` names the
        declared edge. The caller (``monitoring_binding.bind_and_publish``) owner-signs + publishes the binding
        FIRST, then passes its digest here. The caller publishes + reads back the returned signed grant."""
        if self.owner_key is None:
            raise ValueError("granting monitoring authority v2 requires the owner signing key")
        subject = v2_subject(org_id, host)
        oid, h = subject.org_id, subject.host
        nb, na, t, at = float(not_before), float(not_after), float(now), float(issued_at)
        caps = [MonitoringCapability(c) for c in _cap_values(capabilities)]
        if not caps:
            raise ValueError("a v2 grant must carry at least one capability")
        if not (na > nb):
            raise ValueError("not_after must be strictly after not_before")
        proof = self._ownership().proof(oid, h)
        if proof is None or not (t < proof.expires_at):
            raise ValueError(f"no current ownership proof for {h} (org {oid}) — monitoring requires proven ownership")
        na = min(na, float(proof.expires_at))
        if not (na > nb):
            raise ValueError("the ownership proof expires before the requested window starts")
        # The lease is the TIGHT bound — clamp it inside the (possibly proof-clamped) grant window.
        lnb, lna = max(float(lease_not_before), nb), min(float(lease_not_after), na)
        if not (lna > lnb):
            raise ValueError("the lease window is empty after clamping to the grant window")
        st = self._subject_state(oid, h)
        if at <= float(st["issued_hw"]):
            raise ValueError("issued_at must be strictly above the subject's anti-replay high-water")
        epoch = int(st["epoch_hw"]) + 1                      # READ-BACK high-water -> strictly monotone
        # Build the contract document (its own validators re-enforce determinism, pairing and windows).
        doc = MonitoringAuthorityV2(
            subject=subject, capabilities=caps, epoch=epoch, not_before=_dt(nb), not_after=_dt(na),
            lease=MonitoringLease(not_before=_dt(lnb), not_after=_dt(lna)),
            instance_id=instance_id, replica_index=int(replica_index), edge_chain=edge_chain,
            origin=origin, origin_binding_sha256=origin_binding_sha256,   # AS-2g: None/None = unbound (default)
            issued_at=at, issued_by="owner")
        signed = sign_monitoring_authority_v2(doc, {"owner": self.owner_key.private_key_b64})
        # The sovereign spine-of-record: owner-signed core the fold re-verifies, with the TRUE A3 labels.
        core = {"signal": SIGNAL_V2, "kind": subject.kind.value, "org_id": oid, "host": h, "state": STATE_ACTIVE,
                "capabilities": _cap_values(caps), "epoch": epoch, "not_before": nb, "not_after": na,
                "lease_not_before": lnb, "lease_not_after": lna, "instance_id": str(instance_id),
                "replica_index": int(replica_index), "edge_chain": edge_chain,
                "proof_sha256": proof.token_sha256, "issued_at": at}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": TIER_GRANT.label, "decision": DECISION_GRANT,
                   "reason": f"monitoring authority v2 {'+'.join(c.value for c in caps)} for {h} (org {oid}) "
                             f"granted at epoch {epoch} (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return self._to_view((oid, h), core), signed

    def issue_epoch_statement(self, org_id: str, host: str, *, epoch: int, issued_at: float
                              ) -> SignedEpochStatement:
        """Owner-sign + RETURN the publishable ``EpochStatement`` that sets the unit's ``floor = max(local,
        statement)`` for the subject at ``epoch`` (the reconciler, §4.4). Records it on the spine so the fold's
        epoch high-water includes it. The caller publishes the returned statement alongside the grant."""
        if self.owner_key is None:
            raise ValueError("issuing an epoch statement requires the owner signing key")
        subject = v2_subject(org_id, host)
        if not (isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 1):
            raise ValueError("epoch must be a positive integer")
        stmt = EpochStatement(subject=subject, epoch=int(epoch), issued_at=float(issued_at), note="")
        signed = sign_epoch_statement(stmt, {"owner": self.owner_key.private_key_b64})
        core = {"signal": SIGNAL_V2_EPOCH, "kind": subject.kind.value, "org_id": subject.org_id,
                "host": subject.host, "epoch": int(epoch), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": TIER_GRANT.label, "decision": DECISION_GRANT,
                   "reason": f"epoch statement floor {epoch} for {subject.host} (org {subject.org_id})"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return signed

    def revoke(self, org_id: str, host: str, *, issued_at: float, reason: str = ""
               ) -> tuple[int, SignedMonitoringRevocationV2]:
        """Owner-sign + RETURN the publishable v2 revocation and record it on the spine. The revocation epoch is
        minted at ``epoch_highwater + 1`` so it supersedes the live grant (``revocation.epoch >= grant.epoch``)
        AND advances the floor, so a subsequent grant mints above it and is not self-revoked. A3 labels. Returns
        (spine seq, signed revocation). Unpublishing the grant bytes is the caller's job (so the keyless gateway
        stops seeing it)."""
        subject = v2_subject(org_id, host)
        epoch = self.epoch_highwater(subject.org_id, subject.host) + 1
        rev = MonitoringRevocationV2(subject=subject, epoch=epoch, issued_at=float(issued_at), reason=reason)
        signed = sign_monitoring_revocation_v2(rev, {"owner": self.owner_key.private_key_b64}) \
            if self.owner_key is not None else None
        core = {"signal": SIGNAL_V2, "kind": subject.kind.value, "org_id": subject.org_id, "host": subject.host,
                "state": STATE_REVOKED, "epoch": epoch, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": TIER_REVOKE.label, "decision": DECISION_REVOKE,
                   "reason": reason or f"monitoring authority v2 for {subject.host} (org {subject.org_id}) "
                                       f"REVOKED at epoch {epoch} (governed latch)"}
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return seq, signed

    # -- publish + read-back --------------------------------------------------------------------------
    def publish(self, signed: SignedMonitoringAuthorityV2) -> Path:
        """Atomically publish the signed v2 grant for the keyless gateway at its content-addressed
        ``authority_publish_path`` (0700 dir, 0600 temp, fsync, rename). Returns the final path."""
        doc = signed.document
        name = authority_publish_path(doc.subject, instance_id=doc.instance_id, replica_index=doc.replica_index)
        return _atomic_publish(self.publish_dir(), name, signed.model_dump_json().encode("utf-8"))

    def publish_epoch_statement(self, signed: SignedEpochStatement) -> Path:
        """Atomically publish the signed epoch statement alongside the grant (``.epoch.json`` suffix on the
        subject's content-addressed path so it never collides with the grant file)."""
        doc = signed.document
        base = authority_publish_path(doc.subject, instance_id="epoch", replica_index=0)
        name = base[: -len(".json")] + ".epoch.json"
        return _atomic_publish(self.publish_dir(), name, signed.model_dump_json().encode("utf-8"))

    def unpublish(self, org_id: str, host: str, *, instance_id: str, replica_index: int = 0) -> bool:
        """Delete the published grant bytes so the keyless gateway stops seeing it. Idempotent."""
        subject = v2_subject(org_id, host)
        name = authority_publish_path(subject, instance_id=instance_id, replica_index=replica_index)
        try:
            (Path(self.publish_dir()) / name).unlink()
            return True
        except FileNotFoundError:
            return False

    def read_back(self, signed: SignedMonitoringAuthorityV2, trust_root) -> SignedMonitoringAuthorityV2:
        """Re-read the just-published bytes from disk, re-parse them, and VERIFY them against ``trust_root``
        (the owner root). Fail-closed ``ValueError`` if the file is missing, unparseable, does not verify, or
        does not round-trip to the same subject/epoch/capabilities. This is the AS-2f "read-back" guarantee —
        the mint path never reports success for an artifact the keyless plane could not verify."""
        doc = signed.document
        name = authority_publish_path(doc.subject, instance_id=doc.instance_id, replica_index=doc.replica_index)
        p = Path(self.publish_dir()) / name
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError as e:
            raise ValueError(f"read-back failed: published v2 grant unreadable at {p}: {e}") from e
        back = SignedMonitoringAuthorityV2.model_validate_json(raw)
        ok, why = verify_monitoring_authority_v2(back, trust_root)
        if not ok:
            raise ValueError(f"read-back failed: published v2 grant does not verify: {why}")
        b = back.document
        if (b.subject != doc.subject or b.epoch != doc.epoch
                or [c.value for c in b.capabilities] != [c.value for c in doc.capabilities]):
            raise ValueError("read-back failed: published v2 grant does not round-trip to the minted document")
        return back


def _atomic_publish(base: str, name: str, data: bytes) -> Path:
    """Atomically publish public signed bytes: 0700 dir, 0600 temp in the same dir, fsync, rename. Mirrors the
    v1 ``provision._publish_monitoring`` writer (same durability contract; kept here in the sovereign layer)."""
    d = Path(base)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    final = d / name
    tmp = d / (".tmp-" + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return final
