"""AEGIS AS-2g — the SOVEREIGN origin BINDING + PUBLISH step of the monitoring authority.

The publish side of AS-2f. AS-2f (:mod:`monitoring_authority_v2`) mints an owner-signed v2 grant but leaves the
tenant origin OUT (``origin=None`` — its explicit AS-2g seam). AS-2g attaches the proven binding: it owner-signs
and PUBLISHES a per-subject :class:`vigil_core.aegis_origin_binding.AegisOriginBinding` — the artifact the
per-tenant defence (the AS-2d broker's Z3 prover) reads — and mints the grant BOUND to it (the grant carries the
binding's sha256). Both land in the keyless-verifiable publish tree; the data plane cross-checks them before it
arms a forward target (:func:`vigil_core.aegis_origin_binding.grant_binds_origin`).

Wire, don't rebuild (plan §9.1 rule 10). The binding CONTRACT lives once in the shared integrity core
(:mod:`vigil_core.aegis_origin_binding`); the SEALING of the origin-lock secret is AS-2h
(:mod:`vigil_core.aegis_sealing`); the atomic publish + read-back machinery is the AS-2f registry's. This module
only COMPOSES them into the bind+publish step and its read-back + fail-closed revert, and reads the published
state back for the custui Monitoring surface.

PUBLIC-REPO SAFE. The published binding carries NO plaintext secret: its ``origin_secret_sha256`` field is
:func:`origin_secret_commitment` — a DETERMINISTIC domain-separated HMAC-SHA256 (a keyed PRF, AS-2h
:func:`vigil_core.aegis_sealing.secret_mac`) keyed by the origin-lock secret. It reveals nothing about the
secret and carries no plaintext; it is NOT a sha256 of the sealed ciphertext (the at-rest AEAD seal uses a
random nonce and is not reproducible). The data plane matches by recomputing the SAME keyed PRF from the
delivered secret.

Determinism: every time / epoch / commitment is a caller-supplied value; signing is Ed25519 over canonical bytes
(no wall-clock, no RNG on a signed path). Publish is SUPERSEDE (content-addressed path, atomic replace), never an
in-place edit; the append-only spine records every bind. Fail-closed throughout: a missing key, an unbound /
non-matching commitment, or a publish/read-back fault raises and the caller reverts — a bound grant is never left
active without a verifiable published binding.

FATAL-2: SOVEREIGN-only (``assert_no_offense``). Imports only ``vigil_core`` (safe on both planes), sibling
governor modules and stdlib — no ``framework`` / ``strix``.
"""
from __future__ import annotations

from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.aegis_origin_binding import (  # noqa: E402  — the AS-2g contract, consumed not re-coded
    AegisOriginBinding,
    SignedAegisOriginBinding,
    grant_binds_origin,
    origin_binding_digest,
    origin_binding_publish_path,
    sign_aegis_origin_binding,
    verify_aegis_origin_binding,
)
from vigil_core.aegis_sealing import SecretKind, secret_mac  # noqa: E402
from vigil_core.authority_v2 import (  # noqa: E402
    OriginTuple,
    SignedMonitoringAuthorityV2,
    authority_publish_path,
    verify_monitoring_authority_v2,
)

from .authn import signed_payload  # noqa: E402
from .monitoring_authority_v2 import (  # noqa: E402
    DECISION_GRANT,
    TIER_GRANT,
    MonitoringAuthorityV2Registry,
    _atomic_publish,
    v2_subject,
)

# The AS-2g binding spine signal — DISTINCT from the v2 grant / epoch signals so a binding record can never be
# folded as a grant or vice-versa. It is an APPEND-ONLY audit/intent record of the mint; the authoritative
# artifact the data plane reads is the PUBLISHED binding file.
SIGNAL_V2_BINDING = "governor.aegis_origin_binding"

# The authenticated core of a binding spine record (the fields the owner signs over).
_CORE_BINDING = ("signal", "kind", "org_id", "host", "origin_scheme", "origin_host", "origin_port",
                 "edge_chain", "origin_secret_sha256", "binding_sha256", "epoch", "issued_at")


# The fixed label the origin-lock commitment is a MAC over — a domain separator inside the keyed PRF so a tag
# minted for the binding commitment can never be confused with a report/edge MAC under the same secret.
_COMMITMENT_LABEL = b"aegis-origin-binding-commitment/v1"


def origin_secret_commitment(org_id: str, host: str, epoch: int, secret: bytes) -> str:
    """The DETERMINISTIC ``origin_secret_sha256`` commitment the binding carries: a domain-separated HMAC-SHA256
    (AS-2h :func:`vigil_core.aegis_sealing.secret_mac`) over a fixed label, keyed by the origin-lock ``secret``
    and bound to ``(kind=aegis-origin, org, host, epoch)``. It is a PRF output — it reveals NOTHING about the
    secret (public-repo safe) and carries no plaintext — yet it is deterministic (no RNG, unlike the at-rest
    AEAD seal), so the sovereign and the data plane (which holds the DELIVERED secret) compute the BYTE-IDENTICAL
    commitment and the plane can match its secret to the published binding. 64 hex chars."""
    return secret_mac(secret, SecretKind.ORIGIN, org_id, host, int(epoch), _COMMITMENT_LABEL).hex()


def build_origin_binding(reg: MonitoringAuthorityV2Registry, org_id: str, host: str, *, origin_host: str,
                         origin_port: int, edge_chain: str, origin_secret_sha256: str, epoch: int,
                         issued_at: float) -> "tuple[SignedAegisOriginBinding, str]":
    """Owner-sign the per-subject origin binding and RETURN ``(signed, digest)``. The ``digest`` is the
    ``origin_binding_sha256`` the bound grant must carry. Fail-closed ``ValueError`` on a missing owner key or an
    invalid subject / origin / commitment / epoch (the contract's own validators re-enforce determinism + shape).
    HTTPS only (the contract refuses any other scheme and every IP-literal origin)."""
    if reg.owner_key is None:
        raise ValueError("binding a monitoring origin requires the owner signing key")
    subject = v2_subject(org_id, host)
    origin = OriginTuple(scheme="https", host=origin_host, port=int(origin_port))
    doc = AegisOriginBinding(subject=subject, origin=origin, edge_chain=edge_chain,
                             origin_secret_sha256=origin_secret_sha256, epoch=int(epoch),
                             issued_at=float(issued_at), issued_by="owner")
    signed = sign_aegis_origin_binding(doc, {"owner": reg.owner_key.private_key_b64})
    return signed, origin_binding_digest(signed)


def record_binding(reg: MonitoringAuthorityV2Registry, signed: SignedAegisOriginBinding, *,
                   requested_by: str = "owner") -> int:
    """Append the owner-signed binding to the APPEND-ONLY spine (the A3, explicit-required audit trail of the
    bind — same tier labels as a grant). Returns the spine seq. The published file is the authoritative artifact;
    this row is the tamper-evident record that the bind happened."""
    doc = signed.document
    digest = origin_binding_digest(signed)
    core = {"signal": SIGNAL_V2_BINDING, "kind": doc.subject.kind.value, "org_id": doc.subject.org_id,
            "host": doc.subject.host, "origin_scheme": doc.origin.scheme, "origin_host": doc.origin.host,
            "origin_port": int(doc.origin.port), "edge_chain": doc.edge_chain,
            "origin_secret_sha256": doc.origin_secret_sha256, "binding_sha256": digest, "epoch": int(doc.epoch),
            "issued_at": float(doc.issued_at)}
    payload = {**signed_payload(core, reg.owner_key), "by": "owner", "requested_by": str(requested_by),
               "tier": TIER_GRANT.label, "decision": DECISION_GRANT,
               "reason": f"origin binding for {doc.subject.host} (org {doc.subject.org_id}) -> "
                         f"{doc.origin.host}:{doc.origin.port} at epoch {doc.epoch} (owner-signed)"}
    return reg.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def publish_binding(reg: MonitoringAuthorityV2Registry, signed: SignedAegisOriginBinding) -> Path:
    """Atomically publish the signed origin binding for the keyless data plane at its content-addressed
    ``origin_binding_publish_path`` (0700 dir, 0600 temp, fsync, rename — the AS-2f writer). Returns the path."""
    name = origin_binding_publish_path(signed.document.subject)
    return _atomic_publish(reg.publish_dir(), name, signed.model_dump_json().encode("utf-8"))


def unpublish_binding(reg: MonitoringAuthorityV2Registry, org_id: str, host: str) -> bool:
    """Delete the published binding bytes so the keyless data plane stops seeing it. Idempotent."""
    subject = v2_subject(org_id, host)
    name = origin_binding_publish_path(subject)
    try:
        (Path(reg.publish_dir()) / name).unlink()
        return True
    except FileNotFoundError:
        return False


def read_back_binding(reg: MonitoringAuthorityV2Registry, signed: SignedAegisOriginBinding,
                      trust_root) -> SignedAegisOriginBinding:
    """Re-read the just-published binding from disk, re-parse it, and VERIFY it against ``trust_root`` (the owner
    root). Fail-closed ``ValueError`` if the file is missing, unparseable, does not verify, or does not round-trip
    to the same document. The AS-2g read-back guarantee: the bind path never reports success for a binding the
    keyless plane could not verify."""
    name = origin_binding_publish_path(signed.document.subject)
    p = Path(reg.publish_dir()) / name
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"read-back failed: published origin binding unreadable at {p}: {e}") from e
    back = SignedAegisOriginBinding.model_validate_json(raw)
    ok, why = verify_aegis_origin_binding(back, trust_root)
    if not ok:
        raise ValueError(f"read-back failed: published origin binding does not verify: {why}")
    if back.document != signed.document:
        raise ValueError("read-back failed: published origin binding does not round-trip to the minted document")
    return back


def bind_and_publish(reg: MonitoringAuthorityV2Registry, org_id: str, host: str, *, origin_host: str,
                     origin_port: int, edge_chain: str, origin_secret_sha256: str, capabilities,
                     not_before: float, not_after: float, lease_not_before: float, lease_not_after: float,
                     instance_id: str, now: float, issued_at: float, binding_issued_at: float,
                     trust_root, replica_index: int = 0, requested_by: str = "owner") -> dict:
    """The AS-2g bind+publish step: owner-sign + PUBLISH the origin binding, mint the grant BOUND to it, publish
    the grant + its epoch statement, and READ BACK every published artifact — fail-closed with a full revert.

    Order (fail-closed): read back the grant epoch floor -> build + sign the binding AT that epoch -> publish the
    binding -> mint the grant with ``origin`` + the binding digest (``grant`` reads the SAME epoch back, so grant
    and binding share one epoch) -> publish the grant + epoch statement -> read back grant AND binding (each must
    verify against the owner root) -> record the bind on the append-only spine. ANY failure after the grant is
    minted triggers a revert: owner-sign a revocation (the SAFE direction) and unpublish BOTH files, so a bound
    grant is never left active without its verifiable binding. Returns a secret-free summary dict.

    Determinism: caller supplies ``now`` / ``issued_at`` / ``binding_issued_at`` / the commitment; no wall-clock,
    no RNG on a signed path. Raises ``ValueError`` (nothing published) or re-raises the publish fault after revert.
    """
    if reg.owner_key is None:
        raise ValueError("binding + publishing a monitoring origin requires the owner signing key")
    # The binding is minted at the epoch the grant will mint at — epoch_highwater + 1 (strictly monotone). We hold
    # the caller's lock, and neither the binding append nor the grant's intent row advances the v2 epoch fold, so
    # the grant's own read-back lands on this exact epoch.
    epoch = reg.epoch_highwater(org_id, host) + 1
    signed_binding, digest = build_origin_binding(
        reg, org_id, host, origin_host=origin_host, origin_port=int(origin_port), edge_chain=edge_chain,
        origin_secret_sha256=origin_secret_sha256, epoch=epoch, issued_at=float(binding_issued_at))
    origin = signed_binding.document.origin
    binding_path = publish_binding(reg, signed_binding)
    # Mint the BOUND grant. A ValueError here means nothing of the grant was published yet; unpublish the binding
    # we just wrote (it would otherwise dangle with no grant) and surface the refusal.
    try:
        view, signed_grant = reg.grant(
            org_id, host, capabilities=capabilities, not_before=float(not_before), not_after=float(not_after),
            lease_not_before=float(lease_not_before), lease_not_after=float(lease_not_after),
            instance_id=instance_id, now=float(now), issued_at=float(issued_at), replica_index=int(replica_index),
            edge_chain=edge_chain, origin=origin, origin_binding_sha256=digest)
    except ValueError:
        unpublish_binding(reg, org_id, host)
        raise
    if view.epoch != epoch:                       # defence in depth: the grant must land on the binding's epoch
        unpublish_binding(reg, org_id, host)
        raise ValueError(f"bind/grant epoch skew: binding at {epoch}, grant at {view.epoch}")
    try:
        grant_path = reg.publish(signed_grant)
        stmt = reg.issue_epoch_statement(org_id, host, epoch=view.epoch, issued_at=float(issued_at) + 1e-6)
        reg.publish_epoch_statement(stmt)
        root = trust_root
        reg.read_back(signed_grant, root)
        read_back_binding(reg, signed_binding, root)
        record_binding(reg, signed_binding, requested_by=requested_by)
    except Exception as e:   # noqa: BLE001 — never leave a bound-but-unpublished/unverifiable grant
        # Revert DATA-PLANE-FIRST and FAULT-TOLERANTLY. The two PUBLISHED files (grant + binding) are what arm
        # the keyless data plane — grant_binds_origin cross-checks THEM and never consults the spine revocation —
        # so they must come down FIRST, and a fault reverting one must NOT skip the others. A correlated I/O fault
        # (e.g. disk-full / transient IO) can hit both the original write and a revert step; if the spine revoke
        # ran first and raised, the two published files would be stranded on disk still cross-checking as `bound`
        # (a fail-open armed pair). So each step is guarded independently and the spine revoke (the safe-direction
        # audit append the cross-check ignores) runs last. The original publish fault is always surfaced; any
        # revert fault is appended for the operator log.
        revert_faults: list[str] = []
        for _label, _step in (
            ("unpublish-grant",
             lambda: reg.unpublish(org_id, host, instance_id=instance_id, replica_index=int(replica_index))),
            ("unpublish-binding", lambda: unpublish_binding(reg, org_id, host)),
            ("revoke",
             lambda: reg.revoke(org_id, host, issued_at=float(issued_at) + 2e-6,
                                reason="bind publish/read-back failed")),
        ):
            try:
                _step()
            except Exception as re:   # noqa: BLE001 — a revert fault must not skip the remaining reverts
                revert_faults.append(f"{_label}: {type(re).__name__}: {re}")
        tail = f" [revert faults: {'; '.join(revert_faults)}]" if revert_faults else ""
        raise ValueError(
            f"could not publish/verify the bound v2 authority: {type(e).__name__}: {e}{tail}") from e
    return {"org_id": org_id, "host": host, "epoch": view.epoch, "bound": True,
            "capabilities": [c.value for c in view.capabilities],
            "not_before": view.not_before, "not_after": view.not_after,
            "lease_not_before": view.lease_not_before, "lease_not_after": view.lease_not_after,
            "instance_id": view.instance_id, "replica_index": int(view.replica_index),
            "origin_host": origin.host, "origin_port": int(origin.port), "edge_chain": edge_chain,
            "binding_sha256": digest, "grant_published": grant_path.name, "binding_published": binding_path.name,
            "authority": signed_grant.model_dump(mode="json"), "binding": signed_binding.model_dump(mode="json")}


def binding_status(reg: MonitoringAuthorityV2Registry, org_id: str, host: str, *, now: float, trust_root) -> dict:
    """The read-only binding status the custui Monitoring surface shows for one (org, host) — derived from the
    PUBLISHED artifacts the defence actually verifies, not a convenience copy. Returns ``bound`` (the full AS-2g
    cross-check :func:`grant_binds_origin` passes against the published grant + binding files), the origin host/
    port, the edge_chain, a short binding-sha256 PREFIX (never a secret), and the grant's epoch/active state.

    Fail-closed: no active grant, no published grant/binding file, a file that does not verify or does not
    cross-check => ``bound=False`` with a machine-readable ``reason``; never raises on a missing/corrupt file."""
    g = reg.grant_for(org_id, host)
    out: dict = {"host": host, "bound": False, "reason": "no-active-grant", "active": False}
    if g is None:
        return out
    out["active"] = reg.active_at(org_id, host, now=float(now)) is not None
    out["epoch"] = int(g.epoch)
    subject = v2_subject(org_id, host)
    grant_name = authority_publish_path(subject, instance_id=g.instance_id, replica_index=int(g.replica_index))
    gp = Path(reg.publish_dir()) / grant_name
    try:
        graw = gp.read_text(encoding="utf-8")
        signed_grant = SignedMonitoringAuthorityV2.model_validate_json(graw)
    except (OSError, ValueError):
        out["reason"] = "grant-file-unreadable"
        return out
    ok, why = verify_monitoring_authority_v2(signed_grant, trust_root)
    if not ok:
        out["reason"] = f"grant-file-unverified: {why}"
        return out
    gdoc = signed_grant.document
    if gdoc.origin is None or gdoc.origin_binding_sha256 is None:
        out["reason"] = "grant-unbound"
        return out
    out["origin_host"] = gdoc.origin.host
    out["origin_port"] = int(gdoc.origin.port)
    out["edge_chain"] = gdoc.edge_chain
    out["binding_sha256_prefix"] = str(gdoc.origin_binding_sha256)[:12]
    bname = origin_binding_publish_path(subject)
    bp = Path(reg.publish_dir()) / bname
    try:
        braw = bp.read_text(encoding="utf-8")
        signed_binding = SignedAegisOriginBinding.model_validate_json(braw)
    except (OSError, ValueError):
        out["reason"] = "binding-file-unreadable"
        return out
    bound, reason = grant_binds_origin(gdoc, signed_binding, trust_root)
    out["bound"] = bool(bound)
    out["reason"] = reason
    return out


def bindings_overview(reg: MonitoringAuthorityV2Registry, org_id: str, *, now: float, trust_root) -> "list[dict]":
    """The binding status of every active v2 grant of one org (host order) — what the custui Monitoring page
    renders. Only hosts with an active grant appear; each row is the fail-closed :func:`binding_status`."""
    hosts = sorted({g.host for g in reg.grants(org_id)})
    return [binding_status(reg, org_id, h, now=float(now), trust_root=trust_root) for h in hosts]
