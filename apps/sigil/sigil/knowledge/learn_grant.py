"""
sigil.knowledge.learn_grant — the SOVEREIGN producer of the K2b→K3 learn-grant seam (A2 keystone).

This is the REVERSE of the offense→sovereign finding spool. When the owner APPROVES a queued learn-proposal
(``knowledge.learn_proposal``), this signs an inert ``learn_grant`` envelope and writes it to a filesystem
spool the OFFENSE side drains (``vigil_integration.learn_drain``) to run K3 deep-learn. The owner-signed
APPROVAL is the sole trust operation; this only WITNESSES it and hands the offense side a signed pointer.

Boundary + authority invariants:
  * ONLY signed inert bytes cross a directory seam — no plane co-loads the other (the offense consumer
    re-derives the full lead from its OWN intel by ``(slug, vuln_id)``, so a tampered seam can at most cause
    an advisory skill for an in-scope CVE — never a fact, never code).
  * The approval signature binds only ``target_seq`` (see ``agents.approvals``), NOT the vuln_id/slug — so
    slug/vuln_id are read by JOINING each VERIFIED approval's ``target_seq`` back to the queued proposal it
    points at, then signed into the grant here.
  * FAIL-CLOSED + gated every round: exports NOTHING unless the sovereign kill-switch is RELEASED and the
    ``autolearn`` capability latch is ENABLED — the same two gates ``queue_learn`` checks.
  * Idempotent: an approval already exported is skipped (a marker under ``<spool>/exported/``); re-emitting an
    identical grant is a no-op at the spool anyway (content-addressed filename + the consumer's dedup).
  * Boundary-clean: imports ``vigil_core`` (via ``.reuse``/``governor.authn``) + the generic ``finding_spool``
    writer + sigil governance; imports NO ``framework`` / ``strix``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from ..spine.store import SpineStore
from .proposals import LEARN_SIGNAL, sanitize_slug

GRANT_KIND = "learn_grant"
GRANT_SCHEMA = 1
# The signed CORE — the offense verifier reconstructs EXACTLY these fields (dropping sig/pubkey) before it
# checks the signature, so a hostile extra field can never ride inside the signed bytes.
GRANT_CORE_FIELDS = ("schema", "kind", "slug", "vuln_id", "approval_seq")


def approved_learn_grants(store: SpineStore, trusted_pubkey: str) -> list[dict]:
    """Every owner-APPROVED learn-proposal, as an inert grant CORE ``{schema,kind,slug,vuln_id,approval_seq}``.

    An approval is honoured only if it VERIFIES under the owner key (or an owner-authorized device); its
    ``target_seq`` is then joined back to the queued ``knowledge.learn_proposal`` to read the (slug, vuln_id)
    the offense side will re-derive its lead from. A forged/replayed/non-owner approval verifies to False and
    is ignored, so it never produces a grant."""
    from ..agents.approvals import SIGNAL as APPROVAL_SIGNAL
    from ..agents.approvals import verify_approval
    from ..mesh import authorized_devices

    devices = authorized_devices(store, trusted_pubkey)
    seen: set[int] = set()
    grants: list[dict] = []
    for r in store.iter_records():
        p = r.payload
        if p.get("signal") != APPROVAL_SIGNAL or p.get("approval") != "approved":
            continue
        target = p.get("target_seq")
        if not isinstance(target, int) or target in seen:
            continue
        if not verify_approval(r, trusted_pubkey, extra_pubkeys=devices):
            continue                                        # forged / non-owner / replayed → not a grant
        q = store.get(target)
        if q is None or q.payload.get("signal") != LEARN_SIGNAL:
            continue                                        # the approval points at a non-learn record
        vuln_id = str(q.payload.get("vuln_id") or "").strip()
        if not vuln_id:
            continue
        seen.add(target)
        # Re-sanitise the slug at mint — a raw spine-write could bypass the enqueue chokepoint, and this
        # value is owner-SIGNED into a grant the offense side uses as an argv/store/path token.
        grants.append({"schema": GRANT_SCHEMA, "kind": GRANT_KIND,
                       "slug": sanitize_slug(q.payload.get("slug")), "vuln_id": vuln_id,
                       "approval_seq": target})
    return grants


def export_approved_grants(store: SpineStore, *, spool_dir: str | os.PathLike,
                           owner_key=None, trusted_pubkey: Optional[str] = None) -> dict:
    """Sign + spool an inert ``learn_grant`` for each owner-approved learn-proposal not yet exported.

    FAIL-CLOSED: exports NOTHING if the kill-switch is engaged OR autolearn is disabled OR no owner key is
    configured. Idempotent via an ``<spool>/exported/<approval_seq>.json`` marker (written AFTER the spool, so
    a crash mid-way is retried, never lost). Returns ``{exported, skipped, gated}``."""
    from vigil_integration.finding_spool import spool_envelope

    from ..governor import CapabilityGate, KillSwitch
    from ..governor.authn import signed_payload
    from ..governor.identity import ensure_owner_keypair, owner_pubkey

    owner_key = owner_key or ensure_owner_keypair()
    trusted = trusted_pubkey or owner_pubkey()
    if not trusted:
        return {"exported": 0, "skipped": 0, "gated": "no-owner-key"}
    if KillSwitch(store, owner_key=owner_key).is_engaged():
        return {"exported": 0, "skipped": 0, "gated": "kill-switch"}
    if not CapabilityGate(store, owner_key=owner_key).is_enabled("autolearn"):
        return {"exported": 0, "skipped": 0, "gated": "autolearn-disabled"}

    exported_dir = Path(spool_dir) / "exported"
    exported_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(exported_dir, 0o700)
    exported, skipped = 0, 0
    for core in approved_learn_grants(store, trusted):
        marker = exported_dir / f"{int(core['approval_seq'])}.json"
        if marker.exists():
            skipped += 1
            continue
        envelope = signed_payload(core, owner_key)          # core + {sig, pubkey}, owner-signed
        spool_envelope(spool_dir, json.dumps(envelope, sort_keys=True))
        marker.write_text(json.dumps({"approval_seq": core["approval_seq"], "vuln_id": core["vuln_id"]}),
                          encoding="utf-8")
        try:
            os.chmod(marker, 0o600)
        except OSError:
            pass
        exported += 1
    return {"exported": exported, "skipped": skipped, "gated": None}
