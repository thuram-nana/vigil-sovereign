"""ops_sweeps — read-only-by-default operator sweeps over the money seams (sovereign plane).

1. ABANDONED RESERVATIONS. A published ``CreditLaunchLease`` whose ``(slug, nonce)`` was never settled/canceled
   and whose ``not_after`` is more than ``ttl_s`` in the past is ABANDONED: its reserved credits are stuck. The
   sweep REPORTS them. Only with ``apply=True`` (and the caller's explicit opt-in, see ``cli``) does it close each
   out as a FULL REFUND through the EXISTING ``LaunchGate.settle_launch(consumed_units=0)`` path — the same
   owner-keyed, lease-verified, settlement-marker-guarded path a customer cancel uses — so a settle is
   exactly-once per ``(slug, nonce)`` (a re-run finds the marker and no-ops) and the refund is bound to the
   OWNER-SIGNED lease, never to a number this sweep computes. A lease that does not verify under the pinned owner
   key is reported as ``unverified`` and never touched.

2. DANGLING FLUTTERWAVE tx_refs. Nothing on the spine durably records a started checkout, so the operator supplies
   the started set (JSONL of ``{"tx_ref", "created"}``, e.g. the checkout log / a provider export). Each tx_ref
   older than ``ttl_s`` is classified against the billing spool: ``handled`` (a webhook carrying it was drained to
   ``processed/``), ``quarantined`` (only in ``rejected/`` — recoverable, re-drain it), or ``no_webhook``. REPORT
   ONLY: this sweep never mints, never calls the provider, and never moves a file.

SOVEREIGN plane: imports ``sigil`` + ``vigil_core`` + the import-clean credit-lease seam; no framework/offense.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Iterable, Optional

from .reuse import assert_no_offense

assert_no_offense()

_MAX_ENVELOPE = 256 * 1024


def sweep_abandoned_reservations(gate: Any, *, now: float, ttl_s: float, apply: bool = False) -> dict:
    """Report (and with ``apply`` full-refund via ``settle_launch``) every abandoned published lease."""
    from vigil_core import AuthorizerKey, TrustRoot, verify_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import is_lease_settled, list_credit_leases

    if ttl_s < 0:
        raise ValueError("ttl_s must be non-negative")
    kp = gate.owner_key
    if kp is None:
        raise ValueError("no owner key — the sweep cannot verify leases (fail-closed)")
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    base = gate._seam_base()
    rows: list[dict] = []
    for b in list_credit_leases(base):
        ok, _ = verify_credit_launch_lease(b.signed_lease, root)
        doc = b.signed_lease.document
        row = {"slug": b.slug, "org_id": doc.org_id, "nonce": doc.nonce,
               "units_reserved": int(doc.units_reserved), "not_after": doc.not_after.isoformat()}
        if not ok or doc.engagement_slug != b.slug:
            rows.append({**row, "status": "unverified"})
            continue
        if is_lease_settled(base, doc.engagement_slug, doc.nonce):
            continue                                       # already closed out (tombstone pending) — not abandoned
        if doc.not_after.timestamp() + ttl_s > now:
            continue                                       # still live / inside the grace TTL
        if not apply:
            rows.append({**row, "status": "abandoned"})
            continue
        r = gate.settle_launch(signed_lease=b.signed_lease.model_dump(mode="json"), consumed_units=0, now=now)
        if not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
        elif r.get("action") == "launch_already_settled":
            rows.append({**row, "status": "already_settled"})
        else:
            rows.append({**row, "status": "refunded", "refunded": int(r.get("refunded", 0))})
    return {"applied": bool(apply), "items": rows}


def _iter_spool_bodies(d: Path) -> Iterable[dict]:
    """Yield every decodable webhook body (JSON object) in a billing-spool subdir. Never follows symlinks,
    never raises on a hostile/malformed file (it is simply skipped)."""
    if not d.is_dir():
        return
    for fp in sorted(d.glob("*.json")):
        try:
            if fp.is_symlink() or not fp.is_file() or fp.stat().st_size > _MAX_ENVELOPE:
                continue
            env = json.loads(fp.read_text(encoding="utf-8"))
            body = json.loads(base64.b64decode(env["body_b64"], validate=True))
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if isinstance(body, dict):
            yield body


def _body_tx_ref(body: dict) -> Optional[str]:
    data = body.get("data")
    ref = data.get("tx_ref") if isinstance(data, dict) else None
    return ref if isinstance(ref, str) and ref else None


def load_checkouts(path: "str | os.PathLike") -> list[dict]:
    """Parse a JSONL file of started checkouts ``{"tx_ref": str, "created": float}``; malformed lines skipped."""
    out: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            o = json.loads(line)
            ref, created = o["tx_ref"], float(o["created"])
        except (ValueError, KeyError, TypeError):
            continue
        if isinstance(ref, str) and ref.startswith("vigil:"):
            out.append({"tx_ref": ref, "created": created})
    return out


def sweep_dangling_tx_refs(checkouts: list[dict], *, spool_dir: "str | os.PathLike", now: float,
                           ttl_s: float) -> dict:
    """REPORT-ONLY: classify each started checkout older than ``ttl_s`` against the billing spool."""
    spool = Path(spool_dir)
    handled = {r for b in _iter_spool_bodies(spool / "processed") if (r := _body_tx_ref(b))}
    quarantined = {r for b in _iter_spool_bodies(spool / "rejected") if (r := _body_tx_ref(b))}
    rows: list[dict] = []
    seen: set[str] = set()
    for c in checkouts:
        ref = c["tx_ref"]
        if ref in seen or c["created"] + ttl_s > now:
            continue
        seen.add(ref)
        if ref in handled:
            continue
        rows.append({"tx_ref": ref, "created": c["created"],
                     "status": "quarantined" if ref in quarantined else "no_webhook"})
    return {"applied": False, "items": rows}
