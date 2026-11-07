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


def _pending_completions(spool: Path) -> tuple[set, bool]:
    """``(slug, nonce)`` of every completion still waiting in (or quarantined by) the completion spool — i.e.
    not yet drained into ``settle_launch``. Signatures are NOT checked: any claim of a finished run blocks a
    refund (the drain decides the charge). Returns ``(pairs, unreadable)``; ``unreadable`` is True when some
    waiting file could not be parsed, so its (slug, nonce) is unknown — OR when the spool has NONE of the
    expected subdirs (absent / uninitialized / mis-pointed), which must never read as "no pending" (both
    fail-closed: no refunds at all)."""
    pairs: set = set()
    unreadable = False
    saw_subdir = False
    for sub in ("incoming", "working", "rejected"):
        d = spool / sub
        if not d.is_dir():
            continue
        saw_subdir = True
        for fp in sorted(d.glob("*.json*")):
            if fp.name.endswith(".reason"):
                continue
            try:
                if fp.is_symlink() or not fp.is_file() or fp.stat().st_size > _MAX_ENVELOPE:
                    raise ValueError("not a bounded regular file")
                doc = json.loads(fp.read_text(encoding="utf-8"))["document"]
                pairs.add((str(doc["engagement_slug"]), str(doc["nonce"])))
            except (OSError, ValueError, KeyError, TypeError):
                unreadable = True
    if not saw_subdir:
        # An absent / empty / mis-pointed completion spool has NONE of the drain's subdirs. It must NOT read
        # as "no pending completions" and green-light a refund: a completed-but-undrained run's completion
        # lives in the REAL spool, so an unusable view is completion-UNKNOWN (fail-closed — refuse refunds).
        return pairs, True
    return pairs, unreadable


def sweep_abandoned_reservations(gate: Any, *, now: float, ttl_s: float, apply: bool = False,
                                 completion_spool: "Optional[str | os.PathLike]" = None) -> dict:
    """Report (and with ``apply`` full-refund via ``settle_launch``) every abandoned published lease. A lease
    with a completion still pending/quarantined in ``completion_spool`` is reported ``completion_pending`` and
    never refunded (its run finished; the drain must charge it). ``apply`` REQUIRES ``completion_spool``."""
    from vigil_core import AuthorizerKey, TrustRoot, verify_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import is_lease_settled, list_credit_leases

    if ttl_s < 0:
        raise ValueError("ttl_s must be non-negative")
    if apply and completion_spool is None:
        raise ValueError("apply requires completion_spool — a refund could erase a pending charge (fail-closed)")
    kp = gate.owner_key
    if kp is None:
        raise ValueError("no owner key — the sweep cannot verify leases (fail-closed)")
    pending, spool_unreadable = (_pending_completions(Path(completion_spool)) if completion_spool is not None
                                 else (set(), False))
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
        if (doc.engagement_slug, str(doc.nonce)) in pending:
            rows.append({**row, "status": "completion_pending"})
            continue
        if spool_unreadable:
            rows.append({**row, "status": "completion_unknown"})
            continue
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


def sweep_postpaid_reconciliation(postpaid: Any, arrears: Any, invoices: Any, *, now: float,
                                  orgs: "Optional[Iterable[str]]" = None) -> dict:
    """REPORT-ONLY reconciliation of each postpaid org: invoiced-vs-paid vs real consumption.

    Per org, composes the owner-signed postpaid scalars into one row and flags any discrepancy an
    operator should chase:
      * ``uninvoiced_consumption`` — net settled consumption exceeds what has been invoiced
        (``billable_uninvoiced = net_settled_consumed - invoiced > 0``). Reads ``net_settled_consumed``
        (accrued MINUS still-in-flight reserves), NEVER raw ``accrued``, so an in-flight reserve (a
        launch that has not settled) is never mis-reported as un-billed revenue an operator would
        wrongly chase.
      * ``outstanding`` — an invoiced balance remains unpaid (``invoiced - paid > 0``, PP-2b).
      * ``overdue`` — an unpaid invoice is past its net-terms due date at ``now`` (PP-3 dunning read).
      * ``closed_with_balance`` — a DISABLED (closed) line that still carries owed arrears. Disabling a
        line does NOT erase its debt (``postpaid disable`` writes only the account-mode record), so a
        closed line that still owes stays visible (the highest-risk discrepancy — a churned/delinquent
        tenant); only a closed line with no balance of any kind is dropped. Each row carries ``enabled``.
    A row with none of these is ``reconciled``. This is a PURE READ: it only folds owner-signed
    records, writes nothing, mints nothing, settles nothing. The abandoned-reservation RETIRE half of
    PP-4 rides the EXISTING ``sweep_abandoned_reservations`` (owner-keyed, lease-verified, exactly-once
    per ``(slug, nonce)``) under the same ``--apply`` triple-gate — so PP-4 adds no new money-moving code.
    """
    from .governor.postpaid import (
        invoiced_postpaid_total,
        paid_postpaid_total,
        postpaid_outstanding,
        postpaid_overdue_amount,
    )

    want = None if orgs is None else {str(o) for o in orgs}
    rows: list[dict] = []
    for acct in postpaid.accounts():
        oid = acct.org_id
        if want is not None and oid not in want:
            continue
        enabled = acct.is_enabled()
        drawn = int(arrears.accrued(oid))
        billable = int(arrears.net_settled_consumed(oid))     # accrued - in_flight: the billing basis
        in_flight = int(arrears.in_flight_reserved(oid))
        invoiced = int(invoiced_postpaid_total(invoices, oid))
        paid = int(paid_postpaid_total(invoices, oid))
        outstanding = int(postpaid_outstanding(invoices, oid))
        overdue = int(postpaid_overdue_amount(invoices, postpaid, oid, now))
        billable_uninvoiced = max(0, billable - invoiced)
        # A DISABLED (closed) line still carries real, OWED arrears: `postpaid disable` writes only the
        # account-mode record, never the arrears/invoice ledgers, so the debt stays owed and the sibling
        # `postpaid status` / overdue reads still account for it. The audit sweep MUST surface a closed
        # line that still owes (the highest-risk discrepancy); it drops a disabled line ONLY when it is
        # fully settled (no balance of any kind). An enabled line always appears.
        has_balance = any((drawn, billable, in_flight, invoiced, paid, outstanding, overdue))
        if not enabled and not has_balance:
            continue
        flags: list[str] = []
        if billable_uninvoiced > 0:
            flags.append("uninvoiced_consumption")
        if outstanding > 0:
            flags.append("outstanding")
        if overdue > 0:
            flags.append("overdue")
        if not enabled and has_balance:
            flags.append("closed_with_balance")              # a disabled line that still owes
        rows.append({
            "org_id": oid, "enabled": enabled, "drawn": drawn, "billable": billable,
            "in_flight": in_flight, "invoiced": invoiced, "paid": paid, "outstanding": outstanding,
            "overdue": overdue, "billable_uninvoiced": billable_uninvoiced,
            "status": flags if flags else ["reconciled"],
        })
    return {"applied": False, "items": rows}


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
