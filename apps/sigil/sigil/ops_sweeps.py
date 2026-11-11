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
   ``processed/``), ``quarantined`` (only in ``rejected/`` — recoverable, re-drain it), ``retrying`` (parked in
   ``retry/`` for a bounded NET-2b transient-verify retry — the drain will re-try it), or ``no_webhook``. REPORT
   ONLY: this sweep never mints, never calls the provider, and never moves a file.

SOVEREIGN plane: imports ``sigil`` + ``vigil_core`` + the import-clean credit-lease seam; no framework/offense.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, cast

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


def _completion_block(spool: Path, pair: tuple) -> "Callable[[], Optional[str]]":
    """The sweep's refund precondition, re-read from the spool when called: ``completion_pending`` if a
    completion for ``pair`` is waiting / quarantined, ``completion_unknown`` if the spool cannot be fully read,
    else None (the refund may proceed)."""
    def _check() -> Optional[str]:
        pending, unreadable = _pending_completions(spool)
        if pair in pending:
            return "completion_pending"
        return "completion_unknown" if unreadable else None
    return _check


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
    spool = Path(completion_spool) if completion_spool is not None else None
    pending, spool_unreadable = _pending_completions(spool) if spool is not None else (set(), False)
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
        # The spool read above is a snapshot taken before this loop: a completion can land after it. So the
        # settle RE-CHECKS this lease's completion INSIDE its critical section (under the same cross-process lock
        # the settle-drain's charge takes), right before it decides — a run whose completion exists by then is
        # never refunded here.
        r = gate.settle_launch(signed_lease=b.signed_lease.model_dump(mode="json"), consumed_units=0, now=now,
                               refuse_if=_completion_block(cast(Path, spool),   # apply => a spool (checked above)
                                                           (doc.engagement_slug, str(doc.nonce))))
        if r.get("refused"):
            rows.append({**row, "status": str(r["refused"])})
        elif not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
        elif r.get("action") == "launch_already_settled":
            rows.append({**row, "status": "already_settled"})
        else:
            rows.append({**row, "status": "refunded", "refunded": int(r.get("refunded", 0))})
    return {"applied": bool(apply), "items": rows}


_REFUND_OUTCOMES = frozenset({"failed", "canceled"})     # a completion whose settle is the full refund anyway


def _charging_completions(spool: Path) -> tuple[set, bool]:
    """E7 — ``(slug, nonce)`` of every completion anywhere in the completion spool (waiting, claimed, ARCHIVED in
    ``processed/`` or quarantined) whose outcome could CHARGE its launch: any outcome but ``failed`` /
    ``canceled``, whose settle is the same full refund a release makes. (A superseded launch's own refused job
    ends in a quarantined FAILED, which must not block its release; a COMPLETED, even one the drain archived as a
    no-op, must.) Signatures are not checked: any such claim blocks. Returns ``(pairs, unreadable)`` with the same
    fail-closed reading as ``_pending_completions``: an unparseable file, or a spool with none of the drain's
    subdirs, makes the completion state UNKNOWN."""
    pairs: set = set()
    unreadable = False
    saw_subdir = False
    for sub in ("incoming", "working", "processed", "rejected"):
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
                pair = (str(doc["engagement_slug"]), str(doc["nonce"]))
                outcome = doc.get("outcome")
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                unreadable = True
                continue
            if outcome not in _REFUND_OUTCOMES:
                pairs.add(pair)
    return pairs, unreadable or not saw_subdir


def _release_block(spool: Path, pair: tuple) -> "Callable[[], Optional[str]]":
    """The superseded-release precondition, re-read from the spool when called (inside the settle critical
    section): ``completion_pending`` if a charging completion for ``pair`` exists, ``completion_unknown`` if the
    spool cannot be fully read, else None."""
    def _check() -> Optional[str]:
        charging, unreadable = _charging_completions(spool)
        if pair in charging:
            return "completion_pending"
        return "completion_unknown" if unreadable else None
    return _check


def sweep_superseded_reservations(gate: Any, *, now: float, ttl_s: float, apply: bool = False,
                                  completion_spool: "Optional[str | os.PathLike]" = None) -> dict:
    """E7 — report (and with ``apply`` release, i.e. full-refund via ``LaunchGate.release_superseded_reservation``)
    every unsettled credit RESERVATION that a later launch of the same (org, host) superseded on the seam.

    It reads the RESERVATIONS from the spine (``scan_reservations``), not the leases on the seam: the seam holds one
    lease per (org, host), so a launch whose lease a later one replaced is invisible to
    ``sweep_abandoned_reservations`` — its job is refused by the engine and its completion quarantined, so its
    credits stayed held. A reservation is listed when it is unsettled (no settlement evidence on the spine, no seam
    settlement marker) and ``LaunchGate._release_refusal`` finds it superseded (a later reservation of the same
    target exists and the seam lease is not its own) and past its grace (its longest lease window + ``ttl_s`` since
    the reserve); one whose evidence is contradictory is listed as ``outcome_recorded`` / ``seam_inconsistent`` and
    never released. A charging completion for it anywhere in ``completion_spool`` reports ``completion_pending`` (an
    unreadable spool: ``completion_unknown``) and is never refunded. ``apply`` REQUIRES ``completion_spool``; the
    gate re-decides everything inside the settle critical section, exactly once per (slug, nonce)."""
    from vigil_integration.live.credit_lease_broker import is_lease_settled

    from .governor.launch_reservations import scan_reservations

    if ttl_s < 0:
        raise ValueError("ttl_s must be non-negative")
    if apply and completion_spool is None:
        raise ValueError("apply requires completion_spool — a refund could erase a pending charge (fail-closed)")
    kp = gate.owner_key
    if kp is None:
        raise ValueError("no owner key — the sweep cannot verify reservations (fail-closed)")
    spool = Path(completion_spool) if completion_spool is not None else None
    charging, spool_unreadable = _charging_completions(spool) if spool is not None else (set(), False)
    base = gate._seam_base()
    ix = scan_reservations(gate.store, kp.public_key_b64)
    rows: list[dict] = []
    for res in sorted(ix.reservations.values(), key=lambda r: r.seq):
        oid, slug, nonce = res.key
        if res.key in ix.settled or is_lease_settled(base, slug, nonce):
            continue                                       # settled — nothing held
        why = gate._release_refusal(oid, slug, res, ix, now, ttl_s)
        if why in ("not_superseded", "started", "in_grace"):
            continue                                       # not (yet) a superseded reservation
        row = {"slug": slug, "org_id": oid, "nonce": nonce, "units_reserved": res.reserved,
               "reserved_at": res.issued_at}
        if why is not None:
            rows.append({**row, "status": why})
            continue
        if (slug, nonce) in charging:
            rows.append({**row, "status": "completion_pending"})
            continue
        if spool_unreadable:
            rows.append({**row, "status": "completion_unknown"})
            continue
        if not apply:
            rows.append({**row, "status": "superseded"})
            continue
        r = gate.release_superseded_reservation(org_id=oid, slug=slug, nonce=nonce, now=now, grace_s=ttl_s,
                                                refuse_if=_release_block(cast(Path, spool), (slug, nonce)))
        if r.get("refused"):
            rows.append({**row, "status": str(r["refused"])})
        elif not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
        elif r.get("action") == "launch_already_settled":
            rows.append({**row, "status": "already_settled"})
        else:
            rows.append({**row, "status": "released", "refunded": int(r.get("refunded", 0))})
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
    # NET-2b: a webhook parked for a bounded transient-verify retry is PENDING, not missing (no retry/ ⇒ unchanged)
    retrying = {r for b in _iter_spool_bodies(spool / "retry") if (r := _body_tx_ref(b))}
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
                     "status": ("quarantined" if ref in quarantined else
                                "retrying" if ref in retrying else "no_webhook")})
    return {"applied": False, "items": rows}
