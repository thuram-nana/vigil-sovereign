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


def _metered_spend(gate: Any, slug: str, nonce: str) -> dict:
    """For a launch published metered (PRICING M1c), its meter's confirmed spend — what a full refund leaves VIGIL
    paying — so the sweep never refunds metered spend silently. ``{}`` for a flat launch."""
    try:
        if not gate._launch_was_metered(slug, nonce):
            return {}
        from vigil_core.model_grant import meter_id
        from . import config
        from .model_gateway import GrantMeter
        t = GrantMeter(config.MODEL_METER_DIR).totals(meter_id(str(slug), str(nonce)))
        return {"metered_cost_nano": int(t.cost_nano), "metered_requests": int(t.requests)}
    except (OSError, ValueError):
        return {"metered_cost": "unreadable"}


class _SweepDefer(Exception):
    """A settle the sweep must leave for its next pass (a request in flight, a meter not writable right now, or an
    unset pricing setting). ``status`` is the row status to report."""

    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status = status


def _pause_state(base: Any, slug: str, nonce: str) -> "Optional[bool]":
    """True when the CUSTOMER paused this launch (a cleanly-read pause marker holds its nonce, or the customer lifted
    the pause only after the lease window had closed), False when it was not paused, None when either record cannot
    be read (never guessed either way)."""
    try:
        from vigil_integration.live.credit_lease_pause import lease_pause_state, paused_past_expiry
        held_past_expiry = paused_past_expiry(base, slug, nonce)
        paused_now = lease_pause_state(base, slug, nonce)
    except Exception:  # noqa: BLE001 — an import or read failure is "cannot tell", never an answer
        return None
    if held_past_expiry is True or paused_now is True:
        return True                                    # positive evidence either way: still paused, or lifted late
    if held_past_expiry is None or paused_now is None:
        return None
    return False


def _paused_metered_charge(gate: Any, slug: str, nonce: str, reserved: int, now: float) -> int:
    """What a metered launch the customer paused and never resumed used, in credits (owner decision 2026-11-13: it
    is CHARGED for what it used, like a completed or customer-cancelled metered run): the run's meter is CLOSED
    first, then ``min(reserved, max(floor, ceil(confirmed cost x markup / $0.01)))``. Only confirmed spend is
    billed, and a launch with no recorded model request and no confirmed spend is charged nothing (it may never have
    started; the floor covers a run's start-up). Raises :class:`_SweepDefer` when the settle must wait; a broken
    meter raises ``ValueError``."""
    from vigil_core import model_metering as mm
    from vigil_core.model_grant import meter_id
    from . import config
    from .model_gateway import GrantMeter, MeterBusy
    try:
        totals = GrantMeter(config.MODEL_METER_DIR).close(meter_id(str(slug), str(nonce)), now=float(now))
    except MeterBusy as e:
        raise _SweepDefer("deferred", str(e)) from e
    except OSError as e:
        raise _SweepDefer("deferred", f"the run's model meter cannot be written right now: {type(e).__name__}") from e
    if totals.requests == 0 and totals.cost_nano == 0:
        return 0                                       # nothing was used (it may never have started): refunded
    try:
        return mm.credits_for_cost(totals.cost_nano, markup=mm.billing_markup(), floor=mm.run_floor_credits(),
                                   cap=int(reserved))
    except mm.MeteringError as e:
        raise _SweepDefer("deferred_config", f"the charge waits on its pricing configuration: {e}") from e


def sweep_abandoned_reservations(gate: Any, *, now: float, ttl_s: float, apply: bool = False,
                                 completion_spool: "Optional[str | os.PathLike]" = None) -> dict:
    """Report (and with ``apply`` settle via ``settle_launch``) every abandoned published lease. A lease with a
    completion still pending/quarantined in ``completion_spool`` is reported ``completion_pending`` and never
    settled here (its run finished; the drain must charge it). ``apply`` REQUIRES ``completion_spool``.

    How an abandoned launch settles (owner decision 2026-11-13: a scan the customer paused and never resumed is
    charged for what it used):
      * published METERED and PAUSED by the customer (a cleanly-read pause marker holds its nonce, or the pause was
        lifted only after the window closed) -> CHARGED its confirmed metered use, clamped to [floor, reservation]
        (``charged_paused``); a paused launch that made no model request and has no confirmed spend is refunded;
      * published metered, NOT paused -> a run VIGIL lost: refunded in full (``refunded``);
      * published metered, pause state UNREADABLE -> not settled (``pause_unknown``): never guessed either way;
      * published FLAT -> refunded in full: a flat launch has no meter, so what it used cannot be measured.
    Every metered row carries the meter's confirmed spend (``metered_cost_nano``)."""
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
        slug_, nonce_ = str(doc.engagement_slug), str(doc.nonce)
        try:
            metered = bool(gate._launch_was_metered(slug_, nonce_))
        except OSError as e:
            rows.append({**row, "status": "deferred", "error": f"billing mode unreadable: {type(e).__name__}"})
            continue
        paused = _pause_state(base, slug_, nonce_) if metered else False
        if not apply:
            rows.append({**row, "status": "abandoned", "paused": paused, **_metered_spend(gate, slug_, nonce_)})
            continue
        if metered and paused is None:
            rows.append({**row, "status": "pause_unknown", **_metered_spend(gate, slug_, nonce_)})
            continue
        consumed = 0
        if metered and paused:
            try:
                consumed = _paused_metered_charge(gate, slug_, nonce_, int(doc.units_reserved), now)
            except _SweepDefer as e:
                rows.append({**row, "status": e.status, "error": str(e)})
                continue
            except ValueError as e:
                rows.append({**row, "status": "settle_failed", "error": f"the run's model meter is broken: {e}"})
                continue
        r = gate.settle_launch(signed_lease=b.signed_lease.model_dump(mode="json"), consumed_units=consumed, now=now)
        if not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
        elif r.get("action") == "launch_already_settled":
            rows.append({**row, "status": "already_settled"})
        elif consumed > 0:
            rows.append({**row, "status": "charged_paused", "charged": consumed, "refunded": int(r.get("refunded", 0)),
                         **_metered_spend(gate, slug_, nonce_)})
        else:
            rows.append({**row, "status": "refunded", "refunded": int(r.get("refunded", 0)),
                         **_metered_spend(gate, slug_, nonce_)})
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


def _body_tx_ref(body: dict, provider: str = "flutterwave") -> Optional[str]:
    """The checkout reference a spooled webhook body carries (report-only matching, never a money decision):
    Flutterwave's ``data.tx_ref``; Stripe's ``data.object.client_reference_id``, else ``data.object.metadata.tx_ref``."""
    data = body.get("data")
    if provider == "stripe":
        obj = data.get("object") if isinstance(data, dict) else None
        if not isinstance(obj, dict):
            return None
        ref = obj.get("client_reference_id")
        if not (isinstance(ref, str) and ref):
            meta = obj.get("metadata")
            ref = meta.get("tx_ref") if isinstance(meta, dict) else None
    else:
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
                           ttl_s: float, provider: str = "flutterwave") -> dict:
    """REPORT-ONLY: classify each started checkout older than ``ttl_s`` against the billing spool of ``provider``
    (``flutterwave``, the default, or ``stripe``)."""
    if provider not in ("flutterwave", "stripe"):
        raise ValueError(f"unknown billing provider {provider!r}")
    spool = Path(spool_dir)
    handled = {r for b in _iter_spool_bodies(spool / "processed") if (r := _body_tx_ref(b, provider))}
    quarantined = {r for b in _iter_spool_bodies(spool / "rejected") if (r := _body_tx_ref(b, provider))}
    # NET-2b: a webhook parked for a bounded transient-verify retry is PENDING, not missing (no retry/ ⇒ unchanged)
    retrying = {r for b in _iter_spool_bodies(spool / "retry") if (r := _body_tx_ref(b, provider))}
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
