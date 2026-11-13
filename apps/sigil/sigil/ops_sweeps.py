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

3. INTERRUPTED RECORDED SETTLES (``finish_interrupted_settles``, run by the settle drain on every pass while
   ``VIGIL_SETTLE_SPINE_RECORD`` is on): finishes, from its RECORDED decision only, every settle of a lease still on
   the seam that a crash or an error interrupted. Every sweep and that pass read the spine's settlement evidence
   in ONE pass for all the launches they list.

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
    fail-closed: no refunds at all).

    E3bc: the three globs run under the spool lock held SHARED (``<spool>/.spool.lock``), which the drain's
    reverse moves (working/ -> incoming/) hold exclusively — so a completion moved between two globs can never be
    missed. A lock that cannot be taken (busy past its bounded wait, unusable) still scans, but reads as
    ``unreadable`` (completion_unknown: fail-closed). A mis-pointed spool returns before any lock file is
    created."""
    if not any((spool / sub).is_dir() for sub in ("incoming", "working", "rejected")):
        return set(), True
    from vigil_integration.live.seam_lock import locked_file
    try:
        with locked_file(spool / ".spool.lock", shared=True, create=False, chown_like=spool, wait_s=5.0):
            return _scan_pending(spool)
    except OSError:
        pairs, _unreadable = _scan_pending(spool)
        return pairs, True


def _scan_pending(spool: Path) -> tuple[set, bool]:
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
        # READ ORDER (E3bc, pinned): the pause marker BEFORE the late record. resume writes the late record before it
        # clears the pause, so a resume racing these two reads is seen either as still paused or as lifted late —
        # never as "never paused".
        paused_now = lease_pause_state(base, slug, nonce)
        held_past_expiry = paused_past_expiry(base, slug, nonce)
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


def _settle_precondition(spool: Path, pair: tuple, base: Any, *, metered: bool,
                         paused: bool) -> "Callable[[], Optional[str]]":
    """The sweep's settle precondition, evaluated INSIDE the settle's critical section (``refuse_if``), right
    before it decides: ``completion_pending`` if a completion for ``pair`` is waiting / quarantined,
    ``completion_unknown`` if the spool cannot be fully read; for a metered launch, ``pause_unknown`` if its pause
    state cannot be read and ``pause_changed`` if it differs from what this sweep priced the settle on (a pause
    that landed after the up-front read — the next pass applies D4). None: the settle may proceed."""
    def _check() -> Optional[str]:
        pending, unreadable = _pending_completions(spool)
        if pair in pending:
            return "completion_pending"
        if unreadable:
            return "completion_unknown"
        if metered:
            now = _pause_state(base, *pair)
            if now is None:
                return "pause_unknown"
            if bool(now) != bool(paused):
                return "pause_changed"
        return None
    return _check


def root_apply_refusal(required: "Iterable[tuple[str, Any]]", optional: "Iterable[tuple[str, Any]]" = (), *,
                       euid: Optional[int] = None) -> Optional[str]:
    """Why a money-moving ``ops-sweep --apply`` must not run as root here, or None. Only when this process is root
    (``euid``, default ``os.geteuid()``): every ``required`` directory must exist and every ``optional`` one that
    exists must be owned by root — else the sweep would create seam settlement markers and their locks, spine segment
    files or meter state as root inside directories the services own, which those services then cannot write (their
    settles would fail from then on). Each entry is ``(label, path)``."""
    if euid is None:
        geteuid = getattr(os, "geteuid", None)
        euid = geteuid() if geteuid is not None else None
    if euid != 0:
        return None
    for label, path, must in [(lb, p, True) for lb, p in required] + [(lb, p, False) for lb, p in optional]:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            if must:
                return f"the {label} {path} does not exist"
            continue
        except OSError as e:
            return f"the {label} {path} cannot be read ({type(e).__name__})"
        if st.st_uid != 0:
            return f"the {label} {path} is owned by uid {st.st_uid}, not root"
    return None


def _moved(r: dict) -> dict:
    """The amounts a settle actually moved (a roll-forward's ``settle_completed`` row)."""
    return {k: int(r.get(k, 0)) for k in ("refunded", "refunded_plan", "refunded_wallet", "net_spend")}


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
    Every metered row carries the meter's confirmed spend (``metered_cost_nano``).

    E3bc statuses: the settle re-checks the spool and (metered) the pause state INSIDE its critical section, so a
    late completion / pause refuses it as ``completion_pending`` / ``completion_unknown`` / ``pause_changed`` /
    ``pause_unknown`` (nothing written; the next pass decides); a busy settle lock or meter is ``deferred``; a
    settle that finished a recorded decision a crash interrupted is ``settle_completed`` with the amounts it moved.
    With ``VIGIL_SETTLE_SPINE_RECORD`` on, a listed lease whose settlement marker is present (its tombstone pending:
    possibly a settle interrupted after the marker) is FINISHED under ``apply`` (``settle_launch(finish_only=True)``:
    only a recorded decision, never a fresh refund; no TTL or spool check) and reported ``settle_interrupted`` with
    its pending amounts without it. With the flag off such a lease is skipped, as before."""
    from vigil_core import AuthorizerKey, TrustRoot, verify_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import is_lease_settled, list_credit_leases
    from . import config

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
    leases = list_credit_leases(base)
    record = config.settle_spine_record_enabled()
    interrupted: "dict[tuple[str, str, str], dict]" = {}
    if record and not apply:
        # the report reads every marker-present lease's settlement in ONE spine pass (never a scan per lease)
        interrupted = gate.interrupted_settlements(
            [b.signed_lease for b in leases
             if is_lease_settled(base, b.signed_lease.document.engagement_slug, b.signed_lease.document.nonce)])
    for b in leases:
        ok, _ = verify_credit_launch_lease(b.signed_lease, root)
        doc = b.signed_lease.document
        row = {"slug": b.slug, "org_id": doc.org_id, "nonce": doc.nonce,
               "units_reserved": int(doc.units_reserved), "not_after": doc.not_after.isoformat()}
        if not ok or doc.engagement_slug != b.slug:
            rows.append({**row, "status": "unverified"})
            continue
        if is_lease_settled(base, doc.engagement_slug, doc.nonce):
            # already closed out (tombstone pending) — not abandoned. With the settle record on, it may be a settle
            # a crash interrupted after its marker: FINISH it (finish_only: a recorded decision only, never a fresh
            # one), whatever the TTL or the spool says; report-only shows it. Flag off: skipped, exactly as before.
            if record:
                lease_json = b.signed_lease.model_dump(mode="json")
                if apply:
                    r = gate.settle_launch(signed_lease=lease_json, consumed_units=0, now=now, basis="sweep:refund",
                                           finish_only=True)
                    if r.get("rolled_forward"):
                        rows.append({**row, "status": "settle_completed", **_moved(r),
                                     **_metered_spend(gate, str(doc.engagement_slug), str(doc.nonce))})
                    elif not r.get("ok") and r.get("retry"):
                        rows.append({**row, "status": "deferred", "error": r.get("error", "")})
                    elif not r.get("ok"):
                        rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
                else:
                    pending_settle = interrupted.get((str(doc.org_id), str(doc.engagement_slug), str(doc.nonce)))
                    if pending_settle:
                        rows.append({**row, "status": "settle_interrupted", **pending_settle})
            continue
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
        # The spool and pause reads above are a snapshot taken before this settle: a completion or a pause can land
        # after them. So the settle RE-CHECKS both INSIDE its critical section (under the same cross-process lock the
        # settle-drain's charge and a pause take), right before it decides — a run whose completion exists by then is
        # never refunded or charged here, and a pause that landed since is priced by the next pass.
        r = gate.settle_launch(signed_lease=b.signed_lease.model_dump(mode="json"), consumed_units=consumed, now=now,
                               basis=("sweep:paused" if consumed > 0 else "sweep:refund"),
                               refuse_if=_settle_precondition(cast(Path, spool), (slug_, nonce_), base,  # apply => spool
                                                              metered=metered, paused=bool(paused)))
        if r.get("refused"):
            rows.append({**row, "status": str(r["refused"]), **_metered_spend(gate, slug_, nonce_)})
        elif not r.get("ok") and r.get("retry"):
            rows.append({**row, "status": "deferred", "error": r.get("error", "")})
        elif not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
        elif r.get("action") == "launch_already_settled" and r.get("rolled_forward"):
            rows.append({**row, "status": "settle_completed", **_moved(r), **_metered_spend(gate, slug_, nonce_)})
        elif r.get("action") == "launch_already_settled":
            rows.append({**row, "status": "already_settled"})
        elif consumed > 0:
            rows.append({**row, "status": "charged_paused", "charged": consumed, "refunded": int(r.get("refunded", 0)),
                         **_metered_spend(gate, slug_, nonce_)})
        else:
            rows.append({**row, "status": "refunded", "refunded": int(r.get("refunded", 0)),
                         **_metered_spend(gate, slug_, nonce_)})
    return {"applied": bool(apply), "items": rows}


def finish_interrupted_settles(gate: Any, *, now: float, scope: str = "*") -> "list[dict]":
    """FINISH every recorded settle of a lease still on ``gate``'s seam (only ``scope``'s, unless ``*``) that a crash
    or an error interrupted — whatever decided it (a completion, a cancel, a sweep, an expired pause) — so a recorded
    refund never waits for an operator and a relaunch on that host is never held back by it. The settle drain runs
    this on every pass while ``VIGIL_SETTLE_SPINE_RECORD`` is on; with it off this returns ``[]`` and reads nothing.

    A lease is finished when its RECORDED decision has an entry that has not landed (``LaunchGate.
    interrupted_settlements``: every listed lease's evidence read in ONE pass over the spine, the prune-durable
    seen-sets consulted only for an entry the scan did not find), or when its settlement marker is present while the
    lease is still published (a settle stopped before its last step). It goes through ``settle_launch(finish_only=
    True)`` — the exactly-once settle under the cross-process settle lock, which only rolls forward the recorded
    decision (never a fresh one, never this caller's amounts) and then retires the lease — so this moves no money
    that was not already decided.

    One row per lease it acted on: ``settle_completed`` (the moved amounts and the recorded ``basis``),
    ``already_settled`` (nothing was left to move; the lease is retired), ``deferred`` (a busy lock or ledger: the
    next pass retries) or ``settle_failed`` (with ``error``). Never raises for one lease."""
    from vigil_core import AuthorizerKey, TrustRoot, verify_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import is_lease_settled, list_credit_leases

    from . import config

    if not config.settle_spine_record_enabled():
        return []
    kp = gate.owner_key
    if kp is None:
        return []
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    base = gate._seam_base()
    leases = []
    for b in list_credit_leases(base):
        try:
            doc = b.signed_lease.document
            if scope != "*" and doc.engagement_slug != scope:
                continue
            if doc.engagement_slug != b.slug or not verify_credit_launch_lease(b.signed_lease, root)[0]:
                continue                                   # a lease that does not verify is never acted on
        except Exception:  # noqa: BLE001 — an unreadable bundle is skipped
            continue
        leases.append(b)
    if not leases:
        return []                                          # nothing on the seam: the spine is not read
    pending = gate.interrupted_settlements([b.signed_lease for b in leases])
    rows: "list[dict]" = []
    for b in leases:
        doc = b.signed_lease.document
        oid, slug, nonce = str(doc.org_id), str(doc.engagement_slug), str(doc.nonce)
        if (oid, slug, nonce) not in pending and not is_lease_settled(base, slug, nonce):
            continue                                       # no recorded settle of it is left unfinished
        row: dict = {"slug": slug, "org_id": oid, "nonce": nonce}
        try:
            r = gate.settle_launch(signed_lease=b.signed_lease.model_dump(mode="json"), consumed_units=0, now=now,
                                   basis="sweep:refund", finish_only=True)
        except Exception as e:  # noqa: BLE001 — one bad lease never sinks the pass (a settle is atomic)
            rows.append({**row, "status": "settle_failed", "error": f"{type(e).__name__}: {e}"})
            continue
        if r.get("rolled_forward"):
            rows.append({**row, "status": "settle_completed", "basis": str(r.get("basis") or ""), **_moved(r)})
        elif not r.get("ok") and r.get("retry"):
            rows.append({**row, "status": "deferred", "error": str(r.get("error", ""))})
        elif not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": str(r.get("error", ""))})
        elif r.get("action") == "launch_already_settled":
            rows.append({**row, "status": "already_settled"})
    return rows


_REFUND_OUTCOMES = frozenset({"failed", "canceled"})     # a completion whose settle is the full refund anyway


_CHARGING_SUBDIRS = ("incoming", "working", "processed", "rejected")


def _charging_completions(spool: Path) -> tuple[set, bool]:
    """E7 — ``(slug, nonce)`` of every completion anywhere in the completion spool (waiting, claimed, ARCHIVED in
    ``processed/`` or quarantined) whose outcome could CHARGE its launch: any outcome but ``failed`` /
    ``canceled``, whose settle is the same full refund a release makes. (A superseded launch's own refused job
    ends in a quarantined FAILED, which must not block its release; a COMPLETED, even one the drain archived as a
    no-op, must.) Signatures are not checked: any such claim blocks. Returns ``(pairs, unreadable)`` with the same
    fail-closed reading as ``_pending_completions``: an unparseable file, or a spool with none of the drain's
    subdirs, makes the completion state UNKNOWN — and, as there, the globs run under the spool lock held SHARED (a
    lock that cannot be taken still scans, but reads as unreadable)."""
    if not any((spool / sub).is_dir() for sub in _CHARGING_SUBDIRS):
        return set(), True
    from vigil_integration.live.seam_lock import locked_file
    try:
        with locked_file(spool / ".spool.lock", shared=True, create=False, chown_like=spool, wait_s=5.0):
            return _scan_charging(spool)
    except OSError:
        pairs, _unreadable = _scan_charging(spool)
        return pairs, True


def _scan_charging(spool: Path) -> tuple[set, bool]:
    pairs: set = set()
    unreadable = False
    for sub in _CHARGING_SUBDIRS:
        d = spool / sub
        if not d.is_dir():
            continue
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
    return pairs, unreadable


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


def _seam_holds(base: Any, slug: str, nonce: str) -> bool:
    """Whether the seam's lease for ``slug`` is launch ``nonce``'s (``sweep_abandoned_reservations`` then owns it).
    Unreadable reads as False: finishing a recorded settle twice is a no-op (exactly once), missing it is not."""
    from vigil_integration.live.credit_lease_broker import read_credit_lease
    try:
        b = read_credit_lease(base, slug)
        return b is not None and str(b.signed_lease.document.nonce) == str(nonce)
    except Exception:  # noqa: BLE001
        return False


def sweep_superseded_reservations(gate: Any, *, now: float, ttl_s: float, apply: bool = False,
                                  completion_spool: "Optional[str | os.PathLike]" = None) -> dict:
    """E7 — report (and with ``apply`` release, i.e. full-refund via ``LaunchGate.release_superseded_reservation``)
    every unsettled credit RESERVATION that a later launch of the same (org, host) superseded on the seam.

    It reads the RESERVATIONS from the spine (``scan_reservations``), not the leases on the seam: the seam holds one
    lease per (org, host), so a launch whose lease a later one replaced is not in the seam listing
    ``sweep_abandoned_reservations`` reads (its job is refused at the arm and its completion quarantined), and this
    sweep is what settles it. A reservation is listed when it is unsettled (no settlement evidence on the spine, no
    seam settlement marker) and ``LaunchGate._release_refusal`` finds it superseded (a later reservation of the same
    target exists and the seam lease is not its own) and past its grace (its longest lease window + ``ttl_s`` since
    the reserve); one whose evidence is contradictory is listed as ``outcome_recorded`` / ``seam_inconsistent``, and
    one published metered as ``metered`` / ``metered_unknown``, and none of them is released. A charging completion
    for it anywhere in ``completion_spool`` reports ``completion_pending`` (an unreadable spool:
    ``completion_unknown``) and is never refunded. ``apply`` REQUIRES ``completion_spool``; the gate re-decides
    everything inside the settle critical section, exactly once per (slug, nonce): a busy settle lock is
    ``deferred``, and a release that finished a recorded settle a crash interrupted is ``settle_completed`` with
    the amounts it moved. With ``VIGIL_SETTLE_SPINE_RECORD`` on, a SETTLED reservation the seam holds no lease for
    whose recorded decision has an entry that has not landed is finished under ``apply`` (``settle_completed``) and
    reported ``settle_interrupted`` with its pending amounts without it (as ``sweep_abandoned_reservations`` does
    for a lease on the seam)."""
    from vigil_integration.live.credit_lease_broker import is_lease_settled

    from . import config
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
    record = config.settle_spine_record_enabled()
    # ONE pass over the spine: the reservations and, with the settle record on, every settled launch's settlement
    # evidence (its recorded decision and the entries that landed), so no launch is ever re-scanned on its own here
    ix = scan_reservations(gate.store, kp.public_key_b64, evidence=record)
    rows: list[dict] = []
    for res in sorted(ix.reservations.values(), key=lambda r: r.seq):
        oid, slug, nonce = res.key
        row = {"slug": slug, "org_id": oid, "nonce": nonce, "units_reserved": res.reserved,
               "reserved_at": res.issued_at}
        if res.key in ix.settled or is_lease_settled(base, slug, nonce):
            # settled — nothing held. With the settle record on, it may be a settle a crash interrupted after its
            # decision, and with no lease on the seam only this sweep reaches it: FINISH it under ``apply`` (only the
            # recorded decision, never a fresh refund; no grace or spool check) and report it without, exactly as
            # sweep_abandoned_reservations does for a lease on the seam. Its pending part is read from the one-pass
            # evidence above (the prune-durable seen-sets are consulted only for an entry the scan did not find).
            # Flag off: skipped.
            pending = (gate.unlanded_settlement(org_id=oid, slug=slug, nonce=nonce,
                                                evidence=ix.settlement(res.key)) if record else None)
            if pending and not _seam_holds(base, slug, nonce):
                if apply:
                    r = gate.release_superseded_reservation(org_id=oid, slug=slug, nonce=nonce, now=now,
                                                            grace_s=ttl_s, finish_only=True)
                    if r.get("rolled_forward"):
                        rows.append({**row, "status": "settle_completed", **_moved(r)})
                    elif not r.get("ok") and r.get("retry"):
                        rows.append({**row, "status": "deferred", "error": r.get("error", "")})
                    elif not r.get("ok"):
                        rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
                else:
                    rows.append({**row, "status": "settle_interrupted", **pending})
            continue
        why = gate._release_refusal(oid, slug, res, ix, now, ttl_s)
        if why in ("not_superseded", "started", "in_grace"):
            continue                                       # not (yet) a superseded reservation
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
        elif not r.get("ok") and r.get("retry"):
            rows.append({**row, "status": "deferred", "error": r.get("error", "")})
        elif not r.get("ok"):
            rows.append({**row, "status": "settle_failed", "error": r.get("error", "")})
        elif r.get("action") == "launch_already_settled" and r.get("rolled_forward"):
            rows.append({**row, "status": "settle_completed", **_moved(r)})
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
