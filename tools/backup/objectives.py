"""W7-1 — the VIGIL disaster-recovery OBJECTIVES: numeric RPO / RTO, defined ONCE here and ASSERTED by the
recovery drill. Pure stdlib, so both the offense CLI/tests and the sovereign leg import it, and the systemd
drill can invoke it as a plain script (no PYTHONPATH). It imports NEITHER trust domain (no ``framework`` /
``sigil``) — FATAL-2 neutral, exactly like ``retention`` and ``transport`` in this package.

WHY THIS MODULE EXISTS. Before it, the objectives were nowhere: only cadence hints in timer comments, and a
drill that proved the round-trip WORKS but never that it works FAST ENOUGH, or that the data it would recover
is FRESH enough. "How much data can I lose?" and "how long does recovery take?" had no answer a customer could
be handed. This states both as numbers and gives the drill teeth to fail when a real restore misses them.

THE TWO OBJECTIVES (the exact numbers the docs quote — docs/decisions/W7-1-*.md and OBSERVABILITY.md):

  * RPO — Recovery Point Objective = **24 hours** (:data:`RPO_SECONDS`). The most data a disaster can cost you,
    measured in time. It is bounded by the BACKUP CADENCE: ``vigil-backup.timer`` / ``vigil-backup-push.timer``
    fire ``OnCalendar=daily``, so the newest good copy is at most ~24h old. The drill measures the AGE of the
    backup it restores (:func:`data_loss_seconds`, from the timestamped subdir name) and fails if it exceeds
    the RPO. Operationally the RPO is ALSO watched by the ``vigil-alerts`` staleness monitor (W8-1 #467): if the
    backup timer stops firing, the newest copy ages past the RPO and an alarm is raised — the drill's assertion
    and the timer+alert are the two halves that keep the stated RPO true.

  * RTO — Recovery Time Objective = **30 minutes** (:data:`RTO_SECONDS`). The budget for the ``vigil restore``
    DATA-RESTORE step — decrypt + verify the signed manifest + stage + atomic swap + post-restore re-verify.
    The drill times the real restore and fails if it runs longer. HONEST SCOPE (the issue's own point — "RTO
    is unbounded because failover is fully manual"): this RTO covers the AUTOMATED data restore ONLY. It does
    NOT include operator DETECTION of the outage, the human DECISION to fail over, provisioning fresh hardware,
    or DNS / service CUTOVER — those remain MANUAL and are the operator's runbook time, stated separately in
    the decision doc, not something this code can measure or promise. Overclaiming a fully-automated failover
    RTO would be exactly the kind of untrue claim this repo refuses to ship.

Determinism: :func:`assert_within_objectives` and :func:`data_loss_seconds` take an injectable ``now`` and no
global RNG, so they are unit-testable and reproducible. This is a drill/monitoring measurement path, not a
signed decision path, but it is kept wallclock-injectable regardless.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

# --------------------------------------------------------------------------------------------------
# THE STATED OBJECTIVES — the single source of truth. The docs quote these exact numbers, and the
# claims registry (W0-3 #398) pins the doc text to :func:`assert_within_objectives` below.
# --------------------------------------------------------------------------------------------------
# RPO = 24h. Matches the daily backup + off-host push timers (OnCalendar=daily). Tighten those timers AND
# this number together to promise a shorter RPO.
RPO_SECONDS = 24 * 60 * 60
# RTO = 30 min. The budget for the `vigil restore` data-restore step ONLY (NOT manual detection/decision/
# hardware/DNS cutover — those are the operator's runbook time, documented separately, not measured here).
RTO_SECONDS = 30 * 60

# The timestamped-subdir name format `vigil backup` writes (== tools.backup.retention._TS_FMT). Kept in step
# with retention so the age of a backup is read from the same name the reaper recognises.
_TS_FMT = "%Y%m%d-%H%M%S"


class ObjectiveError(Exception):
    """A measured recovery time or data loss EXCEEDED its stated objective, or a backup's age could not be
    measured. Fail-closed: the drill raises this rather than reporting a round-trip that missed the objective
    (or one whose freshness is unknowable) as a clean pass."""


def parse_backup_timestamp(name: str) -> "datetime | None":
    """Parse a timestamped backup subdir name (``YYYYmmdd-HHMMSS``, UTC) to an aware ``datetime``, or return
    ``None`` when it does not match the format ``vigil backup`` writes. Accepts a full path or a bare name."""
    base = str(name).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    try:
        return datetime.strptime(base, _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def data_loss_seconds(backup_name: str, *, now: "datetime | None" = None) -> float:
    """The data loss (the RPO metric) implied by restoring the backup named ``backup_name``: its AGE — the
    maximum span of data written after it that restoring it would lose. Fail-closed: an unparseable name RAISES
    :class:`ObjectiveError` (a backup whose age cannot be read cannot be shown to meet the RPO). ``now``
    defaults to the current UTC time and is injectable for deterministic tests."""
    ts = parse_backup_timestamp(backup_name)
    if ts is None:
        raise ObjectiveError(
            f"cannot measure data loss: backup name {backup_name!r} is not a YYYYmmdd-HHMMSS timestamp")
    ref = now if now is not None else datetime.now(timezone.utc)
    return max(0.0, (ref - ts).total_seconds())


def assert_within_objectives(*, recovery_seconds: float, data_loss_seconds: float,
                             rto_seconds: float = RTO_SECONDS,
                             rpo_seconds: float = RPO_SECONDS) -> dict:
    """The fail-closed DR-objective gate the drill turns on. RAISE :class:`ObjectiveError` if the measured
    recovery time exceeds the RTO, OR the measured data loss exceeds the RPO (either miss fails). Otherwise
    return a report dict. ``rto_seconds`` / ``rpo_seconds`` default to the STATED objectives above; a caller
    may pass tighter (or, for a self-test, deliberately tiny) bounds, but the registered claim is about the
    defaults."""
    if rto_seconds <= 0 or rpo_seconds <= 0:
        raise ObjectiveError("RTO/RPO bounds must be positive")
    problems: list[str] = []
    if recovery_seconds > rto_seconds:
        problems.append(f"recovery time {recovery_seconds:.1f}s exceeds the RTO ({rto_seconds:.0f}s)")
    if data_loss_seconds > rpo_seconds:
        problems.append(f"data loss {data_loss_seconds:.1f}s exceeds the RPO ({rpo_seconds:.0f}s)")
    if problems:
        raise ObjectiveError("DR objective(s) NOT met: " + "; ".join(problems))
    return {
        "recovery_seconds": round(float(recovery_seconds), 3),
        "data_loss_seconds": round(float(data_loss_seconds), 3),
        "rto_seconds": float(rto_seconds), "rpo_seconds": float(rpo_seconds), "met": True,
    }


def objectives_summary() -> dict:
    """The stated objectives as numbers + human strings, for reporting (``objectives show``)."""
    return {"rpo_seconds": RPO_SECONDS, "rto_seconds": RTO_SECONDS, "rpo_human": "24h", "rto_human": "30m"}


# --------------------------------------------------------------------------------------------------
# CLI — the systemd recovery drill invokes ``python3 tools/backup/objectives.py check …`` after a restore.
# Exit 0 = objectives met; 1 = an objective missed (or an unmeasurable backup); 2 = a usage error.
# --------------------------------------------------------------------------------------------------
def _cmd_show(_args: argparse.Namespace) -> int:
    s = objectives_summary()
    print(f"RPO = {s['rpo_human']} ({s['rpo_seconds']}s)  — max data loss (backup cadence)")
    print(f"RTO = {s['rto_human']} ({s['rto_seconds']}s)  — vigil restore data-restore budget "
          "(NOT manual detection/decision/DNS cutover)")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    rto = args.rto_seconds if args.rto_seconds is not None else RTO_SECONDS
    rpo = args.rpo_seconds if args.rpo_seconds is not None else RPO_SECONDS
    try:
        if args.data_loss_seconds is not None:
            loss = float(args.data_loss_seconds)
        elif args.backup_name:
            loss = data_loss_seconds(args.backup_name)
        else:
            print("objectives check: pass --backup-name or --data-loss-seconds", file=sys.stderr)
            return 2
        report = assert_within_objectives(recovery_seconds=float(args.recovery_seconds),
                                          data_loss_seconds=loss, rto_seconds=rto, rpo_seconds=rpo)
    except ObjectiveError as e:
        print(f"objectives check: FAIL — {e}", file=sys.stderr)
        return 1
    print(f"objectives check: OK — recovery {report['recovery_seconds']:.1f}s <= RTO {rto:.0f}s, "
          f"data loss {report['data_loss_seconds']:.1f}s <= RPO {rpo:.0f}s")
    return 0


def main(argv: "list[str] | None" = None) -> int:
    p = argparse.ArgumentParser(prog="objectives", description="VIGIL DR objectives (RPO/RTO)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show", help="print the stated RPO/RTO").set_defaults(func=_cmd_show)
    c = sub.add_parser("check", help="assert a measured recovery time + data loss meet the objectives")
    c.add_argument("--recovery-seconds", type=float, required=True,
                   help="measured wall-clock seconds the restore took")
    c.add_argument("--backup-name", default="",
                   help="the restored backup's timestamped subdir name (YYYYmmdd-HHMMSS) — its age is the data loss")
    c.add_argument("--data-loss-seconds", type=float, default=None,
                   help="explicit data-loss seconds (overrides --backup-name; for tests)")
    c.add_argument("--rto-seconds", type=float, default=None,
                   help=f"override the RTO bound (default {RTO_SECONDS}s)")
    c.add_argument("--rpo-seconds", type=float, default=None,
                   help=f"override the RPO bound (default {RPO_SECONDS}s)")
    c.set_defaults(func=_cmd_check)
    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
