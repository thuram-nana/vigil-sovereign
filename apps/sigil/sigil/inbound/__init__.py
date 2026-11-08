"""sigil.inbound — the sovereign-side ingest of data crossing INTO the personal core.

The only thing that crosses from the offense side is an inert, signed finding (P10). This package
imports NO offense-engine module (``framework.*`` / ``strix.*``) — it treats an incoming finding as
opaque signed DATA, verified with the shared integrity core alone."""

from pathlib import Path

from .finding_receiver import FindingReceiver, ingest_finding
from .spool_watcher import SpoolWatcher

__all__ = ["FindingReceiver", "SpoolWatcher", "ingest_finding", "quarantined_count"]


def quarantined_count(rejected_dir: "str | Path") -> int:
    """Standing number of quarantined ENVELOPES still awaiting operator action under a drain's ``rejected/``
    directory (the ``.reason`` explanation sidecars each quarantine writes are NOT counted; an ``.orphan``
    name-collision copy IS a quarantined envelope and counts).

    Every inbound spool drain (findings, billing webhooks, engagement-completion settles) shares the same
    ``rejected/`` quarantine convention, and every ``drain()`` already moves a failed/forged/out-of-scope
    envelope there instead of appending it. The gap this closes: a drain that quarantined something still
    *exited 0*, so the unit heartbeat recorded success and the staleness dead-man reported the unit HEALTHY —
    a buried settle (a completed run never charged / never refunded), a buried paid webhook (a customer paid,
    no credit), or a buried crossed finding (an oracle-confirmed result lost to its tenant) raised NO alarm.

    The drain CLI calls this AFTER draining and exits non-zero while the count is > 0, so systemd records a
    non-``success`` ``SERVICE_RESULT`` -> the ``unit-heartbeat`` hook writes ``ok=false`` -> the dead-man
    reports the unit FAILED (and ``vigil alerts`` exits non-zero) until a human empties the quarantine. The
    condition is STANDING (read off disk every run), not transient (this run's reject count), so a buried
    envelope keeps alarming on every subsequent drain, never only the one run that first quarantined it.

    Fail-closed: an absent ``rejected/`` means nothing was ever quarantined (0); any OTHER read failure
    (e.g. permissions) is left to propagate so the drain command exits non-zero rather than silently read 0.
    """
    try:
        return sum(1 for p in Path(rejected_dir).iterdir()
                   if p.is_file() and not p.name.endswith(".reason"))
    except FileNotFoundError:
        return 0
