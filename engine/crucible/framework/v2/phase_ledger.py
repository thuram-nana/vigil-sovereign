"""
framework.v2.phase_ledger — the append-only engagement PHASE LEDGER + ``--resume``.

``run_engagement`` runs a fixed, ordered sequence of phases (preflight, intel recon,
transfer priors, the web scan campaign, intel finalize, finding-confidence, chaining,
grounding, sensor fusion, the defender pass, the reasoning pass). Historically it kept
NO phase identity: a run that crashed in a late phase restarted from scratch — re-crawling
and re-auditing the target from the first request.

This module adds a durable, append-only ledger of each phase's lifecycle and a resume
path that skips ONLY the phases which are sound to skip. Its contract, in order of
importance:

  * **Fail-open.** Every ledger write is total: a checkpoint/persist failure is a recorded
    no-op that NEVER raises into — or changes the behaviour of — the engagement. If the
    ledger cannot be written, the run proceeds exactly as if there were no ledger.
  * **Resume skips only what is SOUND to skip — the veracity firewall always re-fires.**
    ``--resume`` is NOT "skip every completed phase": only :data:`RESUMABLE_PHASES` (a strict
    allowlist) may be skipped, and only when a prior run completed them. Exactly two phases
    qualify: the one TRAFFIC-SENDING phase, the scan — which snapshots its authoritative
    :class:`ScanReport` on completion so a resumed run RELOADS that report instead of
    re-crawling/re-auditing the target — and the advisory reasoning pass, whose ONLY effect is
    to EMIT the findings' events onto the append-only event spine (re-running it would
    double-count the same findings on the immutable stream, and it changes no report field, so
    skipping it loses nothing). EVERY OTHER phase — intel finalize, finding-confidence,
    chaining, the GROUNDING veracity firewall, fusion, the defender pass — is no-traffic,
    deterministic reasoning over the reloaded report/world, and MUST re-run on resume: its
    output is an in-memory field of the prior process that nothing reloads, and re-firing the
    grounding firewall (CRUCIBLE invariant #3: a finding is a fact only if its retained
    ``oracle_context`` RE-FIRES; the firewall can only demote) is REQUIRED for a resumed report
    to be as authoritative as a fresh one — not an optional optimization. Re-running them sends
    no traffic and is free. Two of those re-run phases — sensor fusion and the defender pass —
    ALSO write to the spine (fused-lead ``finding`` events / the defender gap-report), so on a
    resume they must recompute their derived fields WITHOUT re-appending those events. That
    spine-idempotency is the CALLER's job, not the allowlist's: :func:`engage.run_engagement`
    hands those phases a NULL sink (its ``_emit_sink`` helper, keyed on :meth:`completed_prior`)
    when the prior run already recorded them, so they re-run in-memory but re-emit nothing. A
    phase that only ``started`` / ``failed`` (crashed before completing) is likewise never
    skipped — it is retried (and it keeps the real sink, so its events are emitted once).
  * **State, never a finding.** The ledger records phase STATE only (``started`` /
    ``completed`` / ``skipped`` / ``failed`` / ``halted`` + a run-status timestamp). It never
    mints a finding, never promotes a lead to a fact, and feeds no deterministic / oracle math.
  * **A paused scan is never a completed scan.** A scan that a reversible PAUSE cut short is
    recorded ``halted`` (:meth:`PhaseLedger.halt`), never ``completed``, and is not snapshotted:
    ``completed`` stays the ONLY status that lets a resume skip a phase, so the resumed run
    RE-RUNS the scan and delivers the whole assessment instead of reloading a truncated one.
  * **Resume state is bound to its launch (customer launches).** The ledger file and the scan
    snapshot are keyed per SLUG, and a customer slug is reused by every launch of the same
    (org, host). :meth:`PhaseLedger.bind_launch` therefore scopes a customer run's resume state
    to ONE launch: its records carry a digest of the launch identity, only records carrying
    that digest count as "completed by a prior run", and the snapshot is reloaded only when its
    bytes hash to the digest THIS launch recorded when it wrote it. A resume can then never
    skip its scan on the strength of an EARLIER launch's ledger, nor reload an earlier launch's
    report. An UNBOUND ledger (every operator / greenfield run) is byte-identical to before.

The ledger lives at ``paths.phase_ledger_path(slug)`` (``<base>/<slug>.phases.jsonl``); the
scan snapshot at ``paths.phase_report_path(slug)``. Under an ephemeral / ZDR session both
re-root onto the purged tmpfs write base, so resume is a persist-by-default feature that an
ephemeral run deliberately forgoes.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from .common import logging as _v2log
from .common import paths as _paths

_log = _v2log.get_logger(__name__)

T = TypeVar("T")

# The ordered phase identities. Constants (not bare strings at call sites) so a typo can
# never silently create a phase that is recorded-but-never-skipped, and so the ledger's
# vocabulary is a single auditable list.
P_PREFLIGHT = "preflight"
P_INTEL_RECON = "intel_recon"
P_TRANSFER = "transfer_priors"
P_SCAN = "scan"
P_INTEL_FINALIZE = "intel_finalize"
P_ASSESS_FINDINGS = "assess_findings"
P_CHAINING = "chaining"
P_GROUNDING = "assess_grounding"
P_FUSION = "fusion"
P_DEFENDER = "defender_pass"
P_REASONING = "reasoning_pass"

ORDERED_PHASES: tuple[str, ...] = (
    P_PREFLIGHT, P_INTEL_RECON, P_TRANSFER, P_SCAN, P_INTEL_FINALIZE,
    P_ASSESS_FINDINGS, P_CHAINING, P_GROUNDING, P_FUSION, P_DEFENDER, P_REASONING,
)

# The ONLY phases a completed prior run may cause ``--resume`` to skip — a strict ALLOWLIST,
# never "every completed phase". A phase belongs here iff skipping it on resume is SOUND, which
# is true for exactly two:
#
#   * P_SCAN      — the one TRAFFIC-SENDING phase. On completion it snapshots its authoritative
#                   ScanReport (persist_report), and a resumed run RELOADS that snapshot instead
#                   of re-crawling/re-auditing, so the target sees no repeat traffic and findings
#                   are never re-counted. Its output is durably reloadable — nothing is lost.
#   * P_REASONING — the ADVISORY pass WHOSE ONLY EFFECT is to EMIT the findings' events onto the
#                   append-only event spine. Re-running it would double-count the SAME findings on
#                   the immutable stream; it changes no report field and no oracle verdict, so
#                   skipping the re-emit loses nothing authoritative.
#
# Every OTHER phase is no-traffic, DETERMINISTIC reasoning over the reloaded report/world whose
# result lives ONLY as an in-memory field of the prior process (grounding, finding_confidence,
# attack_paths, chained_conclusions, entities, predictions, fused_leads/facts, defense) that NOTHING
# reloads. Those MUST re-run on resume — most critically P_GROUNDING, the veracity firewall, whose
# re-execution of each finding's retained oracle_context is REQUIRED (CRUCIBLE invariant #3) for a
# resumed report to be as authoritative as a fresh one and which can only ever DEMOTE. Re-running
# them sends no traffic and is free, so the allowlist below is deliberately minimal: any phase NOT
# named here always re-runs on resume (a fail-safe default — a newly added reasoning phase can never
# be silently dropped from a resumed deliverable).
#
# Note two of those always-re-run phases — P_FUSION and P_DEFENDER — ALSO write to the spine (a
# fused-lead `finding` event per sensor LEAD; the defender gap-report observation + efficacy
# decision). They deliberately stay OUT of this allowlist because they must re-run to recompute
# their in-memory derived fields, but re-running them verbatim would double-count their events. Their
# spine-idempotency is handled by the CALLER, not by skipping them: engage.run_engagement re-runs
# them with a NULL sink (its `_emit_sink`, keyed on `completed_prior`) whenever the prior run already
# recorded the phase, so the computation repeats but the emit does not. This module's contract is
# purely which phase WORK may be skipped; suppressing a re-emit is not skipping the phase.
RESUMABLE_PHASES: frozenset[str] = frozenset({P_SCAN, P_REASONING})

# The ledger status of the record that binds the scan SNAPSHOT to the launch that wrote it (launch-bound
# ledgers only). It is deliberately NOT ``completed``: it never makes a phase skippable, it only carries the
# sha256 of the snapshot bytes so a resume can prove the report on disk is its OWN launch's.
_S_SNAPSHOT = "snapshot"

# Domain separator for the launch tag, so the digest written to the ledger can never collide with (or be
# confused for) any other hash of the same launch identity elsewhere in the system.
_LAUNCH_TAG_DOMAIN = b"vigil.phase-ledger.launch.v1\x00"


def _launch_tag(launch: str) -> str:
    """The value a launch-bound ledger writes into its records: a domain-separated sha256 of the launch
    identity (the owner-signed lease nonce). Only this digest ever reaches the ledger file — the raw identity
    is never written to disk or emitted."""
    return hashlib.sha256(_LAUNCH_TAG_DOMAIN + launch.encode("utf-8")).hexdigest()


class PhaseLedger:
    """Append-only, fail-open phase checkpoint for one engagement.

    Construct once per ``run_engagement`` call. When ``resume`` is set the constructor loads
    the prior run's ledger to learn which phases already completed; :meth:`should_run` /
    :meth:`run_phase` then skip those. Every method swallows its own IO errors — nothing here
    can raise into the engagement.
    """

    def __init__(self, slug: str, *, resume: bool = False, sink: Any = None) -> None:
        self._slug = slug
        self._resume = bool(resume)
        self._sink = sink
        self._completed_prior: set[str] = set()
        # Launch binding (see :meth:`bind_launch`). Unbound by default, which is the per-slug behaviour every
        # operator / greenfield run has always had.
        self._launch_bound = False
        self._launch: str | None = None
        self._path: Path | None = None
        self._report_path: Path | None = None
        try:
            self._path = _paths.phase_ledger_path(slug)
        except Exception:
            self._path = None
        try:
            self._report_path = _paths.phase_report_path(slug)
        except Exception:
            self._report_path = None
        if self._resume:
            self._completed_prior = self._load_completed()

    # ------------------------------------------------------------------ launch binding

    def bind_launch(self, launch: str | None) -> None:
        """Bind this ledger's RESUME STATE to ONE launch. Called once per run by a CUSTOMER launch, before
        any resumable phase is decided; operator / greenfield runs never call it and stay unbound.

        The ledger file and the scan snapshot are keyed per slug, and a customer slug is reused by every
        launch of the same (org, host), so without a binding a resumed launch would treat an EARLIER launch's
        ``completed`` records — and its snapshotted report — as its own. Once bound:

          * every record this run appends carries the launch tag (a digest of ``launch``, never the raw value);
          * only records carrying THIS launch's tag count as completed by a prior run (:meth:`should_run`,
            :meth:`completed_prior`), so an earlier launch's history can never skip this launch's scan;
          * the snapshot is reloaded only when its bytes hash to the digest THIS launch recorded when it
            persisted it (:meth:`load_report`), so an earlier launch's report is never reloaded.

        ``launch=None`` means "a customer launch whose identity could not be read": the ledger is bound to
        NOTHING, so a resume reuses no prior state at all and re-runs the scan. That is the ledger's one
        fail-safe direction — more work, never a skipped-but-not-done phase. TOTAL: never raises (an
        identity that cannot be digested is treated as unknown)."""
        self._launch_bound = True
        try:
            self._launch = _launch_tag(launch) if launch else None
        except Exception:
            self._launch = None   # an unusable identity is an UNKNOWN launch: reuse nothing
        if self._resume:
            self._completed_prior = self._load_completed()

    def _owns(self, rec: dict[str, Any]) -> bool:
        """Whether a prior ledger record belongs to the state this ledger may resume from. Unbound: every
        record (the per-slug behaviour). Bound: only a record carrying THIS launch's tag — an untagged
        record, another launch's record, or any record at all when the launch identity is unknown is not ours."""
        if not self._launch_bound:
            return True
        return self._launch is not None and rec.get("launch") == self._launch

    # ------------------------------------------------------------------ resume state

    def _records(self) -> Iterator[dict[str, Any]]:
        """Every well-formed record in the ledger file, in append order. A missing ledger, an unreadable
        file, or a torn/partial line (a crash mid-write) is skipped, never raised."""
        try:
            if self._path is None or not self._path.is_file():
                return
            text = self._path.read_text(encoding="utf-8")
        except Exception:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue   # a partial/corrupt line never breaks resume
            if isinstance(rec, dict):
                yield rec

    def _load_completed(self) -> set[str]:
        """The set of phases a PRIOR run recorded as ``completed`` — restricted, on a launch-bound ledger,
        to the records of THIS launch (:meth:`_owns`). A missing ledger, an unreadable file, or a
        torn/partial last line (a crash mid-write) all degrade to "nothing known completed" — never a
        raise, so a corrupt checkpoint can only ever cause MORE work (a re-run), never a
        skipped-but-not-done phase."""
        done: set[str] = set()
        for rec in self._records():
            if rec.get("status") == "completed" and self._owns(rec):
                ph = rec.get("phase")
                if isinstance(ph, str):
                    done.add(ph)
        return done

    def _snapshot_digest(self) -> str | None:
        """The sha256 THIS launch recorded for the scan snapshot it last persisted, or None when it recorded
        none (it never snapshotted, the record was lost, or the launch identity is unknown). Launch-bound
        ledgers only."""
        digest: str | None = None
        for rec in self._records():
            if rec.get("phase") == P_SCAN and rec.get("status") == _S_SNAPSHOT and self._owns(rec):
                val = rec.get("sha256")
                digest = val if isinstance(val, str) and val else None
        return digest

    def completed_prior(self) -> set[str]:
        """A copy of the phases a prior run completed (empty unless resuming)."""
        return set(self._completed_prior)

    def should_run(self, phase: str) -> bool:
        """True unless this phase may be SOUNDLY skipped on ``--resume``.

        A phase is skipped iff ALL of: we are resuming, it completed in a prior run, AND it is
        one of the strict :data:`RESUMABLE_PHASES` (the traffic-sending scan, whose snapshot the
        caller reloads, or the spine-emitting reasoning pass, whose re-emit would double-count).
        EVERY OTHER phase always re-runs on resume — it is pure, no-traffic, deterministic
        reasoning over the reloaded report, and skipping it would drop an in-memory-only field of
        the prior process. Most importantly the GROUNDING veracity firewall re-fires on every
        resume: presenting findings without re-running the oracle would violate CRUCIBLE invariant
        #3 (a finding is a fact only if its retained oracle_context RE-FIRES). Re-running these is
        free (no traffic) and required for a resumed report to match a fresh one."""
        if not self._resume:
            return True
        if phase not in RESUMABLE_PHASES:
            return True   # pure-reasoning phase — always re-run on resume (free + required)
        return phase not in self._completed_prior

    # ------------------------------------------------------------------ append (fail-open)

    def _write(self, phase: str, status: str, **extra: Any) -> None:
        """Append one record to the ledger file (no spine emit). TOTAL: any IO failure is swallowed — a
        ledger write can never perturb the engagement. Written owner-only (0600) from creation (no
        world-readable window), matching the framework's at-rest hygiene. A launch-bound ledger tags the
        record with its launch; an unbound ledger writes exactly the record it always has."""
        rec = {"phase": phase, "status": status, "ts": int(time.time()), **extra}
        if self._launch is not None:
            rec["launch"] = self._launch
        try:
            if self._path is not None:
                _paths.secure_dir(self._path.parent)
                fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, default=str,
                                       separators=(",", ":")) + "\n")
        except Exception as exc:
            # A ledger write failure is a recorded no-op (never a raise) — but no longer SILENT: a lost
            # checkpoint is a fail-open the operator should be able to see (a crash afterwards would
            # re-run this phase rather than skip it). Log-only; changes no control flow and no verdict.
            _log.warning("phase_ledger.append_failed", phase=phase, status=status, error=str(exc))

    def _append(self, phase: str, status: str, **extra: Any) -> None:
        """Append one status record and mirror the transition onto the spine. TOTAL (see :meth:`_write`)."""
        self._write(phase, status, **extra)
        self._emit(phase, status)

    def _emit(self, phase: str, status: str) -> None:
        """Mirror the phase transition onto the event spine (best-effort) so the live process
        box can show the current step. Uses the sink's existing ``phase`` ProgressSink method —
        no schema change. A None sink (the default) is a no-op."""
        if self._sink is None:
            return
        try:
            self._sink.phase(f"engage:{phase} {status}", phase=phase, status=status)
        except Exception:
            pass

    def start(self, phase: str) -> None:
        """Record + emit ``phase_started``."""
        self._append(phase, "started")

    def complete(self, phase: str, **extra: Any) -> None:
        """Record + emit ``phase_completed`` — the ONLY status that makes a phase skippable
        on a later resume."""
        self._append(phase, "completed", **extra)

    def skip(self, phase: str) -> None:
        """Record + emit ``phase_skipped`` (a prior-completed phase on resume)."""
        self._append(phase, "skipped")

    def fail(self, phase: str) -> None:
        """Record + emit ``phase_failed`` — a phase whose body raised. NOT completed, so a
        resume RETRIES it."""
        self._append(phase, "failed")

    def halt(self, phase: str) -> None:
        """Record + emit ``phase_halted`` — a phase a reversible PAUSE cut short. It is neither a
        failure (nothing went wrong) nor a completion (its work is not whole): NOT completed, so a
        resume RE-RUNS it rather than treating its partial output as the phase's result."""
        self._append(phase, "halted")

    # ------------------------------------------------------------------ functional wrapper

    def run_phase(self, phase: str, fn: Callable[[], T], *,
                  enabled: bool = True, default: T | None = None) -> T | None:
        """Run one best-effort phase under the ledger and return its value.

        * ``enabled=False``     → skip silently (the phase's opt-in flag is off); return default.
        * skippable on resume   → record ``skipped``; return default WITHOUT running ``fn`` — but
                                  ONLY for a completed :data:`RESUMABLE_PHASES` phase (see
                                  :meth:`should_run`). A pure-reasoning phase always re-runs on
                                  resume, so the veracity firewall is never skipped here.
        * otherwise             → record ``started``, run ``fn``; on success record ``completed``
                                  and return its value; on ANY exception record ``failed`` and
                                  return default (fail-open — matching the existing best-effort
                                  ``try/except: pass`` phases, and leaving the phase un-completed
                                  so a resume retries it).

        ``fn`` may carry its own side effects (mutating the run ``result``); its return value is
        passed straight back. This wrapper NEVER raises."""
        if not enabled:
            # The phase's opt-in flag is off — a legitimate fail-open skip, but make it VISIBLE instead of
            # silent so a skipped step shows up in the record (log-only; returns default exactly as before).
            _log.info("phase_ledger.phase_skipped_disabled", phase=phase)
            return default
        if not self.should_run(phase):
            self.skip(phase)
            return default
        self.start(phase)
        try:
            out = fn()
        except Exception:
            self.fail(phase)
            return default
        self.complete(phase)
        return out

    # ------------------------------------------------------------------ scan snapshot

    def persist_report(self, report: Any) -> None:
        """Snapshot the authoritative :class:`ScanReport` (pydantic JSON) so a resumed run can
        SKIP the traffic-sending scan and reload it. Owner-only on disk (it can hold finding
        evidence). Best-effort: a snapshot failure just means the scan re-runs on resume — it
        never sinks the engagement.

        A launch-bound ledger also records the sha256 of the bytes it wrote, tagged with its launch,
        AFTER the write succeeded. That record is what lets :meth:`load_report` prove the snapshot on
        disk is this launch's own; if either write is lost the resume simply re-runs the scan."""
        try:
            if self._report_path is None or report is None:
                return
            payload = report.model_dump_json()
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            _paths.secure_write(self._report_path, payload)
        except Exception:
            return
        if self._launch is not None:
            self._write(P_SCAN, _S_SNAPSHOT, sha256=digest)

    def load_report(self) -> Any | None:
        """Reload the persisted ScanReport, or None if absent / unreadable / corrupt. A None
        return makes the caller fall back to re-running the scan (fail-open).

        On a launch-bound ledger the snapshot is returned ONLY when its bytes hash to the digest THIS
        launch recorded for it (:meth:`_snapshot_digest`): the snapshot path is per slug, so the file may
        hold an earlier launch's report, and that must never be reloaded as this launch's result."""
        try:
            if self._report_path is None or not self._report_path.is_file():
                return None
            from .scanner.campaign import ScanReport
            if self._launch_bound:
                raw = self._report_path.read_bytes()
                want = self._snapshot_digest()
                if want is None or hashlib.sha256(raw).hexdigest() != want:
                    return None
                return ScanReport.model_validate_json(raw)
            return ScanReport.model_validate_json(
                self._report_path.read_text(encoding="utf-8"))
        except Exception:
            return None
