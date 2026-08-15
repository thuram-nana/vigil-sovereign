"""
framework.v2.phase_ledger — the append-only engagement PHASE LEDGER + ``--resume``.

``run_engagement`` runs a fixed, ordered sequence of phases (preflight, intel recon,
transfer priors, the web scan campaign, intel finalize, finding-confidence, chaining,
grounding, sensor fusion, the defender pass, the reasoning pass). Historically it kept
NO phase identity: a run that crashed in a late phase restarted from scratch — re-crawling
and re-auditing the target from the first request.

This module adds a durable, append-only ledger of each phase's lifecycle and a resume
path that SKIPS the phases a prior run already completed. Its contract, in order of
importance:

  * **Fail-open.** Every ledger write is total: a checkpoint/persist failure is a recorded
    no-op that NEVER raises into — or changes the behaviour of — the engagement. If the
    ledger cannot be written, the run proceeds exactly as if there were no ledger.
  * **Resume-idempotent.** A phase marked ``completed`` in a prior run is skipped on
    ``--resume`` (never re-executed, never double-counted). The one traffic-sending phase —
    the scan — additionally snapshots its authoritative :class:`ScanReport` on completion,
    so a resumed run reloads that report instead of re-crawling/re-auditing. A phase that
    only ``started`` / ``failed`` (crashed before completing) is NOT skipped — it is retried.
  * **State, never a finding.** The ledger records phase STATE only (``started`` /
    ``completed`` / ``skipped`` / ``failed`` + a run-status timestamp). It never mints a
    finding, never promotes a lead to a fact, and feeds no deterministic / oracle math.

The ledger lives at ``paths.phase_ledger_path(slug)`` (``<base>/<slug>.phases.jsonl``); the
scan snapshot at ``paths.phase_report_path(slug)``. Under an ephemeral / ZDR session both
re-root onto the purged tmpfs write base, so resume is a persist-by-default feature that an
ephemeral run deliberately forgoes.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, TypeVar

from .common import paths as _paths

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

    # ------------------------------------------------------------------ resume state

    def _load_completed(self) -> set[str]:
        """The set of phases a PRIOR run recorded as ``completed``. A missing ledger, an
        unreadable file, or a torn/partial last line (a crash mid-write) all degrade to
        "nothing known completed" — never a raise, so a corrupt checkpoint can only ever
        cause MORE work (a re-run), never a skipped-but-not-done phase."""
        done: set[str] = set()
        try:
            if self._path is None or not self._path.is_file():
                return done
            text = self._path.read_text(encoding="utf-8")
        except Exception:
            return done
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue   # a partial/corrupt line never breaks resume
            if isinstance(rec, dict) and rec.get("status") == "completed":
                ph = rec.get("phase")
                if isinstance(ph, str):
                    done.add(ph)
        return done

    def completed_prior(self) -> set[str]:
        """A copy of the phases a prior run completed (empty unless resuming)."""
        return set(self._completed_prior)

    def should_run(self, phase: str) -> bool:
        """False iff we are resuming AND this phase already completed in a prior run."""
        return not (self._resume and phase in self._completed_prior)

    # ------------------------------------------------------------------ append (fail-open)

    def _append(self, phase: str, status: str, **extra: Any) -> None:
        """Append one status record. TOTAL: any IO failure is swallowed — a ledger write can
        never perturb the engagement. Written owner-only (0600) from creation (no
        world-readable window), matching the framework's at-rest hygiene."""
        rec = {"phase": phase, "status": status, "ts": int(time.time()), **extra}
        try:
            if self._path is not None:
                _paths.secure_dir(self._path.parent)
                fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, default=str,
                                       separators=(",", ":")) + "\n")
        except Exception:
            pass   # a ledger write failure is a recorded no-op, never a raise
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

    # ------------------------------------------------------------------ functional wrapper

    def run_phase(self, phase: str, fn: Callable[[], T], *,
                  enabled: bool = True, default: T | None = None) -> T | None:
        """Run one best-effort phase under the ledger and return its value.

        * ``enabled=False``     → skip silently (the phase's opt-in flag is off); return default.
        * resuming + completed  → record ``skipped``; return default WITHOUT running ``fn``.
        * otherwise             → record ``started``, run ``fn``; on success record ``completed``
                                  and return its value; on ANY exception record ``failed`` and
                                  return default (fail-open — matching the existing best-effort
                                  ``try/except: pass`` phases, and leaving the phase un-completed
                                  so a resume retries it).

        ``fn`` may carry its own side effects (mutating the run ``result``); its return value is
        passed straight back. This wrapper NEVER raises."""
        if not enabled:
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
        never sinks the engagement."""
        try:
            if self._report_path is None or report is None:
                return
            _paths.secure_write(self._report_path, report.model_dump_json())
        except Exception:
            pass

    def load_report(self) -> Any | None:
        """Reload the persisted ScanReport, or None if absent / unreadable / corrupt. A None
        return makes the caller fall back to re-running the scan (fail-open)."""
        try:
            if self._report_path is None or not self._report_path.is_file():
                return None
            from .scanner.campaign import ScanReport
            return ScanReport.model_validate_json(
                self._report_path.read_text(encoding="utf-8"))
        except Exception:
            return None
