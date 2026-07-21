"""
fsjob.jobs — the governed background job runner (VIGIL-FUSION F9).

A port of redamon's ``job_runner`` shape (on-disk job meta, status lifecycle, crash recovery on boot),
subordinated to the sovereign core with the ONE inversion that matters for security:

  **Escalation-proof backgrounding.** ``job_spawn`` RE-CHECKS the TARGET tool through the exact same
  sovereign boundary a direct call clears — ``tools.authorize_tool_call`` — which first applies the
  fail-closed ``is_tool_allowed_in_phase`` phase gate (out-of-phase / unregistered ⇒ DENY *before* the
  conjunctive gate is even consulted) and then the injected conjunctive gate. So the agent can NEVER
  background a tool it could not call directly: a permissive gate cannot rescue an out-of-phase tool,
  and no gate wired ⇒ deny. This is the sovereign invariant the red-pen attacks.

Other sovereign properties:

  * **Deterministic ids.** The job id derives from the injected sequence + the (redacted) call, not
    ``uuid``/wallclock — spine-safe and reproducible.
  * **Secret-free provenance.** Job meta is scrubbed through the ONE F3 redaction path before it is
    written to disk or hashed into a signed spine event.
  * **Crash recovery fails closed.** ``recover_on_boot`` flips orphaned ``spawned``/``running`` jobs to
    ``interrupted`` (never silently to ``done``), each transition a signed spine event.
  * **Live execution is deferred.** This slice governs the job *lifecycle + provenance*; it does not
    launch coroutines. The spawn decision, the witnessed meta, and the recovery are the buildable,
    testable core.

Total on untrusted input: every public method returns a structured result and never raises.

Import-clean: stdlib + pydantic-free; reuses ``tools`` (authorize) + the sandbox/spine siblings.
"""

from __future__ import annotations

import functools
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from . import sandbox
from .spine import EventLogError, SpineEventLog
from ..tools import ToolCallVerdict, authorize_tool_call, redact_tool_args

_JOBS_DIR = "jobs"
_META_SUFFIX = ".meta.json"
_SPAWNED, _RUNNING, _INTERRUPTED = "spawned", "running", "interrupted"
_STATUSES = frozenset({_SPAWNED, _RUNNING, "done", "failed", "cancelled", _INTERRUPTED})
_ORPHAN_STATUSES = frozenset({_SPAWNED, _RUNNING})
_MAX_META_BYTES = 256 * 1024


@dataclass(frozen=True)
class JobSpawnResult:
    """The total result of a spawn attempt. ``ok=False`` = the tool could not be backgrounded (denied by
    the phase re-gate / conjunctive gate / fail-closed). ``verdict`` is the underlying tool-call verdict."""

    ok: bool
    reason: str = ""
    job_id: str = ""
    tier: str = ""
    event_id: str = ""
    verdict: Optional[ToolCallVerdict] = None


@dataclass(frozen=True)
class JobActionResult:
    ok: bool
    reason: str = ""
    event_id: str = ""
    data: Optional[Dict[str, Any]] = None


def _job_id(seq: int, tool_name: str, redacted_args: dict) -> str:
    """Deterministic, collision-resistant job id (no uuid/wallclock). The seq guarantees uniqueness
    across spawns; the tool/args make it content-addressed."""
    canonical = json.dumps(redacted_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(f"{seq}\x00{tool_name}\x00{canonical}".encode("utf-8")).hexdigest()
    return digest[:16]


def _total_action(fn: Callable[..., JobActionResult]) -> Callable[..., JobActionResult]:
    @functools.wraps(fn)
    def wrapper(self: "JobRegistry", *args: Any, **kwargs: Any) -> JobActionResult:
        try:
            return fn(self, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — total boundary
            return JobActionResult(False, f"refused ({type(exc).__name__}): {exc}")
    return wrapper


class JobRegistry:
    """Governs the lifecycle + witnessed provenance of background jobs. ``view`` is the registry
    phase-view (tool → allowed phases); ``log`` supplies the injected signer + sequence."""

    def __init__(self, root: str, log: SpineEventLog, *, view: Any,
                 destructive_view: Any = None, engagement: str = "") -> None:
        self._root = sandbox.canonical_root(root)
        self._log = log
        self._view = view
        self._dview = destructive_view
        self._engagement = engagement or log.engagement

    # -- spawn: the escalation-proof re-gate ------------------------------------------------------

    def spawn(self, tool_name: object, tool_args: object, phase: object, *,
              gate: Optional[Callable[..., Any]] = None) -> JobSpawnResult:
        """Background ``tool_name`` ONLY if a direct call would be authorized right now. Never raises."""
        try:
            # RE-GATE through the identical sovereign boundary a direct tool call uses. This calls
            # is_tool_allowed_in_phase FIRST (out-of-phase ⇒ deny before the gate) then the gate.
            verdict = authorize_tool_call(tool_name, tool_args, phase, gate=gate,
                                          view=self._view, destructive_view=self._dview)
            if not verdict.allowed:
                return JobSpawnResult(False, f"backgrounding refused (re-gate): {verdict.reason}",
                                      tier=verdict.tier, verdict=verdict)
            if self._log.signer is None:
                return JobSpawnResult(False, "no signer wired — a job cannot be witnessed (fail-closed)",
                                      tier=verdict.tier, verdict=verdict)
            seq = int(self._log.next_seq())
            redacted = redact_tool_args(tool_args) if isinstance(tool_args, dict) else {}
            job_id = _job_id(seq, str(tool_name), redacted)
            phase_value = getattr(phase, "value", None) or str(phase)
            meta = {
                "job_id": job_id, "tool_name": str(tool_name), "phase": phase_value,
                "tier": verdict.tier, "destructive": verdict.destructive, "status": _SPAWNED,
                "seq": seq, "args": redacted,
            }
            self._write_meta(job_id, meta)
            try:
                event = self._log.append("job.spawn", paths=[self._meta_rel(job_id)],
                                         meta={"tool": str(tool_name), "phase": phase_value,
                                               "tier": verdict.tier, "job_id": job_id,
                                               "destructive": verdict.destructive})
            except EventLogError as exc:
                # Signing failed AFTER the meta was written — remove it so no unwitnessed job persists.
                try:
                    sandbox.unlink_in_sandbox(self._root, self._meta_rel(job_id))
                except OSError:
                    pass
                return JobSpawnResult(False, f"spawn signing failed, rolled back (fail-closed): {exc}",
                                      tier=verdict.tier, verdict=verdict)
            return JobSpawnResult(True, "spawned", job_id=job_id, tier=verdict.tier,
                                  event_id=event.event_id, verdict=verdict)
        except Exception as exc:  # noqa: BLE001 — total boundary
            return JobSpawnResult(False, f"refused ({type(exc).__name__}): {exc}")

    # -- lifecycle transitions --------------------------------------------------------------------

    @_total_action
    def transition(self, job_id: object, new_status: object) -> JobActionResult:
        """Move a job to ``new_status`` (a known status), rewrite its meta, and record a signed
        ``job.transition`` event. Refuses an unknown status or a transition out of a terminal state."""
        if not isinstance(new_status, str) or new_status not in _STATUSES:
            return JobActionResult(False, f"unknown job status {new_status!r}")
        if self._log.signer is None:
            return JobActionResult(False, "no signer wired — transition cannot be witnessed (fail-closed)")
        meta = self._read_meta(job_id)
        if meta is None:
            return JobActionResult(False, "no such job")
        old_status = meta.get("status")
        # Once a job is out of the live states (spawned/running) it is terminal: refuse ANY further
        # transition, including a redundant same-terminal one (done->done), so no extra signed
        # job.transition event ever pollutes the witnessed ledger. An unknown/None status is treated
        # as terminal too (fail-closed).
        if old_status not in _ORPHAN_STATUSES:
            return JobActionResult(False, f"refusing transition from terminal state {old_status!r}")
        meta["status"] = new_status
        jid = str(meta.get("job_id") or job_id)
        self._write_meta(jid, meta)
        event = self._log.append("job.transition", paths=[self._meta_rel(jid)],
                                 meta={"job_id": jid, "from": old_status, "to": new_status})
        return JobActionResult(True, event_id=event.event_id, data={"job_id": jid, "status": new_status})

    @_total_action
    def recover_on_boot(self) -> JobActionResult:
        """Crash recovery: any job left ``spawned``/``running`` from a prior process is flipped to
        ``interrupted`` (fail-closed — never assumed complete), each flip a signed spine event.
        Deterministic order. Malformed/unreadable meta is skipped, never crash-inducing."""
        if self._log.signer is None:
            return JobActionResult(False, "no signer wired — recovery cannot be witnessed (fail-closed)")
        recovered: List[str] = []
        for job_id in self._list_job_ids():
            meta = self._read_meta(job_id)
            if meta is None or meta.get("status") not in _ORPHAN_STATUSES:
                continue
            old = meta.get("status")
            meta["status"] = _INTERRUPTED
            self._write_meta(job_id, meta)
            try:
                self._log.append("job.transition", paths=[self._meta_rel(job_id)],
                                 meta={"job_id": job_id, "from": old, "to": _INTERRUPTED,
                                       "recovery": True})
            except EventLogError:
                continue
            recovered.append(job_id)
        return JobActionResult(True, data={"recovered": recovered})

    # -- reads ------------------------------------------------------------------------------------

    def status(self, job_id: object) -> Optional[Dict[str, Any]]:
        """The (secret-free) meta of one job, or ``None`` if absent/unreadable. Never raises."""
        try:
            return self._read_meta(job_id)
        except Exception:  # noqa: BLE001 — total
            return None

    def list(self) -> List[Dict[str, Any]]:
        """All jobs' meta, sorted by job id (deterministic). Malformed entries skipped. Never raises."""
        out: List[Dict[str, Any]] = []
        try:
            for job_id in self._list_job_ids():
                meta = self._read_meta(job_id)
                if meta is not None:
                    out.append(meta)
        except Exception:  # noqa: BLE001 — total
            return out
        return out

    # -- on-disk meta (via the low-level sandbox kernel; bypasses the tool-layer protected check) --

    def _meta_rel(self, job_id: str) -> str:
        return f"{_JOBS_DIR}/{job_id}{_META_SUFFIX}"

    def _write_meta(self, job_id: str, meta: dict) -> None:
        sandbox.makedirs_in_sandbox(self._root, (_JOBS_DIR,))
        blob = json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        sandbox.write_bytes(self._root, self._meta_rel(job_id), blob, overwrite=True, create_parents=True)

    def _read_meta(self, job_id: object) -> Optional[Dict[str, Any]]:
        if not isinstance(job_id, str) or not job_id:
            return None
        try:
            raw = sandbox.read_bytes(self._root, self._meta_rel(job_id), max_bytes=_MAX_META_BYTES)
        except (FileNotFoundError, sandbox.PathEscapeError, OSError):
            return None
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        return obj if isinstance(obj, dict) else None

    def _list_job_ids(self) -> List[str]:
        try:
            names = sandbox.listdir_in_sandbox(self._root, _JOBS_DIR)
        except (FileNotFoundError, sandbox.PathEscapeError, OSError):
            return []
        return sorted(n[:-len(_META_SUFFIX)] for n in names if n.endswith(_META_SUFFIX))
