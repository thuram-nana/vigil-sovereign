"""
fireteam.wave_progress — the fail-open wave-resume checkpoint (net-new).

A fireteam wave fans a handful of specialist members out under bounded concurrency. Two durability
gaps live in the base orchestrator:

  * member spine writes are buffered in the :class:`~fireteam.spine_queue.SingleWriterSpineQueue` and
    only drained by a SINGLE ``flush`` AFTER ``asyncio.gather`` returns — so a crash mid-wave loses
    EVERY member's spine record, even the ones that finished;
  * a wave keeps no record of which members completed — so a re-run re-executes the whole wave,
    re-spending credit and re-touching the target for members that already finished.

This module is the resume half of the fix (the flush half lives in ``spine_queue.flush_member`` and the
orchestrator). It is a small, **fail-open**, JSON-backed store that records — per ``wave_id``, per
``member_id`` — the member's finished :class:`~fireteam.models.MemberResult` plus the spine refs that
member's records were flushed to. On a resumed wave the orchestrator loads this store and SKIPS the
already-completed members (restoring their result/refs) instead of re-running them.

Design invariants (all load-bearing for the slice):

  * **Fail-open / total.** Every read and every write is wrapped so a missing/corrupt/unwritable store
    is a recorded no-op, never an exception: a load returns ``{}`` (the wave simply re-runs everyone),
    a record silently drops. A checkpoint failure can only ever cost re-execution, never break a wave.
  * **Resume-idempotent, at-least-once.** The orchestrator records a member ONLY after its spine
    records are flushed (flush-then-record). So if the flush lands but the record is dropped, the
    member is re-run on resume (its records written again — acceptable at-least-once duplication); if
    the record lands, the member is skipped (its records already durable, never re-written). A member
    is never *skipped without its records being durable*.
  * **A checkpoint records STATE, never a fact.** A restored ``MemberResult`` carries the member's
    LEADS/CLAIMS exactly as it produced them; it mints nothing. Facts are still minted solely by the
    injected oracle in ``fireteam.collect`` at fan-in. Restoring a member is not promoting a lead.
  * **Determinism.** No wallclock and no RNG touch any spine/oracle math here. A single ``recorded_at``
    epoch stamp is written for operator debugging only and is never read back into any decision.

Import-clean: stdlib + pydantic (via :class:`MemberResult`) only. No ``framework``/``strix`` import, no
network — this is integration-side and stays behind the two-env boundary (shared types come from within
:mod:`vigil_integration`, never across it).
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Optional

from .models import MemberResult

_SCHEMA = "vigil.fireteam.wave_progress.v1"


@dataclass(frozen=True)
class MemberProgress:
    """One completed member's restored checkpoint: its finished result + the spine refs its records
    were flushed to on the run that completed it."""

    result: MemberResult
    refs: tuple[str, ...] = ()


class WaveProgressStore:
    """A fail-open, JSON-file wave-resume checkpoint keyed by ``wave_id`` then ``member_id``.

    The store is a plain read-modify-write JSON document; a wave has at most a handful of members so
    the O(members) rewrite per record is irrelevant. It is safe under the orchestrator's asyncio
    concurrency because :meth:`record` is fully synchronous (no ``await``), so the event loop cannot
    interleave two record calls. It is NOT designed for cross-process concurrent writers — one process
    owns a wave at a time (that is what "resume" means).
    """

    def __init__(self, path: Any) -> None:
        # Store the path but NEVER touch the filesystem in __init__ — construction must not raise.
        try:
            self._path = os.fspath(path)
        except Exception:  # noqa: BLE001 — a bad path degrades to a disabled (no-op) store
            self._path = ""

    # -- read -----------------------------------------------------------------------------------
    def _load_doc(self) -> dict[str, Any]:
        """Read the whole JSON document, fail-open to ``{}`` on any error (missing/corrupt/permission)."""
        if not self._path:
            return {}
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            return doc if isinstance(doc, dict) else {}
        except Exception:  # noqa: BLE001 — a missing/corrupt store means "nothing done yet"
            return {}

    def completed(self, wave_id: str) -> dict[str, MemberProgress]:
        """Return the already-completed members for ``wave_id`` as ``{member_id: MemberProgress}``.

        Fail-open: any read/parse error (or a member entry that no longer validates) yields an EMPTY
        map for that wave, so the wave simply re-runs from scratch — a corrupt checkpoint can never
        cause a member to be wrongly skipped, only wrongly re-run. Never raises."""
        out: dict[str, MemberProgress] = {}
        try:
            waves = self._load_doc().get("waves")
            if not isinstance(waves, dict):
                return {}
            wave = waves.get(str(wave_id))
            if not isinstance(wave, dict):
                return {}
            members = wave.get("members")
            if not isinstance(members, dict):
                return {}
            for mid, entry in members.items():
                if not isinstance(entry, dict):
                    continue
                try:
                    result = MemberResult.model_validate(entry.get("result"))
                except Exception:  # noqa: BLE001 — drop a single un-restorable member, keep the rest
                    continue
                raw_refs = entry.get("refs")
                refs = tuple(str(r) for r in raw_refs) if isinstance(raw_refs, (list, tuple)) else ()
                out[str(mid)] = MemberProgress(result=result, refs=refs)
        except Exception:  # noqa: BLE001 — total on any malformation
            return {}
        return out

    # -- write ----------------------------------------------------------------------------------
    def record(self, wave_id: str, member_id: str, result: Any,
               refs: Optional[list[str]] = None) -> bool:
        """Persist one COMPLETED member (its result + flushed spine refs), fail-open.

        Returns ``True`` iff the checkpoint was durably written, ``False`` on any failure — the caller
        treats a ``False`` as "not checkpointed" and the member is simply re-run on resume. NEVER
        raises: a serialization, permission, or disk error degrades to ``False``.

        Called by the orchestrator AFTER the member's spine records are flushed (flush-then-record), so
        a recorded member's records are already durable (never skipped-without-durable-records)."""
        if not self._path:
            return False
        try:
            payload_result = result.model_dump(mode="json") if isinstance(result, MemberResult) \
                else MemberResult.model_validate(result).model_dump(mode="json")
        except Exception:  # noqa: BLE001 — an un-serializable result is a dropped checkpoint, not a crash
            return False
        clean_refs = [str(r) for r in (refs or [])]
        try:
            doc = self._load_doc()
            if not isinstance(doc.get("waves"), dict):
                doc["schema"] = _SCHEMA
                doc["waves"] = {}
            wave = doc["waves"].setdefault(str(wave_id), {})
            if not isinstance(wave.get("members"), dict):
                wave["members"] = {}
            wave["members"][str(member_id)] = {
                "result": payload_result,
                "refs": clean_refs,
                # debug-only stamp; NEVER read back into any spine/oracle/decision math (determinism).
                "recorded_at": int(time.time()),
            }
            return self._atomic_write(doc)
        except Exception:  # noqa: BLE001 — total: any failure is a dropped checkpoint
            return False

    def _atomic_write(self, doc: dict[str, Any]) -> bool:
        """Write the document atomically (temp file + ``os.replace``) so a crash mid-write never leaves
        a torn/corrupt checkpoint (a torn checkpoint would fail-open to re-run anyway, but atomicity
        keeps already-recorded members intact). Fail-open: returns ``False`` on any error."""
        try:
            data = json.dumps(doc, sort_keys=True, ensure_ascii=False)
        except Exception:  # noqa: BLE001
            return False
        try:
            directory = os.path.dirname(self._path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".wave-progress-", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(data)
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except OSError:
                        pass  # fsync is best-effort; some filesystems/handles reject it
                os.replace(tmp, self._path)
                return True
            except Exception:  # noqa: BLE001 — clean up the temp file, report failure
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                return False
        except Exception:  # noqa: BLE001 — total on any filesystem error
            return False
