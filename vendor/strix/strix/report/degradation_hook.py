"""VIGIL inv 12 (S9): the vendored-side bridge for recording a TYPED proof-degradation cause.

Six sites on the Strix->VIGIL proof path used to swallow a proof failure silently, so "target
clean", "proof subsystem never installed", "capture failed" and "mint crashed" collapsed to one
console state. This module lets each vendored swallow site record a TYPED cause against the run the
VIGIL console exported (``VIGIL_PROOF_RUN_DIR``) WITHOUT coupling the vendored tree to the
integration package at module scope.

A bare vendored checkout (no ``vigil_integration``, or ``VIGIL_PROOF_RUN_DIR`` unset) is a SILENT
no-op -- vendored behaviour stays byte-identical. When the run context IS set the cause is routed to
``vigil_integration.proof.degradation`` (the source of truth for the manifest format); if that
package is itself unimportable -- the most extreme "subsystem unavailable" -- a stdlib fallback
writes the same manifest shape directly, so even a broken integration install stays distinguishable
from a clean target. NEVER raises.

The kind strings below MUST equal ``vigil_integration.proof.degradation``'s constants -- a
drift-guard test in ``integration/tests/test_production_invariants.py`` pins them.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path


logger = logging.getLogger(__name__)

# Typed causes -- MUST match vigil_integration.proof.degradation (pinned by an inv-12 drift guard).
PROOF_SUBSYSTEM_UNAVAILABLE = "proof_subsystem_unavailable"
CAPTURE_FAILED = "capture_failed"
REDRIVE_FAILED = "redrive_failed"
MINT_FAILED = "mint_failed"


def record(kind: str, where: str, exc: BaseException) -> None:
    """Record a TYPED proof-degradation cause against the exported VIGIL run. Best-effort."""
    run_dir = os.environ.get("VIGIL_PROOF_RUN_DIR")
    if not run_dir:
        return  # standalone Strix: no VIGIL run to degrade -- byte-identical no-op
    detail = type(exc).__name__
    try:
        from vigil_integration.proof.degradation import record_from_env  # noqa: PLC0415

        if record_from_env(kind, where=where, detail=detail):
            return
    except Exception:
        # integration unimportable -- fall through to the stdlib writer (exc_info satisfies BLE001)
        logger.debug("inv-12 record via integration failed; using stdlib fallback", exc_info=True)
    _stdlib_record(run_dir, kind, where, detail)


def _stdlib_record(run_dir: str, kind: str, where: str, detail: str) -> None:
    """Write the degradation manifest with stdlib only (the SAME shape proof.degradation uses) for
    the case where ``vigil_integration`` is unavailable. Merges + dedups by ``(kind, where)``.
    Never raises."""
    try:
        d = Path(run_dir) / "proofs"
        d.mkdir(parents=True, exist_ok=True)
        path = d / "_degraded.json"
        causes: list[dict] = []
        if path.is_file():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(doc, dict) and isinstance(doc.get("degradations"), list):
                    causes = [c for c in doc["degradations"] if isinstance(c, dict)]
            except (OSError, ValueError):
                causes = []
        for c in causes:
            if c.get("kind") == kind and str(c.get("where", "")) == where:
                c["count"] = int(c.get("count", 1)) + 1
                break
        else:
            causes.append({"kind": kind, "where": where, "detail": detail, "count": 1})
        causes.sort(key=lambda c: (str(c.get("kind", "")), str(c.get("where", ""))))
        # Atomic write: a torn/half-written manifest must never be observed (mirrors
        # vigil_integration.proof.degradation.record_degradation). Write a sibling .tmp then os.replace.
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"degradations": causes}, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except Exception:
        # a degradation recorder must never break a scan (exc_info satisfies BLE001)
        logger.debug("inv-12 stdlib degradation record failed", exc_info=True)
