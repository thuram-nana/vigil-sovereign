"""
proof.degradation — a TYPED ``verification_degraded`` state for the proof subsystem (inv 12 / S9).

THE GAP THIS CLOSES. Six sites on the Strix→VIGIL proof path used to swallow a proof failure silently, so
four very different realities collapsed into ONE UI state: the console rendered ``pending`` whenever the
proof-record list was empty, and that single state meant, indistinguishably, "the target is genuinely clean"
OR "the proof subsystem never installed (Caido down / bootstrap crashed)" OR "a finding's evidence capture
failed" OR "the mint crashed". An operator reading "no proofs" as "clean" over a subsystem that was actually
DOWN is exactly the optimistic-degradation failure invariant 12 forbids.

WHAT THIS MODULE DOES. It gives each swallow site a TYPED cause to record instead of passing silently,
persists the causes to the run's proof manifest (``<run_dir>/proofs/_degraded.json`` — plain JSON the
console reads with no import of this package, alongside the proof records), and derives the disposition the
UI renders in place of the single ``pending`` boolean.

DOCTRINE (non-negotiable). While the proof subsystem is degraded a FACT and a CLEAN verdict are IMPOSSIBLE:
an empty proof list no longer means "nothing found" — it means "we could not run the check here", so the run
stays LEAD/INCONCLUSIVE (:func:`summarize` never reports ``clean`` while any degradation is recorded, and
the per-finding mint paths already return no FACT on failure). The recorder NEVER raises — a degradation
recorder that broke the scan would be worse than the gap it reports — and this module NEVER imports
``framework`` (module scope is stdlib-only; FATAL-2).

TYPED CAUSES
  * ``PROOF_SUBSYSTEM_UNAVAILABLE`` — the proof_sink bootstrap did not install (the integration import
    failed, the run's governance authority was unprovisionable, or the gateway/Caido was down): NO finding
    on this run can be verified, so an empty proof list must NOT read as clean.
  * ``CAPTURE_FAILED`` — a finding-specific evidence capture was attempted and raised: THAT finding cannot
    reach a FACT (it stays a LEAD) and we do not know it is clean.
  * ``REDRIVE_FAILED`` — a web-re-drivable finding reached VIGIL's OWN gated re-drive and the re-drive
    EXECUTION raised (gateway down / network crash / framework import error inside the mint callback): that
    finding cannot reach a FACT and its absence must NOT read as clean. A LEGITIMATE non-confirmation
    (missing endpoint / gate refusal / oracle non-fire) does NOT raise and stays a plain LEAD — only a
    RAISED execution failure degrades.
  * ``MINT_FAILED`` — an allowed, captured finding reached the mint and the mint crashed: same LEAD floor.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

# The proofs/ manifest file the degradation causes accumulate in. Named with a leading underscore and skipped
# by every proof-record reader (``proof.run.read_proofs`` / ``console.api.proof_list``) so it is never
# mistaken for a proof record. MUST match the skip lists in those readers.
DEGRADED_NAME = "_degraded.json"
PROOFS_SUBDIR = "proofs"

# Typed causes. Stable string constants (they are written to disk + surfaced in the UI).
PROOF_SUBSYSTEM_UNAVAILABLE = "proof_subsystem_unavailable"
CAPTURE_FAILED = "capture_failed"
REDRIVE_FAILED = "redrive_failed"
MINT_FAILED = "mint_failed"

_KINDS = frozenset({PROOF_SUBSYSTEM_UNAVAILABLE, CAPTURE_FAILED, REDRIVE_FAILED, MINT_FAILED})

# The non-degraded dispositions (the healthy states). ``nothing_found`` is the ONLY honest "clean" state and
# is reachable ONLY when no degradation was recorded.
NOTHING_FOUND = "nothing_found"
HAS_PROOFS = "has_proofs"

# Severity order for choosing the PRIMARY disposition when several causes are present: a subsystem-wide
# outage dominates a per-finding capture/mint failure (it says nothing on the run can be trusted).
_PRIMARY_ORDER = (PROOF_SUBSYSTEM_UNAVAILABLE, MINT_FAILED, REDRIVE_FAILED, CAPTURE_FAILED)


def _manifest_path(run_dir: str | os.PathLike) -> Path:
    return Path(run_dir) / PROOFS_SUBDIR / DEGRADED_NAME


def record_degradation(
    run_dir: str | os.PathLike,
    kind: str,
    *,
    where: str = "",
    detail: str = "",
) -> bool:
    """Append a TYPED degradation cause to ``<run_dir>/proofs/_degraded.json``. NEVER raises.

    Deduplicated by ``(kind, where)`` so a swallow site that fires per-finding does not flood the manifest
    (a ``count`` is incremented instead). ``detail`` is a short, bounded, human-readable note (e.g. an
    exception TYPE name — never raw exception text, which could be huge or leak target data); it is clipped.
    Returns True iff a cause was recorded (including an incremented duplicate), False on any error or an
    unknown ``kind`` (fail-closed: an unrecognised cause is dropped rather than corrupting the manifest).
    """
    try:
        if kind not in _KINDS:
            return False
        where = str(where or "")[:200]
        detail = str(detail or "")[:200]
        d = Path(run_dir) / PROOFS_SUBDIR
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        path = _manifest_path(run_dir)
        causes: list[dict[str, Any]] = []
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
                if detail and not c.get("detail"):
                    c["detail"] = detail
                break
        else:
            causes.append({"kind": kind, "where": where, "detail": detail, "count": 1})
        causes.sort(key=lambda c: (str(c.get("kind", "")), str(c.get("where", ""))))
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"degradations": causes}, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)      # atomic swap so a torn write never leaves a half-manifest
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True
    except Exception:  # noqa: BLE001 — a degradation recorder must NEVER raise into the scan path
        return False


def record_from_env(kind: str, *, where: str = "", detail: str = "") -> bool:
    """Record a degradation against the run dir the VIGIL console exported (``VIGIL_PROOF_RUN_DIR``).

    NO-OP (returns False) when the env var is unset — i.e. standalone Strix, where there is no VIGIL run to
    degrade, so vendored behaviour stays byte-identical. This is the entry the vendored Strix swallow sites
    call (via a best-effort, function-local import), so a cause raised deep in the offense process still
    reaches the run manifest the console reads."""
    try:
        run_dir = os.environ.get("VIGIL_PROOF_RUN_DIR")
        if not run_dir:
            return False
        return record_degradation(run_dir, kind, where=where, detail=detail)
    except Exception:  # noqa: BLE001 — never raise
        return False


def read_degradations(run_dir: str | os.PathLike) -> list[dict[str, Any]]:
    """Every recorded degradation cause for a run (plain dicts ``{kind, where, detail, count}``). Total on a
    missing/unreadable manifest (returns ``[]``); never raises."""
    try:
        path = _manifest_path(run_dir)
        if not path.is_file():
            return []
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            return []
        out = [c for c in (doc.get("degradations") or []) if isinstance(c, dict) and c.get("kind") in _KINDS]
        return out
    except (OSError, ValueError):
        return []


def summarize(
    *,
    n_records: int,
    facts: int,
    leads: int,
    denied: int,
    degradations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Derive the run's proof disposition from its proof-record counts + recorded degradations.

    Returns a dict the console merges into ``proof_list``:

      * ``verification_degraded`` — True iff any degradation was recorded. When True, a FACT and a CLEAN
        verdict are BOTH off the table for the run's overall reading: ``clean`` is False and ``disposition``
        is the (most-global) degradation kind, so an empty proof list is never rendered as "nothing found".
      * ``disposition`` — the single distinguishing state, replacing the old ``pending`` boolean:
        ``proof_subsystem_unavailable`` / ``mint_failed`` / ``capture_failed`` (degraded), else
        ``nothing_found`` (healthy + no records) or ``has_proofs`` (healthy + records).
      * ``degraded_causes`` — the recorded causes rolled up per ``kind`` with a total ``count``.
      * ``clean`` — the ONLY honest "nothing to worry about" reading: healthy subsystem AND no records.
    """
    counts: dict[str, int] = {}
    for c in degradations:
        k = str(c.get("kind", ""))
        if k in _KINDS:
            counts[k] = counts.get(k, 0) + int(c.get("count", 1) or 1)
    verification_degraded = bool(counts)

    if verification_degraded:
        disposition = next((k for k in _PRIMARY_ORDER if k in counts), PROOF_SUBSYSTEM_UNAVAILABLE)
    elif n_records <= 0:
        disposition = NOTHING_FOUND
    else:
        disposition = HAS_PROOFS

    degraded_causes = [{"kind": k, "count": counts[k]} for k in _PRIMARY_ORDER if k in counts]

    return {
        "verification_degraded": verification_degraded,
        "disposition": disposition,
        "degraded_causes": degraded_causes,
        # CLEAN is impossible while degraded: only a healthy subsystem with zero records is honestly clean.
        "clean": (not verification_degraded) and n_records <= 0,
    }
