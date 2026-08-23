"""
inconclusive_manifest — the SINGLE stdlib source of truth for the fusion INCONCLUSIVE-COVERAGE artifact.

A fusion sensor that returns INCONCLUSIVE (a declared surface it could NOT assess — a missing cloud/K8s
prerequisite meant NOTHING was assessed there) must never vanish into a silent CLEAN. The run persists each
such surface to a FRAMEWORK-OWNED, stdlib-readable artifact ``<run_dir>/_inconclusive.json``; every consumer
(the dossier, the console proof list, the posture attestation) reads it back through the ONE parser here so
producer and readers can never drift.

WHY ONE MODULE. The schema used to be hand-duplicated in three places — the writer
(``engage_fusion.write_inconclusive_artifact``), the dossier reader (``report.dossier._read_sensor_inconclusive``)
and the console reader (``console.api._sensor_inconclusive_summary``). Three copies of a fail-closed parser are
three chances to disagree; collapsing them here means a shape change is made once.

FATAL-2. This module imports only the Python stdlib — the framework writes it and framework/console read it
over a plain file contract, exactly as the proof-degradation manifest (``proofs/_degraded.json``) is written
by integration and read by the framework with stdlib only. Nothing here imports sigil or the integration
package; the integration side (the posture attestation) may import THIS module function-locally to read the
same file, but the reader stays a pure stdlib file read either way.

FAIL-CLOSED. The writer only ever emits this file on a GENUINE inconclusive (>= 1 collected surface), so its
mere PRESENCE (a non-empty file) means the run is coverage-incomplete — an empty finding set over a surface we
could not look at is not "nothing found". Therefore a present artifact that does NOT parse as a valid manifest
(``{}``, ``[]``, ``{"foo": "bar"}``, ``{"inconclusive": []}``, a row-less / garbage-row list, or unparseable
bytes) still marks the run coverage-incomplete — it just cannot NAME the surfaces, so the reader flags it
``unparsed`` and the caller shows the generic "could not be parsed — treat as inconclusive" notice. Only an
ABSENT or EMPTY file is clean.

DETERMINISTIC. The writer sorts + dedups + counts (no wall-clock / rng) and writes canonical JSON via an
atomic tmp + ``os.replace`` swap, so two runs with the same surfaces produce byte-identical bytes and a torn
write never leaves a half-manifest.

SCHEMA  <run_dir>/_inconclusive.json  ==
    {"inconclusive": [{"sensor": "<sensor>", "missing_prerequisite": "<prereq>", "count": <int>}, ...]}
  sorted by (sensor, missing_prerequisite).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# The run-dir artifact filename (the single constant every producer/reader keys on).
INCONCLUSIVE_ARTIFACT = "_inconclusive.json"


def coerce_surface(item: Any) -> tuple[str, str]:
    """Coerce one collected surface — a ``(sensor, missing_prerequisite)`` pair or a
    ``{"sensor", "missing_prerequisite"}`` dict — to a normalized ``(sensor, missing)`` string pair.
    Never raises; an uncoercible item becomes ``("", "")`` (the writer then drops it)."""
    try:
        if isinstance(item, dict):
            return (str(item.get("sensor") or "").strip(),
                    str(item.get("missing_prerequisite") or "").strip())
        sensor, missing = item
        return (str(sensor or "").strip(), str(missing or "").strip())
    except Exception:
        return ("", "")


def write_manifest(run_dir: Any, surfaces: Any) -> bool:
    """Persist the fusion pass's INCONCLUSIVE ``surfaces`` to ``<run_dir>/_inconclusive.json`` (see the
    SCHEMA above). Written ONLY when there is at least one genuine inconclusive surface — a fully-assessed
    run (empty ``surfaces``) writes NOTHING, so its dossier renders byte-identically to before. Deterministic
    (sorted + deduped + counted, no wall-clock/rng) and atomic (tmp + ``os.replace``). Best-effort/total: any
    error returns False and never raises into the fusion/engage pass. Returns True iff the file was written."""
    try:
        counts: dict[tuple[str, str], int] = {}
        for item in surfaces or ():
            sensor, missing = coerce_surface(item)
            if not sensor:
                continue
            counts[(sensor, missing)] = counts.get((sensor, missing), 0) + 1
        if not counts:
            return False   # no genuine inconclusive surface -> no artifact (byte-identical clean path)
        rows = [{"sensor": s, "missing_prerequisite": m, "count": counts[(s, m)]}
                for (s, m) in sorted(counts)]
        d = Path(run_dir)
        d.mkdir(parents=True, exist_ok=True)
        path = d / INCONCLUSIVE_ARTIFACT
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"inconclusive": rows}, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)         # atomic swap
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True
    except Exception:
        return False


def _valid_rows(doc: Any) -> "list[dict] | None":
    """Return the manifest's normalized rows IFF ``doc`` is a conforming manifest — a dict whose
    ``inconclusive`` value is a NON-EMPTY list in which EVERY row is a dict naming a non-empty ``sensor``.
    Any deviation (wrong top type, missing/mistyped key, an empty list, or a single garbage row) returns
    None so the reader fails CLOSED to the un-nameable state rather than papering over a wrong-shape file."""
    if not isinstance(doc, dict):
        return None
    rows = doc.get("inconclusive")
    if not isinstance(rows, list) or not rows:
        return None
    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            return None                       # a garbage row taints the whole manifest (fail closed)
        sensor = str(r.get("sensor") or "").strip()
        if not sensor:
            return None
        try:
            count = int(r.get("count", 1) or 1)
        except (TypeError, ValueError):
            count = 1
        out.append({"sensor": sensor,
                    "missing_prerequisite": str(r.get("missing_prerequisite", "") or ""),
                    "count": count})
    return out


def read_manifest(run_dir: Any) -> dict:
    """Read ``<run_dir>/_inconclusive.json`` (stdlib only; never trusts the producer) and derive the run's
    coverage state. Returns::

        {"present": bool,               # a non-empty artifact EXISTS
         "valid": bool,                 # it parsed as a conforming, nameable manifest
         "unparsed": bool,              # present but NOT a valid manifest (fail-closed generic notice)
         "coverage_incomplete": bool,   # == present: any present artifact blocks a clean reading
         "surfaces": [{sensor, missing_prerequisite, count}, ...]}   # named only when valid, sorted

    FAIL-CLOSED: the writer emits the file ONLY on a genuine inconclusive, so PRESENCE alone makes the run
    coverage-incomplete — a present-but-unparseable / wrong-shape / empty-list artifact still blocks clean
    (it just cannot be named). ABSENT or EMPTY => a clean, byte-identical reading."""
    present = False
    surfaces: list[dict] = []
    try:
        path = Path(run_dir) / INCONCLUSIVE_ARTIFACT
        if path.is_file():
            raw = path.read_text(encoding="utf-8")
            if raw.strip():
                present = True     # from here a parse/shape failure fails CLOSED (still coverage-incomplete)
                try:
                    doc = json.loads(raw)
                except ValueError:
                    doc = None
                rows = _valid_rows(doc)
                if rows is not None:
                    surfaces = rows
    except OSError:
        # a file we cannot even read is treated as absent (nothing to key a run to); never raises.
        present = present
    valid = present and bool(surfaces)
    return {
        "present": present,
        "valid": valid,
        "unparsed": present and not valid,
        "coverage_incomplete": present,
        "surfaces": sorted(surfaces, key=lambda s: (s["sensor"], s["missing_prerequisite"])),
    }
