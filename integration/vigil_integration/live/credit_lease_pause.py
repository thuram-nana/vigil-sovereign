"""credit_lease_pause — a durable, nonce-scoped, REVERSIBLE pause marker on the cross-plane seam.

This is the sibling of ``credit_lease_broker``'s settlement marker, but with the OPPOSITE purpose and the
OPPOSITE failure mode. A settlement is a one-way close-out (settled stays settled); a PAUSE is a reversible
operational halt — an operator pauses a lease ``(slug, nonce)`` to stop a run proceeding, and later clears it
to resume. It carries the SAME write/read discipline as the settlement marker (atomic write, path containment,
a ``{nonces:[...]}`` set under ``<base>/credit-lease-pauses/<slug>.json``), modelled one-for-one on it:

  ``<base>/credit-lease-pauses/<slug>.json`` — the pause set::

      { "schema_version": 1, "kind": "vigil-credit-lease-pause-v1", "slug": "<slug>", "nonces": ["<nonce>"] }

This is a NEW, SEPARATE module (never a second writer of the broker's files): it writes ONLY the pauses dir,
a sibling of both the leases and settlements dirs, so a ``*.json`` glob of the leases dir never picks it up.

DEFAULT-OFF + money-doctrine-neutral: the substrate adds NO behaviour until an operator records a pause (no
marker file ⇒ ``is_lease_paused`` is False ⇒ nothing changes), and the marker carries NO credit / amount /
catalog / signature field — pausing moves NO money, it only sets a reversible halt flag for a nonce.

FATAL-2 / import-clean: ``vigil_core`` + stdlib only at module scope (the three filesystem primitives are
imported from the import-clean ``credit_lease_broker``, which itself imports only ``vigil_core`` + stdlib); no
``framework`` / offense import, so it is safe to import on BOTH planes (sovereign writer, keyless reader).

----------------------------------------------------------------------------------------------------
CRITICAL: the reader fails CLOSED — the DELIBERATE inversion of ``is_lease_settled``
----------------------------------------------------------------------------------------------------
``is_lease_settled`` fails OPEN to False: "settled" is a safety-ADD on top of the tombstone + single-use
floor, so an unreadable settlement marker safely degrades to "not settled" (the primary revocation still
holds). A PAUSE reader is the mirror image and MUST fail CLOSED. If a pause marker EXISTS but is unreadable
/ corrupt / permission-denied, ``is_lease_paused`` returns **True** (treat as PAUSED / halt) — because a
pause reader that failed to False would let a run that was SUPPOSED to be paused proceed, which is the exact
safety violation a pause exists to prevent. "When the pause state cannot be positively read as 'not paused',
halt." The ONLY two states that return False are: (1) no marker file at all — the DEFAULT-OFF state, nothing
was ever paused; and (2) a cleanly-read marker whose nonce set does NOT contain this nonce. Everything else —
an unsafe/unresolvable slug, or an existing-but-unreadable/corrupt/foreign marker — returns True.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

# Reuse the broker's module-level filesystem primitives verbatim (atomic write, safe id component, resolved
# path-containment barrier) — the task's instruction, and it keeps a single audited copy of each. Importing
# credit_lease_broker pulls in only vigil_core + stdlib, so this module stays FATAL-2 / both-plane safe.
from vigil_integration.live.credit_lease_broker import (
    _atomic_write_json,
    _contained_child,
    _safe_component,
)

__all__ = [
    "pauses_root",
    "pause_path",
    "record_lease_pause",
    "clear_lease_pause",
    "is_lease_paused",
]

_PAUSE_DIRNAME = "credit-lease-pauses"
_PAUSE_SCHEMA = "vigil-credit-lease-pause-v1"
_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------------------------------
# paths (twin of credit_lease_broker.settlements_root / settlement_path)
# ---------------------------------------------------------------------------------------------------


def pauses_root(base_dir: Any) -> Path:
    """The pause-marker root ``<base>/credit-lease-pauses`` (a SIBLING of the leases and settlements dirs, so
    a ``*.json`` glob of the leases dir never picks up a pause marker)."""
    return Path(base_dir) / _PAUSE_DIRNAME


def pause_path(base_dir: Any, slug: Any) -> Optional[Path]:
    """The pause-marker path for ``slug``, or None if the slug is unsafe as a path component (defence in
    depth: a crafted slug can never be joined into a path that escapes the pauses dir)."""
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(pauses_root(base_dir), f"{safe}.json")


# ---------------------------------------------------------------------------------------------------
# writers — record (pause) / clear (resume). Fail-OPEN read-modify-write, mirroring the broker's writers.
#
# CONCURRENCY CONTRACT (same as the broker's settlement writers): each write is atomic (temp+rename via
# _atomic_write_json), so a reader never sees a torn file. But record/clear are a non-atomic READ-modify-WRITE
# of the per-slug nonce set: two UNSERIALIZED concurrent writers on the SAME slug are last-write-wins, which
# could DROP a concurrent pause. Callers MUST serialize writes per slug — the consumers (PR-2+: the sovereign
# Provisioner) hold the per-store spine_lock across the verify -> pause/resume transaction, exactly as
# settle_launch does, so the RMW is serialized at the one call site. This substrate is inert until then and
# adds no lock of its own (matching the settlement marker); the fail-CLOSED reader is the backstop.
# ---------------------------------------------------------------------------------------------------


def _current_paused_nonces(path: Path) -> list[str]:
    """The CURRENT paused-nonce set for the WRITERS' read-modify-write only; [] on any read/parse/kind error.

    NOTE the deliberate asymmetry with the READER: this writer-side read fails OPEN to [] (mirroring
    ``credit_lease_broker._read_settled_nonces``), so ``record`` can overwrite a corrupt marker with a clean
    set that INCLUDES the new pause — which is safe, because record only ever ADDS a halt. The fail-CLOSED
    decision lives in ``is_lease_paused`` (the proceed/halt reader), never here."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(obj, dict) or obj.get("kind") != _PAUSE_SCHEMA:
        return []
    nonces = obj.get("nonces")
    return [str(n) for n in nonces] if isinstance(nonces, list) else []


def record_lease_pause(base_dir: Any, slug: Any, nonce: Any) -> Path:
    """Durably mark the lease ``(slug, nonce)`` PAUSED — after this ``is_lease_paused(base, slug, nonce)`` is
    True until it is cleared. Idempotent: re-recording a nonce rewrites the same set. Raises ValueError on an
    unsafe slug (never writes outside the pauses dir). Reversible by ``clear_lease_pause``."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe lease slug: {slug!r}")
    path = _contained_child(pauses_root(base_dir), f"{safe}.json")
    if path is None:  # containment barrier — unreachable for a _safe_component-clean slug, kept fail-closed
        raise ValueError(f"unsafe lease slug (escapes pauses dir): {slug!r}")
    merged = sorted(set(_current_paused_nonces(path) if path.is_file() else []) | {str(nonce)})
    _atomic_write_json(path, {"schema_version": _SCHEMA_VERSION, "kind": _PAUSE_SCHEMA,
                              "slug": safe, "nonces": merged})
    return path


def clear_lease_pause(base_dir: Any, slug: Any, nonce: Any) -> Path:
    """Durably RESUME the lease ``(slug, nonce)`` — remove ``nonce`` from the pause set, so
    ``is_lease_paused(base, slug, nonce)`` becomes False while OTHER paused nonces for the slug are untouched.
    Idempotent: clearing a nonce that is absent rewrites the same (reduced) set. Raises ValueError on an unsafe
    slug (never writes outside the pauses dir). The exact reverse of ``record_lease_pause``."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe lease slug: {slug!r}")
    path = _contained_child(pauses_root(base_dir), f"{safe}.json")
    if path is None:  # containment barrier — unreachable for a _safe_component-clean slug, kept fail-closed
        raise ValueError(f"unsafe lease slug (escapes pauses dir): {slug!r}")
    remaining = sorted(set(_current_paused_nonces(path) if path.is_file() else []) - {str(nonce)})
    _atomic_write_json(path, {"schema_version": _SCHEMA_VERSION, "kind": _PAUSE_SCHEMA,
                              "slug": safe, "nonces": remaining})
    return path


# ---------------------------------------------------------------------------------------------------
# reader — FAIL-CLOSED (the deliberate inversion of is_lease_settled). See the module docstring.
# ---------------------------------------------------------------------------------------------------


def is_lease_paused(base_dir: Any, slug: Any, nonce: Any) -> bool:
    """True iff the lease ``(slug, nonce)`` must be treated as PAUSED (halt). FAIL-CLOSED — the deliberate
    inversion of ``is_lease_settled`` (which fails OPEN to False): the ONLY two states that return False are
    (1) no marker file at all (DEFAULT-OFF — nothing was ever paused, no behaviour change) and (2) a
    cleanly-read marker whose nonce set does NOT contain this nonce. Every other state returns True: an
    unsafe/unresolvable slug, and an EXISTING-but-unreadable/corrupt/foreign/permission-denied marker — because
    a pause reader that failed to False would let a run that should be paused proceed. Total; never raises."""
    path = pause_path(base_dir, slug)
    if path is None:
        return True            # unsafe / unresolvable slug: cannot read a pause state -> fail-CLOSED (halt)
    try:
        # is_file() is INSIDE the fail-closed try: it swallows ENOENT (-> False, the default-OFF "no marker"
        # case) but NOT EACCES — on the keyless plane a sovereign-written marker under a different uid makes
        # stat() raise PermissionError. A fail-closed reader must HALT on "cannot tell", never propagate, so the
        # probe lives here and any OSError from it (incl. EACCES) is caught below -> True (the ONLY False case
        # is a positively-confirmed absent file).
        if not path.is_file():
            return False       # DEFAULT-OFF: confirmed NO marker file -> not paused (substrate adds no behaviour)
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or obj.get("kind") != _PAUSE_SCHEMA:
            raise ValueError("foreign or malformed pause marker")
        nonces = obj.get("nonces")
        if not isinstance(nonces, list):
            raise ValueError("malformed pause-marker nonce set")
    except (OSError, ValueError):
        return True            # is_file()/read raised (EACCES, ...) OR unreadable/corrupt/foreign -> fail-CLOSED
    return str(nonce) in {str(n) for n in nonces}   # NONCE-SCOPED: only THIS nonce's pause halts THIS nonce
