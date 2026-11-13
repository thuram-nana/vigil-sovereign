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

FATAL-2 / import-clean: ``vigil_core`` + stdlib only at module scope (the four filesystem primitives — atomic
write, path containment, safe slug and the hardened per-file marker lock — are imported from the import-clean
``credit_lease_broker``, which itself imports only ``vigil_core`` + stdlib + the stdlib-only ``seam_lock``); no
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
import os
from pathlib import Path
from typing import Any, Optional

# Reuse the broker's module-level filesystem primitives verbatim (atomic write, safe id component, resolved
# path-containment barrier) — the task's instruction, and it keeps a single audited copy of each. Importing
# credit_lease_broker pulls in only vigil_core + stdlib, so this module stays FATAL-2 / both-plane safe.
from vigil_integration.live.credit_lease_broker import (
    _atomic_write_json,
    _contained_child,
    _marker_lock,
    _safe_component,
)

__all__ = [
    "record_paused_past_expiry",
    "paused_past_expiry",
    "pauses_root",
    "pause_path",
    "record_lease_pause",
    "clear_lease_pause",
    "is_lease_paused",
    "unreadable_pause_markers",
    "pause_store_unreadable",
]

_PAUSE_DIRNAME = "credit-lease-pauses"
# A SIBLING of the pauses dir (never inside it, so the marker enumerations never see it): the launches whose pause
# was still in place when the customer lifted it after the lease window had closed (see record_paused_past_expiry).
_PAST_EXPIRY_DIRNAME = "credit-lease-paused-past-expiry"
_PAST_EXPIRY_SCHEMA = "vigil-credit-lease-paused-past-expiry-v1"
_PAUSE_SCHEMA = "vigil-credit-lease-pause-v1"
_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------------------------------
# paths (twin of credit_lease_broker.settlements_root / settlement_path)
# ---------------------------------------------------------------------------------------------------


def _seam_base(base_dir: Any) -> Any:
    """``base_dir``, or — when it is ``None`` — the DEFAULT cross-plane seam base: ``VIGIL_BASE_DIR``, else
    ``.vigil-live``. This is EXACTLY how the lease verify resolves a ``None`` base
    (``framework.v2.launch_lease._base_dir``, used by ``verify_customer_launch_lease`` /
    ``read_verified_launch_nonce``), so a pause is always looked up under the SAME seam the lease it halts was
    read from. Resolved HERE, at the one path chokepoint every pause function goes through, so no caller can
    reach a different base (or a ``TypeError``) by passing the ``None`` default the lease reader accepts — the
    mismatch that made the launch gate mistake a paused lease for a terminal one and strand it. The engine module
    cannot be imported from this both-plane module (FATAL-2), so the one-line convention is restated and PINNED
    equal by ``integration/tests/test_launch_pause_redrive_gate.py``. Only ``None`` is defaulted (``""`` is left
    as given), matching the lease reader's ``is not None`` test."""
    return base_dir if base_dir is not None else (os.environ.get("VIGIL_BASE_DIR") or ".vigil-live")


def pauses_root(base_dir: Any) -> Path:
    """The pause-marker root ``<base>/credit-lease-pauses`` (a SIBLING of the leases and settlements dirs, so
    a ``*.json`` glob of the leases dir never picks up a pause marker). ``base_dir=None`` resolves to the default
    seam base exactly as the lease verify does (:func:`_seam_base`)."""
    return Path(_seam_base(base_dir)) / _PAUSE_DIRNAME


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
# CONCURRENCY CONTRACT (E3bc, same as the broker's settlement writer): each writer's READ-modify-WRITE of its
# per-slug nonce set runs under that file's own CROSS-PROCESS lock (`credit_lease_broker._marker_lock`, a hardened
# flock on the sibling `<slug>.json.lock`), so two processes pausing / resuming two nonces of one slug can never
# each read the old set and drop the other's nonce. A lock that cannot be taken (busy past its bounded wait, or an
# unusable lock file) RAISES, so the caller records nothing and refuses (fail-closed). Each write is atomic
# (temp+rename via _atomic_write_json), so the READERS (is_lease_paused, lease_pause_state, paused_past_expiry,
# paused_launches, unreadable_pause_markers) stay lock-free and fail-closed and always see a consistent snapshot.
#
# READ / WRITE ORDER (pinned by a test): resume writes the paused-past-expiry record BEFORE it clears the pause,
# and every settle-side reader reads the pause marker BEFORE the paused-past-expiry record — so a late resume
# racing a settle-side read can never be read as "never paused" (the reader sees the pause, or the late record).
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
    with _marker_lock(path):
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
    with _marker_lock(path):
        remaining = sorted(set(_current_paused_nonces(path) if path.is_file() else []) - {str(nonce)})
        _atomic_write_json(path, {"schema_version": _SCHEMA_VERSION, "kind": _PAUSE_SCHEMA,
                                  "slug": safe, "nonces": remaining})
    return path


# ---------------------------------------------------------------------------------------------------
# reader — FAIL-CLOSED (the deliberate inversion of is_lease_settled). See the module docstring.
# ---------------------------------------------------------------------------------------------------


def _marker_nonces(base_dir: Any, slug: Any) -> "Optional[list[str]]":
    """The pause set recorded for ``slug``, in the three states the halt decision distinguishes:

      * ``[]``        — NO marker file at all (DEFAULT-OFF: nothing was ever paused for this slug);
      * ``[nonce..]`` — a CLEANLY-read marker's nonce set;
      * ``None``      — the pause state CANNOT be read: an unsafe/unresolvable slug, or a marker that EXISTS but
                        is unreadable / corrupt / foreign / permission-denied. The caller must HALT.

    The ONE marker read shared by the fail-CLOSED halt reader (:func:`is_lease_paused`) and the doctor probe
    (:func:`unreadable_pause_markers`), so "this marker halts every launch of its slug" and "doctor reports this
    marker as unreadable" are the same predicate by construction. Never raises for a path-like ``base_dir``."""
    path = pause_path(base_dir, slug)
    if path is None:
        return None            # unsafe / unresolvable slug: cannot read a pause state -> the caller halts
    try:
        # is_file() is INSIDE the fail-closed try: it swallows ENOENT (-> False, the default-OFF "no marker"
        # case) but NOT EACCES — on the keyless plane a sovereign-written marker under a different uid makes
        # stat() raise PermissionError. A fail-closed reader must HALT on "cannot tell", never propagate, so the
        # probe lives here and any OSError from it (incl. EACCES) is caught below -> None (the ONLY "no pause"
        # answer is a positively-confirmed absent file).
        if not path.is_file():
            return []          # DEFAULT-OFF: confirmed NO marker file -> nothing paused (substrate adds no behaviour)
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or obj.get("kind") != _PAUSE_SCHEMA:
            raise ValueError("foreign or malformed pause marker")
        nonces = obj.get("nonces")
        if not isinstance(nonces, list):
            raise ValueError("malformed pause-marker nonce set")
    except (OSError, ValueError):
        return None            # is_file()/read raised (EACCES, ...) OR unreadable/corrupt/foreign -> the caller halts
    return [str(n) for n in nonces]


def _past_expiry_path(base_dir: Any, slug: Any) -> Optional[Path]:
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(Path(_seam_base(base_dir)) / _PAST_EXPIRY_DIRNAME, f"{safe}.json")


def _past_expiry_nonces(path: Path) -> "Optional[list[str]]":
    """The recorded nonces: [] for no file, None for an existing file that cannot be read cleanly."""
    try:
        if not path.is_file():
            return []
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or obj.get("kind") != _PAST_EXPIRY_SCHEMA or not isinstance(obj.get("nonces"),
                                                                                                    list):
            raise ValueError("foreign or malformed paused-past-expiry record")
    except (OSError, ValueError):
        return None
    return [str(n) for n in obj["nonces"]]


def record_paused_past_expiry(base_dir: Any, slug: Any, nonce: Any) -> Path:
    """Durably record that the lease ``(slug, nonce)`` was still PAUSED when its window closed, at the moment the
    customer lifts that pause. Lifting a pause after expiry re-admits nothing (the window refuses every re-arm), but
    it must not erase the fact the abandoned-launch sweep and the completion drain bill on: the customer held the
    launch paused through the end of its window. ADD-ONLY (never cleared) and idempotent. Raises ValueError on an
    unsafe slug, and on an existing record that cannot be read cleanly (rewriting it would drop other launches'
    evidence), so the resume that needs it refuses and changes nothing."""
    path = _past_expiry_path(base_dir, slug)
    if path is None:
        raise ValueError(f"unsafe lease slug: {slug!r}")
    with _marker_lock(path):
        current = _past_expiry_nonces(path)
        if current is None:
            raise ValueError("the paused-past-expiry record exists but cannot be read; refusing to overwrite it")
        merged = sorted(set(current) | {str(nonce)})
        _atomic_write_json(path, {"schema_version": _SCHEMA_VERSION, "kind": _PAST_EXPIRY_SCHEMA,
                                  "slug": _safe_component(slug), "nonces": merged})
    return path


def paused_past_expiry(base_dir: Any, slug: Any, nonce: Any) -> Optional[bool]:
    """Tri-state: True when the record holds this nonce, False when there is no record or a clean record without
    it, None when the record cannot be read positively (or the slug is unsafe). Total; never raises."""
    path = _past_expiry_path(base_dir, slug)
    if path is None:
        return None
    nonces = _past_expiry_nonces(path)
    return None if nonces is None else str(nonce) in nonces


def is_lease_paused(base_dir: Any, slug: Any, nonce: Any) -> bool:
    """True iff the lease ``(slug, nonce)`` must be treated as PAUSED (halt). FAIL-CLOSED — the deliberate
    inversion of ``is_lease_settled`` (which fails OPEN to False): the ONLY two states that return False are
    (1) no marker file at all (DEFAULT-OFF — nothing was ever paused, no behaviour change) and (2) a
    cleanly-read marker whose nonce set does NOT contain this nonce. Every other state returns True: an
    unsafe/unresolvable slug, and an EXISTING-but-unreadable/corrupt/foreign/permission-denied marker — because
    a pause reader that failed to False would let a run that should be paused proceed. Total; never raises.
    ``base_dir=None`` reads the default seam base, exactly as the lease verify does (:func:`_seam_base`)."""
    nonces = _marker_nonces(base_dir, slug)
    if nonces is None:
        return True            # the pause state cannot be positively read as "not paused" -> fail-CLOSED (halt)
    return str(nonce) in nonces                     # NONCE-SCOPED: only THIS nonce's pause halts THIS nonce


def lease_pause_state(base_dir: Any, slug: Any, nonce: Any) -> Optional[bool]:
    """Tri-state, for a caller that must NOT guess either way (the abandoned-launch sweep decides whether to CHARGE
    a launch the customer paused and never resumed): ``True`` when a cleanly-read marker holds this nonce,
    ``False`` when there is no marker or a cleanly-read marker without it, and ``None`` when the pause state cannot
    be read positively (an unsafe slug, or an existing marker that is unreadable / corrupt / foreign). Unlike
    :func:`is_lease_paused` (fail-CLOSED to True, right for the halt), this never turns "cannot tell" into an answer.
    Total; never raises."""
    nonces = _marker_nonces(base_dir, slug)
    if nonces is None:
        return None
    return str(nonce) in nonces


def paused_launches(base_dir: Any) -> "list[tuple[str, list[str]]]":
    """pause/resume PR-5 (observability) — enumerate the currently-paused launches as ``(slug, [nonces])`` for
    every marker holding at least one paused nonce. READ-ONLY; TOTAL and fail-SAFE to ``[]`` (an absent /
    unreadable pauses dir, or an individual unreadable/corrupt/foreign marker, simply contributes nothing — a
    best-effort projection must never crash ``vigil doctor``; the fail-CLOSED halt decision stays in
    ``is_lease_paused``, and the markers this projection CANNOT read are reported separately by
    :func:`unreadable_pause_markers`, because each one is a real hold). The slug is the marker's filename stem
    (the path-safe slug component). DEFAULT-OFF:
    with no markers the result is ``[]``, so doctor is byte-identical until a pause is recorded. A paused launch
    is a POSITIVELY-recorded held reservation (expected), NOT a stuck/lost lease — callers surface it as an
    advisory, never an alarm."""
    out: "list[tuple[str, list[str]]]" = []
    try:
        entries = sorted(pauses_root(base_dir).glob("*.json"))
    except OSError:
        return out
    for p in entries:
        try:
            nonces = _current_paused_nonces(p)
        except OSError:                              # defence-in-depth (the helper already fails open to [])
            continue
        if nonces:
            out.append((p.stem, nonces))
    return out


def unreadable_pause_markers(base_dir: Any) -> "list[str]":
    """The slugs whose pause marker EXISTS but cannot be read cleanly — the exact state in which the fail-CLOSED
    :func:`is_lease_paused` answers True for EVERY nonce of that slug, so every launch of the slug (a future
    re-lease included) is HELD although no pause was positively recorded. :func:`paused_launches` skips such a
    marker (it only projects holds it can read), so without this the hold is invisible to ``vigil doctor``.

    Each candidate is classified by the SAME :func:`_marker_nonces` read the halt reader uses, so every slug listed
    here halts. READ-ONLY, total, never raises: an absent / unlistable pauses dir yields ``[]``. That is why this
    list alone is not the whole picture: when the pauses DIRECTORY itself cannot be listed or searched, the halt
    reader may hold slugs this list cannot see (every slug, when a lookup in it fails), and that state is reported
    by :func:`pause_store_unreadable` instead. Only the slug (the marker's canonical, path-safe filename stem) is
    returned — never a nonce, never marker content. A file whose stem is not a canonical safe slug component is
    not any slug's marker (no lookup resolves to it), so it is not listed and its name is never echoed."""
    out: "list[str]" = []
    try:
        entries = sorted(pauses_root(base_dir).glob("*.json"))
    except OSError:
        return out
    for p in entries:
        slug = p.stem
        if _safe_component(slug) != slug:
            continue                                 # not a canonical slug marker: halts nothing, name not echoed
        if _marker_nonces(base_dir, slug) is None:
            out.append(slug)                         # exists but unreadable/corrupt/foreign -> a real hold
    return out


#: A slug that is never any launch's (customer slugs are ``cust_<24hex>``) and is never written: the pause store
#: probe looks it up exactly as the halt reader looks up a slug that has NO marker.
_STORE_PROBE_SLUG = "vigil-pause-store-probe"

#: :func:`pause_store_unreadable` answers.
STORE_LOOKUP_FAILS = "lookup"
STORE_LISTING_FAILS = "listing"


def pause_store_unreadable(base_dir: Any) -> Optional[str]:
    """Whether the pauses DIRECTORY itself cannot be read, as opposed to one marker file in it.

      * ``None`` — the directory is absent (DEFAULT-OFF: nothing was ever paused) or can be listed and searched.
      * ``"lookup"`` (:data:`STORE_LOOKUP_FAILS`) — a slug with NO marker cannot be read as "not paused" (for
        example the directory is not searchable by this uid, after a restore under another owner). The halt
        reader fails CLOSED on that, so EVERY customer launch of EVERY slug is held, and the per-file listings
        (:func:`paused_launches`, :func:`unreadable_pause_markers`) see nothing because the glob swallows the
        error.
      * ``"listing"`` (:data:`STORE_LISTING_FAILS`) — lookups work but the directory cannot be enumerated, so the
        per-file listings are blind: a corrupt marker in it would hold every launch of its slug unseen.

    The lookup check is the halt reader's own :func:`_marker_nonces` on a slug that has no marker, so "lookup"
    is reported exactly when the reader would hold a launch that was never paused. READ-ONLY, total, never raises.
    It returns only one of these fixed words, never a slug, a nonce or marker content."""
    try:
        if _marker_nonces(base_dir, _STORE_PROBE_SLUG) is None:
            return STORE_LOOKUP_FAILS
        with os.scandir(pauses_root(base_dir)) as it:
            for _ in it:
                pass
    except (FileNotFoundError, NotADirectoryError):
        return None                                  # no pauses dir: nothing recorded, and lookups answer "not paused"
    except Exception:  # noqa: BLE001 — any other failure to enumerate (EACCES, EIO, ...) is a blind store
        return STORE_LISTING_FAILS
    return None
