"""credit_lease_broker — the file-backed seam for owner-signed CREDIT-LAUNCH LEASES (Slice K, transport).

The SOVEREIGN plane (``apps/sigil/sigil/ui/launch_gate.py`` via the provisioner) owner-signs a
``CreditLaunchLease`` — the per-launch credit reservation bound to ONE engagement_slug / scope_host / tenant
within a bounded window — and drops the signed bundle here under the SAME ``cust_<slug>`` the G0
``authorization_broker`` uses, so the lease and its EngagementAuthority co-locate for one tenant+host. The
keyless OFFENSE plane reads it back and VERIFIES it against the out-of-band-pinned owner key
(``vigil_core.verify_credit_launch_lease``) BEFORE any traffic — a SEPARATE conjunct from the authority.

This module is the TRANSPORT, not the trust decision: it holds no private key and makes no trust call
(verification is the reader's job, against a pinned owner key). It is a one-for-one twin of
``authorization_broker`` (same atomic-write + path-safety discipline), differing only in the artifact it
carries.

  ``<base>/credit-launch-leases/<slug>.json`` — the owner-signed bundle::

      { "schema_version": 1, "kind": "vigil-credit-launch-lease-seam-v1", "slug": "<slug>",
        "signed_lease": { "document": {...}, "signatures": [{"key_id","signature_b64"}] },
        "trust_root": { "threshold": 1, "authorizers": [{"key_id","name","public_key_b64"}] } }

Public-safe: only PUBLIC keys + signatures + the (owner-authored) lease fields cross — no private key, ever
(the lease itself carries no secret). FATAL-2 / import-clean: ``vigil_core`` + stdlib + the stdlib-only
``seam_lock`` only — safe to import on either plane (the offense reader holds no owner key).
"""

from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

from vigil_core import SignedCreditLaunchLease, TrustRoot
from vigil_integration.live.seam_lock import locked_file

#: How long a marker writer waits for another process's read-merge-replace of the same marker file.
_MARKER_LOCK_WAIT_S = 5.0

__all__ = [
    "CreditLeaseBundle",
    "leases_root",
    "lease_path",
    "write_credit_lease",
    "read_credit_lease",
    "list_credit_leases",
    "settlements_root",
    "settlement_path",
    "record_lease_settlement",
    "is_lease_settled",
    "tombstone_credit_lease",
    "unfinished_settlements",
]

_LEASE_DIRNAME = "credit-launch-leases"
_LEASE_SCHEMA = "vigil-credit-launch-lease-seam-v1"
_SCHEMA_VERSION = 1

# K4-1 / K5 close-out: a settled/canceled lease MUST NOT remain a runnable bearer capability. settle_launch
# records the settled (slug, nonce) in a SIBLING dir (never collides with the leases glob) and TOMBSTONES the
# published bundle; the keyless arm + the sovereign publish_lease both refuse a settled nonce.
_SETTLE_DIRNAME = "credit-lease-settlements"
_SETTLE_SCHEMA = "vigil-credit-lease-settlement-v1"


# ---------------------------------------------------------------------------------------------------
# paths + safe id component (twin of authorization_broker._safe_component / _contained_child)
# ---------------------------------------------------------------------------------------------------


def leases_root(base_dir: Any) -> Path:
    """The leases root ``<base>/credit-launch-leases``."""
    return Path(base_dir) / _LEASE_DIRNAME


def _safe_component(value: Any) -> str:
    """A filesystem-safe id component: no separators, no ``..``, no NUL/whitespace/control chars. Returns ""
    if unsafe. Slugs are ``cust_<24hex>`` tokens in practice; this is defence-in-depth so a crafted slug can
    never escape the leases dir."""
    s = str(value or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s:
        return ""
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return ""
    return s


def _contained_child(root: Path, filename: str) -> Optional[Path]:
    """``root/filename`` ONLY if it normalizes to a *direct* child of ``root``; else None. The resolved-path
    containment barrier CodeQL documents as the ``py/path-injection`` fix — basename strips any directory
    component, realpath normalizes ``..``/symlinks, the ``startswith`` prefix test cannot be fooled, and the
    ``dirname`` equality rejects any nested descendant. Returns the *checked* value so the guarded path is
    what flows to every filesystem sink."""
    root_real = os.path.realpath(str(root))
    name = os.path.basename(filename)
    if name != filename:  # a name carrying a directory component is REFUSED, never silently rewritten
        return None
    final = os.path.realpath(os.path.join(root_real, name))
    if not final.startswith(root_real + os.sep):
        return None
    if os.path.dirname(final) != root_real:
        return None
    return Path(final)


def lease_path(base_dir: Any, slug: str) -> Optional[Path]:
    """The bundle path for ``slug`` (``<base>/credit-launch-leases/<slug>.json``), or None if the slug is
    unsafe as a path component."""
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(leases_root(base_dir), f"{safe}.json")


def _atomic_write_json(path: Path, obj: dict) -> None:
    """Atomically write ``obj`` as canonical JSON at ``path`` (0600, fsync'd, then ``os.replace``)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------
# the signed bundle (public-safe — signatures + public keys + the owner-authored lease fields only)
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CreditLeaseBundle:
    slug: str
    signed_lease: SignedCreditLaunchLease
    trust_root: TrustRoot


def write_credit_lease(
    base_dir: Any, slug: str, signed_lease: SignedCreditLaunchLease, trust_root: TrustRoot
) -> Path:
    """Write the owner-signed credit-lease bundle for ``slug``. Raises ValueError on an unsafe slug (never
    writes outside the leases dir). The bundle carries only public material."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe lease slug: {slug!r}")
    path = _contained_child(leases_root(base_dir), f"{safe}.json")
    if path is None:  # containment barrier — unreachable for a _safe_component-clean slug, kept fail-closed
        raise ValueError(f"unsafe lease slug (escapes leases dir): {slug!r}")
    obj = {
        "schema_version": _SCHEMA_VERSION,
        "kind": _LEASE_SCHEMA,
        "slug": safe,
        "signed_lease": signed_lease.model_dump(mode="json"),
        "trust_root": trust_root.model_dump(mode="json"),
    }
    _atomic_write_json(path, obj)
    return path


def _read_lease_file(path: Path) -> Optional[CreditLeaseBundle]:
    """Parse one bundle file, fail-closed to None on any read/parse/validation error (an unreadable or
    malformed bundle is simply 'no lease', never a partial-trust default). Does NOT verify the signature —
    that is the reader's job against the pinned owner key."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("kind") != _LEASE_SCHEMA:
        return None
    slug = _safe_component(obj.get("slug"))
    if not slug:
        return None
    try:
        signed = SignedCreditLaunchLease.model_validate(obj["signed_lease"])
        trust_root = TrustRoot.model_validate(obj["trust_root"])
    except (KeyError, TypeError, ValueError):
        return None
    return CreditLeaseBundle(slug=slug, signed_lease=signed, trust_root=trust_root)


def read_credit_lease(base_dir: Any, slug: str) -> Optional[CreditLeaseBundle]:
    """Read the owner-signed lease bundle for ``slug`` (public material only; the CALLER verifies the
    signature against the pinned owner key via ``vigil_core.verify_credit_launch_lease``). None if absent,
    unsafe, or malformed."""
    path = lease_path(base_dir, slug)
    if path is None or not path.is_file():
        return None
    return _read_lease_file(path)


def list_credit_leases(base_dir: Any) -> list[CreditLeaseBundle]:
    """Every readable lease bundle. Globs the leases dir (a glob child is always a real entry — no
    traversal), skipping any unreadable/malformed file. Total; never raises."""
    out: list[CreditLeaseBundle] = []
    try:
        for fp in sorted(leases_root(base_dir).glob("*.json")):
            b = _read_lease_file(fp)
            if b is not None:
                out.append(b)
    except OSError:
        pass
    return out


# ---------------------------------------------------------------------------------------------------
# settlement markers + tombstones (K4-1 / K5 money-doctrine close-out)
# ---------------------------------------------------------------------------------------------------


def settlements_root(base_dir: Any) -> Path:
    """The settlement-marker root ``<base>/credit-lease-settlements`` (a SIBLING of the leases dir, so a
    ``*.json`` glob of the leases dir never picks up a marker)."""
    return Path(base_dir) / _SETTLE_DIRNAME


def settlement_path(base_dir: Any, slug: str) -> Optional[Path]:
    """The settlement-marker path for ``slug``, or None if the slug is unsafe as a path component."""
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(settlements_root(base_dir), f"{safe}.json")


def _read_settled_nonces(path: Path) -> list[str]:
    """The settled-nonce list from a marker file; [] on any read/parse/kind error (fail-closed to 'unknown')."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(obj, dict) or obj.get("kind") != _SETTLE_SCHEMA:
        return []
    nonces = obj.get("nonces")
    return [str(n) for n in nonces] if isinstance(nonces, list) else []


@contextmanager
def _marker_lock(path: Path) -> Iterator[None]:
    """Exclusive CROSS-PROCESS lock for one marker file's read-merge-replace, on a sibling ``<name>.lock`` inode
    (it survives the atomic replace of the marker; a ``*.lock`` is a transient the backups skip, and the ``*.json``
    globs of the seam readers never match it). Shared by the settlement marker here and the pause /
    paused-past-expiry markers (``credit_lease_pause``). Hardened (``seam_lock.locked_file``): never follows a
    symlink, refuses a non-regular lock file, waits at most ``_MARKER_LOCK_WAIT_S``. Fail-closed: a lock that
    cannot be opened or taken raises, so the caller records nothing (and settles nothing). A LEAF lock: its holder
    takes no other lock."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with locked_file(path.parent / (path.name + ".lock"), wait_s=_MARKER_LOCK_WAIT_S):
        yield


def record_lease_settlement(base_dir: Any, slug: str, nonce: Any) -> Path:
    """Durably mark the lease ``(slug, nonce)`` SETTLED — after this the arm (``verify_customer_launch_lease``)
    and ``publish_lease`` refuse that nonce. Idempotent: re-recording a nonce rewrites the same set. Raises
    ValueError on an unsafe slug (never writes outside the settlements dir).

    The marker is ONE file per slug holding every settled nonce, so the read-merge-replace runs under
    ``_marker_lock``: two processes settling two leases of one slug can no longer each read the old set and
    replace it with their own (a lost update that dropped the other lease's nonce — which, for a charged lease,
    re-opened its refund)."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe lease slug: {slug!r}")
    path = _contained_child(settlements_root(base_dir), f"{safe}.json")
    if path is None:  # containment barrier — unreachable for a _safe_component-clean slug, kept fail-closed
        raise ValueError(f"unsafe lease slug (escapes settlements dir): {slug!r}")
    with _marker_lock(path):
        merged = sorted(set(_read_settled_nonces(path) if path.is_file() else []) | {str(nonce)})
        _atomic_write_json(path, {"schema_version": _SCHEMA_VERSION, "kind": _SETTLE_SCHEMA,
                                  "slug": safe, "nonces": merged})
    return path


def is_lease_settled(base_dir: Any, slug: str, nonce: Any) -> bool:
    """True iff the lease ``(slug, nonce)`` was POSITIVELY recorded settled. Absent/unsafe/malformed marker →
    False: the tombstone + the single-use issued_at floor are the primary revocation, this durable marker is
    the belt-and-braces for a stale/re-published copy, and a same-host attacker tampering seam files is already
    outside the threat model (the owner signature is the trust anchor, not this operational state). Total;
    never raises."""
    path = settlement_path(base_dir, slug)
    if path is None or not path.is_file():
        return False
    return str(nonce) in _read_settled_nonces(path)


def unfinished_settlements(base_dir: Any, *, now: float, grace: float) -> list[tuple[str, str]]:
    """Every ``(slug, nonce)`` whose lease is still published on the seam although its settlement marker lists it,
    with that marker last written more than ``grace`` seconds before ``now``. A settle records the marker BEFORE it
    moves any money and retires (tombstones) the lease LAST, so such a lease is a settle that has not finished: its
    refund may not have landed yet. Read-only and total: an unreadable lease or marker contributes nothing."""
    out: list[tuple[str, str]] = []
    for b in list_credit_leases(base_dir):
        try:
            doc = b.signed_lease.document
            slug, nonce = str(doc.engagement_slug), str(doc.nonce)
            if not is_lease_settled(base_dir, slug, nonce):
                continue
            path = settlement_path(base_dir, slug)
            if path is None or now < path.stat().st_mtime + float(grace):
                continue
        except Exception:  # noqa: BLE001 — an odd or racing seam is no evidence
            continue
        out.append((slug, nonce))
    return out


def tombstone_credit_lease(base_dir: Any, slug: str, expect_nonce: Any = None) -> bool:
    """Remove the published lease bundle for ``slug`` from the seam, so ``read_credit_lease`` returns None.
    Idempotent + total: True if a bundle was removed, False if none/unsafe, never raises on a missing file.

    When ``expect_nonce`` is given, the bundle is removed ONLY if its signed ``nonce`` MATCHES — so settling an
    OLD lease (K4-1 red-pen LOW) never clobbers a concurrently-published NEWER re-lease's bundle (same slug,
    new nonce): a non-matching OR unreadable bundle is left in place and False is returned. The old lease's
    revocation still holds via its own ``(slug, nonce)`` settlement marker, so this only avoids a within-tenant
    availability footgun, never weakens revocation. ``expect_nonce=None`` removes unconditionally (back-compat)."""
    path = lease_path(base_dir, slug)
    if path is None or not path.is_file():
        return False
    if expect_nonce is not None:
        bundle = _read_lease_file(path)
        try:
            on_disk = str(bundle.signed_lease.document.nonce) if bundle is not None else None
        except Exception:  # noqa: BLE001 — an unreadable bundle: treat as non-matching, leave it (fail-safe)
            on_disk = None
        if on_disk != str(expect_nonce):
            return False     # a different (newer re-lease) or unreadable bundle — do NOT clobber it
    try:
        os.unlink(str(path))
        return True
    except OSError:
        return False
