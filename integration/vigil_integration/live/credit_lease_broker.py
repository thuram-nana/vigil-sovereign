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
(the lease itself carries no secret). FATAL-2 / import-clean: ``vigil_core`` + stdlib + relative imports
only — safe to import on either plane (the offense reader holds no owner key).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from vigil_core import SignedCreditLaunchLease, TrustRoot

__all__ = [
    "CreditLeaseBundle",
    "leases_root",
    "lease_path",
    "write_credit_lease",
    "read_credit_lease",
    "list_credit_leases",
]

_LEASE_DIRNAME = "credit-launch-leases"
_LEASE_SCHEMA = "vigil-credit-launch-lease-seam-v1"
_SCHEMA_VERSION = 1


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
