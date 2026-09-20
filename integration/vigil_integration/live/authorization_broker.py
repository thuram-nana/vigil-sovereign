"""authorization_broker — the file-backed seam for owner-signed TARGET engagement authorizations.

The SOVEREIGN cockpit (``apps/sigil/sigil/ui/target_authorization.py``) owner-signs an
``EngagementAuthority`` (scope = the authorized host(s), environment, a bounded validity window) and drops
the signed bundle here; the OFFENSE console reads it back, VERIFIES the owner signature against the
out-of-band-pinned owner key, writes the charter, and persists the authority + owner trust-root. This
module is the TRANSPORT, not the trust decision — it holds no private key and makes no trust call
(verification is the reader's job, against a pinned owner key).

  ``<base>/target-authorizations/<slug>.json`` — the owner-signed bundle::

      { "schema_version": 1, "kind": "vigil-target-authorization-v1", "slug": "<slug>",
        "signed_authority": { "document": {...}, "signatures": [{"key_id","signature_b64"}] },
        "trust_root": { "threshold": 1, "authorizers": [{"key_id","name","public_key_b64"}] } }

Public-safe: only PUBLIC keys + signatures + the (owner-authored) scope/window cross. No private key,
ever. FATAL-2 / import-clean: ``vigil_core`` + stdlib + relative imports only — safe to import in either
plane. Mirrors ``approval_broker`` (same atomic-write + path-safety discipline).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from vigil_core import SignedAuthority, TrustRoot

__all__ = [
    "TargetAuthorization",
    "authorizations_root",
    "authorization_path",
    "write_authorization",
    "read_authorization",
    "list_authorizations",
]

_AUTHZ_DIRNAME = "target-authorizations"
_AUTHZ_SCHEMA = "vigil-target-authorization-v1"
_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------------------------------
# paths + safe id component (mirrors approval_broker._safe_component / _atomic_write_json)
# ---------------------------------------------------------------------------------------------------


def authorizations_root(base_dir: Any) -> Path:
    """The authorizations root ``<base>/target-authorizations``."""
    return Path(base_dir) / _AUTHZ_DIRNAME


def _safe_component(value: Any) -> str:
    """A filesystem-safe id component: no separators, no ``..``, no NUL/whitespace/control chars. Returns
    "" if unsafe. Slugs are hostname-derived tokens in practice; this is defence-in-depth so a crafted slug
    can never escape the authorizations dir."""
    s = str(value or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s:
        return ""
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return ""
    return s


def authorization_path(base_dir: Any, slug: str) -> Optional[Path]:
    """The bundle path for ``slug`` (``<base>/target-authorizations/<slug>.json``), or None if the slug is
    unsafe as a path component."""
    safe = _safe_component(slug)
    if not safe:
        return None
    return authorizations_root(base_dir) / f"{safe}.json"


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
# the signed bundle (public-safe — signatures + public keys + the owner-authored scope only)
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetAuthorization:
    slug: str
    signed_authority: SignedAuthority
    trust_root: TrustRoot


def write_authorization(
    base_dir: Any, slug: str, signed_authority: SignedAuthority, trust_root: TrustRoot
) -> Path:
    """Write the owner-signed authorization bundle for ``slug``. Raises ValueError on an unsafe slug (never
    writes outside the authorizations dir). The bundle carries only public material."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe authorization slug: {slug!r}")
    path = authorizations_root(base_dir) / f"{safe}.json"
    obj = {
        "schema_version": _SCHEMA_VERSION,
        "kind": _AUTHZ_SCHEMA,
        "slug": safe,
        "signed_authority": signed_authority.model_dump(mode="json"),
        "trust_root": trust_root.model_dump(mode="json"),
    }
    _atomic_write_json(path, obj)
    return path


def _read_authorization_file(path: Path) -> Optional[TargetAuthorization]:
    """Parse one bundle file, fail-closed to None on any read/parse/validation error (an unreadable or
    malformed bundle is simply 'no authorization', never a partial-trust default)."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("kind") != _AUTHZ_SCHEMA:
        return None
    slug = _safe_component(obj.get("slug"))
    if not slug:
        return None
    try:
        signed = SignedAuthority.model_validate(obj["signed_authority"])
        trust_root = TrustRoot.model_validate(obj["trust_root"])
    except (KeyError, TypeError, ValueError):
        return None
    return TargetAuthorization(slug=slug, signed_authority=signed, trust_root=trust_root)


def read_authorization(base_dir: Any, slug: str) -> Optional[TargetAuthorization]:
    """Read the owner-signed bundle for ``slug`` (public material only; the CALLER verifies the signature
    against the pinned owner key). None if absent, unsafe, or malformed."""
    path = authorization_path(base_dir, slug)
    if path is None or not path.is_file():
        return None
    return _read_authorization_file(path)


def list_authorizations(base_dir: Any) -> list[TargetAuthorization]:
    """Every readable authorization bundle. Globs the authorizations dir (a glob child is always a real
    entry — no traversal), skipping any unreadable/malformed file. Total; never raises."""
    out: list[TargetAuthorization] = []
    try:
        for fp in sorted(authorizations_root(base_dir).glob("*.json")):
            ta = _read_authorization_file(fp)
            if ta is not None:
                out.append(ta)
    except OSError:
        pass
    return out
