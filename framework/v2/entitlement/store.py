"""
entitlement.store — load entitlement material from disk.

Three files under `paths.entitlement_dir()` (override with
CRUCIBLE_ENTITLEMENT_DIR):

    trust-root.json    TrustRoot           — required for enforcement
    entitlement.json   SignedEntitlement   — the capability grant
    revocation.json    SignedRevocation    — optional revocation list

Loading is pure I/O + schema validation. It makes no trust decision and
verifies no signature — that is policy.py's job. A malformed file
raises EntitlementError with the path and cause; a missing file returns
None so the policy layer can distinguish "absent" (ungoverned /
baseline-only) from "present but broken" (hostile — deny).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from ..common import paths
from ..common.errors import EntitlementError
from .models import SignedEntitlement, SignedRevocation, TrustRoot

_M = TypeVar("_M", bound=BaseModel)


def _load_model(path: Path, model: type[_M], what: str) -> _M | None:
    if not path.is_file():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise EntitlementError(f"cannot read {what} at {path}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise EntitlementError(f"{what} at {path} is not valid JSON: {e}") from e
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise EntitlementError(f"{what} at {path} failed schema validation: {e}") from e


def load_trust_root(path: Path | None = None) -> TrustRoot | None:
    return _load_model(path or paths.trust_root_path(), TrustRoot, "trust root")


def load_entitlement(path: Path | None = None) -> SignedEntitlement | None:
    return _load_model(path or paths.entitlement_path(), SignedEntitlement, "entitlement")


def load_revocation(path: Path | None = None) -> SignedRevocation | None:
    return _load_model(path or paths.revocation_path(), SignedRevocation, "revocation list")


# ---------------------------------------------------------------------------
# Revocation serial high-water mark (anti-rollback / replay protection)
#
# A revocation list carries a monotonically-increasing `serial`. To stop an
# attacker replacing a current list with an older, validly-signed one (which
# would un-revoke an entitlement), the highest serial ever accepted is
# persisted here and re-checked on every evaluation. The mark is a small,
# framework-written companion file next to the entitlement material; it is
# advanced only after a revocation list is proven validly signed (policy.py).
# ---------------------------------------------------------------------------

_HIGHWATER_FILENAME = "revocation-highwater.json"


def revocation_highwater_path(directory: Path | None = None) -> Path:
    return (directory or paths.entitlement_dir()) / _HIGHWATER_FILENAME


def load_revocation_highwater(path: Path | None = None) -> int | None:
    """Return the highest revocation serial accepted so far, or None if no
    mark has been recorded. A malformed mark raises EntitlementError so a
    governed deployment fails closed rather than silently resetting to zero."""
    p = path or revocation_highwater_path()
    if not p.is_file():
        return None
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise EntitlementError(f"cannot read revocation high-water mark at {p}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise EntitlementError(
            f"revocation high-water mark at {p} is not valid JSON: {e}"
        ) from e
    serial = data.get("serial") if isinstance(data, dict) else None
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 0:
        raise EntitlementError(
            f"revocation high-water mark at {p} has no valid non-negative 'serial'"
        )
    return serial


def store_revocation_highwater(serial: int, path: Path | None = None) -> None:
    """Persist `serial` as the new high-water mark. Written only after the
    revocation list it came from was verified validly signed."""
    p = path or revocation_highwater_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"serial": serial}), encoding="utf-8")
