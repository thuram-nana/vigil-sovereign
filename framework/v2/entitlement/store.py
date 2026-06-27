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
