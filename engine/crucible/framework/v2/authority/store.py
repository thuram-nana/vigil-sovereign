"""
authority.store — persist and load an engagement authority.

The authority is a JSON document under the gitignored `.authority/`
area. The kill-switch (killswitch.py) is a separate file so the hard
stop is independent of — and cannot be undone by rewriting — the
authority document.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from ..common import paths
from ..common.errors import CrucibleError
from ..entitlement.models import TrustRoot
from .models import EngagementAuthority, SignedAuthority
from .signing import verify_authority

__all__ = [
    "AuthorityError",
    "AuthorityUnsigned",
    "save_authority",
    "load_authority",
    "save_signed_authority",
    "load_signed_authority",
    "load_verified_authority",
    "write_authority_root",
    "load_authority_root",
]


class AuthorityError(CrucibleError):
    """Authority document missing or malformed."""


class AuthorityUnsigned(AuthorityError):
    """A signed authority was required but verification failed or the
    document on disk is unsigned."""


def save_authority(authority: EngagementAuthority, path: Path | None = None) -> Path:
    p = path if path is not None else paths.authority_path(authority.engagement_slug)
    paths.secure_write(p, json.dumps(authority.model_dump(mode="json"), indent=2))  # X2: owner-only
    return p


def load_authority(slug: str, path: Path | None = None) -> EngagementAuthority:
    p = path if path is not None else paths.authority_path(slug)
    if not p.is_file():
        raise AuthorityError(f"no engagement authority at {p} for {slug!r}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AuthorityError(f"authority for {slug!r} unreadable: {e}") from e
    try:
        return EngagementAuthority.model_validate(data)
    except ValidationError as e:
        raise AuthorityError(f"authority for {slug!r} is invalid: {e}") from e


# ---------------------------------------------------------------------------
# Signed authorities (high-assurance: tamper-evident scope)
# ---------------------------------------------------------------------------


def save_signed_authority(signed: SignedAuthority, path: Path | None = None) -> Path:
    p = path if path is not None else paths.authority_path(signed.document.engagement_slug)
    paths.secure_write(p, json.dumps(signed.model_dump(mode="json"), indent=2))  # X2: owner-only
    return p


def load_signed_authority(slug: str, path: Path | None = None) -> SignedAuthority:
    p = path if path is not None else paths.authority_path(slug)
    if not p.is_file():
        raise AuthorityError(f"no signed authority at {p} for {slug!r}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AuthorityError(f"signed authority for {slug!r} unreadable: {e}") from e
    try:
        return SignedAuthority.model_validate(data)
    except ValidationError as e:
        raise AuthorityUnsigned(
            f"document for {slug!r} is not a valid signed authority "
            f"(is it an unsigned authority?): {e}"
        ) from e


def load_verified_authority(
    slug: str, trust_root: TrustRoot, path: Path | None = None
) -> EngagementAuthority:
    """Load a signed authority and return its document only if the
    governance threshold signature verifies. Fail closed: a missing,
    unsigned, or badly-signed authority raises rather than returning an
    unverified document."""
    signed = load_signed_authority(slug, path)
    ok, reason = verify_authority(signed, trust_root)
    if not ok:
        raise AuthorityUnsigned(f"authority for {slug!r} failed verification: {reason}")
    return signed.document


# ---------------------------------------------------------------------------
# Governance AUTHORITY trust root — the DEDICATED store, DECOUPLED from the
# entitlement store (Phase 0.1 fix).
#
# `provision_authority` persists the TrustRoot that verifies the signed
# EngagementAuthority so the engage path (`engage._engage_authority_trust_root`)
# and the console remote-engage gate (`actions._has_verified_authority`) can
# LOAD + VERIFY the authority. It MUST NOT be persisted to the entitlement
# store's `trust_root_path()` (`.entitlement/trust-root.json`), because
# `entitlement.policy._enforcement_active()` keys capability enforcement on the
# PRESENCE of a file there: writing an authority root to that path would flip
# entitlement enforcement ON with no grant minted, denying every gated
# capability on a fresh deploy. These functions read/write the SAME `TrustRoot`
# material at `paths.authority_root_path()` (`.authority-root/`, override
# VIGIL_AUTHORITY_ROOT_DIR) instead — a location `entitlement.policy` does NOT
# watch. Serialization + at-rest perms (0600, owner-only via `secure_write`)
# match the entitlement store's own trust-root write byte-for-byte; only the
# LOCATION changes. Capability enforcement stays keyed ONLY on the explicit
# entitlement provisioning flow.
# ---------------------------------------------------------------------------


def write_authority_root(trust_root: TrustRoot, path: Path | None = None) -> Path:
    """Persist the governance authority trust root to the DEDICATED authority-root
    store (never the entitlement store). Owner-only (0600) via ``secure_write``;
    identical serialization to ``entitlement.provision.write_trust_root``."""
    p = path if path is not None else paths.authority_root_path()
    paths.secure_write(p, json.dumps(trust_root.model_dump(mode="json"), indent=2))  # X2: owner-only
    return p


def load_authority_root(path: Path | None = None) -> TrustRoot | None:
    """Load the governance authority trust root from the DEDICATED authority-root
    store. Missing file -> ``None`` (unprovisioned — the caller decides greenfield
    vs. refuse). A present-but-malformed root raises ``AuthorityError`` so a governed
    deployment fails CLOSED rather than silently treating a corrupt root as absent.
    Mirrors ``entitlement.store.load_trust_root`` exactly, only the path differs."""
    p = path if path is not None else paths.authority_root_path()
    if not p.is_file():
        return None
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise AuthorityError(f"cannot read authority trust root at {p}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AuthorityError(f"authority trust root at {p} is not valid JSON: {e}") from e
    try:
        return TrustRoot.model_validate(data)
    except ValidationError as e:
        raise AuthorityError(f"authority trust root at {p} failed schema validation: {e}") from e
