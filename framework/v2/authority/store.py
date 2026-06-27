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


class AuthorityError(CrucibleError):
    """Authority document missing or malformed."""


class AuthorityUnsigned(AuthorityError):
    """A signed authority was required but verification failed or the
    document on disk is unsigned."""


def save_authority(authority: EngagementAuthority, path: Path | None = None) -> Path:
    p = path if path is not None else paths.authority_path(authority.engagement_slug)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(authority.model_dump(mode="json"), indent=2), encoding="utf-8")
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
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(signed.model_dump(mode="json"), indent=2), encoding="utf-8")
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
