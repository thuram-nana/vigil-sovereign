"""
authority.store — persist and load an engagement authority.

The authority is a JSON document under the gitignored `.authority/`
area. The kill-switch (killswitch.py) is a separate file so the hard
stop is independent of — and cannot be undone by rewriting — the
authority document.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import ValidationError

from vigil_core.git_write_grant import GitWriteGrant, SignedGitWriteGrant, verify_git_write_grant
from vigil_core.highwater import highwater_lock

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
    "save_signed_git_write_grant",
    "load_verified_git_write_grant",
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
# GitWriteGrant — a SEPARATE owner-signed, repo-EXACT write grant (repo-connect
# Slice 3-authz). Decoupled from EngagementAuthority (adding a field there would
# break every existing authority signature). Carries expiration + revocation +
# an epoch high-water for supersession-REPLAY protection.
# ---------------------------------------------------------------------------


def _git_write_grant_path(slug: str, path: Path | None = None) -> Path:
    if path is not None:
        return path
    ap = paths.authority_path(slug)
    return ap.parent / (ap.stem + ".git-write-grant.json")


def _git_write_epoch_path(slug: str, path: Path | None = None) -> Path:
    if path is not None:
        return path
    ap = paths.authority_path(slug)
    return ap.parent / (ap.stem + ".git-write-epoch")


def save_signed_git_write_grant(signed: SignedGitWriteGrant, path: Path | None = None) -> Path:
    p = _git_write_grant_path(signed.document.engagement_slug, path)
    paths.secure_write(p, json.dumps(signed.model_dump(mode="json"), indent=2))  # X2: owner-only
    return p


def _read_floor(p: Path) -> "dict | None":
    """The recorded supersession floor ``{epoch, grant_id}``, or None when ABSENT (bootstrap). FAIL-CLOSED on
    a PRESENT-but-unparseable floor: a corrupt / tampered / partially-written ledger RAISES — it must never
    silently reset to a lower floor, which would re-admit a superseded or revoked grant (red-pen HIGH)."""
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AuthorityUnsigned(f"git-write epoch floor at {p} is unreadable/corrupt (refusing to reset): {e}") from e
    if not (isinstance(data, dict) and isinstance(data.get("epoch"), int) and isinstance(data.get("grant_id"), str)):
        raise AuthorityUnsigned(f"git-write epoch floor at {p} is malformed (refusing to reset)")
    return {"epoch": int(data["epoch"]), "grant_id": str(data["grant_id"])}


def _write_floor(p: Path, epoch: int, grant_id: str) -> None:
    """Atomically advance the supersession floor (temp + fsync + ``os.replace``, 0600). RAISES on failure — a
    lost monotonic advance must be LOUD, never silently swallowed (red-pen MEDIUM)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({"epoch": int(epoch), "grant_id": str(grant_id)},
                                separators=(",", ":")).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, p)   # atomic — no torn/empty floor on crash


def load_verified_git_write_grant(
    slug: str, trust_root: TrustRoot, *, path: Path | None = None, epoch_path: Path | None = None,
) -> "GitWriteGrant | None":
    """Load the SIGNED git-write grant for an engagement and return its document ONLY if the governance
    threshold signature verifies AND its epoch is not below the recorded high-water (supersession-REPLAY
    protection). Returns None when there is NO grant (fail-closed default: no write capability).

    Fail-closed: an unsigned / badly-signed grant, or a replayed (below-high-water) grant, RAISES rather than
    returning an unverified or stale document. When a newer grant verifies, the durable epoch high-water is
    advanced, so a revoked / superseded grant can never be replayed back into force. NB: this returns the
    verified CURRENT grant (which may be ``revoked=True``); the capability DECISION is
    :func:`authority.gate.authorize_repo_write`, which denies a revoked / out-of-window / wrong-repo grant."""
    p = _git_write_grant_path(slug, path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AuthorityError(f"git-write grant for {slug!r} unreadable: {e}") from e
    try:
        signed = SignedGitWriteGrant.model_validate(data)
    except ValidationError as e:
        raise AuthorityUnsigned(f"document for {slug!r} is not a valid signed git-write grant: {e}") from e
    ok, reason = verify_git_write_grant(signed, trust_root)
    if not ok:
        raise AuthorityUnsigned(f"git-write grant for {slug!r} failed verification: {reason}")
    grant = signed.document
    if grant.engagement_slug != slug:   # CONTENT binding — a grant for engagement A must not authorize B
        raise AuthorityUnsigned(
            f"git-write grant at {p} is for engagement {grant.engagement_slug!r}, not {slug!r} (refusing)")
    ep = _git_write_epoch_path(slug, epoch_path)
    with highwater_lock(ep):   # serialize read→check→advance across processes (no TOCTOU)
        floor = _read_floor(ep)   # RAISES on a present-but-corrupt floor (fail-closed; never resets)
        if floor is not None:
            if grant.epoch < floor["epoch"]:
                raise AuthorityUnsigned(
                    f"git-write grant for {slug!r} epoch {grant.epoch} is below the floor {floor['epoch']} "
                    "(replayed / superseded grant refused)")
            if grant.epoch == floor["epoch"] and grant.grant_id != floor["grant_id"]:
                raise AuthorityUnsigned(
                    f"git-write grant for {slug!r} at epoch {grant.epoch} does not match the recorded grant_id "
                    "(same-epoch swap refused)")
        if floor is None or grant.epoch > floor["epoch"]:
            _write_floor(ep, grant.epoch, grant.grant_id)   # advance; RAISES on write failure (no silent swallow)
    return grant


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
