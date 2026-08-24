"""Trust-authority registry — the public keys VSCP trusts (W13-7 / #500).

Stores ONLY public material, validated canonical via the shared ``vigil_core`` crypto (the
same non-canonical / low-order rejection the rest of the monorepo uses). WRITES are gated
through the RBAC-of-record: a reviewer is refused before any row is written.
"""
from __future__ import annotations

from dataclasses import dataclass

from vigil_core.crypto import IntegrityError, load_public_key
from vigil_core.rbac import role_can

from ..authorization import PermissionRefused, action_permission
from ..store import VscpStore

__all__ = ["TrustAuthority", "TrustAuthorityRegistry"]


@dataclass(frozen=True)
class TrustAuthority:
    id: str
    name: str
    public_key_b64: str
    created_at: str
    created_by: str


class TrustAuthorityRegistry:
    def __init__(self, store: VscpStore) -> None:
        self._store = store

    def register(self, *, role: str | None, id: str, name: str, public_key_b64: str) -> TrustAuthority:
        """Register a trust authority (public key only). Reviewer/insufficient role ->
        PermissionRefused. A non-canonical / weak key is rejected by ``vigil_core`` before
        any write (reused crypto, not reimplemented)."""
        perm = action_permission("register_trust_authority")
        if not role_can(role, perm):
            raise PermissionRefused(
                f"role {role!r} lacks {perm!r}: registering a trust authority is a write, refused for a "
                "read-only reviewer (W13-7)"
            )
        try:
            load_public_key(public_key_b64)  # canonical + low-order validation (shared crypto)
        except IntegrityError as exc:
            raise ValueError(f"invalid Ed25519 public key: {exc}") from exc
        self._store.conn.execute(
            "INSERT INTO trust_authorities(id, name, public_key_b64, created_by) VALUES (?, ?, ?, ?)",
            (id, name, public_key_b64, str(role)),
        )
        self._store.conn.commit()
        return self.get(id)

    def get(self, id: str) -> TrustAuthority:
        row = self._store.conn.execute(
            "SELECT id, name, public_key_b64, created_at, created_by FROM trust_authorities WHERE id = ?",
            (id,),
        ).fetchone()
        if row is None:
            raise KeyError(id)
        return TrustAuthority(**dict(row))

    def list(self) -> list[TrustAuthority]:
        rows = self._store.conn.execute(
            "SELECT id, name, public_key_b64, created_at, created_by FROM trust_authorities "
            "ORDER BY created_at, id"
        ).fetchall()
        return [TrustAuthority(**dict(r)) for r in rows]
