"""Deployment registry — the control-plane instances VSCP governs (W13-7 / #500).

WRITES are gated through the RBAC-of-record: a reviewer (read-only ``viewer``) that tries
to register a deployment is refused with :class:`~vscp.authorization.PermissionRefused`
BEFORE any row is written. Reads are open to any authenticated principal (viewer+).
"""
from __future__ import annotations

from dataclasses import dataclass

from ..authorization import PermissionRefused, action_permission
from ..store import VscpStore
from vigil_core.rbac import role_can

__all__ = ["Deployment", "DeploymentRegistry"]


@dataclass(frozen=True)
class Deployment:
    id: str
    name: str
    environment: str
    created_at: str
    created_by: str


class DeploymentRegistry:
    def __init__(self, store: VscpStore) -> None:
        self._store = store

    def register(self, *, role: str | None, id: str, name: str, environment: str) -> Deployment:
        """Register a deployment. Reviewer/insufficient role -> PermissionRefused, no write."""
        perm = action_permission("register_deployment")
        if not role_can(role, perm):
            raise PermissionRefused(
                f"role {role!r} lacks {perm!r}: registering a deployment is a write, refused for a "
                "read-only reviewer (W13-7)"
            )
        self._store.conn.execute(
            "INSERT INTO deployments(id, name, environment, created_by) VALUES (?, ?, ?, ?)",
            (id, name, environment, str(role)),
        )
        self._store.conn.commit()
        return self.get(id)

    def get(self, id: str) -> Deployment:
        row = self._store.conn.execute(
            "SELECT id, name, environment, created_at, created_by FROM deployments WHERE id = ?",
            (id,),
        ).fetchone()
        if row is None:
            raise KeyError(id)
        return Deployment(**dict(row))

    def list(self) -> list[Deployment]:
        rows = self._store.conn.execute(
            "SELECT id, name, environment, created_at, created_by FROM deployments ORDER BY created_at, id"
        ).fetchall()
        return [Deployment(**dict(r)) for r in rows]
