"""
common.tenant — the horizontal single-tenant worker contract (Wave D / D2).

CRUCIBLE scales OUT by running ONE tenant per process. That is the whole model:

  * ``crucible_root()`` is an ``lru_cache(maxsize=1)`` — a process resolves exactly one root and
    holds it for its lifetime, and
  * the append-only, hash-chained spine is single-writer-per-engagement.

So a "worker" is just a process that has pinned its tenant. A fleet launcher sets
``CRUCIBLE_TENANT=<id>`` in each child's environment before exec; every ``.blackboard`` / ``.memory``
SQLite path that child resolves then shards under that tenant (see ``common.paths``). The result:

  * N single-tenant workers never contend on ONE SQLite file (SQLite serialises writers per file), and
  * a tenant-A worker can NEVER read or write tenant-B's spine / memory: the ONLY shard it can name
    through the path API is its own. No cross-tenant commingling — a hard sovereignty invariant.

This module is the small, explicit surface over that contract: resolve the tenant, report where a
worker's sharded stores live (health / observability), and a runtime-checkable guard that two tenants'
stores are physically disjoint. It adds no new state and no new env keys beyond ``CRUCIBLE_TENANT``.

Scope. The shard covers the two GLOBAL, cross-engagement singletons — ``.blackboard`` (the spine) and
``.memory`` (MLS). Per-engagement state (``targets/<slug>/`` charter, evidence, authority, kill-switch)
is ALREADY namespaced by slug within a root. For strongest isolation a fleet gives each tenant its OWN
``CRUCIBLE_ROOT`` (separate tree ⇒ separate spine, memory, evidence and authority); the shard here is
what removes the last cross-engagement GLOBAL DB contention/commingling even when a root is shared.
A fleet that must never share a root should assert :func:`is_sharded` (and, for the strong topology, a
distinct ``CRUCIBLE_ROOT``) at worker startup.

Default (no ``CRUCIBLE_TENANT``): the process is the historical single, shared, un-sharded store —
byte-identical to pre-D2.
"""

from __future__ import annotations

from pathlib import Path

from . import paths


def tenant_id() -> str | None:
    """The tenant this process serves, or ``None`` when unsharded (the shared default store).

    Delegates to :func:`common.paths.active_tenant` (the single source of truth + fail-closed
    validation of ``CRUCIBLE_TENANT``). Re-raises its ``CrucibleRootNotFound`` for a set-but-unsafe id
    rather than masking it — a worker with a bad tenant id must fail, never silently share a store."""
    return paths.active_tenant()


def is_sharded() -> bool:
    """True when this process is pinned to a specific tenant (a sharded worker)."""
    return tenant_id() is not None


def store_paths(tenant: str | None = None) -> dict[str, Path]:
    """The resolved on-disk store paths for a tenant — its append-only spine and its MLS memory DB.

    With ``tenant=None`` (default) it reports THIS process's paths (honouring ``CRUCIBLE_TENANT``).
    Passing an explicit ``tenant`` computes another tenant's paths WITHOUT changing this process's env
    — used by :func:`assert_isolated_from` and by tests to prove two tenants are disjoint."""
    if tenant is None:
        return {"blackboard": paths.blackboard_dir() / "store.sqlite",
                "memory": paths.memory_db()}
    # Compute a named tenant's paths deterministically off the same v2 root, without mutating env.
    base = paths.v2_root()
    shard = Path(paths._TENANT_SUBDIR) / _validated(tenant)
    return {"blackboard": base / ".blackboard" / shard / "store.sqlite",
            "memory": base / ".memory" / shard / "store.sqlite"}


def _validated(tenant: str) -> str:
    """Validate an explicitly-supplied tenant id through the same fail-closed rule as the env path, so a
    caller cannot smuggle a traversal component into a computed shard path."""
    raw = (tenant or "").strip()
    if not raw or not paths._TENANT_RE.fullmatch(raw):
        from .errors import CrucibleRootNotFound
        raise CrucibleRootNotFound(
            f"tenant id {tenant!r} is not a safe single path component (fail-closed)")
    return raw


def assert_isolated_from(other_tenant: str) -> None:
    """Sovereignty guard: raise unless THIS process's store paths are physically disjoint from
    ``other_tenant``'s — no shared spine file, no shared memory file, and neither path nested inside
    the other. A cheap, runtime-checkable assertion of the no-cross-tenant-commingling invariant that a
    worker (or a test) can call to prove it can never touch another tenant's data through the path API."""
    mine = store_paths()
    theirs = store_paths(other_tenant)
    for kind in ("blackboard", "memory"):
        a = mine[kind].resolve() if _exists_parent(mine[kind]) else mine[kind]
        b = theirs[kind].resolve() if _exists_parent(theirs[kind]) else theirs[kind]
        if a == b or _is_relative(a, b) or _is_relative(b, a):
            raise AssertionError(
                f"tenant isolation violated on {kind}: this worker's store {a} is not disjoint from "
                f"tenant {other_tenant!r}'s store {b}")


def _exists_parent(p: Path) -> bool:
    try:
        return p.parent.exists()
    except OSError:
        return False


def _is_relative(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def shard_summary() -> dict[str, str]:
    """A flat, printable summary for status / health output: the active tenant (or a marker for the
    shared default) and the resolved spine + memory store paths this worker uses. Total — never raises
    for the default; a set-but-unsafe ``CRUCIBLE_TENANT`` surfaces as the validation error string."""
    try:
        t = tenant_id()
    except Exception as exc:  # noqa: BLE001 — a bad tenant id is a status readout, not a crash
        return {"tenant": f"INVALID ({exc})", "blackboard_db": "-", "memory_db": "-"}
    sp = store_paths()
    return {
        "tenant": t if t is not None else "(shared/default)",
        "blackboard_db": str(sp["blackboard"]),
        "memory_db": str(sp["memory"]),
    }
