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
  * a tenant-A worker can NEVER read or write tenant-B's SPINE or MEMORY: the ONLY shard it can name
    through the path API is its own.

SCOPE OF THE SHARD — read this before claiming tenant isolation.
The D2 shard isolates EXACTLY TWO stores: ``.blackboard`` (the spine) and ``.memory`` (MLS). It does
NOT isolate the per-engagement state, which is namespaced by SLUG, not by tenant:

    targets/<slug>/    (charter, notes, attack-tree, reports)
    <slug> evidence    (evidence_dir / evidence_archive_dir — raw HTTP incl. credential excerpts)
    <slug>.authority   (the signed EngagementAuthority) and <slug>.halt (kill-switch)

Per-slug is per-ENGAGEMENT namespacing, NOT per-tenant. So in a SHARED ``CRUCIBLE_ROOT`` two tenants
(``CRUCIBLE_TENANT=A`` and ``=B``) that run an engagement under the SAME slug — e.g. both scanning the
same target, whose slug is derived from the target — get isolated spine/memory but COMMINGLE their
findings, evidence and authorization under the shared ``targets/<slug>`` / evidence / authority /
kill-switch. That is real cross-tenant commingling of the most sensitive artifacts.

Therefore: ONE ``CRUCIBLE_ROOT`` PER TENANT IS REQUIRED for genuine tenant isolation — it is not
"strongest / optional", it is the deployment requirement. A dedicated root gives a separate tree for
spine, memory, evidence, targets, authority and kill-switch; the shard here additionally removes the
last cross-engagement GLOBAL DB contention within whatever root a tenant is given.

A fleet MUST call :func:`assert_tenant_fleet_isolated` at worker startup: it FAILS CLOSED unless the
process is sharded AND its ``CRUCIBLE_ROOT`` is dedicated to this tenant, so a mis-deploy of two
tenants into one root is a hard startup error, never silent commingling.

Default (no ``CRUCIBLE_TENANT``): the process is the historical single, shared, un-sharded store —
byte-identical to pre-D2. That default is a single-tenant/legacy deployment; it is NOT a multi-tenant
mode, and :func:`assert_tenant_fleet_isolated` refuses it for fleet use.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import paths
from .errors import CrucibleError, CrucibleRootNotFound


class TenantIsolationError(CrucibleError):
    """A fleet deployment does not (or would not) give genuine single-tenant isolation. Raised
    fail-closed by :func:`assert_tenant_fleet_isolated` at worker startup so a mis-deploy — an
    unsharded fleet worker, or two tenants sharing one ``CRUCIBLE_ROOT`` — halts BEFORE it can
    commingle findings / evidence / authorization, never after."""


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


# ---------------------------------------------------------------------------
# Fail-closed fleet-startup isolation guard.
#
# The shard isolates spine + memory only; targets/evidence/authority/killswitch are per-SLUG, so two
# tenants sharing a root AND a slug commingle them. One CRUCIBLE_ROOT per tenant is REQUIRED. This guard
# makes that requirement enforceable: a fleet worker calls it at startup and it FAILS CLOSED unless the
# process is sharded AND its root is dedicated to this tenant. Enforcement = a race-free trust-on-first-
# use ROOT-OWNERSHIP claim (atomic O_EXCL) at the v2 root, plus a scan for another tenant's existing
# spine/memory shard already under the root (catches a root that housed another tenant before any claim).
# ---------------------------------------------------------------------------

_TENANT_OWNER_FILE = ".tenant-owner"


def tenant_claim_path() -> Path:
    """The per-root ownership record — which single tenant owns THIS ``CRUCIBLE_ROOT``. It lives at the v2
    root and is deliberately NOT sharded: it is the root-level lock, one per root. Owner-only on disk."""
    return paths.v2_root() / _TENANT_OWNER_FILE


def root_owner() -> str | None:
    """The tenant recorded as owning this root (the TOFU claim), or ``None`` if the root is unclaimed."""
    try:
        return (tenant_claim_path().read_text(encoding="utf-8").strip() or None)
    except OSError:
        return None


def _other_tenant_shards(active: str) -> list[str]:
    """Tenant shard dirs under this root's ``.blackboard`` / ``.memory`` that belong to a tenant OTHER
    than ``active`` — direct on-disk evidence the root already houses another tenant's spine/memory (so
    it is a SHARED root, and its targets/evidence/authority will commingle). Total: unreadable/absent
    dirs contribute nothing."""
    seen: set[str] = set()
    for base in (paths.v2_root() / ".blackboard" / paths._TENANT_SUBDIR,
                 paths.v2_root() / ".memory" / paths._TENANT_SUBDIR):
        try:
            for child in base.iterdir():
                if child.is_dir() and child.name != active:
                    seen.add(child.name)
        except OSError:
            continue
    return sorted(seen)


def _claim_root(t: str) -> None:
    """Atomically record ``t`` as this root's owner (O_EXCL — race-free). On a lost race (another worker
    claimed in the gap) re-read and FAIL CLOSED if the winner is a different tenant."""
    p = tenant_claim_path()
    paths.secure_dir(p.parent)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, paths.SECURE_FILE_MODE)
    except FileExistsError:
        owner = root_owner()
        if owner is not None and owner != t:
            raise TenantIsolationError(
                f"CRUCIBLE_ROOT was just claimed by tenant {owner!r}, not {t!r} (startup race) — "
                f"refusing to run a second tenant in one root")
        return
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(t + "\n")


def assert_tenant_fleet_isolated(*, claim: bool = True) -> None:
    """FAIL-CLOSED fleet-startup guard for genuine single-tenant isolation. A fleet worker MUST call this
    at startup. It raises :class:`TenantIsolationError` unless BOTH hold:

      1. this process is SHARDED (``CRUCIBLE_TENANT`` set) — the unsharded default is the shared store and
         is NOT tenant-isolated; and
      2. this ``CRUCIBLE_ROOT`` is DEDICATED to this tenant — no other tenant owns it (TOFU claim) and no
         other tenant's spine/memory shard already lives under it.

    Why (see the module docstring): the shard isolates ONLY spine + memory. ``targets/<slug>``,
    ``<slug>`` evidence, ``<slug>.authority`` and ``<slug>.halt`` are per-ENGAGEMENT (slug), not
    per-tenant, so two tenants sharing a root AND a slug commingle findings / evidence / authorization.
    One root per tenant is REQUIRED; this guard turns a mis-deploy into a hard startup error.

    With ``claim=True`` (default) it takes race-free ownership of an unclaimed root (TOFU). With
    ``claim=False`` it is read-only (a dry-run / status probe — verifies but never claims). To re-purpose
    a root for a new tenant, remove its ``.tenant-owner`` file."""
    t = tenant_id()                    # raises CrucibleRootNotFound on an unsafe id; None when unsharded
    if t is None:
        raise TenantIsolationError(
            "fleet worker is not sharded (CRUCIBLE_TENANT unset): the shared/default store is not "
            "tenant-isolated. Set CRUCIBLE_TENANT and give this tenant a dedicated CRUCIBLE_ROOT.")
    # (2a) another tenant's spine/memory shard already under this root => a shared root => commingling
    others = _other_tenant_shards(t)
    if others:
        raise TenantIsolationError(
            f"CRUCIBLE_ROOT is shared: it already houses spine/memory shards for other tenant(s) "
            f"{others!r} besides {t!r}. targets/evidence/authority/kill-switch are NOT tenant-sharded, "
            f"so tenants sharing this root commingle them. Give tenant {t!r} its own CRUCIBLE_ROOT.")
    # (2b) race-free root-ownership claim (TOFU)
    owner = root_owner()
    if owner is not None and owner != t:
        raise TenantIsolationError(
            f"CRUCIBLE_ROOT is owned by tenant {owner!r}, not {t!r}: refusing to run a second tenant in "
            f"one root (would commingle targets/evidence/authority/kill-switch). Give tenant {t!r} its "
            f"own root, or remove {_TENANT_OWNER_FILE} to re-purpose this root.")
    if claim and owner is None:
        _claim_root(t)


def shard_summary() -> dict[str, str]:
    """A flat, printable summary for status / health output: the active tenant (or a marker for the
    shared default), the resolved spine + memory store paths this worker uses, and the root's recorded
    owner (the TOFU claim, or ``(unclaimed)``). Total — never raises for the default; a set-but-unsafe
    ``CRUCIBLE_TENANT`` surfaces as the validation error string."""
    try:
        t = tenant_id()
    except Exception as exc:  # noqa: BLE001 — a bad tenant id is a status readout, not a crash
        return {"tenant": f"INVALID ({exc})", "blackboard_db": "-", "memory_db": "-",
                "root_owner": "-"}
    sp = store_paths()
    return {
        "tenant": t if t is not None else "(shared/default)",
        "blackboard_db": str(sp["blackboard"]),
        "memory_db": str(sp["memory"]),
        "root_owner": root_owner() or "(unclaimed)",
    }
