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
import tempfile
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
# process is sharded AND its root is dedicated to this tenant. Enforcement = a trust-on-first-use
# ROOT-OWNERSHIP claim published ATOMICALLY (write the id to a temp file in the same dir, then os.link it
# into place — link is atomic and refuses an existing target, so the claim file NEVER has an observable
# 0-byte/partial window and a create that loses the race is cleanly refused), plus a scan for another
# tenant's existing spine/memory shard under the root. A malformed/empty/partial claim (old-bug or crash
# residue) is a HARD fail-closed state, NEVER "unclaimed" — so the guard can never degrade to pass-for-all.
# ---------------------------------------------------------------------------

_TENANT_OWNER_FILE = ".tenant-owner"


def tenant_claim_path() -> Path:
    """The per-root ownership record — which single tenant owns THIS ``CRUCIBLE_ROOT``. It lives at the v2
    root and is deliberately NOT sharded: it is the root-level lock, one per root. Owner-only on disk."""
    return paths.v2_root() / _TENANT_OWNER_FILE


def _classify_claim() -> tuple[str, str | None]:
    """Read + classify the on-disk root-ownership claim. Returns one of:

      * ``("absent", None)``       — no claim file: the root is genuinely unclaimed.
      * ``("owned", <tenant>)``    — a well-formed claim naming a VALID tenant id.
      * ``("malformed", <detail>)``— the file exists but is empty / whitespace / not a valid tenant id
        (the OLD 0-byte-window bug's residue, a crash between temp-write and publish that somehow touched
        the path, or manual corruption). This is a HARD fail-closed state, NEVER 'unclaimed', so a partial
        claim can never let the guard degrade to pass-for-all.

    TOTAL and fail-closed on ambiguity: an UNREADABLE file classifies as ``malformed`` (never ``absent``).
    Only a genuine ``FileNotFoundError`` is ``absent``."""
    p = tenant_claim_path()
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ("absent", None)
    except OSError:
        return ("malformed", "<unreadable>")
    val = raw.strip()
    if val and paths._TENANT_RE.fullmatch(val):
        return ("owned", val)
    return ("malformed", raw[:64] or "<empty>")


def root_owner() -> str | None:
    """The tenant recorded as owning this root, or ``None`` when the root is genuinely UNCLAIMED (no file).

    Convenience accessor for status / tests. NOTE: it returns ``None`` only for an absent file; a present-
    but-malformed/empty claim is NOT silently 'unclaimed' — it is a fail-closed state surfaced by
    :func:`assert_tenant_fleet_isolated` and :func:`shard_summary`. Control flow uses :func:`_classify_claim`
    directly, never this accessor, so a malformed residue can never be mistaken for an unclaimed root."""
    state, val = _classify_claim()
    return val if state == "owned" else None


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
    """Publish ``t`` as this root's owner ATOMICALLY. The claim file, once visible at its path, ALWAYS
    contains a valid tenant id: the id is written (+fsync) to a UNIQUE temp file in the SAME directory,
    then hard-LINKED into place. ``os.link`` is atomic and raises ``FileExistsError`` if the claim already
    exists — giving exclusive-create semantics WITHOUT the 0-byte window a create-then-write has. The temp
    is always unlinked (finally), so a lost race or a crash leaves no claim residue at the path.

    On a lost race (another worker linked first) it re-classifies the now-complete claim and FAILS CLOSED
    unless the winner is us (idempotent). Any other link failure (e.g. a FS without hardlinks) also fails
    CLOSED — we never fall back to a replacing rename, which would let a second tenant overwrite the first."""
    p = tenant_claim_path()
    paths.secure_dir(p.parent)
    fd, tmpname = tempfile.mkstemp(prefix=_TENANT_OWNER_FILE + ".", dir=str(p.parent))
    tmp = Path(tmpname)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(t + "\n")
            f.flush()
            os.fsync(f.fileno())              # temp is complete + durable BEFORE it is published
        try:
            os.chmod(tmp, paths.SECURE_FILE_MODE)   # mkstemp is already 0600; be explicit
        except OSError:
            pass
        try:
            os.link(str(tmp), str(p))         # ATOMIC publish; FileExistsError if already claimed
        except FileExistsError:
            state, owner = _classify_claim()
            if state == "owned" and owner == t:
                return                        # we already own it (idempotent / our own prior claim)
            raise TenantIsolationError(
                f"CRUCIBLE_ROOT was claimed by tenant {owner!r} (claim state={state}), not {t!r} "
                f"(startup race) — refusing to run a second tenant in one root")
        except OSError as e:                  # e.g. FS without hardlink support: fail CLOSED, never rename
            raise TenantIsolationError(
                f"could not atomically claim CRUCIBLE_ROOT for tenant {t!r} ({e}) — refusing to run "
                f"without exclusive ownership (fail-closed)") from e
        _fsync_dir(p.parent)                  # best-effort: make the new link durable across a power loss
    finally:
        try:
            os.unlink(tmp)                    # drop the temp; the linked claim (if any) survives
        except OSError:
            pass


def _fsync_dir(d: Path) -> None:
    """Best-effort fsync of a directory so a freshly-linked entry survives a power loss. Never raises."""
    try:
        dfd = os.open(str(d), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


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

    Ownership is published atomically (write a temp file, then ``os.link`` it into place), so a CONCURRENT
    startup of N workers in one root has EXACTLY ONE winner and every other FAILS CLOSED — there is no
    0-byte window a loser could read as 'unclaimed', and a malformed/empty claim (crash residue) fails
    closed for everyone rather than degrading the guard to pass-for-all. With ``claim=True`` (default) an
    absent claim is taken (TOFU); with ``claim=False`` it is read-only (a dry-run / status probe — verifies
    but never claims). To re-purpose a root for a new tenant, remove its ``.tenant-owner`` file."""
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
    # (2b) root-ownership claim (TOFU, atomic publish). Classify the on-disk claim FIRST.
    state, owner = _classify_claim()
    if state == "malformed":
        raise TenantIsolationError(
            f"CRUCIBLE_ROOT has a malformed/empty {_TENANT_OWNER_FILE} (detail={owner!r}): refusing to "
            f"run (fail-closed — a partial/corrupt claim is NEVER treated as unclaimed, so it can't "
            f"degrade the guard to pass-for-all). Likely crash residue; remove {_TENANT_OWNER_FILE} to "
            f"re-purpose this root, then restart.")
    if state == "owned" and owner != t:
        raise TenantIsolationError(
            f"CRUCIBLE_ROOT is owned by tenant {owner!r}, not {t!r}: refusing to run a second tenant in "
            f"one root (would commingle targets/evidence/authority/kill-switch). Give tenant {t!r} its "
            f"own root, or remove {_TENANT_OWNER_FILE} to re-purpose this root.")
    if state == "owned":                       # owner == t: already ours (idempotent re-attach)
        return
    if claim:                                  # state == "absent": take exclusive ownership atomically
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
    state, owner = _classify_claim()
    owner_label = {
        "absent": "(unclaimed)",
        "owned": owner or "(unclaimed)",
        "malformed": "(MALFORMED — fail-closed; remove .tenant-owner to re-purpose)",
    }.get(state, "(unknown)")
    return {
        "tenant": t if t is not None else "(shared/default)",
        "blackboard_db": str(sp["blackboard"]),
        "memory_db": str(sp["memory"]),
        "root_owner": owner_label,
    }
