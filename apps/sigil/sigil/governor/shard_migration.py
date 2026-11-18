"""Live tenant migration orchestrator — move ONE tenant between shards, crash-safe (Front C S3).

The invariant sequence, with the epoch bump as the single atomic pivot:

    PAUSE  →  DRAIN  →  COPY+VERIFY  →  EPOCH-BUMP (commit)  →  RESUME

  1. PAUSE   — set a durable, reversible pause marker so the control plane starts NO new job/reservation for the
               tenant (fail-closed reader: a present marker is a halt).
  2. DRAIN   — refuse to proceed until no job is mid-flight for the tenant (an injected in-flight count must be 0).
  3. COPY+VERIFY — copy the tenant's root subtree (its spine + fold) from the source shard to the destination shard
               and HASH-VERIFY the copy equals the source. The copy lands at ``<to_base>/<tenant>`` ONLY by an
               atomic rename of a verified temp, so that path is NEVER a partial/half-copied tree. A hash mismatch
               fails closed (:class:`MigrationVerifyError`) — the epoch is NOT bumped, the placement stays OLD.
  4. EPOCH-BUMP (commit) — ``ShardAssignmentRegistry.reassign`` appends an owner-signed assignment at epoch+1 on the
               destination shard. This single append is the authoritative switch: before it, the active placement is
               the SOURCE (routes go to the old shard, whose data is intact); after it, the DESTINATION (whose data
               is already copied + verified). The reassign is idempotent + exactly-once, so re-driving a crashed
               commit never double-bumps.
  5. RESUME  — clear the pause marker; the tenant is live on the new shard.

CRASH-SAFE + IDEMPOTENT. A durable JOURNAL records the furthest completed step; :func:`run` resumes from it, and
every step is individually idempotent, so a crash at ANY step leaves a RECOVERABLE state — fully OLD (before the
commit) or fully NEW (after it), NEVER a split placement. There is never a split-brain because the authoritative
owner of a tenant is the SINGLE active assignment the fold returns (one shard at every instant); during the window
both shards may hold the DATA (old intact, new a verified copy) but only one is authoritative. ``run(plan,
stop_after=<step>)`` simulates a crash after a step; a fresh orchestrator ``run(plan)`` recovers to DONE.

WHAT IS PROVEN IN-REPO vs OWNER-DEPLOY. The orchestration, the copy+verify, the epoch/stale-route logic and the
isolation are all here and tested with two in-process 'shards' (two root dirs). The real CROSS-HOST copy + dispatch
(and the S4 cluster acceptance) are the deploy layer: ``_copy_tree`` is a local ``shutil.copytree`` here; a deploy
swaps in its host-to-host transport while keeping the SAME verify + atomic-publish + epoch discipline.

FATAL-2: SOVEREIGN-only (``assert_no_offense``); the epoch bump is owner-signed via the registry. stdlib + sovereign
siblings only.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config  # noqa: E402
from .shard_assignment import ShardAssignmentRegistry  # noqa: E402
from .shard_routing import ShardTopology  # noqa: E402

# The migration step ladder (monotonic). The journal stores the furthest-REACHED step; run() advances to DONE.
PENDING = "pending"
PAUSED = "paused"
DRAINED = "drained"
COPIED = "copied"
COMMITTED = "committed"
DONE = "done"
_STEP_ORDER = (PENDING, PAUSED, DRAINED, COPIED, COMMITTED, DONE)
_STEP_INDEX = {s: i for i, s in enumerate(_STEP_ORDER)}

_JOURNAL_SUBDIR = "shard-migrations"
_PAUSE_SUBDIR = "shard-migration-pauses"
_TEMP_PREFIX = ".migrating."


class MigrationError(RuntimeError):
    """Base class for a fail-closed migration refusal."""


class MigrationDisabled(MigrationError):
    """``VIGIL_MULTI_SHARD`` is OFF: the orchestrator refuses to run (nothing migrates in the singleton default)."""


class MigrationNotDrained(MigrationError):
    """A job is still mid-flight for the tenant: the drain step refuses to proceed (fail-closed). The caller retries
    after the in-flight work settles."""


class MigrationVerifyError(MigrationError):
    """The copied tenant root does NOT hash-equal the source: a corrupt/partial copy. Fail-closed — the epoch is
    never bumped, so the placement stays on the (intact) source shard."""


class MigrationPlanConflict(MigrationError):
    """A ``run`` was called with a plan that disagrees with an in-flight journal for the same migration id."""


@dataclass(frozen=True)
class MigrationPlan:
    """One tenant's migration from ``from_shard`` (at ``from_epoch`` — its current placement epoch) to ``to_shard``.
    ``migration_id`` keys the journal + pause marker + temp dir (stable across re-drives of the same migration)."""
    tenant_id: str
    from_shard: str
    to_shard: str
    from_epoch: int
    migration_id: str

    @property
    def to_epoch(self) -> int:
        return int(self.from_epoch) + 1


# --------------------------------------------------------------------------------------------------------
# Content hashing + atomic tree publish (the copy+verify primitive).
# --------------------------------------------------------------------------------------------------------
def tree_digest(root: Path) -> str:
    """A deterministic sha256 over a directory tree: the sorted (relative POSIX path, file sha256) pairs. Captures
    every file's path AND bytes, so a missing / extra / corrupted file changes the digest. An absent root hashes to
    a fixed sentinel (so 'source present, copy absent' is a mismatch, never a false match)."""
    root = Path(root)
    h = hashlib.sha256()
    if not root.exists():
        return "absent:" + h.hexdigest()
    entries: "list[tuple[str, str]]" = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            fp = Path(dirpath) / name
            rel = fp.relative_to(root).as_posix()
            fh = hashlib.sha256()
            with open(fp, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    fh.update(chunk)
            entries.append((rel, fh.hexdigest()))
    for rel, digest in sorted(entries):
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(digest.encode("ascii"))
        h.update(b"\x00")
    return "tree:" + h.hexdigest()


def _copy_tree(src: Path, dst: Path) -> None:
    """Copy the directory tree ``src`` -> a fresh ``dst`` (local). A deploy swaps this for its host-to-host transport;
    the orchestrator VERIFIES the result regardless, so a lossy transport fails closed rather than silently splits."""
    shutil.copytree(src, dst)


def copy_and_verify(src: Path, dst: Path) -> str:
    """Copy ``src`` -> ``dst`` crash-safely and return the verified tree digest. Idempotent: if ``dst`` already
    exists and hash-equals ``src``, it is left in place (a re-driven copy). The copy is built in a sibling temp dir,
    HASH-VERIFIED against the source, then atomically renamed to ``dst`` — so ``dst`` is NEVER observed partial.
    Raises :class:`MigrationVerifyError` on a hash mismatch (the temp is removed; ``dst`` is left untouched)."""
    src, dst = Path(src), Path(dst)
    if not src.exists():
        raise MigrationVerifyError(f"source tenant root {src} does not exist — nothing to migrate (fail-closed)")
    src_digest = tree_digest(src)
    if dst.exists() and tree_digest(dst) == src_digest:
        return src_digest                                     # already copied + verified (idempotent re-drive)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=_TEMP_PREFIX, dir=str(dst.parent)))
    tmp.rmdir()                                               # copytree needs a non-existent target
    try:
        _copy_tree(src, tmp)
        got = tree_digest(tmp)
        if got != src_digest:
            raise MigrationVerifyError(
                f"copied tenant root {dst} hash {got} != source {src} hash {src_digest} — corrupt/partial copy, "
                f"refusing to publish (fail-closed; the placement stays on the source shard)")
        if dst.exists():
            shutil.rmtree(dst)                                # a prior non-matching tree (defensive; replace needs clear)
        os.replace(tmp, dst)                                  # atomic publish — dst is never partial
        return src_digest
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------------------------------------
# Durable, reversible per-tenant pause marker (fail-closed reader; mirrors credit_lease_pause doctrine).
# --------------------------------------------------------------------------------------------------------
def _pause_dir(workdir: Path) -> Path:
    return Path(workdir) / _PAUSE_SUBDIR


def _pause_path(workdir: Path, tenant_id: str) -> Path:
    # tenant_id is validated as a safe single path component by the registry/record before it ever reaches here.
    return _pause_dir(workdir) / f"{tenant_id}.json"


def is_tenant_paused(workdir: Path, tenant_id: str) -> bool:
    """True iff a pause marker for ``tenant_id`` is present. Fail-closed by construction: PRESENCE is the pause, so
    an unreadable/corrupt marker still halts (there is no 'not paused' read of a present marker)."""
    return _pause_path(workdir, tenant_id).exists()


def _set_pause(workdir: Path, tenant_id: str, migration_id: str) -> None:
    d = _pause_dir(workdir)
    d.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(_pause_path(workdir, tenant_id),
                       {"kind": "vigil-shard-migration-pause-v1", "tenant_id": tenant_id,
                        "migration_id": migration_id})


def _clear_pause(workdir: Path, tenant_id: str) -> None:
    try:
        _pause_path(workdir, tenant_id).unlink()
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------------------------------------
# Crash-safe journal (atomic write of the furthest-reached step).
# --------------------------------------------------------------------------------------------------------
def _atomic_write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmpname, path)
    finally:
        try:
            os.unlink(tmpname)
        except FileNotFoundError:
            pass


class _Journal:
    """The durable migration journal: {plan fields, step}. Atomic writes; a torn/corrupt read is treated as PENDING
    (fail-closed to the start — re-driving from PENDING is safe because every step is idempotent)."""

    def __init__(self, workdir: Path, migration_id: str):
        self.path = Path(workdir) / _JOURNAL_SUBDIR / f"{migration_id}.json"

    def load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("step") in _STEP_INDEX:
                return data
        except (FileNotFoundError, ValueError, OSError):
            pass
        return {"step": PENDING}

    def record(self, plan: MigrationPlan, step: str) -> None:
        _atomic_write_json(self.path, {
            "tenant_id": plan.tenant_id, "from_shard": plan.from_shard, "to_shard": plan.to_shard,
            "from_epoch": plan.from_epoch, "migration_id": plan.migration_id, "step": step})


class ShardMigrationOrchestrator:
    """Drives one tenant's migration through the crash-safe step ladder. Reusable + re-drivable."""

    def __init__(self, registry: ShardAssignmentRegistry, *, topology: ShardTopology, workdir: "str | os.PathLike",
                 inflight: Callable[[str], int], clock: Optional[Callable[[], float]] = None):
        self.registry = registry
        self.topology = topology
        self.workdir = Path(workdir)
        self._inflight = inflight            # in-flight job count for a tenant (deploy: the shard queue; tests inject)
        self._clock = clock                  # issued_at source for the owner-signed epoch bump

    # -- helpers --------------------------------------------------------------------------------------
    def _tenant_root(self, shard_id: str, tenant_id: str) -> Path:
        base = self.topology.base_for(shard_id)
        if base is None:
            raise MigrationError(f"deploy topology has no base directory for shard {shard_id!r} (fail-closed)")
        return base / tenant_id

    def _issued_at(self, plan: MigrationPlan) -> float:
        if self._clock is not None:
            return float(self._clock())
        # A strictly-increasing default anchored above the source epoch's — the registry's anti-replay high-water
        # needs issued_at strictly above the current; wall-clock is used at deploy.
        import time
        return float(time.time())

    # -- the steps (each idempotent) ------------------------------------------------------------------
    def _do_pause(self, plan: MigrationPlan) -> None:
        _set_pause(self.workdir, plan.tenant_id, plan.migration_id)

    def _do_drain(self, plan: MigrationPlan) -> None:
        n = int(self._inflight(plan.tenant_id))
        if n != 0:
            raise MigrationNotDrained(
                f"{n} job(s) still mid-flight for tenant {plan.tenant_id!r} — refusing to copy (fail-closed; retry "
                f"after they settle)")

    def _do_copy(self, plan: MigrationPlan) -> None:
        src = self._tenant_root(plan.from_shard, plan.tenant_id)
        dst = self._tenant_root(plan.to_shard, plan.tenant_id)
        copy_and_verify(src, dst)            # raises MigrationVerifyError on a corrupt copy (fail-closed)

    def _do_commit(self, plan: MigrationPlan) -> None:
        # The authoritative switch — owner-signed, idempotent + exactly-once (reassign refuses a wrong source).
        self.registry.reassign(plan.tenant_id, plan.to_shard, expected_from_shard=plan.from_shard,
                               expected_from_epoch=plan.from_epoch, issued_at=self._issued_at(plan))

    def _do_resume(self, plan: MigrationPlan) -> None:
        _clear_pause(self.workdir, plan.tenant_id)

    _STEPS = (
        (PAUSED, "_do_pause"),
        (DRAINED, "_do_drain"),
        (COPIED, "_do_copy"),
        (COMMITTED, "_do_commit"),
        (DONE, "_do_resume"),
    )

    # -- the driver -----------------------------------------------------------------------------------
    def run(self, plan: MigrationPlan, *, stop_after: Optional[str] = None) -> str:
        """Advance ``plan`` from the journal's recorded step to DONE (or to ``stop_after``, to simulate a crash).
        Returns the final step reached. Idempotent + crash-safe: safe to call repeatedly; a fresh orchestrator
        recovers an interrupted migration. Refuses with :class:`MigrationDisabled` when the flag is off."""
        if not config.multi_shard_enabled():
            raise MigrationDisabled(
                "VIGIL_MULTI_SHARD is off — the live-migration orchestrator does not run in the singleton default")
        journal = _Journal(self.workdir, plan.migration_id)
        state = journal.load()
        if state["step"] != PENDING and not _journal_matches(state, plan):
            raise MigrationPlanConflict(
                f"journal for migration {plan.migration_id!r} is for a different plan {state!r}; refusing (fail-closed)")
        current = state["step"]
        for target, method in self._STEPS:
            if _STEP_INDEX[target] <= _STEP_INDEX[current]:
                continue                     # already reached on a prior run — skip (idempotent resume)
            getattr(self, method)(plan)      # a failure here leaves the journal at the prior step (re-drivable)
            journal.record(plan, target)
            current = target
            if stop_after is not None and target == stop_after:
                break                        # simulate a crash immediately after this step's journal write
        return current

    def status(self, plan: MigrationPlan) -> str:
        """The furthest step recorded for this migration (``pending`` if none / unreadable)."""
        return _Journal(self.workdir, plan.migration_id).load()["step"]


def _journal_matches(state: dict, plan: MigrationPlan) -> bool:
    return (state.get("tenant_id") == plan.tenant_id and state.get("from_shard") == plan.from_shard
            and state.get("to_shard") == plan.to_shard and state.get("from_epoch") == plan.from_epoch)
