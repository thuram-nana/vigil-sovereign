"""Durable external anti-rollback floor (cold-archive hard-prune, C1).

`~/.sigil/floor.json`, mode 0600, at `SIGIL_HOME` root **OUTSIDE `spine/`** so `SpineStore.reset()` /
`sigil ingest --reset` (which rmtree the spine dir) can never lower it — a routine reset shortening the
spine cannot roll the durable floor back under a warm / returning-paired verifier. A sibling
`floor.json.lock` (empty, 0600) serializes concurrent advances; back-up / audit tooling should expect it.

WHY a second, out-of-band witness: `head.json` is a plain file an attacker can overwrite with a
GENUINELY-OLD owner-signed head — a stale rollback the in-band Ed25519 signature alone cannot catch,
because that old head was validly signed. The floor's monotonic {last_seq, base_seq, base_count} plus
the `prev_head_hash` meta-chain catch that replay for any verifier that has ever seen a newer floor.
The floor only ever ADDS rejections (it is checked AFTER the in-band signature check), so with no floor
present, or values it satisfies, behavior is byte-identical to the pre-floor spine.

HONEST LIMIT (accepted, §1.3) — do NOT overclaim: the owner key is FS-resident AND `floor.json` is an
UNSIGNED file at 0600, so a SAME-HOST attacker with the owner's UID (or root) — even WITHOUT the Ed25519
key — defeats the LOCAL verify path by rewriting head.json AND floor.json together (the local verify reads
the floor fresh from that same attacker-controlled disk). The floor's real anti-rollback guarantee holds
only for (i) the routine `--reset` path (the floor lives OUTSIDE spine/, so a spine-dir rmtree can't lower
it), (ii) an OUT-OF-BAND verifier that retained a newer floor (a paired device over WireGuard), and
(iii) an attacker who can overwrite only head.json, not the floor. A COLD verifier bootstrapping off an
untrusted mirror that never authenticates the floor even once is unprotected — class-identical to today's
single-file rollback, NOT widened by pruning. Bounded (not eliminated) by seeding the initial floor over
the authenticated WireGuard pairing channel, never the mirror.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..config import FLOOR_PATH, SCOPE
from ..reuse import SignedChainHead
from ..reuse.canonical import evidence_signing_bytes, sha256_hex
from ..reuse.chain import _head_payload
from .atomicio import atomic_write_text

try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX; floor advance falls back to best-effort (single host)
    fcntl = None  # type: ignore[assignment]


class FloorDowngrade(ValueError):
    """The INTENDED refusal: an advance whose head would lower the floor / break the meta-chain (e.g. a
    stale concurrent signer, or re-signing a shorter spine after a reset). Distinct from a load/write
    FAILURE (a corrupt or wrong-scope floor, an IO error) so `checkpoint()` can treat this one as benign
    (warn) while surfacing a genuine failure loudly."""


class Floor(BaseModel):
    """The persisted anti-rollback watermark. Non-secret (hashes + seqs), but written 0600 as
    defense-in-depth. `head_sig_hash` is the meta-chain identity of the CURRENT accepted head. The
    monotonic quantity is `entry_count` (ABSOLUTE = base_count + live, unchanged across a prune) — it,
    not `last_seq`, is the sound rollback guard: `last_seq` is 0-indexed and is 0 for BOTH an empty spine
    and a 1-record spine, so a 1->0 rollback would slip past a last_seq-only check."""
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    scope: str
    entry_count: int = Field(ge=0)   # ABSOLUTE record count — the primary monotonic anti-rollback quantity
    last_seq: int = Field(ge=0)
    base_seq: int = Field(ge=0)
    base_count: int = Field(ge=0)
    head_sig_hash: str
    updated_ts: str = ""


def head_sig_hash(head: SignedChainHead) -> str:
    """The identity of an ACCEPTED head in the meta-chain: sha256 of its owner-signing bytes (the SAME
    bytes `verify_threshold` checks) — a hash-space distinct from `head_hash` (which hashes the chain
    tip). A v1 head hashes its v1 payload (v2 fields dropped by `_head_payload`), so the hash a v2
    first-prune head names as `prev_head_hash` matches the recorded floor exactly across the schema bump.
    """
    return sha256_hex(evidence_signing_bytes(_head_payload(head)))


def load_floor(path: Optional[Path] = None) -> Optional[Floor]:
    """Read the durable floor. `None` if ABSENT (pre-floor / never-signed spine — floor checks are then
    skipped, byte-identical to before). RAISES on a PRESENT-but-unreadable floor: a corrupt or
    forbid-violating floor is suspicious (tamper / partial write survived), and must never be silently
    treated as absent — that would be a fail-open un-flooring. Callers on the verify path catch the raise
    and fail CLOSED with a distinct message; they never treat it as clean."""
    p = Path(path) if path is not None else FLOOR_PATH
    if not p.exists():
        return None
    fl = Floor.model_validate_json(p.read_text(encoding="utf-8"))
    if fl.scope != SCOPE:
        # A floor for a DIFFERENT scope must not silently govern this spine (a swapped-in / cross-store
        # floor). Suspicious -> raise, so the read path fails CLOSED exactly like a corrupt floor.
        raise ValueError(f"durable floor scope {fl.scope!r} != active scope {SCOPE!r} (wrong-store floor)")
    return fl


def check_floor(head: SignedChainHead, floor: Optional[Floor]) -> tuple[bool, str]:
    """Reject rules. A validly-signed head that nonetheless violates the durable floor is a ROLLBACK
    (stale-head replay / un-prune / older-snapshot replay), reported as TAMPERING by the caller. No
    floor -> pass (byte-identical). Pure + side-effect-free, so it is testable in isolation and shared
    by the write path (`advance_floor`'s downgrade guard, RE-loaded under the lock) and every read path."""
    if floor is None:
        return True, "no durable floor"
    if head.entry_count < floor.entry_count:            # PRIMARY guard: absolute count (prune-invariant)
        return False, (f"ROLLBACK: head entry_count {head.entry_count} < durable floor entry_count "
                       f"{floor.entry_count} (truncated spine / stale head replay)")
    if head.last_seq < floor.last_seq:
        return False, (f"ROLLBACK: head last_seq {head.last_seq} < durable floor last_seq "
                       f"{floor.last_seq} (stale head / truncated spine replay)")
    if head.base_seq < floor.base_seq:
        return False, (f"UN-PRUNE: head base_seq {head.base_seq} < durable floor base_seq "
                       f"{floor.base_seq} (older-snapshot replay)")
    if head.base_count < floor.base_count:
        return False, (f"UN-PRUNE: head base_count {head.base_count} < durable floor base_count "
                       f"{floor.base_count} (older-snapshot replay)")
    if head.schema_version >= 2:
        # META-CHAIN (v2 heads only — a v1 head carries no prev_head_hash so this is dormant until the
        # first prune). This enforces CORRECT-PARENT LINKAGE: a v2 head is accepted iff it IS the recorded
        # accepted head (re-verify) OR links to it via prev_head_hash (its child). It blocks replay of a
        # stale head from a PRIOR prune generation and any head that does not descend from the accepted
        # one. NOTE: true SINGLE-SUCCESSOR uniqueness (rejecting a second, different owner-signed child of
        # the same parent) is NOT enforced here — that requires the pre-committed snapshot_seq cross-check
        # landing in Slice D/E; here the monotonic entry_count/base_* guards already bound a sibling.
        if head_sig_hash(head) != floor.head_sig_hash and head.prev_head_hash != floor.head_sig_hash:
            return False, ("META-CHAIN BREAK: v2 head neither is the recorded accepted head nor descends "
                           "from it (stale/forked owner-signed head replay)")
    return True, "within durable floor"


@contextmanager
def floor_lock(path: Optional[Path] = None) -> Iterator[None]:
    """Exclusive CROSS-PROCESS lock serializing a floor advance (and the head write that precedes it in
    checkpoint()) so the load->check->write triple is ATOMIC and last-writer-MONOTONIC, not
    last-writer-wins. Without it, two racing checkpoint() callers each read a STALE prior floor, both pass
    the downgrade guard, and the later os.replace can roll the floor BACKWARDS — opening a false-CLEAN
    window for a stale-head replay. Binds the flock to a sibling lockfile's inode (survives the atomic
    replace of floor.json). Best-effort where fcntl is absent (single-host assumption)."""
    p = Path(path) if path is not None else FLOOR_PATH
    lockp = p.parent / (p.name + ".lock")
    fd = None
    try:
        try:
            lockp.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(lockp), os.O_RDWR | os.O_CREAT, 0o600)
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError:  # pragma: no cover — lock unsupported on this fs; best-effort
                    pass
        except OSError:
            # Cannot create/open the lockfile — a read-only SIGIL_HOME, a root-owned floor.json.lock left
            # by a stray `sudo`, ENOSPC. DEGRADE to best-effort UNLOCKED rather than brick signing (the
            # `fcntl is None` path degrades the same way). A genuinely unwritable home then fails at the
            # floor `_write` and routes to checkpoint()'s LOUD branch — never the head sign itself.
            fd = None
        yield
    finally:
        if fd is not None:
            os.close(fd)


def _write(floor: Floor, path: Optional[Path]) -> Floor:
    p = Path(path) if path is not None else FLOOR_PATH
    atomic_write_text(p, floor.model_dump_json(), prefix=".floor-")
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover — non-POSIX / unusual fs; content is non-secret, mode is best-effort
        pass
    return floor


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _floor_of(head: SignedChainHead) -> Floor:
    return Floor(scope=SCOPE, entry_count=head.entry_count, last_seq=head.last_seq,
                 base_seq=head.base_seq, base_count=head.base_count,
                 head_sig_hash=head_sig_hash(head), updated_ts=_now_iso())


def advance_floor(head: SignedChainHead, *, path: Optional[Path] = None, _locked: bool = False) -> Floor:
    """Advance the durable floor to a just-committed head — UPWARD-ONLY. The load->check->write is done
    under `floor_lock` and the prior floor is RE-LOADED inside the lock, so a concurrent advance that
    already wrote a higher floor is observed and this stale write is REFUSED (raises ValueError) — making
    the floor last-writer-MONOTONIC, never last-writer-wins. Refuses to lower any monotonic field or break
    the meta-chain — the exact thing the floor exists to prevent. Written atomically
    (temp->fsync->replace->dir-fsync) at 0600, only AFTER the head has committed. `_locked=True` when the
    caller (checkpoint) already holds `floor_lock` for the same critical section — do not re-acquire."""
    p = Path(path) if path is not None else FLOOR_PATH
    if _locked:
        return _advance_locked(head, p)
    with floor_lock(p):
        return _advance_locked(head, p)


def _advance_locked(head: SignedChainHead, p: Path) -> Floor:
    prior = load_floor(p)                                # RE-LOAD under the lock — sees a racing advance
    if prior is not None:
        ok, msg = check_floor(head, prior)
        if not ok:
            raise FloorDowngrade(f"refusing to advance the durable floor DOWNWARD/off-chain: {msg}")
    return _write(_floor_of(head), p)


def reset_floor(head: SignedChainHead, *, path: Optional[Path] = None) -> Floor:
    """DELIBERATE downward re-seed — the ONLY path that may lower the floor. For a legitimate
    `--reset` / restore, gated by the caller: `sigil floor reset` re-signs the current spine with the
    owner key (so the new floor names a fresh owner-signed head) and requires an explicit `--yes`. No
    monotonic guard — that is the whole point — but still under `floor_lock` so it cannot interleave with
    a concurrent advance and lose its write."""
    p = Path(path) if path is not None else FLOOR_PATH
    with floor_lock(p):
        return _write(_floor_of(head), p)
