"""slug_lease — a durable, ATOMIC, crash-safe, cross-process per-slug ENGAGEMENT lease (Wave D / D1).

The console's launch guard used to be a check-then-act pair — ``_slug_has_running_run`` (scan the run
registry for a 'running' meta of the slug) serialised only by a process-local ``threading.Lock``. That is
NOT atomic across processes: two independent launches for the SAME slug — two ``engage --resume`` POSTs, or
a console plus a hand-run CLI — can each read "no run of this slug is running", then each ``_write_meta
(status=running)`` and spawn, forking that slug's ``{slug}.spine`` hash-chain. A lock in ONE process cannot
close a race between TWO processes.

This module is the atomic replacement. It reuses the same discipline as
``vigil_integration.live.nonce_ledger.NonceLedger`` — an ``O_CREAT | O_EXCL`` exclusive create as the
serialization point — but adds what a lease needs that a single-use nonce ledger deliberately does NOT
have: a lease can be RELEASED (so the next engagement of the slug starts at once) and a crashed holder's
lease can be RECLAIMED (so a dead holder never wedges the slug forever). A ``NonceLedger`` marker is
permanent by design; a lease marker is transient.

Guarantees
----------
* ATOMIC + CROSS-PROCESS: :meth:`SlugLease.acquire` for one slug returns ``ok=True`` to at most one caller
  among any number racing across any number of processes — the winner is whoever's ``O_EXCL`` create of the
  per-slug marker file succeeds. Every loser is cleanly refused (``ok=False``), never corrupted.
* CRASH-SAFE (no permanent wedge): a holder that exits without :meth:`release` leaves its marker behind, but
  the marker records the holder's ``pid`` + host ``boot_id``. A later acquirer treats a marker whose holder
  process is GONE (or whose ``boot_id`` differs — every pre-reboot pid is dead) as STALE and RECLAIMS it.
  So a dead holder is always reclaimable; only a LIVE holder blocks.
* NO false-negative (never two live holders of one slug): reclaim of a stale marker is serialised by a
  per-generation reclaim token (its own ``O_EXCL`` create), so of N racers reclaiming the same dead
  generation exactly one removes it, and a fresh marker can only be created into the FREED slot via ``O_EXCL``
  — one winner. Critically, the unlink is gated on the PROVEN-DEAD generation identity that ``acquire`` passes
  in, never on a fresh re-read: a reclaimer unlinks the marker ONLY IF it still carries exactly that dead
  generation AND is still dead. So a peer that already reclaimed the slot and created a FRESH LIVE lease in the
  window is never unlinked (its epoch differs from the dead one) — this is what stops the concurrent-reclaim
  clobber that would otherwise leave two (or more) live holders of one slug.
* NO false-positive deadlock: the reclaim token itself records the reclaimer's liveness, so a reclaimer that
  crashes mid-reclaim does not wedge the generation — the next acquirer sees the token's holder is dead, drops
  it, and reclaims. A parseable holder is judged by process liveness; a torn/empty marker (a crash mid-write)
  is judged ALIVE only within a short birth grace (a writer between create and write) and DEAD afterwards.

NAMED RESIDUAL — within-boot pid reuse. Liveness keys on ``pid`` + ``boot_id``. If a crashed holder's pid is
recycled to an UNRELATED live process within the SAME boot (no reboot, so ``boot_id`` is unchanged), the
stale marker reads as held and the slug stays blocked until that unrelated process exits. This is a BOUNDED
false-POSITIVE (an over-cautious refusal / temporary wedge), NEVER a false-negative — it can never let two
engagements run one slug. It mirrors exactly the same residual in ``console.actions.reconcile_orphaned_runs``
(no portable pidfd / process-start-time check without new syscalls); it is stated here, not silently claimed
away. A reboot resolves it deterministically (``boot_id`` changes ⇒ every prior pid is dead ⇒ reclaimable).

Import-clean: stdlib only (no framework/strix/sigil), so both the offense console
(``framework.v2.console.actions``) and the engagement scheduler (``framework.v2.engagement_scheduler``)
can use it without crossing the two-env boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

#: A torn/empty holder file (a crash between the exclusive create and the identity write) is given the
#: benefit of the doubt — treated as a LIVE writer mid-create — only within this many seconds of its mtime;
#: afterwards it is a crashed write and is reclaimable. The create→write window is sub-millisecond, so a few
#: seconds is a >1000x safety margin that still bounds how long a torn marker can wedge a slug.
_BIRTH_GRACE_S = 5.0

#: Bounded acquire attempts. A single reclaim frees the slot in one round, so 2 attempts suffice for the
#: common stale case; extra rounds only absorb live reclaim contention. Exhaustion returns a conservative
#: refusal (never a spurious grant), so it can never cause two live holders.
_MAX_ATTEMPTS = 8


def _boot_id() -> str:
    """The host boot id (Linux ``/proc/sys/kernel/random/boot_id``), or "" if unavailable. Recorded on a
    lease so a pid RECYCLED across a reboot is not mistaken for the original holder — after a reboot every
    prior pid is definitively dead. Mirrors ``console.actions._boot_id``."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _pid_alive(pid: object) -> bool:
    """True iff ``pid`` names a live process. Reaps our own exited children first (WNOHANG) so an exited
    child does not read as a live zombie, then probes with ``os.kill(pid, 0)``. Mirrors the console's
    ``_pid_alive`` discipline; deliberately never ``waitpid``-reaps a non-child."""
    try:
        p = int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if p <= 0:
        return False
    try:
        reaped, _ = os.waitpid(p, os.WNOHANG)   # our own exited child is reaped here → not alive
        if reaped == p:
            return False
    except ChildProcessError:
        pass                                    # not our child — probe by signal
    except OSError:
        pass
    try:
        os.kill(p, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                             # exists but not ours to signal — still alive
    except OSError:
        return False
    return True


@dataclass
class LeaseResult:
    """The outcome of :meth:`SlugLease.acquire`. ``ok`` is the single-winner verdict; ``token`` is the
    epoch the winner passes back to :meth:`SlugLease.release` (so it can only release its OWN generation)."""

    ok: bool
    slug: str
    token: str = ""
    reason: str = ""
    holder: "dict | None" = None


class SlugLease:
    """A durable, atomic, crash-safe, cross-process per-slug lease. ``dir`` is the marker directory (one
    marker file per currently-leased slug, plus transient per-generation reclaim tokens)."""

    def __init__(self, path: "str | os.PathLike") -> None:
        self.dir = Path(path)

    # -- paths ---------------------------------------------------------------------------------------
    def _key(self, slug: str) -> str:
        # sha256 → fixed [0-9a-f]{64}: the slug can neither escape the directory (no separators / '..') nor,
        # via any metacharacter, name anything but its own marker; distinct slugs never collide.
        return hashlib.sha256(slug.encode("utf-8")).hexdigest()

    def _marker(self, slug: str) -> Path:
        return self.dir / self._key(slug)

    def _reclaim_token(self, slug: str, epoch: str) -> Path:
        # A '.' namespace-separates reclaim tokens from markers (a marker is exactly 64 hex, no dot) so they
        # never collide; ``epoch`` is [0-9a-f], safe as a filename component.
        return self.dir / f"{self._key(slug)}.reclaim.{epoch}"

    # -- io ------------------------------------------------------------------------------------------
    def _read(self, path: Path) -> "dict | None":
        """The parsed holder record at ``path``, or None if absent/torn/empty. Total."""
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if not raw.strip():
            return None
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None

    def _epoch_of(self, path: Path) -> str:
        """A STABLE identifier for the current generation at ``path`` — the recorded ``epoch`` when the file
        parses, else a digest of its raw bytes (so even a torn marker names one deterministic reclaim
        token). "" iff the file is gone."""
        holder = self._read(path)
        if isinstance(holder, dict) and holder.get("epoch"):
            return str(holder["epoch"])
        try:
            raw = path.read_bytes()
        except OSError:
            return ""
        return "torn-" + hashlib.sha256(raw).hexdigest()[:24]

    def _within_grace(self, path: Path) -> bool:
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            return False                        # gone → not a live writer
        return 0 <= age < _BIRTH_GRACE_S

    def _alive(self, holder: "dict | None", path: Path) -> bool:
        """Liveness of the holder recorded at ``path``. A parseable holder is judged by process liveness
        (with the ``boot_id`` reboot guard); a torn/empty holder is a live writer only within the birth
        grace, dead afterwards."""
        if not isinstance(holder, dict) or not holder:
            return self._within_grace(path)     # empty file: a writer mid-create, or a crashed write if old
        pid = holder.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return self._within_grace(path)
        boot = str(holder.get("boot_id") or "")
        cur_boot = _boot_id()
        if cur_boot and boot and cur_boot != boot:
            return False                        # a reboot killed every prior pid → definitely dead
        return _pid_alive(pid)

    def _write_holder(self, fd: int, holder: dict) -> None:
        """Write+fsync the holder identity into an already exclusively-created ``fd``, then fsync the dir, so
        the holder's pid/boot survives a crash and reclaim decisions read a real identity, not an empty file."""
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(holder, fh, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._fsync_dir()

    def _fsync_dir(self) -> None:
        try:
            dfd = os.open(str(self.dir), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)

    def _unlink(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    # -- reclaim -------------------------------------------------------------------------------------
    def _reclaim(self, slug: str, marker: Path, dead_gen: str) -> bool:
        """Attempt to free ``marker``, whose generation ``dead_gen`` the caller PROVED dead. Returns True iff
        the slot may now be free (the caller re-attempts the O_EXCL create), False iff a LIVE reclaimer
        currently owns this generation (back off and retry).

        SOUNDNESS — the unlink is gated on the PROVEN-DEAD generation identity, never on "whatever is at the
        marker now". ``dead_gen`` is the generation ``acquire`` observed dead (its epoch, or a digest of a
        torn marker). This call:
          1. serialises on a per-generation reclaim token named by ``dead_gen`` (its own O_EXCL), so of N
             racers reclaiming the SAME dead generation exactly one proceeds;
          2. under that token, RE-READS the marker and unlinks it ONLY IF it STILL carries exactly
             ``dead_gen`` AND is STILL dead.
        If the generation has already flipped — a peer reclaimed it and a FRESH LIVE lease now sits in the slot
        (the concurrent-reclaim clobber) — then ``cur_gen != dead_gen`` (epochs are 128-bit random, so a live
        generation never collides with the dead one) and the unlink is REFUSED; the caller re-loops and is
        cleanly refused by the live holder. The extra ``not _alive(cur)`` re-check also refuses the unlink if
        ``dead_gen`` reads live again (a within-boot pid reuse), trading a wrong unlink for a bounded, safe
        false-positive. The token itself carries the reclaimer's liveness, so a reclaimer that crashes
        mid-reclaim is detected (dead) and its token dropped — no generation can wedge."""
        if not dead_gen:
            return True                         # nothing identified to reclaim → re-attempt create
        token = self._reclaim_token(slug, dead_gen)
        try:
            tfd = os.open(str(token), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # someone is (or was) reclaiming THIS generation. If that reclaimer is alive, defer to it.
            rec = self._read(token)
            if self._alive(rec, token):
                return False                    # a live reclaimer owns it — back off
            self._unlink(token)                 # a crashed reclaimer — drop its token; next round recreates it
            return False
        except OSError:
            return False
        try:
            self._write_holder(tfd, {"epoch": secrets.token_hex(8), "pid": os.getpid(),
                                     "boot_id": _boot_id(), "ts": time.time(), "role": "reclaim"})
            cur = self._read(marker)
            # derive the current generation id from the SAME read used for the liveness check below (so the two
            # can never disagree across a flip), mirroring how ``acquire`` captured ``dead_gen``.
            cur_gen = (str(cur["epoch"]) if isinstance(cur, dict) and cur.get("epoch")
                       else self._epoch_of(marker))
            if not cur_gen:
                return True                     # already freed by another reclaimer → re-attempt create
            # Unlink ONLY the exact generation acquire proved dead, and only if it is STILL dead. A generation
            # that has flipped (a peer reclaimed it → a fresh LIVE lease now sits here) has a different epoch,
            # so cur_gen != dead_gen and we must NOT touch it — that is the clobber this gate prevents.
            if cur_gen == dead_gen and not self._alive(cur, marker):
                self._unlink(marker)
                return True
            return True                         # changed / now-live generation → re-loop; the O_EXCL retry
                                                # then fails and the live holder cleanly refuses us
        finally:
            self._unlink(token)                 # release the reclaim right for this generation

    # -- public api ----------------------------------------------------------------------------------
    def acquire(self, slug: str, *, run_id: str = "", pid: "int | None" = None,
                extra: "dict | None" = None) -> LeaseResult:
        """ATOMICALLY claim the engagement lease for ``slug``. Returns ``ok=True`` to at most one caller
        across all processes; every other caller for the same slug — while a LIVE holder holds it — gets
        ``ok=False``. A STALE marker (dead holder) is reclaimed and the caller may still win. ``pid``
        defaults to this process (the console is the sole starter of runs); ``run_id``/``extra`` are recorded
        for audit and for the UI liveness read."""
        s = str(slug or "").strip()
        if not s:
            return LeaseResult(ok=False, slug="", reason="refusing to lease an empty slug")
        try:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as e:
            return LeaseResult(ok=False, slug=s, reason=f"lease dir unavailable ({type(e).__name__})")
        marker = self._marker(s)
        holder_pid = int(pid) if isinstance(pid, int) and pid > 0 else os.getpid()
        for _ in range(_MAX_ATTEMPTS):
            epoch = secrets.token_hex(16)
            record = {"epoch": epoch, "slug": s, "run_id": str(run_id or ""), "pid": holder_pid,
                      "boot_id": _boot_id(), "ts": time.time()}
            if isinstance(extra, dict):
                record.update({k: v for k, v in extra.items() if k not in record})
            try:
                fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                holder = self._read(marker)
                if self._alive(holder, marker):
                    return LeaseResult(ok=False, slug=s, reason="a live engagement holds this slug",
                                       holder=holder)
                # Stale holder. Capture the identity of the generation we JUST PROVED dead (from this very
                # observation, not a fresh re-read) and reclaim ONLY that generation. Gating the unlink on the
                # proven-dead identity — never on "whatever is at the marker now" — is what stops a lagging
                # reclaimer from unlinking a peer's fresh LIVE lease (the concurrent-reclaim clobber).
                dead_gen = (str(holder["epoch"]) if isinstance(holder, dict) and holder.get("epoch")
                            else self._epoch_of(marker))
                if not self._reclaim(s, marker, dead_gen):
                    time.sleep(0.002)           # a live reclaimer is working — brief back-off, then retry
                continue
            except OSError as e:
                return LeaseResult(ok=False, slug=s, reason=f"lease io error ({type(e).__name__})")
            else:
                self._write_holder(fd, record)
                return LeaseResult(ok=True, slug=s, token=epoch, holder=record)
        # exhausted under contention: refuse conservatively (a refusal can never create two live holders)
        return LeaseResult(ok=False, slug=s, reason="lease contended")

    def release(self, slug: str, token: str) -> bool:
        """Release the lease for ``slug`` IFF this caller still holds generation ``token`` (its acquire
        epoch). Returns True iff it released. A non-matching token — the lease was reclaimed after a crash,
        or already released — is a no-op (never removes another holder's live lease). Total; never raises."""
        s = str(slug or "").strip()
        t = str(token or "").strip()
        if not s or not t:
            return False
        marker = self._marker(s)
        holder = self._read(marker)
        if isinstance(holder, dict) and str(holder.get("epoch") or "") == t:
            self._unlink(marker)
            self._fsync_dir()
            return True
        return False

    def rebind(self, slug: str, token: str, pid: int) -> bool:
        """Re-point the lease's liveness at ``pid`` (the spawned engagement CHILD), keeping the same
        generation ``token``. The lease is acquired with the launcher's pid BEFORE the child exists (to close
        the acquire race); once the child is running, rebinding to the child pid makes staleness track the
        ACTUAL engagement process — exactly what ``reconcile_orphaned_runs`` keys on (``meta['pid']`` is the
        child) — so a child reparented past a dead launcher still reads as held (no double-run) while a dead
        child is reclaimable. A no-op unless the caller still holds ``token`` (never rebinds a reclaimed
        lease). Best-effort; a rebind failure just leaves the launcher-pid holder, which is still correct
        (the launcher outlives the run on the normal path). Total; never raises."""
        s = str(slug or "").strip()
        t = str(token or "").strip()
        if not s or not t or not isinstance(pid, int) or pid <= 0:
            return False
        marker = self._marker(s)
        holder = self._read(marker)
        if not (isinstance(holder, dict) and str(holder.get("epoch") or "") == t):
            return False                        # not our generation (reclaimed/released) — leave it alone
        updated = dict(holder)
        updated["pid"] = int(pid)
        updated["boot_id"] = _boot_id()
        updated["rebound_ts"] = time.time()
        tmp = marker.with_name(marker.name + f".rebind.{secrets.token_hex(6)}")
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            return False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(updated, fh, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            # re-check we STILL hold this generation, then atomically swap it into place (rename is atomic, so
            # a reader never sees a torn holder; a lease reclaimed in the meantime is not clobbered because we
            # re-verify the epoch first — a tiny TOCTOU remains but only ever re-points OUR own live child).
            cur = self._read(marker)
            if not (isinstance(cur, dict) and str(cur.get("epoch") or "") == t):
                self._unlink(tmp)
                return False
            os.replace(str(tmp), str(marker))
            self._fsync_dir()
            return True
        except OSError:
            self._unlink(tmp)
            return False

    def is_held(self, slug: str) -> bool:
        """True iff a LIVE holder currently holds ``slug`` — the honest liveness read for the UI (a stale
        marker of a crashed holder reads as NOT held, because it is reclaimable). Total."""
        s = str(slug or "").strip()
        if not s:
            return False
        marker = self._marker(s)
        return self._alive(self._read(marker), marker)

    def holder(self, slug: str) -> "dict | None":
        """The recorded holder of ``slug`` (whatever the marker says), or None. For audit/diagnostics —
        callers wanting the liveness verdict use :meth:`is_held`."""
        s = str(slug or "").strip()
        if not s:
            return None
        return self._read(self._marker(s))
