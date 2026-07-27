"""
common.ephemeral — opt-in ephemeral / ZDR session (Phase D2).

Persist-by-default is the doctrine: a normal run writes its evidence, audit log, spine
and reports to disk so the operator can grep, re-verify, and report. But some runs must
leave NOTHING behind and must never route reasoning through a data-retaining vendor — a
sensitive target, a client machine, a demo on a shared host. ``--ephemeral`` makes that a
per-session choice without changing the default.

An ephemeral session guarantees three things for its lifetime, and undoes them on exit:

  1. TMPFS + PURGE.  A fresh in-memory dir (``/dev/shm`` when available, else the system
     temp) becomes the write root for the per-engagement sinks (evidence archive, audit
     log) and the run store. On exit the whole dir is removed and its absence is VERIFIED;
     a residual raises ``EphemeralPurgeError`` (fail-closed — 'leaves nothing on disk' is
     the whole promise). An ``atexit`` net purges it even on an unclean exit.

  2. ZDR / LOCAL TIER.  The sovereignty tier is forced to ``TRUSTED_CLOUD`` (or an operator
     override via ``CRUCIBLE_EPHEMERAL_TIER`` — e.g. ``AIR_GAPPED`` for purely local). Under
     that tier the direct consumer Anthropic API and Claude Code OAuth are REFUSED at backend
     construction; auto-selection prefers ``anthropic-zdr`` (zero-data-retention) then local.
     The env var drives ``is_sovereign_mode()`` so the egress allowlist is enforced too; an
     injected policy is set so the force wins even over a sealed tier.

  3. SUPPRESS PERSISTENCE.  Write paths that CANNOT be tmpfs-redirected (the on-disk spine/
     blackboard, plan-input, learned bandit, outcome ledger) are suppressed by the ``--ephemeral``
     engage path FORCING their flags off up front (``args.spine = False``, ``args.bandit_file =
     None``, ``args.learn = False``) BEFORE the spine opens — so the spine sink is never built,
     and plan-input (spine-gated) is skipped transitively. ``is_active()`` is a status query for
     consumers/tests; it is not itself the suppression seam (the flag-forcing is).

Everything restores exactly on exit (env, injected policy, the paths write-root), so a
persisting run in the same process afterwards is byte-identical to never having gone
ephemeral. Default (no session) => byte-identical: nothing here runs unless ``--ephemeral``.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import paths
from .errors import EphemeralPurgeError

# The sovereignty tier an ephemeral session forces by default: local + jurisdictional cloud
# + Anthropic-ZDR; the direct consumer Anthropic API and Claude Code OAuth are refused. An
# operator who wants purely-local can set CRUCIBLE_EPHEMERAL_TIER=AIR_GAPPED.
_DEFAULT_EPHEMERAL_TIER = "TRUSTED_CLOUD"
_EPHEMERAL_TIER_ENV = "CRUCIBLE_EPHEMERAL_TIER"
_TIER_ENV = "CRUCIBLE_SOVEREIGNTY_TIER"
# Operator override for where the in-memory dir lives (else /dev/shm, else system temp).
_EPHEMERAL_DIR_ENV = "CRUCIBLE_EPHEMERAL_DIR"

# The single currently-active session (an ephemeral run is a per-process, per-session
# choice; sessions do not nest). ``is_active()`` reads this.
_ACTIVE: "EphemeralSession | None" = None

# Dirs still awaiting purge, drained by the atexit net so an unclean exit still cleans up.
_PENDING_PURGE: set[str] = set()


def _tmpfs_parent() -> Path:
    """Where the in-memory session dir is created. Preference: an explicit
    ``CRUCIBLE_EPHEMERAL_DIR`` override, then ``/dev/shm`` (a real tmpfs on Linux — truly
    in-memory), then the system temp dir (``TMPDIR``). Best-effort: an unwritable candidate
    falls through to the next."""
    override = os.environ.get(_EPHEMERAL_DIR_ENV, "").strip()
    if override:
        p = Path(override)
        try:
            p.mkdir(parents=True, exist_ok=True)
            if os.access(p, os.W_OK):
                return p
        except OSError:
            pass
    shm = Path("/dev/shm")
    try:
        if shm.is_dir() and os.access(shm, os.W_OK):
            return shm
    except OSError:
        pass
    return Path(tempfile.gettempdir())


def _resolve_forced_tier() -> str:
    """The tier name an ephemeral session forces. Honours ``CRUCIBLE_EPHEMERAL_TIER`` when it
    names a real, non-permissive tier; otherwise the ZDR default. Never resolves to
    PERMISSIVE (that would defeat the point) — an unknown or permissive override falls back
    to the ZDR default."""
    raw = os.environ.get(_EPHEMERAL_TIER_ENV, "").strip().upper()
    if raw in ("AIR_GAPPED", "SOVEREIGN_CLOUD", "TRUSTED_CLOUD"):
        return raw
    return _DEFAULT_EPHEMERAL_TIER


def _purge(path: Path) -> None:
    """Remove ``path`` recursively and VERIFY it is gone. Raises ``EphemeralPurgeError`` if a
    residual survives two attempts — ephemeral must actually leave nothing on disk."""
    for _ in range(2):
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            _PENDING_PURGE.discard(str(path))
            return
    # a residual dir is an integrity failure, not a best-effort miss
    raise EphemeralPurgeError(
        f"ephemeral tmpfs dir not fully purged (residual remains): {path}")


@atexit.register
def _purge_pending_atexit() -> None:
    """Last-resort cleanup: purge any session dir whose context manager did not run to
    completion (a crash / os._exit-adjacent path). Best-effort here — atexit must not raise —
    but the normal exit path already purged-and-verified."""
    for s in list(_PENDING_PURGE):
        shutil.rmtree(s, ignore_errors=True)
        _PENDING_PURGE.discard(s)


@dataclass
class EphemeralSession:
    """A live ephemeral/ZDR session. Built and entered by :func:`ephemeral_session`; holds the
    tmpfs base and the saved state to restore on exit. Not reusable — one enter/exit."""

    base_dir: Path
    forced_tier: str
    _prev_tier_env: str | None = field(default=None, repr=False)
    _prev_tier_env_present: bool = field(default=False, repr=False)
    _prev_policy: object = field(default=None, repr=False)
    _prev_sealed: object = field(default=None, repr=False)
    _entered: bool = field(default=False, repr=False)

    # ---- write-store helpers the callers use ----

    def run_dir(self, name: str) -> Path:
        """A run-store dir under the tmpfs base (the console redirects its run store here)."""
        d = self.base_dir / "runs" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def targets_root(self) -> Path:
        """The tmpfs base the per-engagement write sinks (evidence, audit log) re-root under."""
        return self.base_dir / "targets"


_console_base: Path | None = None


def console_run_base() -> Path:
    """A tmpfs base for console-launched EPHEMERAL run stores — in-memory, off the repo disk.
    Created once per process and registered for the atexit purge, so a console ephemeral run
    is reclaimed when the console exits (the console is long-running and has no per-run session
    scope, so it can't use ``ephemeral_session`` directly). Recreated if it was purged."""
    global _console_base
    if _console_base is None or not _console_base.exists():
        parent = _tmpfs_parent()
        _console_base = Path(tempfile.mkdtemp(prefix="crucible-console-ephemeral-", dir=str(parent)))
        try:
            _console_base.chmod(paths.SECURE_DIR_MODE)
        except OSError:
            pass
        _PENDING_PURGE.add(str(_console_base))
    return _console_base


def is_active() -> bool:
    """True while an ephemeral session is open. Write paths that cannot be tmpfs-redirected
    consult this to SUPPRESS an on-disk write (spine, plan-input, bandit, outcomes)."""
    return _ACTIVE is not None


def active() -> "EphemeralSession | None":
    """The current session, or None."""
    return _ACTIVE


def _ambient_tier_name() -> str:
    """The current effective sovereignty tier name BEFORE the session forces anything (honours a
    sealed latch via ``current()``). Fail-safe: on any error we report the loosest tier so the
    stricter-of comparison always keeps the requested ZDR tier — ephemeral never accidentally
    RELAXES because we could not read the ambient state."""
    try:
        from ..kernel import sovereignty
        return sovereignty.current().tier.value
    except Exception:
        return "PERMISSIVE"


def _stricter(a: str, b: str) -> str:
    """Return the STRICTER of two tier names on the sovereignty ordering (definition order is
    AIR_GAPPED strictest ... PERMISSIVE loosest). Total: an unknown name is treated as the
    loosest, so a valid stricter tier always wins — the comparison fails safe toward MORE
    restriction."""
    try:
        from ..kernel.sovereignty import Tier
        order = [t.value for t in Tier]          # definition order: strict -> loose
        ra = order.index(a) if a in order else len(order)
        rb = order.index(b) if b in order else len(order)
        return a if ra <= rb else b
    except Exception:
        return b


def _force_tier(session: EphemeralSession) -> None:
    """Force the ZDR/local tier for the session: set the env var (drives ``current()`` and the
    egress guard's ``is_sovereign_mode()``) AND inject a policy (wins even over a sealed tier),
    saving the prior state for restore.

    NEVER RELAXES an already-stricter ambient tier (red-pen BLOCK-1): the tier actually forced is
    the STRICTER of the ambient effective tier and the requested ZDR tier, so an operator who was
    already SOVEREIGN_CLOUD / AIR_GAPPED is not silently downgraded to TRUSTED_CLOUD by entering
    ephemeral. Snapshots BOTH private sovereignty globals — the injected policy AND the X6 seal
    latch — because ``set_policy`` clears the seal latch; restore rewrites them directly so an
    ambient seal survives the session exactly."""
    from ..kernel import sovereignty

    session._prev_tier_env_present = _TIER_ENV in os.environ
    session._prev_tier_env = os.environ.get(_TIER_ENV)

    # Read the ambient tier FIRST — this latches a PENDING X6 seal (if the seal env is set but
    # not yet latched) — then snapshot BOTH private module states (injected policy + seal latch)
    # so restore puts back exactly what was in effect, including a seal we just triggered.
    forced = _stricter(_ambient_tier_name(), session.forced_tier)
    session._prev_policy = getattr(sovereignty, "_active_policy", None)
    session._prev_sealed = getattr(sovereignty, "_sealed_policy", None)
    session.forced_tier = forced

    os.environ[_TIER_ENV] = forced
    sovereignty.set_policy(sovereignty.SovereigntyPolicy(tier=sovereignty.Tier(forced)))


def _restore_tier(session: EphemeralSession) -> None:
    """Undo :func:`_force_tier` exactly — restore the env var (or remove it if it was unset) and
    rewrite BOTH sovereignty globals (the injected policy and the seal latch) directly. We bypass
    ``set_policy`` on restore because it nulls the seal latch; writing the globals back verbatim
    keeps an ambient seal that predated the session intact (red-pen BLOCK-1)."""
    from ..kernel import sovereignty

    if session._prev_tier_env_present:
        os.environ[_TIER_ENV] = session._prev_tier_env or ""
    else:
        os.environ.pop(_TIER_ENV, None)
    sovereignty._active_policy = session._prev_policy    # None restores env-derived; else re-inject
    sovereignty._sealed_policy = session._prev_sealed    # keep any pre-session X6 seal latch exactly


class _EphemeralCM:
    """The concrete context manager (a class so enter/exit can restore precise prior state)."""

    def __init__(self) -> None:
        self.session: EphemeralSession | None = None

    def __enter__(self) -> EphemeralSession:
        global _ACTIVE
        if _ACTIVE is not None:
            # sessions do not nest; a second one would fight over the global tier/paths state.
            raise EphemeralPurgeError("an ephemeral session is already active (they do not nest)")
        parent = _tmpfs_parent()
        base = Path(tempfile.mkdtemp(prefix="crucible-ephemeral-", dir=str(parent)))
        # owner-only from creation (mkdtemp is already 0700, but be explicit / defensive).
        try:
            base.chmod(paths.SECURE_DIR_MODE)
        except OSError:
            pass
        _PENDING_PURGE.add(str(base))
        session = EphemeralSession(base_dir=base, forced_tier=_resolve_forced_tier())
        try:
            # re-root the per-engagement WRITE sinks (evidence, audit log) under the tmpfs base.
            session.targets_root.mkdir(parents=True, exist_ok=True)
            paths.set_ephemeral_write_root(session.targets_root)
            _force_tier(session)
        except Exception:
            # partial setup failed: undo the redirect and purge the tmpfs dir so nothing leaks
            # (the `with` body never runs, so __exit__ would not be called to clean up).
            paths.set_ephemeral_write_root(None)
            _restore_tier(session)
            shutil.rmtree(base, ignore_errors=True)
            _PENDING_PURGE.discard(str(base))
            raise
        session._entered = True
        _ACTIVE = session
        self.session = session
        return session

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        global _ACTIVE
        session = self.session
        _ACTIVE = None
        if session is None:
            return False
        # restore the redirects/tier FIRST so a persisting run afterward is byte-identical,
        # even if the purge below raises.
        try:
            paths.set_ephemeral_write_root(None)
        finally:
            _restore_tier(session)
        # purge-and-verify last. A purge failure is raised (fail-closed) unless the body was
        # already unwinding an exception — then we don't mask the original.
        try:
            _purge(session.base_dir)
        except EphemeralPurgeError:
            if exc_type is None:
                raise
        return False


def ephemeral_session() -> _EphemeralCM:
    """Context manager for an ephemeral/ZDR session. Use as::

        with ephemeral_session() as sess:
            ... run the engagement, writing under sess.targets_root / sess.run_dir(...) ...
        # here: the tmpfs dir is purged-and-verified, tier + paths + write-root restored

    See the module docstring for the three guarantees. Restores prior state on exit even if
    the body raises. Sessions do NOT nest — entering a second one while one is active raises."""
    return _EphemeralCM()
