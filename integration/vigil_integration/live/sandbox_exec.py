"""sandbox_exec — a network-isolated, filesystem-confined exec sandbox (VIGIL write/exec tier).

Runs an ARBITRARY command inside a bubblewrap (``bwrap``) sandbox where the two safety floors are enforced
by KERNEL isolation, not by an allowlist:

  * **NO EGRESS** — the network namespace is unshared (``--unshare-net``), so nothing inside can reach any
    host (DNS fails, every connect fails). This is the never-liftable egress floor, by construction.
  * **NO WRITE OUTSIDE THE WORKSPACE** — the host root is mounted READ-ONLY (``--ro-bind / /``); the ONLY
    writable paths are the bound workspace dir (``--bind ws ws``) and an ephemeral ``--tmpfs /tmp``. A write
    anywhere else fails with EROFS.

Inside those floors the command may be ARBITRARY (a full ``/bin/sh -c``), because the box cannot egress or
escape the workspace — this is the "do everything a local shell can" tier, made safe by ISOLATION rather
than by the read-only allowlist that the un-sandboxed host path (``live.executor.execute_terminal``) uses.

Fail-CLOSED: ``bwrap`` missing / unusable, or an unsafe workspace, REFUSES to run — there is deliberately NO
fallback to an un-sandboxed exec, since that would silently drop the isolation the whole tier depends on.
Time-boxed + output-capped; ``--die-with-parent`` (no orphan) + ``--new-session`` (no TIOCSTI terminal
injection). Import-clean: stdlib only (no framework / strix / sigil), so it is safe in either environment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

DEFAULT_TIMEOUT = 60.0
DEFAULT_OUTPUT_CAP = 1_000_000  # 1 MB per stream

# The isolation profile. --unshare-all unshares the net/pid/ipc/uts/cgroup (and user) namespaces; the
# load-bearing one for the egress floor is the NET unshare. --ro-bind mounts the host root READ-ONLY; a
# fresh --proc/--dev keep the box from leaking host process/device state; --tmpfs /tmp is ephemeral scratch;
# --die-with-parent kills the box if we die; --new-session blocks TIOCSTI stdin-injection escapes. The
# workspace bind + --chdir are appended per call (the ONLY writable host path).
_BWRAP_BASE_FLAGS = (
    "--unshare-all", "--die-with-parent", "--new-session",
    "--ro-bind", "/", "/",
    "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
)


class SandboxUnavailable(RuntimeError):
    """bwrap is not installed / not usable — the sandbox tier cannot run (fail-closed, never a fallback)."""


@dataclass(frozen=True)
class SandboxOutcome:
    exit_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


def bwrap_path() -> Optional[str]:
    """The resolved ``bwrap`` binary, or ``None`` if it is not on PATH. (Presence is necessary but not
    sufficient — a sandbox that cannot construct its namespaces still fails closed at run time.)"""
    return shutil.which("bwrap")


def _safe_workspace(workspace: str | os.PathLike) -> Optional[Path]:
    """The workspace resolved to a real, existing directory that is NOT a symlink (the writable bind must be
    a genuine dir under our control, never a symlink an attacker could repoint). ``None`` (⇒ refuse) for a
    missing / non-dir / symlinked / unresolvable path. Total — never raises."""
    try:
        p = Path(workspace)
        if p.is_symlink() or not p.is_dir():
            return None
        rp = p.resolve(strict=True)
        if rp.is_symlink() or not rp.is_dir():
            return None
        return rp
    except (OSError, ValueError, RuntimeError):
        return None


def build_bwrap_argv(command: str, workspace: Path, *, bwrap: str) -> list[str]:
    """The full argv: ``bwrap <isolation flags> --bind <ws> <ws> --chdir <ws> -- /bin/sh -c <command>``.
    The command is a SINGLE argv element after ``-c`` (it runs in a shell INSIDE the isolated box, which is
    safe — the box cannot egress or escape), so it can never inject into bwrap's OWN option list."""
    ws = str(workspace)
    return [bwrap, *(_BWRAP_BASE_FLAGS), "--bind", ws, ws, "--chdir", ws, "--", "/bin/sh", "-c", command]


def _default_runner(argv: list[str], *, timeout: float, output_cap: int) -> SandboxOutcome:
    """Run the assembled bwrap argv with NO shell on the OUTSIDE (argv list), stdin closed, captured +
    time-boxed + output-capped. A timeout kills the process group (``--die-with-parent`` reaps the box).
    Total — a spawn error is a captured failure, never a raise."""
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as te:
        so = (te.stdout or "") if isinstance(te.stdout, str) else (te.stdout.decode("utf-8", "replace") if te.stdout else "")
        se = (te.stderr or "") if isinstance(te.stderr, str) else (te.stderr.decode("utf-8", "replace") if te.stderr else "")
        return _cap(SandboxOutcome(exit_code=None, stdout=so, stderr=se, timed_out=True), output_cap)
    except OSError as e:
        return SandboxOutcome(exit_code=None, stdout="", stderr=f"sandbox spawn error: {type(e).__name__}: {e}")
    return _cap(SandboxOutcome(exit_code=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or ""), output_cap)


def _cap(outcome: SandboxOutcome, output_cap: int) -> SandboxOutcome:
    trunc = False
    so, se = outcome.stdout, outcome.stderr
    if len(so) > output_cap:
        so, trunc = so[:output_cap], True
    if len(se) > output_cap:
        se, trunc = se[:output_cap], True
    return SandboxOutcome(exit_code=outcome.exit_code, stdout=so, stderr=se,
                          timed_out=outcome.timed_out, truncated=outcome.truncated or trunc)


def run_sandboxed(
    command: str,
    *,
    workspace: str | os.PathLike,
    timeout: float = DEFAULT_TIMEOUT,
    output_cap: int = DEFAULT_OUTPUT_CAP,
    run: Callable[..., SandboxOutcome] = _default_runner,
) -> SandboxOutcome:
    """Run ``command`` inside the network-isolated, workspace-confined bwrap sandbox. Fail-CLOSED: a missing
    ``bwrap`` raises :class:`SandboxUnavailable` (NO un-sandboxed fallback — dropping the isolation is never
    acceptable); an unsafe/absent workspace or an empty command raises ``ValueError``. Otherwise returns the
    captured :class:`SandboxOutcome`. The ``run`` seam is injectable for tests; the real default spawns bwrap
    with no outer shell."""
    cmd = command if isinstance(command, str) else str(command or "")
    if not cmd.strip():
        raise ValueError("refusing to run an empty sandbox command")
    bwrap = bwrap_path()
    if not bwrap:
        raise SandboxUnavailable(
            "bubblewrap (bwrap) is not installed — the isolated write/exec tier cannot run; install bwrap "
            "(apt install bubblewrap). There is deliberately NO un-sandboxed fallback.")
    ws = _safe_workspace(workspace)
    if ws is None:
        raise ValueError(f"unsafe or missing sandbox workspace: {workspace!r}")
    argv = build_bwrap_argv(cmd, ws, bwrap=bwrap)
    return run(argv, timeout=timeout, output_cap=output_cap)
