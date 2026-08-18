"""Wrap a live tool spawn in the loopback-only egress supervisor.

WHAT THIS CLOSES. The live Kali-tool path spawns tools directly on the host. Its no-egress guarantee was
held by an argv allowlist — the wapiti module allowlist, nuclei's ``-disable-update-check``, nikto's
``-notel`` — and verified only by argv-CONSTRUCTION tests. That is a guarantee that a tool will not be
ASKED to egress. It is not a guarantee that the tool does not egress anyway, which is exactly the class of
defect that kept recurring: wapiti's DEFAULT modules reached ``wapiti3.ovh``; ``wapp`` downloaded a
technology database; nuclei phoned home on two sensor routes that no gate covered. Each was invisible
until something RAN.

``tools/egress-guard/egress_guard.c`` polices ``connect(2)``, ``sendto(2)`` and ``sendmsg(2)`` with a
seccomp user-notify filter: loopback (``127.0.0.0/8``, ``::1``, ``::ffff:127.x``) and non-IP families
(AF_UNIX, netlink) proceed; anything else is refused with ECONNREFUSED and recorded. Because it filters
the SYSCALL rather than libc, it covers statically linked Go binaries — measured: ``nuclei`` (static)
attempts a DNS connect merely to print its version, and the guard blocks it. An ``LD_PRELOAD`` shim
cannot see that call at all, which is why this is the primary mechanism and not the fallback.

ALL THREE SEND SYSCALLS, NOT JUST ``connect``. Policing ``connect`` alone was a measured BYPASS: an
unconnected UDP socket needs no connect, so ``sendto(fd, buf, len, 0, &dest, ...)`` put a packet on the
wire while the guard reported ``seen=0 blocked=0``. A forked child is covered for free (a seccomp filter
is inherited across ``fork``), and a non-blocking connect is refused on its ``EINPROGRESS`` path — both
attacked and both held.

DEFAULT OFF, opt-in by environment, so an operator's ordinary host run is byte-identical unless they ask
for the guard. Live-fire and CI turn it on.

  VIGIL_EGRESS_GUARD=1            wrap spawns when the guard binary is available
  VIGIL_EGRESS_GUARD=require      wrap, and REFUSE to spawn if the guard is unavailable (fail closed)
  VIGIL_EGRESS_GUARD_FAIL=1       a blocked connect fails the run (guard exits 97) rather than only logging
  VIGIL_EGRESS_GUARD_BIN=<path>   explicit binary path (else the in-repo build is used)
  VIGIL_EGRESS_GUARD_LOG=<path>   append the guard's decisions here

HONEST BOUND 1 — TOCTOU. Allowed connects use SECCOMP_USER_NOTIF_FLAG_CONTINUE, which has a documented
race: a thread could rewrite the sockaddr between our read and the kernel's. That matters when sandboxing
code that is trying to escape. It does not describe this deployment — the tools are authorized,
correlatable and owner-run — so the guard is a control against a tool's own defaults and a mis-built
argv, NOT a containment boundary for hostile code. The kernel-isolation boundary remains ``sandbox_exec``
(bwrap ``--unshare-all``).

HONEST BOUND 2 — WHAT THE FILTER DOES NOT COVER. It polices ``connect``/``sendto``/``sendmsg`` on the
NATIVE architecture. Three gaps follow, none of them hypothetical:

  * a 32-bit (i386) binary matches no arch branch, so every syscall is ALLOWED and the run records
    ``seen=0 blocked=0`` — indistinguishable from a tool that tried nothing;
  * ``sendmmsg`` and ``io_uring`` submissions (``IORING_OP_CONNECT``/``IORING_OP_SEND``) are not
    filtered; and
  * an exit code of 97 from the tool ITSELF is indistinguishable from the guard's
    ``EGRESS_BLOCKED_EXIT``. Read the log to disambiguate — ``blocked=`` is the ground truth, the exit
    code is a convenience.

None of the tools this engine drives is 32-bit or uses io_uring today, which is why these are bounds
rather than holes — but a bound nobody wrote down is how the last three defects here started.

HONEST BOUND 3 — THE GUARD STRIPS PRIVILEGE, AND THAT CAN SILENCE A TOOL. An unprivileged seccomp filter
REQUIRES ``PR_SET_NO_NEW_PRIVS``, and that flag also blocks setuid/setgid and FILE CAPABILITY elevation.
Measured on this machine: ``/usr/lib/nmap/nmap`` carries ``cap_net_raw``; run under the guard it cannot
acquire it, and it reports **no open ports at all** while exiting 0. That is not a degraded result, it is
a FALSE NEGATIVE wearing the clothes of a clean one — precisely the failure this repository exists to
prevent. So the guard REFUSES to wrap a tool known to depend on elevated privilege rather than run it
crippled: a loud refusal beats a silent no-op. See ``_PRIVILEGE_DEPENDENT`` below.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# The guard's exit code when --fail-on-egress is set and at least one send was blocked.
#
# NOT a reserved value: a tool that exits 97 by itself is indistinguishable from this, and an earlier
# comment here claimed otherwise. The log's ``blocked=`` count is the ground truth; this exit code is a
# convenience for a caller that does not read the log.
EGRESS_BLOCKED_EXIT = 97

_REPO_BIN = Path(__file__).resolve().parents[3] / "tools" / "egress-guard" / "egress_guard"


# Tools that need elevated privilege to do their job, which NO_NEW_PRIVS would silently remove.
#
# `nmap` is the measured case: Kali ships /usr/bin/nmap as a wrapper that re-execs
# /usr/lib/nmap/nmap (file capabilities cap_net_raw,cap_net_admin,cap_net_bind_service). Under the
# guard the capability cannot be acquired and nmap emits XML with NO <port> element at all, exit 0 —
# indistinguishable from a target with nothing listening.
#
# A STATIC CHECK ON argv[0] IS NOT ENOUGH, which is why this list exists at all: /usr/bin/nmap itself
# carries no capabilities; they live on the binary it re-execs. So the name is the reliable signal and
# the filesystem check below is the belt-and-braces for anything else that is directly privileged.
_PRIVILEGE_DEPENDENT = frozenset({"nmap"})


class EgressGuardUnavailable(RuntimeError):
    """Raised only in ``require`` mode: the guard was demanded and could not be found."""


class EgressGuardWouldBreakTool(RuntimeError):
    """The guard would strip privilege this tool needs, turning its output into a false negative."""


def _is_privileged_binary(path: str) -> bool:
    """True if ``path`` is setuid/setgid or carries file capabilities — either of which NO_NEW_PRIVS
    would neutralise. Total: an unreadable path or a kernel without xattr support answers False."""
    try:
        mode = os.stat(path).st_mode
        if mode & (0o4000 | 0o2000):
            return True
    except OSError:
        return False
    try:
        return b"" != os.getxattr(path, "security.capability")
    except (OSError, AttributeError, ValueError):
        return False


def refuses_to_wrap(tool_argv: list) -> str | None:
    """Why this argv must not be wrapped, or None if wrapping is safe.

    Refusing is the whole point: a guard that quietly turns a scanner into a no-op is worse than no
    guard, because its silence reads as a clean result."""
    if not tool_argv:
        return None
    argv0 = str(tool_argv[0])
    name = os.path.basename(argv0).lower()
    if name in _PRIVILEGE_DEPENDENT:
        return (f"{name} depends on elevated privilege (file capabilities). The guard must set "
                f"NO_NEW_PRIVS to install an unprivileged seccomp filter, which blocks that "
                f"elevation — {name} would run crippled and report NOTHING while exiting 0, a false "
                f"negative indistinguishable from a clean target. Run {name} unguarded (its argv is "
                f"already scope-pinned to loopback), or guard the tools that actually phone home.")
    if _is_privileged_binary(argv0):
        return (f"{argv0} is setuid/setgid or carries file capabilities; NO_NEW_PRIVS would strip "
                f"them and the tool's result could not be trusted.")
    return None


def _mode() -> str:
    return (os.environ.get("VIGIL_EGRESS_GUARD") or "").strip().lower()


def enabled() -> bool:
    return _mode() in {"1", "true", "yes", "on", "require"}


def required() -> bool:
    return _mode() == "require"


def guard_binary() -> str | None:
    """The guard executable, or None. Explicit env path wins; then the in-repo build; then PATH."""
    explicit = (os.environ.get("VIGIL_EGRESS_GUARD_BIN") or "").strip()
    if explicit:
        return explicit if os.access(explicit, os.X_OK) else None
    if _REPO_BIN.is_file() and os.access(_REPO_BIN, os.X_OK):
        return str(_REPO_BIN)
    return shutil.which("egress_guard")


# A missing binary in plain enabled mode degrades to argv-unchanged (the documented, byte-identical
# fallback). That degradation was SILENT — an operator who set VIGIL_EGRESS_GUARD=1 believing spawns were
# syscall-supervised got no signal that the binary was never built, so every tool ran UNGUARDED with the
# same output as a guarded run. Emit ONE loud line to stderr the first time this happens in a process:
# louder than silence, quieter than a line per spawn (a scan spawns dozens of tools). `require` mode is
# unaffected — it still raises. Reset-once so the notice fires again in a fresh process (and is testable).
_warned_unavailable = False


def _warn_unavailable_once() -> None:
    """Warn ONCE per process that the guard was requested (VIGIL_EGRESS_GUARD=1) but its binary is absent,
    so spawns proceed UNGUARDED at the syscall level. Not an error — the argv allowlist and loopback pin
    stay in force and the run continues; this only makes the degradation visible instead of silent."""
    global _warned_unavailable
    if _warned_unavailable:
        return
    _warned_unavailable = True
    print(
        "[egress-guard] WARNING: VIGIL_EGRESS_GUARD is set but the guard binary was not found — tool "
        "spawns proceed UNGUARDED at the syscall level (the argv allowlist and loopback pin still apply, "
        "but the connect(2)/sendto(2)/sendmsg(2) supervisor does NOT). Build it with "
        "`make -C tools/egress-guard`, set VIGIL_EGRESS_GUARD_BIN=<path>, or use VIGIL_EGRESS_GUARD=require "
        "to fail closed.",
        file=sys.stderr,
    )


def wrap_argv(argv: list) -> list:
    """Return ``argv`` prefixed with the guard when it is enabled, else ``argv`` unchanged.

    Fail-closed only in ``require`` mode: there, an unavailable guard raises rather than silently
    spawning an unguarded tool — a guard you believe is on but is not is worse than no guard. In plain
    enabled mode an unavailable binary degrades to the previous behaviour (argv unchanged) but now emits
    ONE loud stderr warning (see :func:`_warn_unavailable_once`), because the guard is an ADDITIONAL
    control layered over the argv allowlist that is still in force.
    """
    if not enabled():
        return list(argv)
    breakage = refuses_to_wrap(list(argv))
    if breakage is not None:
        # NOT an exception: this tool is meant to run, just not under the guard. Returning the argv
        # unchanged keeps the scan honest (the argv allowlist and the loopback IP pin are still in
        # force); raising here would break every nmap row the moment the guard was switched on.
        return list(argv)
    binary = guard_binary()
    if binary is None:
        if required():
            raise EgressGuardUnavailable(
                "VIGIL_EGRESS_GUARD=require but the guard binary was not found — build it with "
                "`make -C tools/egress-guard` or set VIGIL_EGRESS_GUARD_BIN")
        _warn_unavailable_once()
        return list(argv)
    pre: list = [binary]
    log = (os.environ.get("VIGIL_EGRESS_GUARD_LOG") or "").strip()
    if log:
        pre += ["--log", log]
    if (os.environ.get("VIGIL_EGRESS_GUARD_FAIL") or "").strip().lower() in {"1", "true", "yes", "on"}:
        pre.append("--fail-on-egress")
    pre.append("--")
    return pre + [str(a) for a in argv]


def blocked_egress(exit_code: int | None) -> bool:
    """True when a run ended because the guard refused a non-loopback connect (fail-on-egress mode)."""
    return exit_code == EGRESS_BLOCKED_EXIT
