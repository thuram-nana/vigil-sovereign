"""Wrap a live tool spawn in the loopback-only egress supervisor.

WHAT THIS CLOSES. The live Kali-tool path spawns tools directly on the host. Its no-egress guarantee was
held by an argv allowlist — the wapiti module allowlist, nuclei's ``-disable-update-check``, nikto's
``-notel`` — and verified only by argv-CONSTRUCTION tests. That is a guarantee that a tool will not be
ASKED to egress. It is not a guarantee that the tool does not egress anyway, which is exactly the class of
defect that kept recurring: wapiti's DEFAULT modules reached ``wapiti3.ovh``; ``wapp`` downloaded a
technology database; nuclei phoned home on two sensor routes that no gate covered. Each was invisible
until something RAN.

``tools/egress-guard/egress_guard.c`` polices ``connect(2)`` with a seccomp user-notify filter: loopback
(``127.0.0.0/8``, ``::1``, ``::ffff:127.x``) and non-IP families (AF_UNIX, netlink) proceed; anything else
is refused with ECONNREFUSED and recorded. Because it filters the SYSCALL rather than libc, it covers
statically linked Go binaries — measured: ``nuclei`` (static) attempts a DNS connect merely to print its
version, and the guard blocks it. An ``LD_PRELOAD`` shim cannot see that call at all, which is why this is
the primary mechanism and not the fallback.

DEFAULT OFF, opt-in by environment, so an operator's ordinary host run is byte-identical unless they ask
for the guard. Live-fire and CI turn it on.

  VIGIL_EGRESS_GUARD=1            wrap spawns when the guard binary is available
  VIGIL_EGRESS_GUARD=require      wrap, and REFUSE to spawn if the guard is unavailable (fail closed)
  VIGIL_EGRESS_GUARD_FAIL=1       a blocked connect fails the run (guard exits 97) rather than only logging
  VIGIL_EGRESS_GUARD_BIN=<path>   explicit binary path (else the in-repo build is used)
  VIGIL_EGRESS_GUARD_LOG=<path>   append the guard's decisions here

HONEST BOUND. Allowed connects use SECCOMP_USER_NOTIF_FLAG_CONTINUE, which has a documented TOCTOU: a
thread could rewrite the sockaddr between our read and the kernel's. That matters when sandboxing code
that is trying to escape. It does not describe this deployment — the tools are authorized, correlatable
and owner-run — so the guard is a control against a tool's own defaults and a mis-built argv, NOT a
containment boundary for hostile code. The kernel-isolation boundary remains ``sandbox_exec`` (bwrap
``--unshare-all``).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

# The guard's exit code when --fail-on-egress is set and at least one connect was blocked. Distinct from
# any tool's own exit code so the two are never confused in a record.
EGRESS_BLOCKED_EXIT = 97

_REPO_BIN = Path(__file__).resolve().parents[3] / "tools" / "egress-guard" / "egress_guard"


class EgressGuardUnavailable(RuntimeError):
    """Raised only in ``require`` mode: the guard was demanded and could not be found."""


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


def wrap_argv(argv: list) -> list:
    """Return ``argv`` prefixed with the guard when it is enabled, else ``argv`` unchanged.

    Fail-closed only in ``require`` mode: there, an unavailable guard raises rather than silently
    spawning an unguarded tool — a guard you believe is on but is not is worse than no guard. In plain
    enabled mode an unavailable binary degrades to the previous behaviour (argv unchanged), because the
    guard is an ADDITIONAL control layered over the argv allowlist that is still in force.
    """
    if not enabled():
        return list(argv)
    binary = guard_binary()
    if binary is None:
        if required():
            raise EgressGuardUnavailable(
                "VIGIL_EGRESS_GUARD=require but the guard binary was not found — build it with "
                "`make -C tools/egress-guard` or set VIGIL_EGRESS_GUARD_BIN")
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
