"""SEAM BASE — the ONE resolver for the cross-plane seam base directory (E3a).

The seam base is the directory every plane meets in for a customer launch: the sovereign cockpit publishes the
owner-signed credit lease, the target authorization and the pause / settlement markers there; the keyless
offense engine verifies the lease, burns its single-use floor and records its arm attempts there; the settle
drain reads the lease and writes the settlement + tombstone there; the offense backup captures it. Every one of
them used to restate ``os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"`` on its own, CWD-relative, so two
processes started from different working directories (the shipped units do exactly that) silently read and
wrote different trees: the drain found no published lease, every completion became a no-op, and the reserved
credits were never charged or refunded.

Precedence: an ``explicit`` value > ``$VIGIL_BASE_DIR`` > ``.vigil-live`` (an empty value counts as unset, as
the copies it replaces did). The winner is absolutised HERE, once (``~`` expanded, made absolute against the
current directory), so a path one process hands to another — a child's env, a printed command — names the same
directory wherever it is read. For a given working directory this is the same directory the relative copies
named, so behaviour with ``VIGIL_BASE_DIR`` set, or the default used from the same directory, is unchanged.

:func:`require_seam_base` is the strict form for a MONEY process (the settle drain): it refuses, instead of
silently picking one, when the settings it can see disagree.

FATAL-2: stdlib ONLY — no ``framework.*``, no ``sigil.*``, no ``vigil_integration.*`` — so the sovereign plane,
the integration glue and the keyless offense engine all import this one leaf.
"""
from __future__ import annotations

import os
from typing import Any

#: The environment variable every plane reads the seam base from.
SEAM_BASE_ENV = "VIGIL_BASE_DIR"
#: The default seam base, relative to the current directory (the historical convention).
DEFAULT_SEAM_BASE = ".vigil-live"
#: The settle drain's former, separate seam variable. Still honoured only to REFUSE a contradiction: a drain
#: configured with it must name the same directory as ``VIGIL_BASE_DIR`` (or it settles against a tree the
#: cockpit never published to).
LEGACY_SETTLE_BASE_ENV = "VIGIL_SETTLE_BASE_DIR"


class SeamBaseError(ValueError):
    """The seam-base settings a money process was given are contradictory or unusable."""


def _absolute(raw: Any) -> str:
    value = str(raw)
    try:
        return os.path.abspath(os.path.expanduser(value))
    except (OSError, ValueError):   # e.g. the working directory was removed: keep the historical relative form
        return value


def resolve_seam_base(explicit: Any = None) -> str:
    """THE seam base, as an ABSOLUTE path: ``explicit`` > ``$VIGIL_BASE_DIR`` > ``.vigil-live``. Total: never
    raises (if the current directory cannot be read the winner is returned as given, as the copies did)."""
    return _absolute(explicit or os.environ.get(SEAM_BASE_ENV) or DEFAULT_SEAM_BASE)


def require_seam_base(explicit: Any = None, *, aliases: "tuple[str, ...]" = (LEGACY_SETTLE_BASE_ENV,)) -> str:
    """The seam base for a MONEY process, refusing ambiguity. Every source that is SET — ``explicit``,
    ``$VIGIL_BASE_DIR`` and each variable in ``aliases`` — must resolve to the directory
    :func:`resolve_seam_base` picks, and none may still carry an unexpanded systemd specifier (``%h`` etc.:
    systemd never expands one inside an ``EnvironmentFile`` value, so it reaches the process literally and
    would name a wrong, empty directory). Raises :class:`SeamBaseError` naming every source otherwise. With
    nothing set it is :func:`resolve_seam_base` (the ``.vigil-live`` default)."""
    sources: list[tuple[str, str]] = []
    if explicit:
        sources.append(("--base-dir", str(explicit)))
    for name in (SEAM_BASE_ENV, *aliases):
        value = os.environ.get(name)
        if value:
            sources.append((name, value))
    for name, value in sources:
        if "%" in value:
            raise SeamBaseError(
                f"{name}={value!r} still carries an unexpanded systemd specifier — systemd does not expand % "
                f"inside an EnvironmentFile value. Set an absolute path.")
    base = resolve_seam_base(explicit)
    if any(_absolute(value) != base for _, value in sources):
        named = ", ".join(f"{name}={value!r} ({_absolute(value)})" for name, value in sources)
        raise SeamBaseError(
            f"contradictory seam base settings: {named}. They must all name ONE directory (the cockpit, the "
            f"offense engine and every drain share it); refusing rather than picking one.")
    return base
