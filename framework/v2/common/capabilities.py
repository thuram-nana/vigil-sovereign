"""
common.capabilities — probe for OPTIONAL, heavy dependencies (Workstream G).

CRUCIBLE ships lean and deterministic: every capability declared here has a
pure-stdlib fallback and is **absent by default**. These probes let a subsystem
ask "is the accelerated / enriched backend importable?" cheaply (via
``importlib.util.find_spec``, without importing the heavy module) so it can
choose a code path WITHOUT changing behaviour when the dep is missing.

Doctrine (see CLAUDE.md / metacognition):

  * An optional dep may only **accelerate** or **enrich** — never gate a
    surface out, never feed the deterministic oracle / SCE / calibration
    inputs, and never promote a finding.
  * It must not introduce nondeterminism on the default/replayed path. Where
    the mere *presence* of a dep could change results (numeric acceleration,
    a semantic model), the accelerated path is ALSO guarded behind an explicit
    opt-in flag, so the default path is byte-identical whether or not the dep
    happens to be importable in the environment.

Capabilities:

    has_numpy()    — numpy importable (fast integer numerics)
    has_z3()       — z3 importable (bounded SMT / constraint feasibility)
    has_semantic() — sentence-transformers importable (semantic embeddings)

Opt-in gates (dep present AND flag set):

    fast_numerics_enabled()  — CRUCIBLE_FAST_NUMERICS + numpy
"""

from __future__ import annotations

import importlib.util
import os
from functools import lru_cache

# --------------------------------------------------------------------------
# Raw importability probes — cached (importability does not change at runtime).
# --------------------------------------------------------------------------


def _spec_exists(module: str) -> bool:
    """True iff ``module`` is importable, WITHOUT importing it. Total: any
    probing error (malformed namespace package, partially-installed dep) is
    treated as 'absent' so a broken optional dep degrades to the default path
    rather than raising."""
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


@lru_cache(maxsize=None)
def has_numpy() -> bool:
    return _spec_exists("numpy")


@lru_cache(maxsize=None)
def has_z3() -> bool:
    # z3-solver installs a top-level module named ``z3``.
    return _spec_exists("z3")


@lru_cache(maxsize=None)
def has_semantic() -> bool:
    # sentence-transformers installs ``sentence_transformers``.
    return _spec_exists("sentence_transformers")


# --------------------------------------------------------------------------
# Opt-in flags — read live (env may be set per-process/per-test), never cached.
# --------------------------------------------------------------------------

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def fast_numerics_enabled() -> bool:
    """numpy acceleration is OPT-IN: it fires only when numpy is importable AND
    ``CRUCIBLE_FAST_NUMERICS`` is truthy. Default OFF, so the deterministic
    pure-Python numeric path runs even in environments where numpy is present
    (which keeps the regression gate byte-identical)."""
    return _flag("CRUCIBLE_FAST_NUMERICS") and has_numpy()


def reset_cache() -> None:
    """Clear the importability caches (tests that simulate presence/absence)."""
    has_numpy.cache_clear()
    has_z3.cache_clear()
    has_semantic.cache_clear()


__all__ = [
    "has_numpy",
    "has_z3",
    "has_semantic",
    "fast_numerics_enabled",
    "reset_cache",
]
