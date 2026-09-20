"""vigil_core.posture — the ONE parse of VIGIL's deployment-posture env, shared by both trust planes.

Two independent trust planes have to agree, byte-for-byte, on the same two facts:

  * whether the opt-in PRODUCTION posture is armed (``VIGIL_POSTURE=production`` / ``prod``), and
  * whether the legacy embedded shared owner token is honored.

The offense / integration plane reads them in ``vigil_integration.doctor``'s refuse-to-start PRODUCTION
gate (``vigil up`` / ``vigil engage``); the sovereign plane reads them in ``sigil.ui.server``'s request
auth. If those two parses ever drifted, a start path could pass while the running server still honored a
credential the posture forbids — a fail-open seam. Keeping the parse HERE, in the namespace-pure package
BOTH planes already import, makes "mirror the rule in both places" structural rather than a discipline that
can rot.

PURE STDLIB, namespace-pure: this module imports nothing from ``framework`` / ``strix`` / ``sigil`` /
``vigil_integration``, so it can be imported from either trust domain without dragging a dependency across
the two-env boundary (FATAL-2). It is a handful of env reads and predicates.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

# The deployment-posture selector. ``production`` / ``prod`` (case-insensitive) arm the refuse-to-start
# PRODUCTION gate; anything else (unset included) leaves it inert. The two values mirror build_envs.sh's
# lock_missing_or_die parse so the CLI, the build, and the server never disagree on what "production" means.
POSTURE_ENV = "VIGIL_POSTURE"
_PRODUCTION_VALUES = frozenset({"production", "prod"})

# The legacy embedded shared owner token toggle. UNSET (the default) => the token is ENABLED: it is a
# documented fail-open dev convenience so the owner physically at the host is never locked out. Set to a
# falsy value => the operator has EXPLICITLY disabled it (per-user proof-of-possession auth only).
LEGACY_OWNER_TOKEN_ENV = "SIGIL_LEGACY_OWNER_TOKEN"
_FALSY = frozenset({"0", "off", "false", "no", "disabled"})

# The GOVERNED deployment posture (a client / national-agency deployment that still needs external egress).
# Truthy ``VIGIL_GOVERNED`` disables the legacy fail-open owner token — requiring per-user proof-of-possession
# auth, exactly like production — WITHOUT arming production's refuse-to-start / loopback-only egress lockdown.
# So a governed deployment is fail-closed on AUTH and can still run authorized EXTERNAL engagements (the two
# concerns production bundles are decoupled here). Unset (the default) leaves both facts unchanged, so dev /
# single-owner-on-host bearer access is never silently broken.
GOVERNED_ENV = "VIGIL_GOVERNED"
_TRUTHY = frozenset({"1", "on", "true", "yes", "enabled"})


def _env(env: "Optional[Mapping[str, str]]") -> "Mapping[str, str]":
    return os.environ if env is None else env


def production_posture(env: "Optional[Mapping[str, str]]" = None) -> "Optional[str]":
    """The raw ``VIGIL_POSTURE`` value IFF it selects the production posture (case-insensitive
    ``production`` / ``prod``), else ``None``. The single source of truth for 'is the production posture
    armed?' — every caller keys on this so the arming rule cannot drift between the start paths and the
    running server."""
    raw = _env(env).get(POSTURE_ENV, "").strip()
    return raw if raw.lower() in _PRODUCTION_VALUES else None


def is_production_posture(env: "Optional[Mapping[str, str]]" = None) -> bool:
    """True IFF the PRODUCTION posture is armed. Convenience over ``production_posture(...) is not None``."""
    return production_posture(env) is not None


def is_governed_posture(env: "Optional[Mapping[str, str]]" = None) -> bool:
    """True IFF the GOVERNED deployment posture is armed (truthy ``VIGIL_GOVERNED``). Governed refuses the
    legacy fail-open owner token — requiring per-user proof-of-possession auth, the same auth posture
    production enforces — but WITHOUT production's refuse-to-start / loopback-only egress lockdown, so an
    authorized external engagement can still run. Default (unset) is False, so it never silently changes
    an existing deployment's behaviour."""
    return _env(env).get(GOVERNED_ENV, "").strip().lower() in _TRUTHY


def legacy_owner_token_disabled(env: "Optional[Mapping[str, str]]" = None) -> bool:
    """True IFF the operator has EXPLICITLY disabled the legacy shared owner token via a falsy
    ``SIGIL_LEGACY_OWNER_TOKEN``. Default (unset / any non-falsy value) is ENABLED ⇒ ``False``."""
    return _env(env).get(LEGACY_OWNER_TOKEN_ENV, "").strip().lower() in _FALSY


def legacy_owner_token_grants_owner(env: "Optional[Mapping[str, str]]" = None) -> bool:
    """Whether the legacy embedded shared owner token may resolve to the owner principal RIGHT NOW.

    FAIL-CLOSED under production OR governed: ``VIGIL_POSTURE=production`` (W10-7) AND the GOVERNED posture
    (``VIGIL_GOVERNED`` truthy) both refuse the token unconditionally — per-user proof-of-possession auth is
    required there — regardless of the toggle. Outside those the operator may still opt out explicitly with
    ``SIGIL_LEGACY_OWNER_TOKEN=0``. So the token grants owner ONLY when the posture is neither production nor
    governed AND the toggle has not been disabled."""
    return (
        (not is_production_posture(env))
        and (not is_governed_posture(env))
        and (not legacy_owner_token_disabled(env))
    )
