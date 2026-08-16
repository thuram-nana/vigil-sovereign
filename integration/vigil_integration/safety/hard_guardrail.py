"""
hard_guardrail — RE-EXPORT of the deterministic scope floor now owned by ``vigil_core`` (Slice 0).

The canonical guard was relocated to ``vigil_core.hard_guardrail`` (pure stdlib, namespace-pure) so BOTH
the offense engine (``framework.v2``) and this integration plane import the SAME floor without a reversed
``framework → vigil_integration`` import edge (FATAL-2). This module re-exports the full public API so every
existing importer of ``vigil_integration.safety.hard_guardrail`` keeps working byte-identically — mirroring
the ``vigil_core.gate`` ← ``vigil_integration.conjunctive_gate`` precedent.

Public API (see ``vigil_core.hard_guardrail`` for the implementation and doctrine):
  * ``is_hard_blocked`` / ``assert_not_hard_blocked`` / ``candidate_hosts`` / ``normalize_domain`` — the
    pure, env-free categorical matcher (gov/mil/edu/IGO, client-independent).
  * ``protected_guard_enabled`` — the owner toggle reader (fail-safe: unset/empty/junk ⇒ protected).
  * ``HardBlockError`` — the fail-closed categorical refusal.
"""

from __future__ import annotations

from vigil_core.hard_guardrail import *  # noqa: F401,F403 — re-export the full public API
from vigil_core.hard_guardrail import __all__  # noqa: F401 — keep `import *` surface identical
