"""coverage_flag — the master, default-OFF flag for the F4 graph's coverage rollup (S5).

``VIGIL_COVERAGE_VIEW`` gates (a) whether the spine→graph projector recognises the S5 ``tested`` record
kind and the ``ChainStep -[TESTED]-> asset`` coverage edge, and (b) whether ``graph.query`` exposes the
``coverage(view)`` read at all. It mirrors ``objectives_flag.objectives_enabled`` /
``projector.lifecycle_enabled`` exactly: a KEYLESS, offense-plane ENV read, never a secret, framework-free
(stdlib ``os`` only) — FATAL-2 clean.

Default OFF — the affirmative-flag convention: unset / empty / any value outside ``{1,true,yes,on}`` is OFF.
When OFF the projector treats ``tested`` as an UNKNOWN kind (already fail-closed-ignored), NO ``TESTED`` edge
is projected, and ``graph.query`` exposes NO ``coverage`` symbol — so the query public API and the projected
``GraphView`` are BYTE-IDENTICAL to the pre-slice read-model. Nothing here mints, authorises, or widens scope:
it only decides whether the (inert, non-authoritative) coverage edge and read are available at all. A coverage
claim grants nothing and can NEVER become an input that relaxes a gate.
"""

from __future__ import annotations

import os
from typing import Mapping, Optional

COVERAGE_ENV = "VIGIL_COVERAGE_VIEW"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def coverage_view_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """True iff the coverage rollup is switched on (``VIGIL_COVERAGE_VIEW`` ∈ {1,true,yes,on},
    case-insensitive). Default OFF: unset / empty / any other value is OFF, the projected ``GraphView`` stays
    byte-identically the pre-slice read-model (the ``tested`` record is ignored as an unknown kind, no
    ``TESTED`` edge), and ``graph.query`` exposes no ``coverage`` function. Keyless: it reads an env flag,
    never a secret — FATAL-2 clean, mirroring ``objectives_enabled`` / ``lifecycle_enabled``."""
    e = os.environ if env is None else env
    return str(e.get(COVERAGE_ENV, "") or "").strip().lower() in _TRUTHY
