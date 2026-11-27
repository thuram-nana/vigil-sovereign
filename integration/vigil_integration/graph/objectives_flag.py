"""objectives_flag — the master, default-OFF flag for the F4 graph's charter-objective projection (S3).

``VIGIL_GRAPH_OBJECTIVES`` gates whether the spine→graph projector recognises the S3 record kinds (a
declared charter ``goal`` and a crown-jewel ``reach``) and the step→objective ``PURSUES`` linkage. It
mirrors ``multilang_flag.multilang_codescan_enabled`` / ``oracle_families.redrive_flag_enabled`` exactly:
a KEYLESS, offense-plane ENV read, never a secret, framework-free (stdlib ``os`` only).

Default OFF — the affirmative-flag convention: unset / empty / any value outside ``{1,true,yes,on}`` is
OFF. When OFF the projector treats ``goal`` / ``reach`` as UNKNOWN kinds (already fail-closed-ignored) and
a step's declared objective id produces NO ``PURSUES`` edge, so the ``GraphView`` is BYTE-IDENTICAL to the
pre-S3 read-model. Nothing here mints, authorises, or widens scope: it only decides whether the (inert,
non-authoritative) Goal node and its edges are projected at all.
"""

from __future__ import annotations

import os
from typing import Mapping, Optional

OBJECTIVES_ENV = "VIGIL_GRAPH_OBJECTIVES"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def objectives_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """True iff the charter-objective projection is switched on (``VIGIL_GRAPH_OBJECTIVES`` ∈
    {1,true,yes,on}, case-insensitive). Default OFF: unset / empty / any other value is OFF, and the
    projected ``GraphView`` stays byte-identically the pre-S3 read-model (``goal`` / ``reach`` records are
    ignored as unknown kinds, a step's objective id adds no ``PURSUES`` edge). Keyless: it reads an env
    flag, never a secret — FATAL-2 clean, mirroring ``redpen_enabled`` / ``multilang_codescan_enabled``."""
    e = os.environ if env is None else env
    return str(e.get(OBJECTIVES_ENV, "") or "").strip().lower() in _TRUTHY
